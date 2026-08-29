"use strict";

const { describe, it, beforeEach, afterEach, mock } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  resolveOutboxDir,
  resolveDeadLetterDir,
  ensureOutboxDir,
  enqueueOutboxEntry,
  listOutboxEntries,
  listDeadLetterEntries,
  acknowledgeOutboxEntry,
  transmitOutboxEntry,
  drainOutbox,
  createEvidenceBuffer,
  OUTBOX_DIR_NAME,
  MAX_ATTEMPTS_BEFORE_QUARANTINE,
} = require("./index.js");

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "ttagent-outbox-"));
}

describe("outbox", () => {
  let dir;
  let outboxDir;

  beforeEach(() => {
    dir = makeTempDir();
    outboxDir = resolveOutboxDir(dir);
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("resolves the default outbox directory under the config dir", () => {
    assert.equal(outboxDir, path.join(dir, OUTBOX_DIR_NAME));
  });

  it("persists entries with 0600 files under a 0700 directory", () => {
    ensureOutboxDir(outboxDir);
    const entry = enqueueOutboxEntry(outboxDir, {
      id: "outbox-test-1",
      result: { jobId: "job-1", attemptId: "attempt-1", status: "succeeded" },
      evidence: [{ jobId: "job-1", evidenceItems: [{ eventType: "validation.passed", observedAt: "2026-07-24T00:00:00.000Z" }] }],
    });

    assert.equal(entry.id, "outbox-test-1");
    const filePath = path.join(outboxDir, "outbox-test-1.json");
    assert.equal(fs.existsSync(filePath), true);

    if (process.platform !== "win32") {
      const dirMode = fs.statSync(outboxDir).mode & 0o777;
      const fileMode = fs.statSync(filePath).mode & 0o777;
      assert.equal(dirMode, 0o700);
      assert.equal(fileMode, 0o600);
    }

    const listed = listOutboxEntries(outboxDir);
    assert.equal(listed.length, 1);
    assert.equal(listed[0].result.status, "succeeded");
    assert.equal(listed[0].evidence.length, 1);
  });

  it("transmits evidence then result and acknowledges only after success", async () => {
    const entry = enqueueOutboxEntry(outboxDir, {
      id: "outbox-tx-1",
      result: { jobId: "job-1", attemptId: "a1", status: "succeeded" },
      evidence: [{ jobId: "job-1", evidenceItems: [{ eventType: "policy.checked", observedAt: "2026-07-24T00:00:00.000Z" }] }],
    });

    const order = [];
    const client = {
      reportEvidence: async (body) => {
        order.push("evidence");
        assert.equal(body.jobId, "job-1");
      },
      reportResult: async (body) => {
        order.push("result");
        assert.equal(body.status, "succeeded");
      },
    };

    await transmitOutboxEntry(entry, client);
    assert.deepEqual(order, ["evidence", "result"]);

    acknowledgeOutboxEntry(outboxDir, entry.id);
    assert.equal(listOutboxEntries(outboxDir).length, 0);
  });

  it("leaves the entry on disk when transmission fails so retries stay idempotent", async () => {
    enqueueOutboxEntry(outboxDir, {
      id: "outbox-fail-1",
      result: { jobId: "job-2", attemptId: "a2", status: "succeeded" },
      evidence: [],
    });

    let nowMs = Date.parse("2026-08-27T00:00:00.000Z");
    const client = {
      reportEvidence: async () => {},
      reportResult: async () => {
        throw new Error("network down");
      },
    };

    const drain = await drainOutbox(outboxDir, client, { now: () => nowMs });
    assert.equal(drain.transmitted, 0);
    assert.equal(drain.remaining, 1);
    assert.equal(listOutboxEntries(outboxDir)[0].result.status, "succeeded");
    assert.equal(listOutboxEntries(outboxDir)[0].attempts, 1);

    // Retrying before the backoff window elapses is deferred, not attempted.
    let calls = 0;
    const okClient = {
      reportEvidence: async () => {},
      reportResult: async () => {
        calls += 1;
      },
    };
    const tooSoon = await drainOutbox(outboxDir, okClient, { now: () => nowMs + 1000 });
    assert.equal(calls, 0);
    assert.equal(tooSoon.deferred, 1);
    assert.equal(tooSoon.remaining, 1);

    // Once the backoff window has elapsed, the entry is retried again.
    nowMs += 20_000;
    const retry = await drainOutbox(outboxDir, okClient, { now: () => nowMs });
    assert.equal(calls, 1);
    assert.equal(retry.transmitted, 1);
    assert.equal(retry.remaining, 0);
  });

  it("backs off exponentially (within jitter tolerance) and caps at a maximum retry interval", () => {
    const { computeRetryBackoffMs } = require("./index.js");
    const assertWithinJitter = (actual, base) => {
      assert.ok(
        actual >= Math.floor(base * 0.8) && actual <= Math.ceil(base * 1.2),
        `expected ${actual} to be within +/-20% of ${base}`,
      );
    };
    for (let i = 0; i < 25; i += 1) {
      assertWithinJitter(computeRetryBackoffMs(0), 15_000);
      assertWithinJitter(computeRetryBackoffMs(1), 30_000);
      assertWithinJitter(computeRetryBackoffMs(2), 60_000);
      assertWithinJitter(computeRetryBackoffMs(20), 30 * 60_000);
    }
  });

  it("computeRetryBackoffMs returns a positive integer and varies across calls (jitter is actually applied)", () => {
    const { computeRetryBackoffMs } = require("./index.js");
    const samples = new Set();
    for (let i = 0; i < 50; i += 1) {
      const value = computeRetryBackoffMs(3);
      assert.equal(Number.isInteger(value), true);
      assert.ok(value > 0);
      samples.add(value);
    }
    // Statistically near-impossible for 50 jittered samples to collapse
    // to a single value unless jitter was accidentally removed.
    assert.ok(samples.size > 1);
  });

  it("createEvidenceBuffer collects reportEvidence without networking", async () => {
    const buffer = createEvidenceBuffer();
    await buffer.reportEvidence({ jobId: "j", evidenceItems: [] });
    await buffer.reportEvidence({ jobId: "j2", evidenceItems: [] });
    const taken = buffer.takeEvidence();
    assert.equal(taken.length, 2);
    assert.deepEqual(buffer.takeEvidence(), []);
  });

  it("quarantines a permanently-failing entry (4xx-style error) into dead-letter/, keeping its diagnostic fields", async () => {
    enqueueOutboxEntry(outboxDir, {
      id: "outbox-permanent-1",
      result: { jobId: "job-perm", attemptId: "a1", status: "succeeded" },
      evidence: [],
    });

    const nowMs = Date.parse("2026-08-28T00:00:00.000Z");
    const client = {
      reportEvidence: async () => {},
      reportResult: async () => {
        throw Object.assign(new Error("reportResult failed with HTTP 409"), { status: 409, code: "http_error" });
      },
    };

    const drain = await drainOutbox(outboxDir, client, { now: () => nowMs });
    assert.equal(drain.transmitted, 0);
    assert.equal(drain.quarantined, 1);
    assert.equal(drain.remaining, 0);

    // Gone from the main outbox on the very next listing.
    assert.equal(listOutboxEntries(outboxDir).length, 0);

    const deadLetter = listDeadLetterEntries(outboxDir);
    assert.equal(deadLetter.length, 1);
    assert.equal(deadLetter[0].id, "outbox-permanent-1");
    assert.equal(deadLetter[0].attempts, 1);
    assert.equal(deadLetter[0].lastErrorMessage, "reportResult failed with HTTP 409");
    assert.equal(typeof deadLetter[0].lastAttemptAt, "string");
    assert.equal(deadLetter[0].result.status, "succeeded");

    if (process.platform !== "win32") {
      const deadLetterDir = resolveDeadLetterDir(outboxDir);
      const dirMode = fs.statSync(deadLetterDir).mode & 0o777;
      const fileMode = fs.statSync(path.join(deadLetterDir, "outbox-permanent-1.json")).mode & 0o777;
      assert.equal(dirMode, 0o700);
      assert.equal(fileMode, 0o600);
    }
  });

  it("quarantines an entry once it reaches MAX_ATTEMPTS_BEFORE_QUARANTINE, even without a permanent-error signal", async () => {
    enqueueOutboxEntry(outboxDir, {
      id: "outbox-exhausted-1",
      result: { jobId: "job-exhaust", attemptId: "a1", status: "succeeded" },
      evidence: [],
    });

    let nowMs = Date.parse("2026-08-28T00:00:00.000Z");
    const client = {
      reportEvidence: async () => {},
      reportResult: async () => {
        // No status at all: never classified permanent by the default
        // heuristic, so only attempt exhaustion can quarantine this one.
        throw new Error("connection reset");
      },
    };

    let lastDrain;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS_BEFORE_QUARANTINE; attempt += 1) {
      lastDrain = await drainOutbox(outboxDir, client, { now: () => nowMs });
      if (attempt < MAX_ATTEMPTS_BEFORE_QUARANTINE) {
        assert.equal(lastDrain.quarantined, 0, `attempt ${attempt} should not quarantine yet`);
        assert.equal(listOutboxEntries(outboxDir).length, 1);
        // Push nowMs past whatever backoff (with jitter) was just set so
        // the next drain call actually attempts a retry.
        const [pending] = listOutboxEntries(outboxDir);
        nowMs = Date.parse(pending.nextRetryAt) + 1;
      }
    }

    assert.equal(lastDrain.quarantined, 1);
    assert.equal(lastDrain.remaining, 0);
    assert.equal(listOutboxEntries(outboxDir).length, 0);

    const deadLetter = listDeadLetterEntries(outboxDir);
    assert.equal(deadLetter.length, 1);
    assert.equal(deadLetter[0].attempts, MAX_ATTEMPTS_BEFORE_QUARANTINE);
    assert.equal(deadLetter[0].lastErrorMessage, "connection reset");
  });

  it("does NOT quarantine a transient failure (5xx or no status) -- it stays retryable with backoff", async () => {
    enqueueOutboxEntry(outboxDir, {
      id: "outbox-transient-1",
      result: { jobId: "job-transient", attemptId: "a1", status: "succeeded" },
      evidence: [],
    });
    enqueueOutboxEntry(outboxDir, {
      id: "outbox-transient-2",
      result: { jobId: "job-transient-2", attemptId: "a1", status: "succeeded" },
      evidence: [],
    });

    const nowMs = Date.parse("2026-08-28T00:00:00.000Z");
    let call = 0;
    const client = {
      reportEvidence: async () => {},
      reportResult: async () => {
        call += 1;
        if (call === 1) {
          throw Object.assign(new Error("reportResult failed with HTTP 503"), { status: 503, code: "http_error" });
        }
        // Plain network failure, no status/code at all.
        throw new Error("network request to control plane failed");
      },
    };

    const drain = await drainOutbox(outboxDir, client, { now: () => nowMs });
    assert.equal(drain.transmitted, 0);
    assert.equal(drain.quarantined, 0);
    assert.equal(drain.remaining, 2);

    const stillPending = listOutboxEntries(outboxDir);
    assert.equal(stillPending.length, 2);
    for (const entry of stillPending) {
      assert.equal(entry.attempts, 1);
      assert.equal(typeof entry.nextRetryAt, "string");
    }
    assert.equal(listDeadLetterEntries(outboxDir).length, 0);
  });

  it("401/403 are treated as transient by the default classifier (recoverable via credential re-read, not this entry's content)", async () => {
    enqueueOutboxEntry(outboxDir, {
      id: "outbox-auth-1",
      result: { jobId: "job-auth", attemptId: "a1", status: "succeeded" },
      evidence: [],
    });

    const nowMs = Date.parse("2026-08-28T00:00:00.000Z");
    const client = {
      reportEvidence: async () => {},
      reportResult: async () => {
        throw Object.assign(new Error("reportResult failed with HTTP 401"), { status: 401, code: "http_error" });
      },
    };

    const drain = await drainOutbox(outboxDir, client, { now: () => nowMs });
    assert.equal(drain.quarantined, 0);
    assert.equal(drain.remaining, 1);
    assert.equal(listOutboxEntries(outboxDir).length, 1);
  });

  it("a caller-supplied isPermanent classifier overrides the default heuristic", async () => {
    enqueueOutboxEntry(outboxDir, {
      id: "outbox-custom-classifier-1",
      result: { jobId: "job-custom", attemptId: "a1", status: "succeeded" },
      evidence: [],
    });

    const nowMs = Date.parse("2026-08-28T00:00:00.000Z");
    const client = {
      reportEvidence: async () => {},
      reportResult: async () => {
        // No HTTP status at all -- the default classifier would call
        // this transient, but the custom classifier below overrides it.
        throw new Error("CERTOPS_TRUST_RESULT_INVALID");
      },
    };

    const drain = await drainOutbox(outboxDir, client, {
      now: () => nowMs,
      isPermanent: (err) => err.message === "CERTOPS_TRUST_RESULT_INVALID",
    });
    assert.equal(drain.quarantined, 1);
    assert.equal(listOutboxEntries(outboxDir).length, 0);
    assert.equal(listDeadLetterEntries(outboxDir).length, 1);
  });

  it("drainOutbox performs exactly one full directory listing per call, even with many due and deferred entries", async () => {
    const nowMs = Date.parse("2026-08-28T00:00:00.000Z");
    ensureOutboxDir(outboxDir);
    // Write fixture entries directly (bypassing enqueueOutboxEntry's
    // full atomic-write + permissions-hardening path, which is
    // irrelevant to what this test asserts and would dominate its
    // runtime with icacls calls on win32) so this stays a fast,
    // focused check of the readdirSync call count.
    const writeFixtureEntry = (id, extra = {}) => {
      const entry = {
        id,
        createdAt: "2026-08-27T00:00:00.000Z",
        result: { jobId: id, attemptId: "a1", status: "succeeded" },
        evidence: [],
        ...extra,
      };
      fs.writeFileSync(path.join(outboxDir, `${id}.json`), `${JSON.stringify(entry)}\n`, "utf8");
      return entry;
    };
    for (let i = 0; i < 50; i += 1) {
      writeFixtureEntry(`outbox-due-${i}`);
    }
    for (let i = 0; i < 50; i += 1) {
      writeFixtureEntry(`outbox-deferred-${i}`, {
        attempts: 1,
        nextRetryAt: new Date(nowMs + 60_000).toISOString(),
      });
    }

    const client = {
      reportEvidence: async () => {},
      reportResult: async () => {},
    };

    let readdirCalls = 0;
    const original = fs.readdirSync.bind(fs);
    const spy = mock.method(fs, "readdirSync", (...args) => {
      readdirCalls += 1;
      return original(...args);
    });

    let drain;
    try {
      drain = await drainOutbox(outboxDir, client, { now: () => nowMs });
    } finally {
      spy.mock.restore();
    }

    assert.equal(drain.transmitted, 50);
    assert.equal(drain.deferred, 50);
    assert.equal(drain.quarantined, 0);
    assert.equal(drain.remaining, 50);
    // Exactly one readdirSync call for the main outbox directory. (No
    // dead-letter directory was touched since nothing was quarantined.)
    assert.equal(readdirCalls, 1);
  });
});
