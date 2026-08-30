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
  pruneDeadLetterEntries,
  createEvidenceBuffer,
  OUTBOX_DIR_NAME,
  MAX_TRANSIENT_RETRY_AGE_MS,
  FALLBACK_MAX_ATTEMPTS_BEFORE_QUARANTINE,
  MAX_DEAD_LETTER_AGE_MS,
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

  it("quarantines a transient failure once it has been retrying for MAX_TRANSIENT_RETRY_AGE_MS, even without a permanent-error signal", async () => {
    const createdAtMs = Date.parse("2026-08-28T00:00:00.000Z");
    enqueueOutboxEntry(outboxDir, {
      id: "outbox-exhausted-1",
      createdAt: new Date(createdAtMs).toISOString(),
      result: { jobId: "job-exhaust", attemptId: "a1", status: "succeeded" },
      evidence: [],
    });

    const client = {
      reportEvidence: async () => {},
      reportResult: async () => {
        // No status at all: never classified permanent by the default
        // heuristic, so only the transient-retry-age ceiling can
        // quarantine this one.
        throw new Error("connection reset");
      },
    };

    // First attempt, right when the entry becomes due: fails, starts backoff.
    const firstAttempt = await drainOutbox(outboxDir, client, { now: () => createdAtMs });
    assert.equal(firstAttempt.quarantined, 0);
    assert.equal(listOutboxEntries(outboxDir).length, 1);

    // Well past the first attempt's short backoff, but still short of the
    // ceiling: still retryable.
    const beforeCeiling = await drainOutbox(outboxDir, client, {
      now: () => createdAtMs + MAX_TRANSIENT_RETRY_AGE_MS - 1000,
    });
    assert.equal(beforeCeiling.quarantined, 0);
    assert.equal(listOutboxEntries(outboxDir).length, 1);

    // Past the ceiling (and past the short backoff set by the previous
    // attempt): quarantined as a last resort.
    const atCeiling = await drainOutbox(outboxDir, client, {
      now: () => createdAtMs + MAX_TRANSIENT_RETRY_AGE_MS + 60_000,
    });
    assert.equal(atCeiling.quarantined, 1);
    assert.equal(atCeiling.remaining, 0);
    assert.equal(listOutboxEntries(outboxDir).length, 0);

    const deadLetter = listDeadLetterEntries(outboxDir);
    assert.equal(deadLetter.length, 1);
    assert.equal(deadLetter[0].lastErrorMessage, "connection reset");
  });

  it("quarantines a transient failure via the attempt-count fallback when createdAt cannot be parsed", async () => {
    ensureOutboxDir(outboxDir);
    // Written directly (bypassing enqueueOutboxEntry's createdAt
    // validation) to simulate a corrupted/hand-edited entry file with an
    // unparseable createdAt -- the only case where the fallback ceiling
    // (rather than the age-based one) governs quarantine.
    fs.writeFileSync(
      path.join(outboxDir, "outbox-corrupt-createdat.json"),
      `${JSON.stringify({
        id: "outbox-corrupt-createdat",
        createdAt: "not-a-real-date",
        result: { jobId: "job-corrupt", attemptId: "a1", status: "succeeded" },
        evidence: [],
        attempts: FALLBACK_MAX_ATTEMPTS_BEFORE_QUARANTINE - 1,
      })}\n`,
      "utf8",
    );

    const nowMs = Date.parse("2026-08-28T00:00:00.000Z");
    const client = {
      reportEvidence: async () => {},
      reportResult: async () => {
        throw new Error("connection reset");
      },
    };

    const drain = await drainOutbox(outboxDir, client, { now: () => nowMs });
    assert.equal(drain.quarantined, 1);
    assert.equal(listOutboxEntries(outboxDir).length, 0);
    assert.equal(listDeadLetterEntries(outboxDir).length, 1);
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

  it("pruneDeadLetterEntries deletes dead-letter entries older than MAX_DEAD_LETTER_AGE_MS", async () => {
    const deadLetterDir = resolveDeadLetterDir(outboxDir);
    fs.mkdirSync(deadLetterDir, { recursive: true });
    const nowMs = Date.parse("2026-08-28T00:00:00.000Z");

    const writeDeadLetterEntry = (id, createdAt, mtime) => {
      const entry = {
        id,
        createdAt,
        result: { jobId: id, attemptId: "a1", status: "succeeded" },
        evidence: [],
        attempts: 5,
      };
      const filePath = path.join(deadLetterDir, `${id}.json`);
      fs.writeFileSync(filePath, `${JSON.stringify(entry)}\n`, "utf8");
      // No quarantinedAt/lastAttemptAt on these fixtures (simulating a
      // legacy pre-fix entry), so age falls back to the file's own
      // mtime; back-date it to the entry's createdAt to exercise that
      // fallback rather than "now" (when the fixture happens to be
      // written).
      fs.utimesSync(filePath, new Date(mtime), new Date(mtime));
    };

    writeDeadLetterEntry(
      "outbox-old",
      new Date(nowMs - MAX_DEAD_LETTER_AGE_MS - 60_000).toISOString(),
      nowMs - MAX_DEAD_LETTER_AGE_MS - 60_000,
    );
    writeDeadLetterEntry("outbox-recent", new Date(nowMs).toISOString(), nowMs);

    const result = pruneDeadLetterEntries(outboxDir, nowMs);
    assert.equal(result.deleted, 1);

    const remaining = listDeadLetterEntries(outboxDir);
    assert.equal(remaining.length, 1);
    assert.equal(remaining[0].id, "outbox-recent");
  });

  it("an entry quarantined now survives an immediate prune pass even though its original createdAt is already past the dead-letter age ceiling", async () => {
    // Reproduces an agent that was offline for >30 days: the very first
    // post-restart transmission attempt exceeds the transient-retry
    // ceiling (measured from createdAt) and is quarantined immediately,
    // then the same poll tick's rate-limited prune pass runs right away
    // (startImmediately: true on the poll loop).
    const createdAtMs = Date.parse("2026-08-28T00:00:00.000Z");
    enqueueOutboxEntry(outboxDir, {
      id: "outbox-stale-restart-1",
      createdAt: new Date(createdAtMs).toISOString(),
      result: { jobId: "job-stale", attemptId: "a1", status: "succeeded" },
      evidence: [],
    });

    const nowMs = createdAtMs + MAX_TRANSIENT_RETRY_AGE_MS + MAX_DEAD_LETTER_AGE_MS + 60_000;
    const client = {
      reportEvidence: async () => {},
      reportResult: async () => {
        throw new Error("connection reset");
      },
    };

    const drain = await drainOutbox(outboxDir, client, { now: () => nowMs });
    assert.equal(drain.quarantined, 1);
    assert.equal(listOutboxEntries(outboxDir).length, 0);
    assert.equal(listDeadLetterEntries(outboxDir).length, 1);

    // The prune pass that runs immediately afterward must not delete
    // an entry that was only just quarantined, regardless of how old
    // its original createdAt is.
    const prune = pruneDeadLetterEntries(outboxDir, nowMs);
    assert.equal(prune.deleted, 0);
    const survivors = listDeadLetterEntries(outboxDir);
    assert.equal(survivors.length, 1);
    assert.equal(survivors[0].id, "outbox-stale-restart-1");
    assert.equal(typeof survivors[0].quarantinedAt, "string");

    // It only ages out MAX_DEAD_LETTER_AGE_MS after quarantinedAt, not
    // after the original createdAt.
    const stillTooSoon = pruneDeadLetterEntries(outboxDir, nowMs + MAX_DEAD_LETTER_AGE_MS - 60_000);
    assert.equal(stillTooSoon.deleted, 0);

    const nowAgedOut = pruneDeadLetterEntries(outboxDir, nowMs + MAX_DEAD_LETTER_AGE_MS + 60_000);
    assert.equal(nowAgedOut.deleted, 1);
  });

  it("pruneDeadLetterEntries falls back to lastAttemptAt, then file mtime, then createdAt when quarantinedAt is absent (legacy entries)", async () => {
    const deadLetterDir = resolveDeadLetterDir(outboxDir);
    fs.mkdirSync(deadLetterDir, { recursive: true });
    const nowMs = Date.parse("2026-08-28T00:00:00.000Z");

    // Legacy entry written directly (as a pre-fix quarantine would have
    // left it): no quarantinedAt, but a recent lastAttemptAt should
    // still protect it from a createdAt that is already past the
    // retention ceiling.
    const legacyPath = path.join(deadLetterDir, "outbox-legacy-1.json");
    fs.writeFileSync(
      legacyPath,
      `${JSON.stringify({
        id: "outbox-legacy-1",
        createdAt: new Date(nowMs - MAX_DEAD_LETTER_AGE_MS - 60_000).toISOString(),
        lastAttemptAt: new Date(nowMs).toISOString(),
        result: { jobId: "job-legacy", attemptId: "a1", status: "succeeded" },
        evidence: [],
        attempts: 5,
      })}\n`,
      "utf8",
    );

    const result = pruneDeadLetterEntries(outboxDir, nowMs);
    assert.equal(result.deleted, 0);
    assert.equal(listDeadLetterEntries(outboxDir).length, 1);
  });

  it("pruneDeadLetterEntries deletes the oldest entries once past maxEntries, even if none are individually aged out", async () => {
    const deadLetterDir = resolveDeadLetterDir(outboxDir);
    fs.mkdirSync(deadLetterDir, { recursive: true });
    const nowMs = Date.parse("2026-08-28T00:00:00.000Z");
    const total = 5;

    for (let i = 0; i < total; i += 1) {
      const entry = {
        id: `outbox-overflow-${String(i).padStart(2, "0")}`,
        createdAt: new Date(nowMs - (total - i) * 1000).toISOString(),
        result: { jobId: `job-${i}`, attemptId: "a1", status: "succeeded" },
        evidence: [],
      };
      fs.writeFileSync(
        path.join(deadLetterDir, `${entry.id}.json`),
        `${JSON.stringify(entry)}\n`,
        "utf8",
      );
    }

    const result = pruneDeadLetterEntries(outboxDir, nowMs, { maxEntries: 3 });
    assert.equal(result.deleted, 2);
    const remaining = listDeadLetterEntries(outboxDir);
    assert.equal(remaining.length, 3);
    // The two oldest (lowest index, oldest createdAt) were the ones removed.
    assert.equal(remaining[0].id, "outbox-overflow-02");
  });
});
