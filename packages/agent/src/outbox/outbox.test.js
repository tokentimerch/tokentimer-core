"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  resolveOutboxDir,
  ensureOutboxDir,
  enqueueOutboxEntry,
  listOutboxEntries,
  acknowledgeOutboxEntry,
  transmitOutboxEntry,
  drainOutbox,
  createEvidenceBuffer,
  OUTBOX_DIR_NAME,
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

    const client = {
      reportEvidence: async () => {},
      reportResult: async () => {
        throw new Error("network down");
      },
    };

    const drain = await drainOutbox(outboxDir, client);
    assert.equal(drain.transmitted, 0);
    assert.equal(drain.remaining, 1);
    assert.equal(listOutboxEntries(outboxDir)[0].result.status, "succeeded");

    let calls = 0;
    const okClient = {
      reportEvidence: async () => {},
      reportResult: async () => {
        calls += 1;
      },
    };
    const retry = await drainOutbox(outboxDir, okClient);
    assert.equal(calls, 1);
    assert.equal(retry.transmitted, 1);
    assert.equal(retry.remaining, 0);
  });

  it("createEvidenceBuffer collects reportEvidence without networking", async () => {
    const buffer = createEvidenceBuffer();
    await buffer.reportEvidence({ jobId: "j", evidenceItems: [] });
    await buffer.reportEvidence({ jobId: "j2", evidenceItems: [] });
    const taken = buffer.takeEvidence();
    assert.equal(taken.length, 2);
    assert.deepEqual(buffer.takeEvidence(), []);
  });
});
