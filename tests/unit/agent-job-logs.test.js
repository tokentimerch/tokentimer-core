"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {
  projectRetainedBytes,
  LOCK_ORDER,
  OPERATION_LOCKS,
  assertLockSequence,
  batchKeyOf,
  contentHash,
  logsComplete,
  resolveIngest,
  resolveRetentionDays,
  resolveDailyByteLimit,
  shouldAbandon,
  shouldDeleteStream,
  takeIngestOrders,
  scrubIncomingLines,
  shapeAgentLogRead,
  deliveryState,
  decodeCursor,
} = require("../../apps/api/services/certops/agentJobLogs");
const { scrubAgentLogText, scrubAgentLogFields } = require("../../packages/log-scrub/agent-log-text");

const fixtures = JSON.parse(fs.readFileSync(
  path.join(__dirname, "../../packages/contracts/certops/fixtures/log-redaction.json"),
  "utf8",
));

function line(seq, message = `line ${seq}`) {
  const stored = {
    seq,
    level: "info",
    step: "deploy",
    message,
    fields: null,
  };
  stored.hash = contentHash(stored);
  stored.bytes = Buffer.byteLength(message, "utf8");
  return stored;
}

function freshState(overrides = {}) {
  return {
    streamingEnabled: true,
    status: "pending",
    acceptUntil: null,
    resolvedThroughSeq: 0,
    acceptedLines: 0,
    acceptedBytes: 0,
    serverDroppedLines: 0,
    agentGapLines: 0,
    rejectedBatches: 0,
    conflictCount: 0,
    conflicts: {},
    lastBatchKey: null,
    lastAck: null,
    lastHttpStatus: null,
    stored: {},
    ...overrides,
  };
}

function batchFrom(lines, final = false, droppedBefore = 0) {
  return {
    key: batchKeyOf(lines, final, droppedBefore),
    lines,
    final,
    droppedBefore,
    rejected: false,
  };
}

describe("agent job log read", () => {
  const secret = "visible-only-to-managers";
  const streams = [{
    claimId: "claim-1",
    attempt: 1,
    status: "streaming",
    streamingEnabled: true,
    agentGapLines: 0,
    serverDroppedLines: 0,
  }];
  const lines = [{
    claimId: "claim-1",
    attempt: 1,
    seq: 1,
    ts: "2026-10-08T00:00:00.000Z",
    level: "info",
    step: "deploy",
    message: secret,
    redactionCount: 0,
    ingestOrder: 4,
  }];

  it("hides line text from viewers and keeps polling while the job can retry", () => {
    const view = shapeAgentLogRead({
      jobStatus: "pending",
      streams,
      lines,
      limit: 10,
      includeText: false,
    });
    assert.deepEqual(view.items, []);
    assert.equal(JSON.stringify(view).includes(secret), false);
    assert.equal(view.logsComplete, false);
    assert.equal(deliveryState({ ...view, linesVisible: false }), "You need manager access to view agent output");
  });

  it("pages managers by ingest order and reports a retry gap", () => {
    const extra = { ...lines[0], seq: 2, ingestOrder: 9, message: "second" };
    const page = shapeAgentLogRead({
      jobStatus: "succeeded",
      streams: [{ ...streams[0], status: "final" }],
      lines: [extra, lines[0], { ...lines[0], seq: 3, ingestOrder: 10, message: "third" }],
      limit: 2,
      includeText: true,
    });
    assert.deepEqual(page.items.map((item) => item.message), [secret, "second"]);
    assert.equal(page.hasMore, true);
    assert.equal(page.logsComplete, true);
    const waiting = shapeAgentLogRead({
      jobStatus: "pending",
      streams: [{ ...streams[0], status: "final" }],
      lines: [],
      limit: 10,
      includeText: true,
    });
    assert.equal(deliveryState({ ...waiting, linesVisible: true }), "Waiting for the next attempt");
  });

  it("returns a resume cursor on the last page and echoes it on an empty one", () => {
    const last = shapeAgentLogRead({
      jobStatus: "running",
      streams: [{ ...streams[0], status: "streaming" }],
      lines: [{ ...lines[0], ingestOrder: 4 }],
      limit: 10,
      includeText: true,
    });
    assert.equal(last.hasMore, false);
    assert.equal(decodeCursor(last.nextCursor), 4);
    const empty = shapeAgentLogRead({
      jobStatus: "running",
      streams: [{ ...streams[0], status: "streaming" }],
      lines: [],
      limit: 10,
      includeText: true,
      cursorOrder: 4,
    });
    assert.equal(decodeCursor(empty.nextCursor), 4);
    const viewer = shapeAgentLogRead({ ...empty, lines: [], includeText: false, cursorOrder: 4 });
    assert.equal(viewer.nextCursor, null);
  });
});

describe("agent job log ingest", () => {
  it("keeps every operation on the shared lock order", () => {
    for (const names of Object.values(OPERATION_LOCKS)) {
      assertLockSequence(names);
      let previous = -1;
      for (const name of names) {
        const index = LOCK_ORDER.indexOf(name);
        assert.ok(index > previous);
        previous = index;
      }
    }
  });

  it("returns a stable ack and does not move counters when a partial batch is retried", () => {
    const lines = Array.from({ length: 10 }, (_, index) => line(index + 1, "x".repeat(10)));
    const batch = batchFrom(lines);
    const first = resolveIngest(freshState(), batch, { maxLines: 2, maxBytes: 1_000_000, quotaLimitBytes: 0 });
    assert.equal(first.ack.newlyStored, 2);
    assert.equal(first.ack.serverDroppedCount, 8);
    assert.equal(first.nextState.serverDroppedLines, 8);
    const second = resolveIngest(first.nextState, batch, { maxLines: 2, maxBytes: 1_000_000, quotaLimitBytes: 0 });
    assert.equal(second.kind, "replay");
    assert.deepEqual(second.ack, first.ack);
    assert.equal(second.delta.quotaBytes, 0);
    assert.equal(second.nextState.serverDroppedLines, first.nextState.serverDroppedLines);
    assert.equal(second.nextState.acceptedLines, first.nextState.acceptedLines);
  });

  it("acknowledges a repeated empty final without failing", () => {
    const batch = batchFrom([], true);
    const first = resolveIngest(freshState(), batch);
    assert.equal(first.nextState.status, "final");
    assert.equal(first.ack.newlyStored, 0);
    const second = resolveIngest(first.nextState, batch);
    assert.equal(second.kind, "replay");
    assert.equal(second.httpStatus, 200);
    assert.deepEqual(second.ack, first.ack);
    assert.equal(second.nextState.rejectedBatches, 0);
  });

  it("counts an agent gap once across retries", () => {
    const lines = [line(5), line(6)];
    const batch = batchFrom(lines);
    const first = resolveIngest(freshState(), batch);
    assert.equal(first.nextState.agentGapLines, 4);
    const second = resolveIngest(first.nextState, batch);
    assert.equal(second.nextState.agentGapLines, 4);
  });

  it("does not charge quota twice for two jobs sharing a day when the second does not fit", () => {
    const big = line(1, "y".repeat(80));
    const limit = 100;
    const first = resolveIngest(freshState(), batchFrom([big]), { quotaLimitBytes: limit, quotaUsedBytes: 0 });
    const used = first.delta.quotaBytes;
    const second = resolveIngest(freshState(), batchFrom([line(1, "z".repeat(80))]), {
      quotaLimitBytes: limit,
      quotaUsedBytes: used,
    });
    assert.equal(used + second.delta.quotaBytes <= limit, true);
    assert.equal(second.ack.serverDroppedCount, 1);
    assert.equal(second.delta.quotaBytes, 0);
  });

  it("projects retained bytes from jobs, retention, and workspace count", () => {
    assert.equal(projectRetainedBytes({
      bytesPerJob: 2000,
      jobsPerWorkspacePerDay: 10,
      retentionDays: 7,
      workspaces: 3,
    }), 420000);
  });

  it("assigns ingest order from the job counter and never from deleted rows", () => {
    const first = takeIngestOrders(0, 2);
    assert.deepEqual(first.orders, [1, 2]);
    const afterPurge = takeIngestOrders(first.next, 1);
    assert.ok(afterPurge.orders[0] > first.orders.at(-1));
  });

  it("keeps polling open across a retry gap and a quiet long job", () => {
    assert.equal(logsComplete("pending", []), false);
    assert.equal(logsComplete("succeeded", []), true);
    assert.equal(logsComplete("succeeded", [{ status: "streaming" }]), false);
    assert.equal(logsComplete("succeeded", [{ status: "final" }, { status: "abandoned" }]), true);
    const quiet = {
      status: "streaming",
      acceptUntil: new Date(Date.now() + 60_000).toISOString(),
    };
    assert.equal(shouldAbandon(quiet, new Date()), false);
    assert.equal(shouldAbandon({ ...quiet, acceptUntil: new Date(Date.now() - 1000).toISOString() }, new Date()), true);
  });

  it("keeps empty stream rows until their own expiry", () => {
    const now = new Date("2026-10-08T00:00:00.000Z");
    const recent = {
      status: "final",
      closedAt: "2026-10-07T00:00:00.000Z",
    };
    assert.equal(shouldDeleteStream(recent, now, 30), false);
    const old = {
      status: "final",
      closedAt: "2026-01-01T00:00:00.000Z",
    };
    assert.equal(shouldDeleteStream(old, now, 30), true);
    assert.equal(shouldDeleteStream({ status: "streaming", closedAt: old.closedAt }, now, 30), false);
  });

  it("rejects private material in fields and redacts the shared fixture corpus", () => {
    for (const fixture of fixtures) {
      if (fixture.fields) {
        const result = scrubAgentLogFields(fixture.fields);
        assert.equal(result.rejected, fixture.expect.rejected === true, fixture.name);
        const encoded = JSON.stringify(result.fields);
        for (const secret of fixture.expect.excludes || []) {
          assert.equal(encoded.includes(secret), false, fixture.name);
        }
        continue;
      }
      const result = scrubAgentLogText(fixture.input);
      assert.equal(result.rejected, fixture.expect.rejected === true, fixture.name);
      for (const secret of fixture.expect.excludes || []) {
        assert.equal(result.text.includes(secret), false, fixture.name);
      }
      for (const part of fixture.expect.includes || []) {
        assert.equal(result.text.includes(part), true, fixture.name);
      }
    }
    const incoming = scrubIncomingLines([{
      seq: 1,
      ts: "2026-10-08T00:00:00.000Z",
      level: "info",
      step: "other",
      message: "ok",
      fields: { note: "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----" },
    }]);
    assert.equal(incoming.rejected, true);
  });

  it("drops secret-bearing structured field names even for short values", () => {
    const result = scrubAgentLogFields({
      password: "hunter2",
      apiKey: "abc123",
      accessToken: "short-token",
      privateKey: "not-a-pem",
      host: "server01",
    });
    assert.equal(result.rejected, false);
    assert.deepEqual(result.fields, { host: "server01" });
    assert.ok(result.redactions >= 4);
  });

  it("counts agent droppedBefore on an empty final batch", () => {
    const afterLine = resolveIngest(freshState(), {
      key: "k1",
      lines: [line(1)],
      final: false,
      droppedBefore: 0,
    });
    assert.equal(afterLine.nextState.agentGapLines, 0);
    const finalEmpty = resolveIngest(afterLine.nextState, {
      key: "k-final",
      lines: [],
      final: true,
      droppedBefore: 1,
    });
    assert.equal(finalEmpty.kind, "applied");
    assert.equal(finalEmpty.nextState.status, "final");
    assert.equal(finalEmpty.nextState.agentGapLines, 1);
    const replay = resolveIngest(finalEmpty.nextState, {
      key: "k-final",
      lines: [],
      final: true,
      droppedBefore: 1,
    });
    assert.equal(replay.kind, "replay");
    assert.equal(replay.nextState.agentGapLines, 1);
  });

  it("does not double-count droppedBefore when the same hole is a seq gap", () => {
    const afterLine = resolveIngest(freshState(), {
      key: "k1",
      lines: [line(1)],
      final: false,
    });
    const afterDrop = resolveIngest(afterLine.nextState, {
      key: "k2",
      lines: [line(4)],
      final: false,
      droppedBefore: 2,
    });
    assert.equal(afterDrop.nextState.agentGapLines, 2);
    assert.equal(afterDrop.nextState.resolvedThroughSeq, 4);
  });

  it("includes droppedBefore in the batch key so drop-count changes are not replayed as the prior ack", () => {
    const lines = [line(2)];
    assert.notEqual(batchKeyOf(lines, false, 0), batchKeyOf(lines, false, 1));
    const first = resolveIngest(freshState(), {
      ...batchFrom(lines, false, 1),
    });
    assert.equal(first.nextState.agentGapLines, 1);
    const sameKeyDifferentDrop = resolveIngest(first.nextState, {
      key: batchKeyOf(lines, false, 0),
      lines,
      final: false,
      droppedBefore: 0,
    });
    // Different key means this is not treated as a silent replay of the
    // previous batch; seqs are already resolved so gaps do not move again.
    assert.equal(sameKeyDifferentDrop.kind, "applied");
    assert.equal(sameKeyDifferentDrop.nextState.agentGapLines, 1);
  });

  it("does not re-apply droppedBefore when an older batch is replayed after an intervening batch", () => {
    const batchA = batchFrom([line(1)], false, 1);
    const batchB = batchFrom([line(2)], false, 0);
    const afterA = resolveIngest(freshState(), batchA);
    assert.equal(afterA.nextState.agentGapLines, 1);
    const afterB = resolveIngest(afterA.nextState, batchB);
    assert.equal(afterB.nextState.agentGapLines, 1);
    assert.equal(afterB.nextState.lastBatchKey, batchB.key);
    const replayA = resolveIngest(afterB.nextState, batchA);
    assert.equal(replayA.kind, "applied");
    assert.equal(replayA.ack.newlyStored, 0);
    assert.equal(replayA.ack.duplicateCount, 1);
    assert.equal(replayA.nextState.agentGapLines, 1);
    // Zero newly accepted lines with a nonzero drop delta still must not inflate.
    const replayAAgain = resolveIngest(replayA.nextState, batchA);
    assert.equal(replayAAgain.nextState.agentGapLines, 1);
  });

  it("rejects malformed retention and daily-byte env values", () => {
    const { MAX_AGENT_LOG_RETENTION_DAYS } = require("../../apps/api/services/certops/agentJobLogs");
    assert.equal(resolveRetentionDays({ CERTOPS_AGENT_LOG_RETENTION_DAYS: "0.5" }), 30);
    assert.equal(resolveRetentionDays({ CERTOPS_AGENT_LOG_RETENTION_DAYS: "30days" }), 30);
    assert.equal(resolveRetentionDays({ CERTOPS_AGENT_LOG_RETENTION_DAYS: "0" }), 0);
    assert.equal(resolveRetentionDays({ CERTOPS_AGENT_LOG_RETENTION_DAYS: "14" }), 14);
    assert.equal(resolveRetentionDays({ CERTOPS_AGENT_LOG_RETENTION_DAYS: "3650" }), 3650);
    assert.equal(resolveRetentionDays({ CERTOPS_AGENT_LOG_RETENTION_DAYS: "3651" }), 30);
    assert.equal(resolveRetentionDays({ CERTOPS_AGENT_LOG_RETENTION_DAYS: "2147483648" }), 30);
    assert.equal(MAX_AGENT_LOG_RETENTION_DAYS, 3650);
    assert.equal(resolveDailyByteLimit({ CERTOPS_AGENT_LOG_DAILY_BYTES: "100MB" }), 0);
    assert.equal(resolveDailyByteLimit({ CERTOPS_AGENT_LOG_DAILY_BYTES: "1048576" }), 1048576);
  });

  it("exposes jobStatus on shaped read payloads", () => {
    const shaped = shapeAgentLogRead({
      jobStatus: "failed",
      streams: [{ claimId: "c", attempt: 1, status: "final", streamingEnabled: true }],
      lines: [],
      limit: 10,
      includeText: true,
      storageEnabled: true,
    });
    assert.equal(shaped.jobStatus, "failed");
    assert.equal(shaped.logsComplete, true);
  });

  it("treats terminal jobs with no stream rows as complete without claiming a finished stream", () => {
    assert.equal(logsComplete("succeeded", []), true);
    assert.equal(
      deliveryState({
        logsComplete: true,
        streams: [],
        linesVisible: true,
        storageEnabled: true,
      }),
      "No agent output recorded",
    );
  });
});
