/**
 * Place bounded transport faults between a real running agent and the actual API.
 * Imported by certops-native-agent-e2e.test.js for retry, lost-ACK replay, batch split
 * and oversized-line cases. Forward genuine authenticated uploads, retain only bounded
 * counters, and compare persisted rows/gaps and terminal job outcome before cleanup. */
"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");

const cases = [
  ["native-agent-log-transient-retry", "transient"],
  ["native-agent-log-lost-acknowledgement", "lost-ack"],
  ["native-agent-log-413-split", "split"],
  ["native-agent-log-413-drop-accounting", "drop"],
];
function createNativeLogFaults() {
  const jobs = new Map();
  const digest = body => crypto.createHash("sha256").update(JSON.stringify(body)).digest("hex");
  function incoming(url, parsed, response, respond) {
    if (!url.endsWith("/logs")) return false;
    const body = parsed.body, state = jobs.get(body?.jobId);
    if (!state) return false;
    assert.ok(Array.isArray(body.lines));
    state.requests.push({ hash: digest(body), lines: structuredClone(body.lines), final: body.final === true, droppedBefore: body.droppedBefore });
    if (body.final || !body.lines.length) return false;
    if (!state.original) state.original = structuredClone(body);
    if (state.mode === "transient" && state.faults < 3) {
      const attempt = state.faults++;
      if (attempt === 2) response.destroy();
      else respond(attempt === 0 ? 503 : 429, Buffer.from("{}"), { "retry-after": "0" });
      return true;
    }
    if (["split", "drop"].includes(state.mode) && body.lines.length > 1) {
      state.splits++; respond(413, Buffer.from("{}")); return true;
    }
    if (state.mode === "drop" && !state.droppedSeq) {
      state.droppedSeq = body.lines[0].seq;
      respond(413, Buffer.from("{}")); return true;
    }
    return false;
  }
  function replied(url, parsed, status, output, response) {
    if (!url.endsWith("/logs")) return false;
    const body = parsed.body, state = jobs.get(body?.jobId);
    if (!state) return false;
    assert.equal(status, 200, "Actual upstream must accept the unmodified log envelope");
    const acknowledgement = JSON.parse(output.toString());
    state.accepted.push({ hash: digest(body), newlyStored: acknowledgement.newlyStored, acknowledgement, final: body.final === true });
    if (state.mode === "lost-ack" && body.lines.length && !state.lostAck) {
      state.lostAck = true; response.destroy(); return true;
    }
    return false;
  }
  async function qualify({ gate, fixture, prefix, create, row, stop, start, wait, prohibited }) {
    gate.report.fixtureSources ??= [];
    gate.report.fixtureSources.push({ file: "tests/e2e/helpers/certops-native-log-faults.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") });
    for (const [id, mode] of cases) {
      await gate.scenario(id, async () => {
        await stop();
        const jobId = await create();
        const state = { mode, requests: [], accepted: [], faults: 0, splits: 0 };
        jobs.set(jobId, state); start();
        await wait(async () => (await row(jobId)).status === "succeeded");
        let persisted;
        await wait(async () => {
          const response = await fixture.request(`${prefix}/jobs/${jobId}/agent-log`);
          assert.equal(response.status, 200);
          if (!response.body.logsComplete || !response.body.streams.length || !response.body.streams.every(stream => stream.status === "final")) return false;
          persisted = response.body; return true;
        });
        gate.report.nativeLogFaultDiagnostics ??= [];
        gate.report.nativeLogFaultDiagnostics.push({ scenario: id, requests: state.requests.length, accepted: state.accepted.map(batch => ({ hash: batch.hash, newlyStored: Number.isInteger(batch.newlyStored) ? batch.newlyStored : -1, final: batch.final })), sequences: persisted.items.map(line => line.seq), gaps: persisted.streams.map(stream => stream.agentGapLines), faults: state.faults, splits: state.splits, droppedSeq: state.droppedSeq || 0 });
        assert.ok(state.original?.lines.length > 1, "The native executor must actually emit a splittable batch");
        assert.equal((await row(jobId)).attempt_count, 1);
        assert.equal(persisted.jobStatus, "succeeded");
        const expected = new Map();
        for (const request of state.requests) for (const line of request.lines) {
          const previous = expected.get(line.seq);
          if (previous) assert.deepEqual(line, previous, "Transport retries must preserve original native lines");
          expected.set(line.seq, line);
        }
        if (mode === "drop") expected.delete(state.droppedSeq);
        assert.deepEqual(persisted.items.map(line => line.seq), [...expected.keys()].sort((a, b) => a - b));
        for (const line of persisted.items) assert.equal(line.message, expected.get(line.seq).message);
        const stored = (await fixture.pool.query("SELECT count(*)::int AS count,count(DISTINCT seq)::int AS distinct_count FROM certops_agent_job_log WHERE workspace_id=$1 AND job_id=$2", [fixture.workspaceId, jobId])).rows[0];
        assert.equal(stored.count, expected.size); assert.equal(stored.distinct_count, expected.size);
        assert.equal(persisted.streams.reduce((sum, stream) => sum + stream.agentGapLines, 0), mode === "drop" ? 1 : 0);
        assert.equal(persisted.streams.reduce((sum, stream) => sum + stream.serverDroppedLines, 0), 0);
        const serialized = JSON.stringify(persisted);
        for (const secret of prohibited) assert.equal(serialized.includes(secret), false);
        if (mode === "transient") {
          assert.equal(state.faults, 3);
          assert.equal(new Set(state.requests.slice(0, 4).map(request => request.hash)).size, 1);
        }
        if (mode === "lost-ack") {
          assert.equal(state.lostAck, true);
          assert.equal(state.accepted.filter(batch => batch.hash === state.accepted[0].hash).length, 2);
          // Exact last-batch replay returns the original acknowledgement. Its
          // newlyStored describes that original acceptance, not a second write.
          assert.deepEqual(state.accepted[1].acknowledgement, state.accepted[0].acknowledgement);
        }
        if (["split", "drop"].includes(mode)) assert.ok(state.splits > 0);
        if (mode === "drop") assert.equal(state.droppedSeq, state.original.lines[0].seq);
        assert.equal(state.accepted.filter(batch => batch.final).length, 1);
        gate.report.nativeLogFaults ??= [];
        gate.report.nativeLogFaults.push({ scenario: id, actualNativeConsole: true, jobSucceeded: true, attempts: 1, persistedLines: persisted.items.length, agentGapLines: mode === "drop" ? 1 : 0, serverDroppedLines: 0, finalAcknowledged: true });
        jobs.delete(jobId);
      }, { oracle: "Actual unmodified native console transport and real API persistence; only loopback HTTP responses or connection acknowledgements are faulted, no diagnostic messages or outcomes are synthesized" });
    }
  }
  return { incoming, replied, qualify };
}
module.exports = { createNativeLogFaults, cases };
