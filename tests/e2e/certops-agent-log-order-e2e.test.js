"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const crypto = require("node:crypto");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createRegisteredAgent } = require("./helpers/certops-registered-agent");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("actual agent telemetry ordering, conflict and final closure", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable API and PostgreSQL
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl);
  let ready = false; let primaryError;
  const gate = createHostGate({ suite: "agent-log-order-api", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_LOG_ORDER_REPORT, requiredCapabilities: ["api", "postgres"], fixtureSource: { file: "tests/e2e/certops-agent-log-order-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true } }) });
  gate.report.executionScope = "Actual registered-agent telemetry with synthetic public diagnostic lines; no certificate execution or native process interruption claimed";
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    const agent = await createRegisteredAgent(fixture, baseUrl, ["job-log-stream-v1"]); const { jobId, claimId } = await agent.claimNoop();
    const timestamp = new Date().toISOString();
    const line = (seq, message = `Public diagnostic ${seq}`) => ({ seq, ts: timestamp, level: "info", step: "verify", message });
    const send = (lines, extra = {}) => agent.machine(`jobs/${jobId}/logs`, "log", { jobId, claimId, final: false, ...(lines.length ? { firstSeq: lines[0].seq } : {}), lines, ...extra });
    const read = () => fixture.request(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs/${jobId}/agent-log`);
    const state = async () => (await fixture.pool.query("SELECT resolved_through_seq,accepted_lines,agent_gap_lines,conflict_count,status FROM certops_agent_log_stream WHERE workspace_id=$1 AND job_id=$2 AND claim_id=$3", [fixture.workspaceId, jobId, claimId])).rows[0];
    await gate.scenario("agent-log-gap-accounting", async () => {
      const result = await send([line(3)], { droppedBefore: 2 }); assert.equal(result.status, 200); assert.equal(result.body.ackThroughSeq, 3);
      const stored = await state(); assert.equal(Number(stored.agent_gap_lines), 2); assert.equal(Number(stored.accepted_lines), 1);
      assert.deepEqual((await read()).body.items.map((item) => item.seq), [3]);
    });
    await gate.scenario("agent-log-late-replay-no-backfill", async () => {
      const late = await send([line(1), line(2)], { droppedBefore: 2 }); assert.equal(late.status, 200); assert.equal(late.body.ackThroughSeq, 3); assert.equal(late.body.newlyStored, 0);
      assert.equal((await send([line(4)])).status, 200);
      assert.equal((await send([line(3)], { droppedBefore: 2 })).status, 200);
      const stored = await state(); assert.equal(Number(stored.agent_gap_lines), 2); assert.equal(Number(stored.accepted_lines), 2);
      assert.deepEqual((await read()).body.items.map((item) => item.seq), [3, 4]);
    }, { oracle: "Older resolved batches cannot backfill gaps or count their drop delta twice after an intervening batch" });
    await gate.scenario("agent-log-conflicting-replay-preserves-original", async () => {
      assert.equal((await send([line(3, "Conflicting later diagnostic")])).status, 200);
      assert.equal(Number((await state()).conflict_count), 1);
      assert.equal((await read()).body.items.find((item) => item.seq === 3).message, "Public diagnostic 3");
      assert.equal((await send([line(3, "Conflicting later diagnostic")])).status, 200); assert.equal(Number((await state()).conflict_count), 1);
    });
    await gate.scenario("agent-log-noncontiguous-batch-refusal", async () => {
      const before = await state(); const refused = await send([line(5), line(7)]); assert.equal(refused.status, 400);
      assert.deepEqual(await state(), before); assert.deepEqual((await read()).body.items.map((item) => item.seq), [3, 4]);
    });
    await gate.scenario("agent-log-final-closes-only-stream", async () => {
      assert.equal((await send([], { final: true })).status, 200); assert.equal((await state()).status, "final");
      assert.equal((await send([line(5)])).status, 409); assert.equal((await send([], { final: true })).status, 200);
      assert.equal((await fixture.pool.query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, jobId])).rows[0].status, "claimed");
      assert.deepEqual((await read()).body.items.map((item) => item.seq), [3, 4]);
    }, { oracle: "Telemetry finalization does not fabricate a terminal job; additional unresolved lines are refused and history remains stable" });
  } catch (error) { primaryError = error; throw error; }
  finally {
    try { if (ready) { await gate.scenario("agent-log-order-cleanup", fixture.cleanup); await gate.finish({ requiredScenarios: require("../../docs/certops/qualification-suites.json").suites["agent-log-order-api"] }); } else await fixture.cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Log ordering qualification and cleanup failed"); throw error; }
  }
});
