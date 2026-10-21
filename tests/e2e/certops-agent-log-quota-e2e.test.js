/**
 * Qualification notes: Fleet execution-log quota qualification
 * `agent-log-quota-api` uses registered noop claims and production PostgreSQL log ingestion with a
 * fixture 1000-byte daily budget. Racing streams share one budget; replay does not charge again,
 * workspaces remain independent, disabled storage does not charge, and telemetry finalization
 * preserves job state. Native fleet load and elapsed retention remain separate.
 *
 * Runner and report settings: `CERTOPS_LOG_QUOTA_REPORT`.
 *
 * Shared execution and evidence policy: docs/certops/e2e-qualification.md.
 */
/**
 * Supporting fleet-log quota integration against actual PostgreSQL and registered API claims.
 * Run through the API qualification runner with an explicitly disposable stack. Ingestion uses
 * the production service with a supplied small quota/disabled-storage environment; diagnostic
 * lines are fixtures. No global API configuration, quota rows or job outcomes are rewritten.
 */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const crypto = require("node:crypto");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createRegisteredAgent } = require("./helpers/certops-registered-agent");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
const { ingestAgentJobLogs } = require("../../apps/api/services/certops/agentJobLogs");
const scenarios = ["fleet-log-quota-concurrent-streams", "fleet-log-quota-replay-once", "fleet-log-quota-workspace-isolation", "fleet-log-storage-disabled-no-charge", "fleet-log-quota-final-keeps-job", "fleet-log-quota-cleanup"];
test("production fleet-log quota concurrency and workspace isolation", { timeout: 120000 }, async t => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable API and PostgreSQL
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl);
  const fixtures = []; let ready = false; let primary;
  const gate = createHostGate({ suite: "agent-log-quota-api", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_LOG_QUOTA_REPORT, requiredCapabilities: ["api", "postgres"], fixtureSource: { file: "tests/e2e/certops-agent-log-quota-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: fixtures.length > 0 }, postgres: { available: fixtures.length > 0 } }) });
  gate.report.executionScope = "Actual API registration/claims and PostgreSQL production ingestion; supplied quota/storage environment and public diagnostic fixtures, no installed native agent";
  const quotaEnv = { CERTOPS_AGENT_LOG_DAILY_BYTES: "1000", CERTOPS_AGENT_LOG_RETENTION_DAYS: "30" };
  async function claim(fixture) {
    const agent = await createRegisteredAgent(fixture, baseUrl, ["job-log-stream-v1"]);
    const claimed = await agent.claimNoop();
    const id = (await fixture.pool.query("SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [fixture.workspaceId, agent.agentId])).rows[0].id;
    return { fixture, agent: { id, workspaceId: fixture.workspaceId }, ...claimed };
  }
  function batch(item, lines, final = false) { return { jobId: item.jobId, claimId: item.claimId, final, ...(lines.length ? { firstSeq: lines[0].seq } : {}), lines }; }
  const line = { seq: 1, ts: new Date().toISOString(), level: "info", step: "verify", message: "Public quota diagnostic " + "x".repeat(700), fields: null };
  const ingest = (item, body, env = quotaEnv) => ingestAgentJobLogs({ dbPool: item.fixture.pool, agent: item.agent, jobId: item.jobId, body, env });
  const quota = async fixture => (await fixture.pool.query("SELECT used_bytes,used_lines FROM certops_agent_log_daily_quota WHERE workspace_id=$1 AND quota_day=CURRENT_DATE", [fixture.workspaceId])).rows;
  try {
    fixtures.push(await createApiFixture(baseUrl)); fixtures.push(await createApiFixture(baseUrl));
    assert.equal(await gate.preflight(), true); ready = true;
    const first = await claim(fixtures[0]), second = await claim(fixtures[0]), foreign = await claim(fixtures[1]);
    const bodies = [batch(first, [line]), batch(second, [line])]; let acknowledgements;
    await gate.scenario(scenarios[0], async () => {
      acknowledgements = await Promise.all([ingest(first, bodies[0]), ingest(second, bodies[1])]);
      assert.ok(acknowledgements.every(result => result.httpStatus === 200));
      const rows = await fixtures[0].pool.query("SELECT count(*)::int AS n FROM certops_agent_job_log WHERE workspace_id=$1", [fixtures[0].workspaceId]);
      assert.equal(rows.rows[0].n, 1);
      const counters = (await quota(fixtures[0]))[0]; assert.equal(Number(counters.used_lines), 1); assert.ok(Number(counters.used_bytes) > 700 && Number(counters.used_bytes) <= 1000);
      const streams = await fixtures[0].pool.query("SELECT sum(server_dropped_lines)::int AS dropped FROM certops_agent_log_stream WHERE workspace_id=$1", [fixtures[0].workspaceId]);
      assert.equal(streams.rows[0].dropped, 1);
    }, { oracle: "Two real claimed streams race the same locked workspace/day budget; exactly one public line fits and the other is accounted as a server drop" });
    await gate.scenario(scenarios[1], async () => {
      const before = await quota(fixtures[0]);
      const repeated = await Promise.all([ingest(first, bodies[0]), ingest(second, bodies[1])]);
      assert.ok(repeated.every(result => result.httpStatus === 200)); assert.deepEqual(repeated.map(result => result.body), acknowledgements.map(result => result.body)); assert.deepEqual(await quota(fixtures[0]), before);
    });
    await gate.scenario(scenarios[2], async () => {
      const accepted = await ingest(foreign, batch(foreign, [line])); assert.equal(accepted.httpStatus, 200); assert.equal(accepted.body.newlyStored, 1);
      assert.equal(Number((await quota(fixtures[1]))[0].used_lines), 1);
      assert.equal((await fixtures[1].pool.query("SELECT count(*)::int AS n FROM certops_agent_job_log WHERE workspace_id=$1", [fixtures[1].workspaceId])).rows[0].n, 1);
    });
    await gate.scenario(scenarios[3], async () => {
      const disabled = await claim(fixtures[0]); const before = await quota(fixtures[0]);
      const result = await ingest(disabled, batch(disabled, [line]), { ...quotaEnv, CERTOPS_AGENT_LOG_RETENTION_DAYS: "0" });
      assert.equal(result.httpStatus, 200); assert.deepEqual(await quota(fixtures[0]), before);
      assert.equal((await fixtures[0].pool.query("SELECT count(*)::int AS n FROM certops_agent_job_log WHERE job_id=$1", [disabled.jobId])).rows[0].n, 0);
    });
    await gate.scenario(scenarios[4], async () => {
      for (const item of [first, second]) {
        assert.equal((await ingest(item, batch(item, [], true))).httpStatus, 200);
        assert.equal((await item.fixture.pool.query("SELECT status FROM certificate_jobs WHERE id=$1", [item.jobId])).rows[0].status, "claimed");
        assert.equal((await item.fixture.pool.query("SELECT status FROM certops_agent_log_stream WHERE job_id=$1 AND claim_id=$2", [item.jobId, item.claimId])).rows[0].status, "final");
      }
    });
  } catch (error) { primary = error; throw error; }
  finally {
    const cleanup = async () => { const failures = []; for (const fixture of fixtures.reverse()) { try { await fixture.cleanup(); } catch (error) { failures.push(error); } } if (failures.length) throw new AggregateError(failures, "Owned fleet fixture cleanup failed"); };
    try { if (ready) { await gate.scenario(scenarios[5], cleanup); await gate.finish({ requiredScenarios: scenarios }); } else await cleanup(); }
    catch (error) { if (primary) throw new AggregateError([primary, error], "Fleet quota fixture and cleanup failed"); throw error; }
  }
});
