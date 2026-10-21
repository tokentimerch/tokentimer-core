/**
 * Qualification notes: Actual elapsed log abandonment and production worker retention
 * The manual `certops-log-maintenance-qualification.yml` workflow requires an exclusive disposable
 * API/PostgreSQL stack because purge is global. A real registered noop result starts the production
 * 300,000-millisecond grace. The unchanged maintenance sweep must observe the actual deadline, refuse
 * foreign fixture data, and preserve owned cleanup; database dates are not rewritten. No push starts
 * the five-minute wait.
 *
 * Runner and report settings: `CERTOPS_LOG_MAINTENANCE_REPORT`.
 *
 * Run prerequisites: `CERTOPS_AGENT_LOG_RETENTION_DAYS=0`,
 * `CERTOPS_LOG_MAINTENANCE_EXCLUSIVE_STACK=1`, `CERTOPS_CSR_DISPOSABLE_STACK=1`.
 *
 * Scopes: `agent-log-maintenance-worker`.
 *
 * Shared execution and evidence policy: docs/certops/e2e-qualification.md.
 */
/**
 * Real five-minute upload grace and production worker retention qualification.
 * The manual workflow owns an EXCLUSIVE disposable API/PostgreSQL stack because
 * log purge is global. A registered protocol fixture supplies diagnostic lines
 * and a signed noop result; a child invokes the unchanged production worker.
 * Host/DB clocks advance normally. No timestamps, outcomes or journals are
 * rewritten. This is supporting worker integration, not native agent execution.
 */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { fork } = require("node:child_process");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createRegisteredAgent } = require("./helpers/certops-registered-agent");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
const { verifyFacts } = require("../../scripts/certops-log-maintenance-report");
const sources = ["tests/e2e/helpers/certops-log-maintenance-worker.mjs", "apps/worker/src/certops-worker.js", "apps/api/services/certops/agentJobLogs.js"];
const scenarios = ["log-maintenance-genuine-stream-terminal-job", "log-maintenance-default-grace-preserves-lines", "log-maintenance-actual-five-minute-abandonment", "log-maintenance-late-upload-refused", "log-maintenance-disabled-retention-worker-purge", "log-maintenance-purge-idempotency", "log-maintenance-owned-cleanup"];

test("actual log upload grace, abandoned stream and worker retention", { timeout: 420000 }, async t => {
  const base = process.env.CERTOPS_CSR_API_URL;
  if (!base && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires exclusive disposable API/PostgreSQL and five real elapsed minutes
    t.skip("Exclusive disposable maintenance stack required"); return;
  }
  assert.ok(base); assert.equal(process.env.CERTOPS_LOG_MAINTENANCE_EXCLUSIVE_STACK, "1");
  const fixture = await createApiFixture(base);
  const root = path.resolve(__dirname, "../..");
  const gate = createHostGate({ suite: "agent-log-maintenance-worker", strict: true, evidenceLevel: "integration", reportPath: process.env.CERTOPS_LOG_MAINTENANCE_REPORT, requiredCapabilities: ["api", "postgres", "workerProcess"], fixtureSource: { file: "tests/e2e/certops-log-maintenance-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true }, workerProcess: { available: fs.existsSync(path.join(root, sources[0])) } }) });
  gate.report.fixtureSources = sources.map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") }));
  gate.report.executionScope = "Actual public machine protocol, PostgreSQL and production maintenance child process with real five-minute default upload grace; retention zero is the supported immediate storage-off policy, not an observed day of retention. Diagnostic noop is not native execution.";
  let ready = false, primary, agent, claim, originalJob, streamBefore, started;
  const workers = new Set();
  async function stopChild(child) {
    if (child.exitCode !== null || child.signalCode !== null || !child.pid) return;
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("Owned maintenance process did not exit")), 5000);
      child.once("exit", () => { clearTimeout(timer); resolve(); });
      child.kill("SIGKILL");
    });
  }
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  const job = async () => (await fixture.pool.query("SELECT status,completed_at,result_metadata,attempt_count,claim_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, claim.jobId])).rows[0];
  const stream = async () => (await fixture.pool.query("SELECT status,closed_at,accept_until,finalized_at,resolved_through_seq FROM certops_agent_log_stream WHERE workspace_id=$1 AND job_id=$2", [fixture.workspaceId, claim.jobId])).rows[0];
  const count = async () => Number((await fixture.pool.query("SELECT COUNT(*) FROM certops_agent_job_log WHERE workspace_id=$1 AND job_id=$2", [fixture.workspaceId, claim.jobId])).rows[0].count);
  function worker(operation) {
    return new Promise((resolve, reject) => {
      const child = fork(path.join(root, sources[0]), [], { cwd: root, stdio: ["ignore", "ignore", "ignore", "ipc"], env: { ...process.env, ENABLE_METRICS: "false", CERTOPS_LOG_MAINTENANCE_OPERATION: operation, CERTOPS_LOG_MAINTENANCE_WORKSPACE_ID: fixture.workspaceId } });
      workers.add(child); let message;
      const timer = setTimeout(() => { void stopChild(child).then(() => reject(new Error("Owned maintenance child exceeded deadline")), reject); }, 30000);
      child.on("message", value => { if (value?.kind === "certops-log-maintenance") message = value; });
      child.once("error", error => { clearTimeout(timer); if (!child.pid) workers.delete(child); reject(error); });
      child.once("exit", () => workers.delete(child));
      child.once("close", code => { clearTimeout(timer); if (code !== 0 || message?.operation !== operation || message?.onlySelectedSweep !== true || message?.pid !== child.pid) reject(new Error("Actual maintenance process or bounded proof failed")); else resolve(message.result); });
    });
  }
  const log = (seq, final = false) => agent.machine(`jobs/${claim.jobId}/logs`, "log", { jobId: claim.jobId, claimId: claim.claimId, firstSeq: seq, final, lines: [{ seq, ts: new Date().toISOString(), level: "info", step: "verify", message: `Owned public maintenance diagnostic ${seq}` }] });
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    await gate.scenario(scenarios[0], async () => {
      agent = await createRegisteredAgent(fixture, base, ["job-log-stream-v1"]); claim = await agent.claimNoop();
      assert.equal((await log(1)).status, 200); assert.equal((await log(2)).status, 200);
      assert.equal((await agent.machine("jobs/results", "result", { jobId: claim.jobId, attemptId: claim.job.attemptId, nonce: claim.job.nonce, status: "succeeded", keyRotated: false })).status, 200);
      started = process.hrtime.bigint(); originalJob = await job(); assert.equal(originalJob.status, "succeeded");
      streamBefore = await stream(); assert.equal(streamBefore.status, "streaming");
      assert.ok(streamBefore.closed_at instanceof Date); assert.ok(streamBefore.accept_until instanceof Date);
      assert.equal(streamBefore.accept_until.getTime() - streamBefore.closed_at.getTime(), 300000);
      assert.equal(await count(), 2);
    });
    await gate.scenario(scenarios[1], async () => {
      const result = await worker("abandon"); assert.equal(result.abandoned, 0);
      assert.equal((await stream()).status, "streaming"); assert.equal(await count(), 2); assert.deepEqual(await job(), originalJob);
    });
    await gate.scenario(scenarios[2], async () => {
      // Require both clocks independently. The monotonic interval starts AFTER
      // actual result ingestion, so setup latency cannot shorten the observed wait.
      while (Number(process.hrtime.bigint() - started) / 1e6 < 300000 || Date.now() <= streamBefore.accept_until.getTime()) await new Promise(resolve => setTimeout(resolve, 1000));
      const measured = Number(process.hrtime.bigint() - started) / 1e6;
      const actualDb = (await fixture.pool.query("SELECT NOW()>$1::timestamptz AS expired", [streamBefore.accept_until])).rows[0]; assert.equal(actualDb.expired, true);
      const result = await worker("abandon"); assert.equal(result.abandoned, 1);
      const after = await stream(); assert.equal(after.status, "abandoned"); assert.ok(after.finalized_at);
      assert.equal(after.accept_until.getTime(), streamBefore.accept_until.getTime()); assert.equal(await count(), 2); assert.deepEqual(await job(), originalJob);
      gate.report.maintenance = { defaultGraceMs: 300000, observedMonotonicMs: measured, actualDatabaseExpired: true, timestampsRewritten: false, originalJobSucceeded: true, abandonedStreams: 1, lateUploadRefused: false, purgedLines: 0, tombstoneRetained: false, repeatedPurgeDeleted: -1, onlySelectedWorkerSweeps: true, retentionDays: 0, scope: "actual-default-five-minute-grace-and-supported-retention-zero" };
    });
    await gate.scenario(scenarios[3], async () => {
      const refused = await log(3); assert.equal(refused.status, 409); assert.equal(refused.body.code, "CERTOPS_AGENT_LOG_CLOSED");
      assert.equal(await count(), 2); assert.deepEqual(await job(), originalJob); gate.report.maintenance.lateUploadRefused = true;
    });
    await gate.scenario(scenarios[4], async () => {
      const purged = await worker("purge"); assert.equal(purged.deletedLines, 2); assert.equal(purged.deletedStreams, 0);
      assert.equal(await count(), 0); assert.equal((await stream()).status, "abandoned"); assert.deepEqual(await job(), originalJob);
      const read = await fixture.request(`${prefix}/jobs/${claim.jobId}/agent-log`); assert.equal(read.status, 200); assert.deepEqual(read.body.items, []); assert.equal(read.body.logsComplete, true);
      gate.report.maintenance.purgedLines = 2; gate.report.maintenance.tombstoneRetained = true;
    });
    await gate.scenario(scenarios[5], async () => {
      const again = await worker("purge"); assert.equal(again.deletedLines, 0); assert.equal(again.deletedStreams, 0);
      gate.report.maintenance.repeatedPurgeDeleted = 0; verifyFacts(gate.report.maintenance); assert.deepEqual(await job(), originalJob);
    });
  } catch (error) { primary = error; throw error; }
  finally {
    const cleanup = async () => {
      const exits = await Promise.allSettled([...workers].map(stopChild));
      const failed = exits.filter(result => result.status === "rejected").map(result => result.reason);
      // A worker with a live database connection must not race fixture deletion.
      if (failed.length) throw new AggregateError(failed, "Owned workers could not be stopped before database cleanup");
      await fixture.cleanup();
    };
    try { if (ready) { await gate.scenario(scenarios.at(-1), cleanup); await gate.finish({ requiredScenarios: scenarios }); } else await cleanup(); }
    catch (error) { if (primary) throw new AggregateError([primary, error], "Maintenance qualification and cleanup failed"); throw error; }
  }
});
module.exports = { scenarios, sources };
