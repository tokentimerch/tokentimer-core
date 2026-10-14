"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createRegisteredAgent } = require("./helpers/certops-registered-agent");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
const scenarios = ["pause-ingestion-owned-claims", "pause-ingestion-audited-pause", "pause-ingestion-blocked-provision", "pause-ingestion-existing-result-evidence", "pause-ingestion-audited-resume", "pause-ingestion-cleanup"];
test("workspace pause blocks new work while retaining owned result ingestion", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable authenticated API PostgreSQL and signing keys
    t.skip("Disposable API required"); return;
  }
  assert.ok(baseUrl);
  const fixture = await createApiFixture(baseUrl);
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  const gate = createHostGate({ suite: "pause-ingestion-api", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_PAUSE_INGESTION_REPORT, requiredCapabilities: ["api", "postgres"], fixtureSource: { file: "tests/e2e/certops-pause-ingestion-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true } }) });
  gate.report.executionScope = "Authenticated public pause and dispatch boundaries with protocol-reported noop evidence/results; no native certificate mutation";
  let ready = false, failure, agent, owned, waiting;
  const claim = () => agent.machine("jobs/claim", "claim", { maxJobs: 1, supportedActions: ["noop"] });
  const row = async (id) => (await fixture.pool.query("SELECT status,attempt_count FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, id])).rows[0];
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    await gate.scenario(scenarios[0], async () => {
      agent = await createRegisteredAgent(fixture, baseUrl);
      owned = await agent.claimNoop();
      const created = await fixture.request(`${prefix}/jobs`, "POST", { operation: "noop" });
      assert.equal(created.status, 201); waiting = created.body.job.id;
    });
    await gate.scenario(scenarios[1], async () => {
      assert.equal((await fixture.request(`${prefix}/settings`, "PUT", { certOpsPaused: true, reason: "Qualification pause ingestion" })).status, 200);
      assert.equal((await fixture.request(`${prefix}/settings`, "PUT", { certOpsPaused: true, reason: "Qualification duplicate pause" })).status, 200);
      const audits = (await fixture.pool.query("SELECT metadata FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_WORKSPACE_PAUSED'", [fixture.workspaceId])).rows;
      assert.equal(audits.length, 1); assert.equal(audits[0].metadata.reason, "Qualification pause ingestion");
      const response = await claim(); assert.equal(response.status, 409); assert.equal(response.body.code, "CERTOPS_WORKSPACE_PAUSED");
      assert.deepEqual(await row(waiting), { status: "pending", attempt_count: 0 });
    });
    await gate.scenario(scenarios[2], async () => {
      for (const operation of ["noop", "issue"]) {
        const response = await fixture.request(`${prefix}/jobs`, "POST", { operation }); assert.equal(response.status, 409);
      }
      assert.equal((await fixture.request(`${prefix}/jobs`)).status, 200);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM managed_certificates WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count, 0);
    });
    await gate.scenario(scenarios[3], async () => {
      assert.equal((await agent.machine("heartbeat", "heartbeat", { agentVersion: "1.0.0" })).status, 200);
      const evidenceId = crypto.randomUUID();
      const evidence = await agent.machine("jobs/results", "evidence", { jobId: owned.jobId, claimId: owned.claimId, evidenceItems: [{ evidenceId, eventType: "policy.checked", observedAt: new Date().toISOString(), summary: "Protocol qualification noop policy observation" }] });
      assert.equal(evidence.status, 200); assert.equal(evidence.body.evidenceCount, 1);
      const result = await agent.machine("jobs/results", "result", { jobId: owned.jobId, attemptId: owned.job.attemptId, nonce: owned.job.nonce, status: "succeeded", keyRotated: false });
      assert.equal(result.status, 200); assert.equal((await row(owned.jobId)).status, "succeeded");
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2", [fixture.workspaceId, owned.jobId])).rows[0].count, 1);
    });
    await gate.scenario(scenarios[4], async () => {
      assert.equal((await fixture.request(`${prefix}/settings`, "PUT", { certOpsPaused: false, reason: "Qualification resume ingestion" })).status, 200);
      const audits = (await fixture.pool.query("SELECT metadata FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_WORKSPACE_RESUMED'", [fixture.workspaceId])).rows;
      assert.equal(audits.length, 1); assert.equal(audits[0].metadata.reason, "Qualification resume ingestion");
      const response = await claim(); assert.equal(response.status, 200); assert.equal(response.body.jobs.length, 1); assert.equal(response.body.jobs[0].jobId, waiting);
      assert.deepEqual(await row(waiting), { status: "claimed", attempt_count: 1 });
    });
  } catch (error) { failure = error; }
  finally {
    try { if (ready) await gate.scenario(scenarios[5], () => fixture.cleanup()); else await fixture.cleanup(); } catch (error) { failure = failure ? new AggregateError([failure, error], "Pause qualification cleanup failed") : error; }
    try { if (ready) await gate.finish({ requiredScenarios: scenarios }); } catch (error) { failure = failure ? new AggregateError([failure, error], "Pause qualification incomplete") : error; }
  }
  if (failure) throw failure;
});
