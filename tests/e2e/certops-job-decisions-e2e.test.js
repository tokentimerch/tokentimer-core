"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createRegisteredAgent } = require("./helpers/certops-registered-agent");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");

test("real API approval rejection and protocol terminal transitions", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires isolated authenticated API and PostgreSQL
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl);
  const fixture = await createApiFixture(baseUrl);
  let viewer; let ready = false; let primaryError;
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  const gate = createHostGate({ suite: "job-decisions-api", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_JOB_DECISIONS_REPORT, requiredCapabilities: ["api", "postgres"], probeCapabilities: async () => ({ api: { available: true }, postgres: { available: true } }) });
  gate.report.fixtureSource = { file: "tests/e2e/certops-job-decisions-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") };
  gate.report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  gate.report.executionScope = "Actual protocol outcomes for noop jobs; no certificate mutation or automatic retry execution claimed";
  const row = async (id) => (await fixture.pool.query("SELECT status,error_code,needs_operator_reconciliation,completed_at FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, id])).rows[0];
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    const agent = await createRegisteredAgent(fixture, baseUrl);
    viewer = await createApiFixture(baseUrl);
    await fixture.pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'viewer')", [fixture.workspaceId, viewer.userId]);
    assert.equal((await fixture.request(`${prefix}/settings`, "PUT", { certOpsRequireApprovalAlways: true, reason: "Qualification rejection policy" })).status, 200);
    let rejectedId;
    await gate.scenario("job-decisions-viewer-refusal", async () => {
      const created = await fixture.request(`${prefix}/jobs`, "POST", { operation: "noop" }); assert.equal(created.status, 201); rejectedId = created.body.job.id;
      assert.equal((await viewer.request(`${prefix}/jobs/${rejectedId}/reject`, "POST", { reason: "Unauthorized decision" })).status, 403);
      assert.equal((await row(rejectedId)).status, "pending_approval");
    });
    await gate.scenario("job-decisions-pending-not-claimed", async () => {
      const claimed = await agent.machine("jobs/claim", "claim", { maxJobs: 1, supportedActions: ["noop"] }); assert.equal(claimed.status, 200);
      assert.equal(claimed.body.jobs.length, 0); assert.equal((await row(rejectedId)).status, "pending_approval");
    });
    await gate.scenario("job-decisions-requester-withdrawal-paused", async () => {
      assert.equal((await fixture.request(`${prefix}/settings`, "PUT", { certOpsPaused: true, reason: "Qualification incident pause" })).status, 200);
      assert.equal((await fixture.request(`${prefix}/jobs/${rejectedId}/reject`, "POST", { reason: "Requester withdraws own request" })).status, 200);
      const stored = await row(rejectedId); assert.equal(stored.status, "rejected"); assert.equal(stored.error_code, "CERTOPS_APPROVAL_REJECTED"); assert.ok(stored.completed_at);
      assert.equal((await fixture.request(`${prefix}/settings`, "PUT", { certOpsPaused: false, certOpsRequireApprovalAlways: false, reason: "Qualification resume" })).status, 200);
    });
    await gate.scenario("job-decisions-terminal-redecision-refusal", async () => {
      for (const decision of ["approve", "reject"]) assert.equal((await fixture.request(`${prefix}/jobs/${rejectedId}/${decision}`, "POST", { reason: "Repeated terminal decision" })).status, 409);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certops_job_approvals WHERE workspace_id=$1 AND job_id=$2", [fixture.workspaceId, rejectedId])).rows[0].count, 1);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_JOB_APPROVAL_REJECTED' AND metadata->>'jobId'=$2", [fixture.workspaceId, rejectedId])).rows[0].count, 1);
    });
    let success; let successBody;
    await gate.scenario("job-decisions-claimed-success", async () => {
      success = await agent.claimNoop(); assert.equal((await row(success.jobId)).status, "claimed");
      successBody = { jobId: success.jobId, attemptId: success.job.attemptId, nonce: success.job.nonce, status: "succeeded", keyRotated: false };
      assert.equal((await agent.machine("jobs/results", "result", successBody)).status, 200); assert.equal((await row(success.jobId)).status, "succeeded");
    });
    await gate.scenario("job-decisions-terminal-replay", async () => {
      const duplicate = await agent.machine("jobs/results", "result", successBody); assert.equal(duplicate.status, 200); assert.equal(duplicate.body.duplicate, true);
      assert.equal((await agent.machine("jobs/results", "result", { ...successBody, status: "failed", errorMessage: "Conflicting terminal replay" })).status, 409);
      assert.equal((await row(success.jobId)).status, "succeeded");
    });
    await gate.scenario("job-decisions-orphan-reconciliation", async () => {
      const claimed = await agent.claimNoop();
      assert.equal((await agent.machine("jobs/results", "result", { jobId: claimed.jobId, attemptId: claimed.job.attemptId, nonce: claimed.job.nonce, status: "orphaned_unknown_effect", errorMessage: "Qualification simulated uncertain noop effect" })).status, 200);
      const stored = await row(claimed.jobId); assert.equal(stored.status, "orphaned_unknown_effect"); assert.equal(stored.needs_operator_reconciliation, true);
    }, { oracle: "Actual signed claim and protocol-reported synthetic uncertainty persists operator reconciliation; no host failure synthesized" });
    const competing = await createRegisteredAgent(fixture, baseUrl);
    let raceJobId; let owner; let foreign; let raceJob;
    await gate.scenario("job-decisions-two-agent-claim", async () => {
      const created = await fixture.request(`${prefix}/jobs`, "POST", { operation: "noop" }); assert.equal(created.status, 201); raceJobId = created.body.job.id;
      const agents = [agent, competing];
      const results = await Promise.all(agents.map((candidate) => candidate.machine("jobs/claim", "claim", { maxJobs: 1, supportedActions: ["noop"] })));
      results.forEach((result) => assert.equal(result.status, 200));
      const owned = results.flatMap((result, index) => result.body.jobs.filter((job) => (job.jobId || job.id) === raceJobId).map((job) => ({ index, job })));
      assert.equal(owned.length, 1); owner = agents[owned[0].index]; foreign = agents[1 - owned[0].index]; raceJob = owned[0].job;
      const stored = (await fixture.pool.query("SELECT status,attempt_count,claim_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, raceJobId])).rows[0];
      assert.equal(stored.status, "claimed"); assert.equal(stored.attempt_count, 1); assert.equal(String(stored.claim_id), String(raceJob.claimId));
    }, { oracle: "Two independently registered agents issue concurrent authenticated claims; one owned attempt is persisted" });
    await gate.scenario("job-decisions-foreign-result-fence", async () => {
      const body = { jobId: raceJobId, attemptId: raceJob.attemptId, nonce: raceJob.nonce, status: "succeeded", keyRotated: false };
      const rejected = await foreign.machine("jobs/results", "result", body); assert.equal(rejected.status, 409);
      assert.equal((await row(raceJobId)).status, "claimed");
      assert.equal((await owner.machine("jobs/results", "result", body)).status, 200); assert.equal((await row(raceJobId)).status, "succeeded");
      const repeated = await Promise.all([owner.machine("jobs/claim", "claim", { maxJobs: 1, supportedActions: ["noop"] }), foreign.machine("jobs/claim", "claim", { maxJobs: 1, supportedActions: ["noop"] })]);
      for (const response of repeated) { assert.equal(response.status, 200); assert.equal(response.body.jobs.length, 0); }
    }, { oracle: "A different authenticated agent cannot consume the owner's nonce or complete its job; owner remains able to report" });
  } catch (error) { primaryError = error; throw error; }
  finally {
    const cleanup = async () => { try { await fixture.cleanup(); } finally { if (viewer) await viewer.cleanup(); } };
    try { if (ready) { await gate.scenario("job-decisions-cleanup", cleanup); await gate.finish({ requiredScenarios: require("../../docs/certops/qualification-suites.json").suites["job-decisions-api"] }); } else await cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Job decision qualification and finalization failed"); throw error; }
  }
});
