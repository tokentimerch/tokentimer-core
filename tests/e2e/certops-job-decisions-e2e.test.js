/**
 * Supporting API/PostgreSQL qualification: real API approval rejection and protocol terminal transitions.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * The registered fixture sends genuine machine-protocol requests; it does not run
 * an installed native agent. Named strict reports and owned cleanup are mandatory. */
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
    // skip-reason: prerequisite - requires isolated authenticated API and PostgreSQL
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl);
  const fixture = await createApiFixture(baseUrl);
  let viewer; let ready = false; let primaryError;
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  const gate = createHostGate({ suite: "job-decisions-api", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_JOB_DECISIONS_REPORT, requiredCapabilities: ["api", "postgres"], probeCapabilities: async () => ({ api: { available: true }, postgres: { available: true } }) });
  gate.report.fixtureSource = { file: "tests/e2e/certops-job-decisions-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") };
  gate.report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  gate.report.executionScope = "Actual protocol outcomes for noop and reload jobs; no host mutation or automatic retry execution claimed";
  const row = async (id) => (await fixture.pool.query("SELECT status,error_code,needs_operator_reconciliation,completed_at FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, id])).rows[0];
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    const targetName = "qualification.example.test";
    const validateCommand = "cancellation-validate";
    const reloadCommand = "cancellation-reload";
    const agent = await createRegisteredAgent(fixture, baseUrl, [], {
      declaredTargetSelectors: [targetName],
      declaredCommandProfileNames: [validateCommand, reloadCommand],
    });
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
    await gate.scenario("job-decisions-operator-cancellation", async () => {
      const cancelPath = id => `${prefix}/jobs/${id}/cancel`;
      const claimReload = () => agent.claimJob({
        operation: "reload", subjectType: "domain", subjectId: targetName,
        payload: { reloadService: "qualification-fixture", reloadCommandRefs: { validate: validateCommand, reload: reloadCommand } },
      });
      const agentRow = (await fixture.pool.query(
        "SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
        [fixture.workspaceId, agent.agentId],
      )).rows[0];
      const queuedResponse = await fixture.request(`${prefix}/jobs`, "POST", {
        operation: "noop", assignedAgentId: agentRow.id,
      });
      assert.equal(queuedResponse.status, 201, JSON.stringify(queuedResponse.body));
      const queued = queuedResponse.body.job.id;
      const detail = await fixture.request(`${prefix}/jobs/${queued}`);
      assert.equal(detail.body.job.canCancel, true);
      assert.equal((await viewer.request(cancelPath(queued), "POST")).status, 403);
      assert.equal((await fixture.request(`${prefix}/settings`, "PUT", {
        certOpsPaused: true, reason: "Qualification cancellation while paused",
      })).status, 200);
      let decisions;
      try {
        decisions = await Promise.all([
          fixture.request(cancelPath(queued), "POST"),
          fixture.request(cancelPath(queued), "POST"),
        ]);
      } finally {
        assert.equal((await fixture.request(`${prefix}/settings`, "PUT", {
          certOpsPaused: false, reason: "Qualification cancellation finished",
        })).status, 200);
      }
      assert.deepEqual(decisions.map(decision => decision.status).sort(), [200, 409]);
      assert.deepEqual(decisions.find(decision => decision.status === 200).body, {
        jobId: queued, status: "cancelled", needsOperatorReconciliation: false,
      });
      assert.equal((await row(queued)).status, "cancelled");

      const unstarted = await agent.claimNoop();
      const cancelBeforeRenewal = await fixture.request(cancelPath(unstarted.jobId), "POST");
      assert.equal(cancelBeforeRenewal.status, 200);
      assert.deepEqual(cancelBeforeRenewal.body, {
        jobId: unstarted.jobId, status: "cancelled", needsOperatorReconciliation: false,
      });
      assert.equal((await agent.renewLease(unstarted.jobId, unstarted.claimId)).status, 409);

      const competingLease = await claimReload();
      const [cancelRace, renewRace] = await Promise.all([
        fixture.request(cancelPath(competingLease.jobId), "POST"),
        agent.renewLease(competingLease.jobId, competingLease.claimId),
      ]);
      assert.equal(cancelRace.status, 200, JSON.stringify(cancelRace.body));
      assert.ok([200, 409].includes(renewRace.status), JSON.stringify(renewRace.body));
      const expectedRaceStatus = renewRace.status === 200 ? "orphaned_unknown_effect" : "cancelled";
      assert.equal(cancelRace.body.status, expectedRaceStatus);
      assert.equal((await row(competingLease.jobId)).status, expectedRaceStatus);

      const running = await claimReload();
      assert.equal((await agent.renewLease(running.jobId, running.claimId)).status, 200);
      assert.equal((await row(running.jobId)).status, "running");
      const stop = await fixture.request(cancelPath(running.jobId), "POST");
      assert.equal(stop.status, 200, JSON.stringify(stop.body));
      assert.deepEqual(stop.body, {
        jobId: running.jobId, status: "orphaned_unknown_effect", needsOperatorReconciliation: true,
      });
      assert.equal((await agent.renewLease(running.jobId, running.claimId)).status, 409);
      const late = await agent.machine("jobs/results", "result", {
        jobId: running.jobId, attemptId: running.job.attemptId, nonce: running.job.nonce,
        status: "succeeded", keyRotated: false,
      });
      assert.equal(late.status, 409);
      const stored = await row(running.jobId);
      assert.equal(stored.status, "orphaned_unknown_effect");
      assert.equal(stored.needs_operator_reconciliation, true);
      assert.ok(stored.completed_at);

      const readOnly = await agent.claimNoop();
      assert.equal((await agent.renewLease(readOnly.jobId, readOnly.claimId)).status, 200);
      const readOnlyCancel = await fixture.request(cancelPath(readOnly.jobId), "POST");
      assert.equal(readOnlyCancel.status, 200);
      assert.deepEqual(readOnlyCancel.body, {
        jobId: readOnly.jobId, status: "cancelled", needsOperatorReconciliation: false,
      });
      assert.equal((await row(readOnly.jobId)).needs_operator_reconciliation, false);

      for (const [source, executorKind] of [["executor", "agent"], ["controller_provisioning", "controller"]]) {
        const unsupportedJob = (await fixture.pool.query(
          "INSERT INTO certificate_jobs(workspace_id,operation,status,source,executor_kind) VALUES($1,'deploy','running',$2,$3) RETURNING id",
          [fixture.workspaceId, source, executorKind],
        )).rows[0].id;
        const unsupported = await fixture.request(cancelPath(unsupportedJob), "POST");
        assert.equal(unsupported.status, 409);
        assert.equal(unsupported.body.code, "CERTOPS_JOB_CANCELLATION_UNSUPPORTED");
        assert.equal((await row(unsupportedJob)).status, "running");
      }
      const rolloutApproval = (await fixture.pool.query(
        `INSERT INTO certificate_jobs(workspace_id,operation,status,source,executor_kind,assigned_agent_id,payload)
         VALUES($1,'deploy','pending_approval','api','agent',$2,$3::jsonb) RETURNING id`,
        [fixture.workspaceId, agentRow.id, JSON.stringify({ distributionRollout: {} })],
      )).rows[0].id;
      const rolloutDetail = await fixture.request(`${prefix}/jobs/${rolloutApproval}`);
      assert.equal(rolloutDetail.status, 200);
      assert.equal(rolloutDetail.body.job.canCancel, false);
      const rolloutCancel = await fixture.request(cancelPath(rolloutApproval), "POST");
      assert.equal(rolloutCancel.status, 409);
      assert.match(rolloutCancel.body.error, /distribution lifecycle controls/);
      assert.equal((await row(rolloutApproval)).status, "pending_approval");
      const trustJob = (await fixture.pool.query(
        `INSERT INTO certificate_jobs(workspace_id,operation,status,source,executor_kind,assigned_agent_id)
         VALUES($1,'distribute-trust','pending','api','agent',$2) RETURNING id`,
        [fixture.workspaceId, agentRow.id],
      )).rows[0].id;
      const manager = await createApiFixture(baseUrl);
      try {
        await fixture.pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'workspace_manager')", [fixture.workspaceId, manager.userId]);
        const managerDetail = await manager.request(`${prefix}/jobs/${trustJob}`);
        assert.equal(managerDetail.status, 200, JSON.stringify(managerDetail.body));
        assert.equal(managerDetail.body.job.canCancel, false);
        const managerCancellation = await manager.request(cancelPath(trustJob), "POST");
        assert.equal(managerCancellation.status, 403, JSON.stringify(managerCancellation.body));
        assert.equal((await row(trustJob)).status, "pending");
        const adminDetail = await fixture.request(`${prefix}/jobs/${trustJob}`);
        assert.equal(adminDetail.body.job.canCancel, true);
        assert.equal((await fixture.request(cancelPath(trustJob), "POST")).status, 200);
      } finally {
        await manager.cleanup();
      }
      const unreconciled = (await fixture.pool.query(
        `INSERT INTO certificate_jobs
          (workspace_id,operation,status,source,executor_kind,assigned_agent_id,
           needs_operator_reconciliation,reconciliation_reason)
          VALUES($1,'deploy','pending','api','agent',$2,true,'effects_unknown') RETURNING id`,
        [fixture.workspaceId, agentRow.id],
      )).rows[0].id;
      const refused = await fixture.request(cancelPath(unreconciled), "POST");
      assert.equal(refused.status, 409);
      assert.match(refused.body.error, /Reconcile the previous attempt/);
      assert.equal((await row(unreconciled)).needs_operator_reconciliation, true);
      // Leave no queued fixture for the subsequent independent claim scenario.
      await fixture.pool.query(
        "UPDATE certificate_jobs SET status='orphaned_unknown_effect' WHERE workspace_id=$1 AND id=$2",
        [fixture.workspaceId, unreconciled],
      );
      for (const jobId of [queued, unstarted.jobId, competingLease.jobId, running.jobId, readOnly.jobId, trustJob]) {
        const log = await fixture.pool.query(
          "SELECT created_by_user_id FROM certificate_job_log WHERE workspace_id=$1 AND job_id=$2 AND event_type='job.cancelled'",
          [fixture.workspaceId, jobId],
        );
        assert.deepEqual(log.rows, [{ created_by_user_id: fixture.userId }]);
        const audit = await fixture.pool.query(
          "SELECT actor_user_id FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_JOB_CANCELLED' AND metadata->>'jobId'=$2",
          [fixture.workspaceId, jobId],
        );
        assert.deepEqual(audit.rows, [{ actor_user_id: fixture.userId }]);
      }
    }, { oracle: "One cancel wins; real signed lease renewal and late result prove control-plane fencing and durable operator attribution" });
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
    try { if (ready) { await gate.scenario("job-decisions-cleanup", cleanup); await gate.finish({ requiredScenarios: require("../../scripts/certops-qualification-manifest").suites["job-decisions-api"] }); } else await cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Job decision qualification and finalization failed"); throw error; }
  }
});
