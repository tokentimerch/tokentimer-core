"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createCertificateJob } = require("../../apps/api/services/certops/jobs");
const { EXECUTE, VALIDATE, prepareDestinationJob, assertDestinationExecutionSource } =
  require("../../apps/api/services/certops/deploymentDestinations");
const { hashDeploymentDestinationValidation } = require("../../packages/contracts/certops/deployment-destination.cjs");

const workspaceId = "00000000-0000-4000-8000-000000000001";
const assignedAgentId = "00000000-0000-4000-8000-000000000002";
const validationJobId = "00000000-0000-4000-8000-000000000003";
const requesterId = "00000000-0000-4000-8000-000000000004";
const executeJobId = "00000000-0000-4000-8000-000000000005";
const wireAgentId = "agent.portal-42";
const scope = {
  version: 1, zoneRef: "zone-1", destinationKind: "test-appliance", destinationRef: "portal-1",
  materialRef: "certificate-local", materialRevision: "revision-2", fingerprintSha256: "a".repeat(64),
};
const validation = {
  configurationSha256: "a".repeat(64), trustSha256: "b".repeat(64), observedStateSha256: "c".repeat(64),
  planSha256: "d".repeat(64), affectedServiceRefs: ["admin-portal"], permittedEffects: ["replace-cert"],
};
const unavailable = { code: "CERTOPS_DESTINATION_VALIDATION_UNAVAILABLE" };

function fixtures() {
  const claimId = "validation-claim-1";
  const receipt = {
    version: 1, validation,
    bindingSha256: hashDeploymentDestinationValidation({
      jobId: validationJobId, claimId, agentId: wireAgentId, workspaceId, deploymentDestination: scope,
    }, validation),
  };
  const committed = {
    id: validationJobId, claim_id: claimId, validation_fresh: true, payload: { deploymentDestination: scope },
    result_metadata: { deploymentDestinationValidation: { version: 1, agentId: wireAgentId, claimId, receipt } },
  };
  const checks = [];
  const client = { query(sql, params) {
    if (sql.includes("FROM certops_agents")) return { rows: [{ id: assignedAgentId, agentId: wireAgentId }] };
    assert.match(sql, /FOR SHARE/);
    assert.match(sql, /claimed_by_agent_id = assigned_agent_id/);
    assert.deepEqual(params, [validationJobId, workspaceId, assignedAgentId, 900]);
    return { rows: [committed] };
  } };
  return {
    committed, receipt, checks,
    options: {
      client, workspaceId, requestedByUserId: requesterId, transactionOwned: true, assignedAgentId,
      destinationValidationJobId: validationJobId,
      deploymentDestinationPolicy: { authorize(context) { checks.push(context); return true; } },
    },
  };
}

test("ordinary job callers cannot create either destination operation", async () => {
  for (const operation of [VALIDATE, EXECUTE]) {
    await assert.rejects(createCertificateJob({ workspaceId, operation }), unavailable);
  }
});

test("execution derives its exact scope and effects from a fresh committed validation and binds the assigned agent", async () => {
  const { options, committed, receipt, checks } = fixtures();
  const job = await prepareDestinationJob(options, workspaceId, EXECUTE);
  assert.deepEqual(job.payload.deploymentDestination, scope);
  assert.deepEqual(job.payload.deploymentDestinationExecution, {
    version: 1, validationJobId, validationClaimId: committed.claim_id, receipt,
  });
  assert.equal(job.requiredTargetSelector, scope.destinationRef);
  assert.equal(job.mode, "real");
  assert.equal(job.executorKind, "agent");
  assert.equal(checks[0].phase, "queue");
  assert.equal(checks[0].agentId, wireAgentId);
  assert.equal(checks[0].agentRowId, assignedAgentId);
  const sourceCheck = {
    client: options.client, workspaceId, assignedAgentId, agentId: wireAgentId, jobId: executeJobId, payload: job.payload,
  };
  await assertDestinationExecutionSource(sourceCheck);
  await assert.rejects(assertDestinationExecutionSource({ ...sourceCheck, agentId: assignedAgentId }), unavailable);
  await assert.rejects(assertDestinationExecutionSource({ ...sourceCheck, jobId: validationJobId }), unavailable);
  await assert.rejects(assertDestinationExecutionSource({
    ...sourceCheck, payload: { ...job.payload, deploymentDestination: { ...scope, materialRevision: "different" } },
  }), unavailable);
  committed.validation_fresh = false;
  await assert.rejects(assertDestinationExecutionSource(sourceCheck), unavailable);
});

test("execution ignores no authority fields and refuses token callers, caller supplied plans, and inactive policy", async () => {
  const { options } = fixtures();
  for (const override of [
    { payload: { deploymentDestination: scope } },
    { requestedByApiTokenId: "token-id" },
    { status: "pending" },
    { deploymentDestinationPolicy: { authorize: () => false } },
  ]) await assert.rejects(prepareDestinationJob({ ...options, ...override }, workspaceId, EXECUTE), unavailable);
});
