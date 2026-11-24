"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createCertificateJob } = require("../../apps/api/services/certops/jobs");
const { EXECUTE, VALIDATE, prepareDestinationJob, assertDestinationExecutionSource,
  assertDestinationOperationLease, reserveDestinationOperation, persistSignedDestinationDispatch,
  checkDestinationResult, loadDestinationValidation } =
  require("../../apps/api/services/certops/deploymentDestinations");
const { hashDeploymentDestinationValidation, hasMatchingDeploymentDestinationOperation } = require("../../packages/contracts/certops/deployment-destination.cjs");

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
  mutationDomainSha256: "e".repeat(64),
};
const unavailable = { code: "CERTOPS_DESTINATION_VALIDATION_UNAVAILABLE" };

function fixtures({ includeMutationDomain = true } = {}) {
  const claimId = "validation-claim-1";
  const observed = { ...validation };
  if (!includeMutationDomain) delete observed.mutationDomainSha256;
  const receipt = {
    version: 1, validation: observed,
    bindingSha256: hashDeploymentDestinationValidation({
      jobId: validationJobId, claimId, agentId: wireAgentId, workspaceId, deploymentDestination: scope,
    }, observed),
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


test("legacy validation is readable but requires revalidation before execution queue or approval", async () => {
  const { options, receipt, committed, checks } = fixtures({ includeMutationDomain: false });
  const accepted = await loadDestinationValidation({
    client: options.client, workspaceId, assignedAgentId, validationJobId,
  });
  assert.deepEqual(accepted.execution.receipt, receipt);
  assert.equal(accepted.execution.receipt.validation.mutationDomainSha256, undefined);

  const revalidation = {
    code: "CERTOPS_DESTINATION_VALIDATION_UNAVAILABLE",
    message: "Validate the destination again to bind its mutation domain before executing",
  };
  await assert.rejects(prepareDestinationJob(options, workspaceId, EXECUTE), revalidation);
  await assert.rejects(assertDestinationExecutionSource({
    client: options.client, workspaceId, assignedAgentId, agentId: wireAgentId, jobId: executeJobId,
    payload: {
      deploymentDestination: scope,
      deploymentDestinationExecution: {
        version: 1, validationJobId, validationClaimId: committed.claim_id, receipt,
      },
    },
  }), revalidation);
  assert.deepEqual(checks, []);
});

test("reserves one canonical mutation domain across jobs, claims, aliases and agents", async () => {
  const { options } = fixtures();
  const { payload } = await prepareDestinationJob(options, workspaceId, EXECUTE);
  const domain = "e".repeat(64);
  const otherDomain = "f".repeat(64);
  const claimId = "00000000-0000-4000-8000-000000000006";
  const nextClaimId = "00000000-0000-4000-8000-000000000007";
  const nextJobId = "00000000-0000-4000-8000-000000000008";
  const agent = { id: assignedAgentId, workspaceId, agentId: wireAgentId };
  const job = {
    id: executeJobId, assigned_agent_id: assignedAgentId, operation: EXECUTE,
    status: "pending", mode: "real", attempt_count: 0, payload,
    approved_payload_hash: "a".repeat(64), approved_canonical_intent_hash: "b".repeat(64),
  };
  const holds = new Map();
  const policy = { resolveMutationDomain: () => domain };
  let allowLock = true;
  let dispatch;
  const client = { query(sql, params) {
    if (sql.includes("pg_try_advisory_xact_lock")) return { rows: [{ locked: allowLock }] };
    if (sql.includes("INSERT INTO certops_deployment_destination_operations")) {
      assert.match(sql, /ON CONFLICT DO NOTHING/);
      const key = params[0] + ":" + params[1];
      if (holds.has(key) || Array.from(holds.values()).some((value) => value[3] === params[3])) {
        return { rows: [] };
      }
      holds.set(key, params);
      return { rows: [{ operation_id: params[2] }] };
    }
    if (sql.includes("FROM certops_deployment_destination_operations")) {
      assert.match(sql, /FOR SHARE/);
      const held = holds.get(params[0] + ":" + params[1]);
      return { rows: held?.every((part, index) => part === params[index]) ? [{ operation_id: params[2] }] : [] };
    }
    assert.match(sql, /UPDATE certificate_jobs/);
    dispatch = JSON.parse(params[3]);
    return { rows: [{ id: executeJobId }] };
  } };

  const ownerArgs = { client, agent, job, policy, claimId };
  assert.equal(await reserveDestinationOperation({ ...ownerArgs, policy: {} }), null);
  assert.equal(await reserveDestinationOperation({
    ...ownerArgs, policy: { resolveMutationDomain: () => otherDomain },
  }), null);
  allowLock = false;
  assert.equal(await reserveDestinationOperation(ownerArgs), null);
  assert.equal(holds.size, 0);
  allowLock = true;
  const operation = await reserveDestinationOperation(ownerArgs);
  const nonce = "execution-claim-nonce-0001";
  const signedJob = {
    jobId: executeJobId, workspaceId, agentId: wireAgentId, claimId, action: EXECUTE, ...payload,
    deploymentDestinationApproval: { payloadSha256: job.approved_payload_hash, intentSha256: job.approved_canonical_intent_hash },
    deploymentDestinationOperation: operation,
  };
  assert.equal(hasMatchingDeploymentDestinationOperation(signedJob), true);
  assert.equal(hasMatchingDeploymentDestinationOperation({ ...signedJob, claimId: nextClaimId }), false);
  assert.equal(hasMatchingDeploymentDestinationOperation({
    ...signedJob, deploymentDestination: { ...scope, materialRevision: "different" },
  }), false);
  assert.equal(hasMatchingDeploymentDestinationOperation({
    ...signedJob, deploymentDestinationApproval: { ...signedJob.deploymentDestinationApproval, intentSha256: "c".repeat(64) },
  }), false);
  assert.deepEqual(holds.get(workspaceId + ":" + domain), [
    workspaceId, domain, operation.operationId, executeJobId, claimId, assignedAgentId,
  ]);

  const nextAgent = { ...agent, agentId: "agent-alias-2", id: requesterId };
  const alias = { ...scope, zoneRef: "second-zone", destinationRef: "second-name", materialRevision: "revision-3" };
  const nextValidationJobId = "00000000-0000-4000-8000-000000000009";
  const nextValidationClaimId = "next-validation-claim";
  const nextReceipt = {
    ...payload.deploymentDestinationExecution.receipt,
    bindingSha256: hashDeploymentDestinationValidation({
      jobId: nextValidationJobId, claimId: nextValidationClaimId, workspaceId,
      agentId: nextAgent.agentId, deploymentDestination: alias,
    }, validation),
  };
  const anotherJob = {
    ...job, id: nextJobId, assigned_agent_id: nextAgent.id,
    payload: {
      ...payload, deploymentDestination: alias,
      deploymentDestinationExecution: {
        version: 1, validationJobId: nextValidationJobId, validationClaimId: nextValidationClaimId, receipt: nextReceipt,
      },
    },
  };
  assert.equal(await reserveDestinationOperation({ ...ownerArgs, job: anotherJob, agent: nextAgent, claimId: nextClaimId }), null);
  assert.equal(await reserveDestinationOperation({ ...ownerArgs, claimId: nextClaimId }), null);

  await persistSignedDestinationDispatch({ client, signedJob, nonce, agentRowId: agent.id });
  assert.deepEqual(dispatch.operation, operation);
  await assert.rejects(persistSignedDestinationDispatch({ client, signedJob, nonce, agentRowId: nextAgent.id }), unavailable);
  const claimed = {
    ...job, claim_id: claimId, status: "running", lease_live: true,
    result_metadata: { deploymentDestinationDispatch: dispatch },
  };
  await assertDestinationOperationLease({ client, agent, job: claimed, policy });
  await assert.rejects(assertDestinationOperationLease({ client, agent, job: claimed, policy: {} }), unavailable);
  await assert.rejects(assertDestinationOperationLease({
    client, agent, job: claimed, policy: { resolveMutationDomain: () => otherDomain },
  }), unavailable);
  await assert.rejects(assertDestinationOperationLease({
    client, agent, job: { ...claimed, claim_id: nextClaimId }, policy,
  }), unavailable);

  const resultPolicy = { authorize: () => true };
  const result = await checkDestinationResult({
    client, agent, job: claimed, policy: resultPolicy, body: { nonce }, jobStatus: "blocked",
  });
  assert.deepEqual(result.deploymentDestinationDispatch.operation, operation);
  assert.equal(holds.size, 1);
  await checkDestinationResult({
    client, agent, job: { ...claimed, status: "blocked", result_metadata: result },
    policy: resultPolicy, body: { nonce }, jobStatus: "blocked",
  });
  assert.equal(holds.size, 1);
  await assert.rejects(checkDestinationResult({
    client, agent, job: claimed, policy: resultPolicy, body: { nonce }, jobStatus: "succeeded",
  }), { code: "CERTOPS_DESTINATION_VALIDATION_RECEIPT_INVALID" });
  holds.delete(workspaceId + ":" + domain);
  await assert.rejects(assertDestinationOperationLease({ client, agent, job: claimed, policy }), unavailable);
  await assert.rejects(checkDestinationResult({
    client, agent, job: claimed, policy: resultPolicy, body: { nonce }, jobStatus: "blocked",
  }), unavailable);
});
