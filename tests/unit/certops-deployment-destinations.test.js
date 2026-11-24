"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createCertificateJob } = require("../../apps/api/services/certops/jobs");
const { ingestResult } = require("../../apps/api/services/certops/agentDispatch");
const { EXECUTE, VALIDATE, OBSERVE, assertDestinationObservationSource, prepareDestinationJob, assertDestinationExecutionSource,
  assertDestinationOperationLease, reserveDestinationOperation, persistSignedDestinationDispatch,
  checkDestinationResult, loadDestinationValidation } =
  require("../../apps/api/services/certops/deploymentDestinations");
const { hashDeploymentDestinationValidation, hasMatchingDeploymentDestinationOperation,
  createDeploymentDestinationOperation, hashDeploymentDestinationObservation } = require("../../packages/contracts/certops/deployment-destination.cjs");

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

test("ordinary job callers cannot create native destination operations", async () => {
  for (const operation of [VALIDATE, EXECUTE, OBSERVE]) {
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

test("reserves one canonical mutation domain across jobs, claims, aliases, agents and workspaces", async () => {
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
    if (sql.includes("pg_try_advisory_xact_lock")) {
      assert.deepEqual(params, [`certops-destination-domain-v1:${domain}`]);
      return { rows: [{ locked: allowLock }] };
    }
    if (sql.includes("INSERT INTO certops_deployment_destination_operations")) {
      assert.match(sql, /ON CONFLICT DO NOTHING/);
      const key = params[1];
      if (holds.has(key) || Array.from(holds.values()).some((value) => value[3] === params[3])) {
        return { rows: [] };
      }
      holds.set(key, params);
      return { rows: [{ operation_id: params[2] }] };
    }
    if (sql.includes("FROM certops_deployment_destination_operations")) {
      assert.match(sql, /FOR SHARE/);
      const held = holds.get(params[1]);
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
  assert.deepEqual(holds.get(domain), [
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

  const remappedAgent = { ...nextAgent, workspaceId: "00000000-0000-4000-8000-000000000010" };
  const remappedJob = { ...anotherJob, payload: {
    ...anotherJob.payload,
    deploymentDestinationExecution: {
      ...anotherJob.payload.deploymentDestinationExecution,
      receipt: { ...nextReceipt, bindingSha256: hashDeploymentDestinationValidation({
        jobId: nextValidationJobId, claimId: nextValidationClaimId, workspaceId: remappedAgent.workspaceId,
        agentId: remappedAgent.agentId, deploymentDestination: alias,
      }, validation) },
    },
  } };
  assert.equal(await reserveDestinationOperation({
    ...ownerArgs, job: remappedJob, agent: remappedAgent, claimId: nextClaimId,
  }), null);

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
  holds.delete(domain);
  await assert.rejects(assertDestinationOperationLease({ client, agent, job: claimed, policy }), unavailable);
  await assert.rejects(checkDestinationResult({
    client, agent, job: claimed, policy: resultPolicy, body: { nonce }, jobStatus: "blocked",
  }), unavailable);
});

test("observation uses the authenticated historical claim and persists only a bounded read-only receipt", async () => {
  const { options } = fixtures();
  const { payload } = await prepareDestinationJob(options, workspaceId, EXECUTE);
  const ownerClaimId = "00000000-0000-4000-8000-000000000006";
  const currentClaimId = "00000000-0000-4000-8000-000000000007";
  const jobId = "00000000-0000-4000-8000-000000000008";
  const domain = payload.deploymentDestinationExecution.receipt.validation.mutationDomainSha256;
  const agent = { id: assignedAgentId, workspaceId, agentId: wireAgentId };
  const approval = { payloadSha256: "a".repeat(64), intentSha256: "b".repeat(64) };
  const ownership = createDeploymentDestinationOperation({
    ...payload, agentId: wireAgentId, workspaceId, claimId: ownerClaimId, deploymentDestinationApproval: approval,
  }, domain);
  const historical = {
    operation_id: ownership.operationId, owner_job_id: executeJobId, owner_claim_id: ownerClaimId,
    mutation_domain_sha256: domain, payload, approved_payload_hash: approval.payloadSha256,
    approved_canonical_intent_hash: approval.intentSha256,
    result_metadata: { deploymentDestinationDispatch: { operation: ownership } },
  };
  let currentDomain = domain;
  let canRead = true;
  let dispatch;
  const checks = [];
  const client = { query(sql, params) {
    if (sql.includes("FROM certops_agents")) return { rows: [{ id: assignedAgentId, agentId: wireAgentId }] };
    if (sql.includes("JOIN certificate_jobs j")) {
      assert.match(sql, /h.owner_agent_id = \$3/);
      assert.match(sql, /j.operation = 'execute-deployment-destination'/);
      assert.doesNotMatch(sql, /j.claim_id|lease_live|validation_fresh/);
      return { rows: params[0] === workspaceId && params[1] === ownership.operationId && params[2] === assignedAgentId ? [historical] : [] };
    }
    assert.match(sql, /UPDATE certificate_jobs/);
    assert.equal(params[6], "deploymentDestinationObservation");
    dispatch = JSON.parse(params[3]);
    return { rows: [{ id: jobId }] };
  } };
  const policy = {
    authorize({ phase, operation, scope: authorizedScope }) {
      assert.equal(operation, OBSERVE);
      assert.equal(authorizedScope.materialRef, undefined);
      assert.equal(authorizedScope.materialRevision, undefined);
      assert.equal(authorizedScope.fingerprintSha256, undefined);
      checks.push(phase);
      return canRead;
    },
    resolveMutationDomain({ scope: localSelector }) {
      assert.equal(localSelector.mutationDomainSha256, undefined);
      return currentDomain;
    },
  };
  const request = {
    ...options, client, deploymentDestinationPolicy: policy, destinationObservationOperationId: ownership.operationId,
  };
  const prepared = await prepareDestinationJob(request, workspaceId, OBSERVE);
  const observationScope = prepared.payload.deploymentDestinationObservation;
  assert.deepEqual(observationScope, {
    version: 1, operationId: ownership.operationId, mutationDomainSha256: domain,
    ownerJobId: executeJobId, ownerClaimId, validationJobId,
    zoneRef: scope.zoneRef, destinationKind: scope.destinationKind, destinationRef: scope.destinationRef,
  });
  assert.equal(prepared.payload.deploymentDestination, undefined);
  assert.equal(prepared.requiredTargetSelector, scope.destinationRef);
  await assert.rejects(prepareDestinationJob({
    ...request, payload: { deploymentDestinationObservation: observationScope },
  }, workspaceId, OBSERVE), unavailable);

  const nonce = "observation-claim-nonce-0001";
  const signedJob = {
    ...prepared.payload, action: OBSERVE, jobId, claimId: currentClaimId, workspaceId, agentId: wireAgentId,
  };
  await persistSignedDestinationDispatch({ client, signedJob, nonce, agentRowId: assignedAgentId });
  const job = {
    id: jobId, operation: OBSERVE, status: "running", mode: "real", lease_live: true,
    assigned_agent_id: assignedAgentId, required_target_selector: scope.destinationRef, claim_id: currentClaimId,
    payload: prepared.payload, result_metadata: { deploymentDestinationDispatch: dispatch },
  };
  await assertDestinationObservationSource({ client, agent, job, policy });
  await assert.rejects(assertDestinationObservationSource({
    client, agent: { ...agent, id: requesterId }, job, policy,
  }), unavailable);
  historical.owner_claim_id = currentClaimId;
  await assert.rejects(assertDestinationObservationSource({ client, agent, job, policy }), unavailable);
  historical.owner_claim_id = ownerClaimId;
  currentDomain = "9".repeat(64);
  await assert.rejects(assertDestinationObservationSource({ client, agent, job, policy }), unavailable);
  currentDomain = domain;

  const observation = { state: "observed", observedStateSha256: "f".repeat(64), affectedServiceRefs: ["admin-portal"] };
  const receipt = {
    version: 1, observation, bindingSha256: hashDeploymentDestinationObservation(signedJob, observation),
  };
  const observationResult = (sourceJob = job, patch = {}) => checkDestinationResult({
    client, agent, job: sourceJob, policy, jobStatus: "succeeded",
    body: { nonce, deploymentDestinationObservationReceipt: receipt, ...patch },
  });
  await assert.rejects(observationResult({ ...job, operation: "renew" }), unavailable);
  const invalidReceipt = { code: "CERTOPS_DESTINATION_VALIDATION_RECEIPT_INVALID" };
  await assert.rejects(observationResult(job, { deploymentDestinationObservationReceipt: null }), invalidReceipt);
  await assert.rejects(observationResult(job, { deploymentDestinationValidation: payload.deploymentDestinationExecution.receipt }), invalidReceipt);
  await assert.rejects(observationResult(job, { nonce: "earlier-claim-nonce-0001" }), invalidReceipt);
  canRead = false;
  await assert.rejects(observationResult(), unavailable);
  canRead = true;
  const recorded = await observationResult();
  assert.deepEqual(recorded.deploymentDestinationObservation, {
    version: 1, claimId: currentClaimId, agentId: wireAgentId, receipt,
  });
  const terminal = { ...job, status: "succeeded", lease_live: false, result_metadata: recorded };
  canRead = false;
  assert.deepEqual(await observationResult(terminal), recorded);
  const changed = { ...observation, observedStateSha256: "c".repeat(64) };
  await assert.rejects(observationResult(terminal, { deploymentDestinationObservationReceipt: {
    version: 1, observation: changed, bindingSha256: hashDeploymentDestinationObservation(signedJob, changed),
  } }), invalidReceipt);
  assert.deepEqual(checks, ["queue", "result", "result"]);

  // Exercise the terminal writer and nonce replay with the same signed scope.
  const liveJob = { ...job, claimed_by_agent_id: agent.id };
  let storedJob = { ...liveJob };
  const queries = [];
  const timeline = [];
  const resultClient = { async query(sql, params) {
    queries.push(sql);
    if (sql.includes("FOR UPDATE")) return { rows: [storedJob] };
    if (sql.includes("JOIN certificate_jobs j")) return client.query(sql, params);
    if (sql.includes("UPDATE certificate_jobs")) {
      assert.match(sql, /lease_expires_at > clock_timestamp\(\)/);
      storedJob = { ...storedJob, status: params[1], error_code: params[2], error_message: params[3],
        completed_at: new Date(), result_metadata: JSON.parse(params[6]) };
      return { rows: [storedJob] };
    }
    if (sql.includes("INSERT INTO certificate_job_log")) timeline.push(params);
    return { rows: [] };
  }, release() {} };
  const report = (patch = {}) => ingestResult({
    dbPool: { connect: async () => resultClient }, agent,
    body: { jobId, claimId: currentClaimId, nonce, status: "succeeded", deploymentDestinationObservationReceipt: receipt, ...patch },
    deps: {
      deploymentDestinationPolicy: policy,
      assertCurrentAgentCredential() {},
      consumeNonce: () => storedJob.status === "running" ? { consumed: true } :
        { consumed: false, code: "CERTOPS_NONCE_REPLAYED" },
    },
  });
  canRead = true;
  assert.equal((await report()).status, "succeeded");
  assert.deepEqual(storedJob.result_metadata.deploymentDestinationObservation, recorded.deploymentDestinationObservation);
  canRead = false;
  assert.deepEqual(await report(), { ok: true, duplicate: true });
  await assert.rejects(report({ deploymentDestinationObservationReceipt: {
    version: 1, observation: changed, bindingSha256: hashDeploymentDestinationObservation(signedJob, changed),
  } }), invalidReceipt);
  assert.equal(queries.filter((sql) => sql.includes("UPDATE certificate_jobs")).length, 1);
  assert.equal(queries.filter((sql) => sql.includes("INSERT INTO certificate_job_log")).length, 1);

  const localDetail = "https://appliance.fixture.test refused /private/portal-client.pem";
  canRead = true;
  storedJob = { ...liveJob };
  await report({ status: "blocked", deploymentDestinationObservationReceipt: null,
    errorMessage: localDetail, rejectionReason: localDetail });
  assert.equal(storedJob.error_code, "AGENT_RESULT_BLOCKED");
  assert.equal(storedJob.error_message, "destination_observation_failed");
  assert.equal(timeline.at(-1)[4], "destination_observation_failed");
  assert.ok(!JSON.stringify(storedJob).includes(localDetail));
  assert.ok(!JSON.stringify(timeline.at(-1)).includes(localDetail));

  storedJob = { ...liveJob };
  await report({ status: "blocked", deploymentDestinationObservationReceipt: null,
    errorMessage: "destination_observation_ownership_unavailable" });
  assert.equal(storedJob.error_message, "destination_observation_ownership_unavailable");
  assert.equal(queries.some((sql) => /(?:INSERT INTO|UPDATE|DELETE FROM) certops_deployment_destination_operations/.test(sql)), false);
  assert.equal(historical.result_metadata.deploymentDestinationDispatch.operation, ownership);
});
