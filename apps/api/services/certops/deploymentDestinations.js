"use strict";

const { createHash } = require("node:crypto");
const { canonicalizeJobPayload } = require("../../../../packages/contracts/certops/canonical-json.cjs");
const {
  VALIDATE_DEPLOYMENT_DESTINATION: VALIDATE,
  EXECUTE_DEPLOYMENT_DESTINATION: EXECUTE,
  isDeploymentDestinationAction: isDestinationOperation,
  hashDeploymentDestinationValidation,
} = require("../../../../packages/contracts/certops/deployment-destination.cjs");
const {
  validateDeploymentDestinationScope: validScope,
  validateDeploymentDestinationReceipt: validReceipt,
  validateDeploymentDestinationExecution: validExecution,
} = require("../../../../packages/contracts/certops/validate-signed-job.cjs");
const { containsPrivateKeyMaterial, containsGenericSecretMaterial } = require("../../utils/secretMaterial");

const UNAVAILABLE = "CERTOPS_DESTINATION_VALIDATION_UNAVAILABLE";
const INVALID_RECEIPT = "CERTOPS_DESTINATION_VALIDATION_RECEIPT_INVALID";
const VALIDATION_MAX_AGE_MS = 15 * 60_000;
const UUID_PATTERN = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;

function destinationError(code = UNAVAILABLE) {
  return Object.assign(new Error(code === INVALID_RECEIPT
    ? "Deployment destination validation receipt is invalid"
    : "Deployment destination operation is unavailable"), { code });
}

function containsSecret(value) {
  return containsPrivateKeyMaterial(value) || containsGenericSecretMaterial(value);
}

function hashPublic(value) {
  return createHash("sha256").update(canonicalizeJobPayload(value)).digest("hex");
}

function claimBinding({ jobId, workspaceId, agentId, claimId, operation, scope, nonce }) {
  return hashPublic({ jobId, workspaceId, agentId, claimId, operation, scope, nonce });
}

function executionAuthorityHash(payload, payloadSha256, intentSha256) {
  return hashPublic({ execution: payload.deploymentDestinationExecution, approval: { payloadSha256, intentSha256 } });
}

function assertSignedDestinationAuthority(job) {
  const authoritySha256 = job.result_metadata?.deploymentDestinationDispatch?.authoritySha256;
  if (!authoritySha256 || authoritySha256 !== executionAuthorityHash(
    job.payload, job.approved_payload_hash, job.approved_canonical_intent_hash,
  )) throw destinationError();
}

async function persistSignedDestinationDispatch({ client, signedJob, nonce }) {
  const bindingSha256 = claimBinding({
    jobId: signedJob.jobId,
    workspaceId: signedJob.workspaceId,
    agentId: signedJob.agentId,
    claimId: signedJob.claimId,
    operation: signedJob.action,
    scope: signedJob.deploymentDestination,
    nonce,
  });
  const dispatch = { bindingSha256 };
  if (signedJob.action === EXECUTE) {
    const { payloadSha256, intentSha256 } = signedJob.deploymentDestinationApproval;
    dispatch.authoritySha256 = executionAuthorityHash(signedJob, payloadSha256, intentSha256);
  }
  const result = await client.query(
    `UPDATE certificate_jobs
        SET result_metadata = jsonb_set(result_metadata, '{deploymentDestinationDispatch}', $4::jsonb, true)
      WHERE id = $1 AND workspace_id = $2 AND claim_id = $3 AND status = 'claimed'
        AND operation = $5 AND payload->'deploymentDestination' = $6::jsonb
      RETURNING id`,
    [signedJob.jobId, signedJob.workspaceId, signedJob.claimId, JSON.stringify(dispatch),
      signedJob.action, JSON.stringify(signedJob.deploymentDestination)],
  );
  if (!result.rows[0]) throw destinationError();
}

async function requireDestinationPolicy({ client, policy, phase, workspaceId, agent, job }) {
  const scope = job.payload?.deploymentDestination;
  if (typeof policy?.authorize !== "function" || !isDestinationOperation(job.operation) ||
      job.mode !== "real" || String(job.assigned_agent_id ?? "") !== String(agent.id) ||
      !agent.agentId || !validScope(scope) || job.required_target_selector !== scope.destinationRef ||
      containsSecret(scope)) throw destinationError();
  const allowed = await policy.authorize({
    client,
    phase,
    workspaceId,
    agentRowId: agent.id,
    agentId: agent.agentId,
    operation: job.operation,
    jobId: job.id == null ? null : String(job.id),
    requestedByUserId: job.requested_by_user_id ?? null,
    approvedByUserId: job.approved_by_user_id ?? null,
    scope: Object.freeze(structuredClone(scope)),
  });
  if (allowed !== true) throw destinationError();
}

function verifyReceipt({ jobId, claimId, workspaceId, agentId, scope, receipt }) {
  if (!validScope(scope) || !validReceipt(receipt) || containsSecret(receipt) ||
      receipt.bindingSha256 !== hashDeploymentDestinationValidation({
        jobId, claimId, workspaceId, agentId, deploymentDestination: scope,
      }, receipt.validation)) throw destinationError(INVALID_RECEIPT);
}

async function checkDestinationResult({ client, policy, agent, job, body, jobStatus }) {
  if (!isDestinationOperation(job.operation)) {
    if (body.deploymentDestinationValidation != null) throw destinationError();
    return null;
  }
  if (typeof policy?.authorize !== "function") throw destinationError();
  const scope = job.payload?.deploymentDestination;
  const receipt = body.deploymentDestinationValidation ?? null;
  const active = job.status === "claimed" || job.status === "running";
  const expectsReceipt = job.operation === VALIDATE && jobStatus === "succeeded";
  const mixedOutput = ["trustResult", "enrollmentResult", "preflightResult", "publicationReceipt",
    "publicationCertificatePem", "deploymentReceipt", "cleanupReceipt", "reconciliationReceipt",
    "keyRotated"].some((field) => body[field] != null);

  if (job.mode !== "real" || !agent.agentId || !validScope(scope) ||
      (active && job.lease_live !== true) || mixedOutput || (receipt !== null) !== expectsReceipt ||
      (job.operation === VALIDATE && !["succeeded", "failed", "blocked", "rejected"].includes(jobStatus)) ||
      typeof body.nonce !== "string") throw destinationError(INVALID_RECEIPT);

  const dispatch = job.result_metadata?.deploymentDestinationDispatch;
  if (dispatch?.bindingSha256 !== claimBinding({
    jobId: String(job.id), workspaceId: agent.workspaceId, agentId: agent.agentId,
    claimId: String(job.claim_id), operation: job.operation, scope, nonce: body.nonce,
  })) throw destinationError(INVALID_RECEIPT);

  if (receipt) verifyReceipt({
    jobId: String(job.id), claimId: String(job.claim_id),
    workspaceId: agent.workspaceId, agentId: agent.agentId, scope, receipt,
  });
  if (active && job.operation === VALIDATE) {
    await requireDestinationPolicy({ client, policy, phase: "result", workspaceId: agent.workspaceId, agent, job });
  } else if (!active &&
      hashPublic({ receipt }) !== hashPublic({ receipt: job.result_metadata?.deploymentDestinationValidation?.receipt ?? null })) {
    throw destinationError(INVALID_RECEIPT);
  }

  return {
    deploymentDestinationDispatch: dispatch,
    ...(receipt ? { deploymentDestinationValidation: {
      version: 1, agentId: agent.agentId, claimId: String(job.claim_id), receipt: structuredClone(receipt),
    } } : {}),
  };
}

async function loadDestinationValidation({ client, workspaceId, validationJobId, assignedAgentId }) {
  const query = await client.query(
    `SELECT id, claim_id, payload, result_metadata,
            (completed_at > clock_timestamp() - make_interval(secs => $4)) AS validation_fresh
       FROM certificate_jobs
      WHERE id = $1 AND workspace_id = $2 AND assigned_agent_id = $3
        AND claimed_by_agent_id = assigned_agent_id
        AND operation = 'validate-deployment-destination' AND mode = 'real'
        AND status = 'succeeded'
      FOR SHARE`,
    [validationJobId, workspaceId, assignedAgentId, VALIDATION_MAX_AGE_MS / 1000],
  );
  const row = query.rows[0];
  const record = row?.result_metadata?.deploymentDestinationValidation;
  const scope = row?.payload?.deploymentDestination;
  if (!row?.validation_fresh || !record || record.version !== 1 ||
      record.claimId !== String(row.claim_id) || typeof record.agentId !== "string") throw destinationError();

  verifyReceipt({ jobId: String(row.id), claimId: record.claimId, workspaceId, agentId: record.agentId,
    scope, receipt: record.receipt });
  return { scope, agentId: record.agentId, execution: {
    version: 1, validationJobId: String(row.id), validationClaimId: record.claimId, receipt: record.receipt,
  } };
}

async function prepareDestinationJob(options, workspaceId, operation) {
  const { client, deploymentDestinationPolicy: policy, assignedAgentId, requestedByUserId } = options;
  if (!client || options.transactionOwned !== true || typeof policy?.authorize !== "function" ||
      (typeof client.connect === "function" && typeof client.idleCount === "number") ||
      !UUID_PATTERN.test(assignedAgentId ?? "") || !requestedByUserId ||
      options.requestedByApiTokenId != null || options.requestedByConnectionId != null ||
      options.subjectType != null || options.subjectId != null || (options.mode != null && options.mode !== "real") ||
      options.resultMetadata != null || options.status != null || options.source === "automation") {
    throw destinationError();
  }
  const agent = (await client.query(
    `SELECT id, agent_id AS "agentId" FROM certops_agents
      WHERE workspace_id = $1 AND id = $2 AND status = 'active' FOR SHARE`,
    [workspaceId, assignedAgentId],
  )).rows[0];
  if (!agent) throw destinationError();

  const payload = { schemaVersion: 1 };
  if (operation === VALIDATE) {
    if (Object.keys(options.payload ?? {}).some((key) => key !== "deploymentDestination")) throw destinationError();
    payload.deploymentDestination = options.payload?.deploymentDestination;
  } else {
    if (options.payload != null || !UUID_PATTERN.test(options.destinationValidationJobId ?? "")) throw destinationError();
    const accepted = await loadDestinationValidation({
      client, workspaceId, assignedAgentId, validationJobId: options.destinationValidationJobId,
    });
    if (accepted.agentId !== agent.agentId || accepted.execution.receipt.validation.permittedEffects.length === 0) throw destinationError();
    payload.deploymentDestination = accepted.scope;
    payload.deploymentDestinationExecution = accepted.execution;
  }
  await requireDestinationPolicy({
    client, policy, phase: "queue", workspaceId, agent,
    job: {
      operation, mode: "real", assigned_agent_id: assignedAgentId, requested_by_user_id: requestedByUserId, payload,
      required_target_selector: payload.deploymentDestination?.destinationRef,
    },
  });
  return {
    ...options, payload, mode: "real", executorKind: "agent", source: "api",
    requiredTargetSelector: payload.deploymentDestination.destinationRef,
    requiredDnsProvider: null, requiredCommandProfile: null,
  };
}

async function assertDestinationExecutionSource({ client, workspaceId, jobId, assignedAgentId, agentId, payload }) {
  const execution = payload?.deploymentDestinationExecution;
  if (!validExecution(execution) || !validScope(payload?.deploymentDestination) ||
      !UUID_PATTERN.test(execution.validationJobId) || execution.validationJobId === String(jobId)) throw destinationError();
  const accepted = await loadDestinationValidation({ client, workspaceId, assignedAgentId, validationJobId: execution.validationJobId });
  if ((agentId != null && agentId !== accepted.agentId) ||
      hashPublic(execution) !== hashPublic(accepted.execution) ||
      hashPublic(payload.deploymentDestination) !== hashPublic(accepted.scope)) throw destinationError();
}

module.exports = {
  VALIDATE, EXECUTE, UNAVAILABLE, INVALID_RECEIPT, isDestinationOperation,
  persistSignedDestinationDispatch, requireDestinationPolicy, checkDestinationResult,
  prepareDestinationJob, loadDestinationValidation, assertDestinationExecutionSource,
  assertSignedDestinationAuthority,
};
