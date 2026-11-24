"use strict";

const { createHash } = require("node:crypto");
const { canonicalizeJobPayload, isPlainObject } = require("./canonical-json.cjs");

const VALIDATE_DEPLOYMENT_DESTINATION = "validate-deployment-destination";
const EXECUTE_DEPLOYMENT_DESTINATION = "execute-deployment-destination";
const OBSERVE_DEPLOYMENT_DESTINATION = "observe-deployment-destination";
const isSha256 = (value) => typeof value === "string" && value.length === 64 && /^[a-f0-9]+$/.test(value);

function isDeploymentDestinationAction(action) {
  return action === VALIDATE_DEPLOYMENT_DESTINATION || action === EXECUTE_DEPLOYMENT_DESTINATION ||
    action === OBSERVE_DEPLOYMENT_DESTINATION;
}

/**
 * Binds the public observation to the verified validation job and its claim.
 * This digest has meaning only with the native authenticated result.
 */
function hashDeploymentDestinationValidation(job, validation) {
  return createHash("sha256").update(canonicalizeJobPayload({
    action: VALIDATE_DEPLOYMENT_DESTINATION,
    jobId: job.jobId,
    claimId: job.claimId,
    workspaceId: job.workspaceId,
    agentId: job.agentId,
    scope: job.deploymentDestination,
    validation,
  })).digest("hex");
}

function hasMatchingDeploymentDestinationReceipt(job) {
  const execution = job.deploymentDestinationExecution;
  if (execution.validationJobId === job.jobId) return false;

  return hashDeploymentDestinationValidation({
    jobId: execution.validationJobId,
    claimId: execution.validationClaimId,
    workspaceId: job.workspaceId,
    agentId: job.agentId,
    deploymentDestination: job.deploymentDestination,
  }, execution.receipt.validation) === execution.receipt.bindingSha256;
}

function createDeploymentDestinationOperation(job, mutationDomainSha256) {
  const operationId = createHash("sha256").update(canonicalizeJobPayload({
    contract: "certops-deployment-destination-operation-v1",
    workspaceId: job.workspaceId,
    agentId: job.agentId,
    mutationDomainSha256,
    scope: job.deploymentDestination,
    execution: job.deploymentDestinationExecution,
    approval: job.deploymentDestinationApproval,
  })).digest("hex");
  return { version: 1, operationId, mutationDomainSha256, ownerClaimId: job.claimId };
}

function hasMatchingDeploymentDestinationOperation(job) {
  const operation = job.deploymentDestinationOperation;
  return operation?.version === 1 &&
    typeof operation.mutationDomainSha256 === "string" && /^[a-f0-9]{64}$/.test(operation.mutationDomainSha256) &&
    typeof job.claimId === "string" && operation.ownerClaimId === job.claimId &&
    operation.mutationDomainSha256 === job.deploymentDestinationExecution?.receipt?.validation?.mutationDomainSha256 &&
    operation.operationId === createDeploymentDestinationOperation(job, operation.mutationDomainSha256).operationId;
}

function hashDeploymentDestinationObservation(job, observation) {
  return createHash("sha256").update(canonicalizeJobPayload({
    action: OBSERVE_DEPLOYMENT_DESTINATION,
    jobId: job.jobId,
    claimId: job.claimId,
    workspaceId: job.workspaceId,
    agentId: job.agentId,
    scope: job.deploymentDestinationObservation,
    observation,
  })).digest("hex");
}

// The caller verifies the dispatch signature and keeps that payload immutable.
// Persist this separate protected record before an approved effect may begin.
function createDeploymentDestinationExecutionIntent(job) {
  const operation = job?.deploymentDestinationOperation;
  const validation = job?.deploymentDestinationExecution?.receipt?.validation;
  if (job?.action !== EXECUTE_DEPLOYMENT_DESTINATION || job.mode !== "real" ||
      job.claimId !== job.attemptId || !Array.isArray(validation?.permittedEffects) ||
      !validation.permittedEffects.length || !Array.isArray(validation.affectedServiceRefs) ||
      validation.affectedServiceRefs.length < 1 || validation.affectedServiceRefs.length > 8 ||
      !isSha256(validation.planSha256) || !isSha256(job.deploymentDestination?.fingerprintSha256) ||
      ![job.jobId, job.claimId, job.workspaceId, job.agentId, job.nonce].every(
        (value) => typeof value === "string" && value.length > 0,
      )) return null;
  try {
    if (!hasMatchingDeploymentDestinationOperation(job) || !hasMatchingDeploymentDestinationReceipt(job)) return null;
  } catch {
    return null;
  }
  return {
    version: 1,
    workspaceId: job.workspaceId,
    agentId: job.agentId,
    ownerJobId: job.jobId,
    ownerClaimId: job.claimId,
    operationId: operation.operationId,
    mutationDomainSha256: operation.mutationDomainSha256,
    planSha256: validation.planSha256,
  };
}

function executionOutcomeMatchesApproval(job, outcome) {
  if (!isPlainObject(outcome)) return false;
  if (outcome.state === "unknown") return Object.keys(outcome).length === 1;
  const approvedServices = job.deploymentDestinationExecution.receipt.validation.affectedServiceRefs;
  const verifiedServices = outcome.verifiedServiceRefs;
  return outcome.state === "confirmed" && Object.keys(outcome).length === 4 &&
    outcome.verifiedFingerprintSha256 === job.deploymentDestination.fingerprintSha256 &&
    isSha256(outcome.verificationSha256) &&
    Array.isArray(verifiedServices) && verifiedServices.length === approvedServices.length &&
    new Set(verifiedServices).size === verifiedServices.length &&
    approvedServices.every((ref) => verifiedServices.includes(ref));
}

// The caller reads the durable intent back and obtains verified destination
// facts before sealing the receipt. The digest binds those facts to the claim.
function bindDeploymentDestinationExecutionReceipt(job, recordedIntent, outcome) {
  const intent = createDeploymentDestinationExecutionIntent(job);
  if (!intent || !isPlainObject(recordedIntent) || !isPlainObject(outcome) ||
      Object.keys(recordedIntent).length !== Object.keys(intent).length ||
      !Object.entries(intent).every(([key, value]) => Object.hasOwn(recordedIntent, key) && recordedIntent[key] === value)) return null;
  let boundOutcome;
  try {
    boundOutcome = structuredClone(outcome);
  } catch {
    return null;
  }
  if (!executionOutcomeMatchesApproval(job, boundOutcome)) return null;
  const intendedEffectSha256 = createHash("sha256").update(canonicalizeJobPayload({
    contract: "certops-deployment-destination-execution-intent-v1", intent,
  })).digest("hex");
  const bindingSha256 = createHash("sha256").update(canonicalizeJobPayload({
    contract: "certops-deployment-destination-execution-receipt-v1",
    intendedEffectSha256, nonce: job.nonce, outcome: boundOutcome,
  })).digest("hex");
  return { version: 1, intendedEffectSha256, outcome: boundOutcome, bindingSha256 };
}

function hasMatchingDeploymentDestinationExecutionReceipt(job, recordedIntent, receipt) {
  if (!isPlainObject(receipt) || receipt.version !== 1 || Object.keys(receipt).length !== 4) return false;
  const expected = bindDeploymentDestinationExecutionReceipt(job, recordedIntent, receipt.outcome);
  return expected !== null && receipt.intendedEffectSha256 === expected.intendedEffectSha256 &&
    receipt.bindingSha256 === expected.bindingSha256;
}

module.exports = {
  OBSERVE_DEPLOYMENT_DESTINATION,
  hashDeploymentDestinationObservation,
  createDeploymentDestinationExecutionIntent,
  bindDeploymentDestinationExecutionReceipt,
  hasMatchingDeploymentDestinationExecutionReceipt,
  createDeploymentDestinationOperation,
  hasMatchingDeploymentDestinationOperation,
  VALIDATE_DEPLOYMENT_DESTINATION,
  EXECUTE_DEPLOYMENT_DESTINATION,
  isDeploymentDestinationAction,
  hashDeploymentDestinationValidation,
  hasMatchingDeploymentDestinationReceipt,
};
