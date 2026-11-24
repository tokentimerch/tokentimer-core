"use strict";

const { createHash } = require("node:crypto");
const { canonicalizeJobPayload } = require("./canonical-json.cjs");

const VALIDATE_DEPLOYMENT_DESTINATION = "validate-deployment-destination";
const EXECUTE_DEPLOYMENT_DESTINATION = "execute-deployment-destination";

function isDeploymentDestinationAction(action) {
  return action === VALIDATE_DEPLOYMENT_DESTINATION || action === EXECUTE_DEPLOYMENT_DESTINATION;
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

module.exports = {
  createDeploymentDestinationOperation,
  hasMatchingDeploymentDestinationOperation,
  VALIDATE_DEPLOYMENT_DESTINATION,
  EXECUTE_DEPLOYMENT_DESTINATION,
  isDeploymentDestinationAction,
  hashDeploymentDestinationValidation,
  hasMatchingDeploymentDestinationReceipt,
};
