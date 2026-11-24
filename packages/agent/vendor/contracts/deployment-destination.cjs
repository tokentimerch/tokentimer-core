"use strict";

const { createHash } = require("node:crypto");
const { canonicalizeJobPayload } = require("./canonical-json.cjs");

const VALIDATE_DEPLOYMENT_DESTINATION = "validate-deployment-destination";

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

module.exports = { VALIDATE_DEPLOYMENT_DESTINATION, hashDeploymentDestinationValidation };
