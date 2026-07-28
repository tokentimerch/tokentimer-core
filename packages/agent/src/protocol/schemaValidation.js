"use strict";

/**
 * Agent-side CertOps protocol validation.
 *
 * The actual validator is precompiled ahead-of-time from the canonical
 * agent-protocol schema into a standalone, dependency-free module (vendored
 * under vendor/contracts/agent-protocol-validator.generated.js). ajv and
 * ajv-formats are devDependencies used only by that build step
 * (scripts/build-protocol-validator.js); the shipped agent package has zero
 * runtime dependencies, matching what the installer actually ships (it
 * copies packages/agent excluding node_modules and never runs an install).
 * Refresh both the schema and the generated validator via
 * scripts/sync-vendor.js.
 *
 * Shape/enum/type checks only — semantic authorization stays in the runtime
 * and control-plane services.
 */

const agentProtocolSchema = require("../../vendor/contracts/agent-protocol.schema.json");
const validateCompiled = require("../../vendor/contracts/agent-protocol-validator.generated.js");

function formatAjvError(error) {
  if (error.keyword === "additionalProperties") {
    const pathLabel = error.instancePath || "/";
    return `${pathLabel} has unknown field "${error.params.additionalProperty}"`;
  }
  if (
    error.keyword === "enum" &&
    typeof error.instancePath === "string" &&
    error.instancePath.endsWith("/status")
  ) {
    return "result body.status is invalid";
  }
  const pathLabel = error.instancePath || "/";
  return `${pathLabel} ${error.message || "is invalid"}`.trim();
}

/**
 * @param {*} message
 * @returns {{ valid: boolean, errors: string[] }}
 */
function validateAgentProtocolMessage(message) {
  const valid = validateCompiled(message);
  if (valid) return { valid: true, errors: [] };
  return {
    valid: false,
    errors: (validateCompiled.errors || []).map(formatAjvError),
  };
}

module.exports = {
  validateAgentProtocolMessage,
  agentProtocolSchemaId: agentProtocolSchema.$id,
};
