"use strict";

/**
 * Agent-side CertOps protocol validation compiled from the canonical
 * agent-protocol schema (vendored under vendor/contracts so the shipped
 * package stays self-contained; refresh via scripts/sync-vendor.js).
 *
 * Shape/enum/type checks only — semantic authorization stays in the runtime
 * and control-plane services.
 */

const Ajv = require("ajv");
const addFormats = require("ajv-formats");
const agentProtocolSchema = require("../../vendor/contracts/agent-protocol.schema.json");

// Module-level compile (once per process), matching the contracts test AJV
// config: draft-07 schemas, allErrors, non-strict, formats plugin.
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
const validateCompiled = ajv.compile(agentProtocolSchema);

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
