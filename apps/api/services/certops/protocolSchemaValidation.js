"use strict";

/**
 * API-side CertOps agent-protocol validation compiled from the canonical
 * schema at packages/contracts/certops/agent-protocol.schema.json.
 *
 * Shape/enum/type checks only — lease ownership, mode-vs-status rules,
 * nonce/sequence gates, and claim authorization stay in agentDispatch.
 */

const Ajv = require("ajv");
const addFormats = require("ajv-formats");
const agentProtocolSchema = require("../../../../packages/contracts/certops/agent-protocol.schema.json");

const CERTOPS_AGENT_MESSAGE_INVALID = "CERTOPS_AGENT_MESSAGE_INVALID";

// Module-level compile (once per process). Same AJV options as agent-side and
// contracts tests: allErrors, strict:false, ajv-formats.
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
    return "status is invalid";
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

function messageError(message) {
  const error = new Error(message);
  error.code = CERTOPS_AGENT_MESSAGE_INVALID;
  return error;
}

/**
 * Assert a full envelope matches the schema and the expected messageType.
 * Returns the envelope body object (never null) for handlers that need it.
 *
 * @param {*} envelope
 * @param {string} expectedMessageType
 * @returns {object} body
 */
function assertValidAgentProtocolEnvelope(envelope, expectedMessageType) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw messageError("Message envelope must be a JSON object");
  }
  if (envelope.messageType !== expectedMessageType) {
    throw messageError(`messageType must be ${expectedMessageType}`);
  }
  // Claim polls historically omit body; normalize before schema check so
  // null/undefined does not fail claimBody's object type.
  if (
    expectedMessageType === "claim" &&
    (envelope.body === undefined || envelope.body === null)
  ) {
    envelope.body = {};
  }
  const { valid, errors } = validateAgentProtocolMessage(envelope);
  if (!valid) {
    throw messageError(errors[0] || "Message envelope is invalid");
  }
  if (!envelope.body || typeof envelope.body !== "object" || Array.isArray(envelope.body)) {
    throw messageError("Message body must be a JSON object");
  }
  return envelope.body;
}

module.exports = {
  CERTOPS_AGENT_MESSAGE_INVALID,
  validateAgentProtocolMessage,
  assertValidAgentProtocolEnvelope,
  agentProtocolSchemaId: agentProtocolSchema.$id,
};
