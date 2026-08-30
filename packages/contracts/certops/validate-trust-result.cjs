"use strict";

/**
 * Standalone validator for trust-result-contract.schema.json: the return-path
 * counterpart of validate-signed-job.cjs, which validates the signed job
 * payload sent to an agent. Implements the trust-result contract described in
 * docs/adr/0012-certops-windows-execution-surface-and-trust-anchors.md.
 *
 * `.cjs` because packages/contracts/package.json declares "type": "module".
 *
 * SCOPE: shape only. Cross-checking a result's agentId/store/
 * fingerprintSha256/transitionGeneration against the signed job it claims to
 * answer depends on database state, so it lives in the service layer (see
 * trustAnchors.js's ingestTrustJobResult).
 */

const TRUST_RESULT_CONTRACT_SCHEMA = require("./trust-result-contract.schema.json");
const SIGNED_DISPATCH_PAYLOAD_SCHEMA = require("./signed-dispatch-payload.schema.json");

let ajvInstance = null;

/**
 * Lazily constructs a shared Ajv instance, so a caller that never validates a
 * result never pays Ajv's compile cost.
 */
function getAjv() {
  if (ajvInstance) return ajvInstance;

  // eslint-disable-next-line global-require -- lazy by design, see above
  const Ajv = require("ajv");
  // eslint-disable-next-line global-require
  const addFormats = require("ajv-formats");

  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  ajv.addSchema(SIGNED_DISPATCH_PAYLOAD_SCHEMA);
  ajv.addSchema(TRUST_RESULT_CONTRACT_SCHEMA);

  ajvInstance = ajv;
  return ajvInstance;
}

/**
 * Validates an untrusted agent-reported trust-job result. Never throws on
 * malformed input.
 *
 * @param {unknown} result
 * @returns {{ valid: boolean, errors: Array<object>|null }}
 */
function validateTrustResult(result) {
  const ajv = getAjv();
  const validateFn = ajv.getSchema(TRUST_RESULT_CONTRACT_SCHEMA.$id);
  if (!validateFn) {
    throw new Error(
      "validate-trust-result: trust-result-contract.schema.json was not " +
        "registered with Ajv; this is a programmer error, not an " +
        "untrusted-input problem",
    );
  }
  const valid = validateFn(result);
  return { valid, errors: valid ? null : validateFn.errors };
}

module.exports = {
  TRUST_RESULT_CONTRACT_SCHEMA,
  validateTrustResult,
  _test: {
    getAjv,
    SIGNED_DISPATCH_PAYLOAD_SCHEMA,
  },
};
