"use strict";

/**
 * Issuer adapters (ADR-0014).
 *
 * A renewal executor owns the key, the CSR, leases, the job journal and
 * deployment. It hands the CSR to an issuer and acts on the typed outcome
 * the issuer returns, so a new issuer kind never touches custody or deploy
 * code.
 *
 * An issuer is `{ kind, step, submit, retrieve? }`. `step` is the journal
 * stage recorded before submit runs. `submit({ csrPem, domains })` resolves
 * to one of these outcomes:
 *
 *   issued         certificatePem holds the leaf, followed by any chain.
 *   pending        the CA queued the request under requestId.
 *   denied         the CA answered and refused this request.
 *   refused        agent-local policy declined before the CA was contacted.
 *   failed         no certificate, and nothing at the CA to come back for.
 *   not_submitted  the transport proves the request never reached the CA.
 *   uncertain      the request may have reached the CA. Never resubmit it.
 *
 * Any outcome may carry `evidence` items, which the executor reports before
 * acting on the outcome. An issuer that can return pending must implement
 * `retrieve(requestId)`, which resolves to the same vocabulary.
 */

const { createAcmeIssuer } = require("./acme");

const ISSUANCE_OUTCOMES = Object.freeze([
  "issued",
  "pending",
  "denied",
  "refused",
  "failed",
  "not_submitted",
  "uncertain",
]);

// Kinds this agent build can run. The contract also defines adcs, which an
// agent without it must never fall back to ACME for.
const IMPLEMENTED_ISSUER_KINDS = Object.freeze(["acme"]);

// AD CS RequestIds are 32-bit unsigned (enrollment-result contract).
const MAX_REQUEST_ID = 0xffffffff;

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

/**
 * A job without issuerKind is an acme job, so jobs that predate issuer
 * kinds keep running unchanged.
 *
 * @param {object} job signature-verified job payload
 * @returns {{ kind: string }|{ error: string }}
 */
function resolveJobIssuerKind(job) {
  const kind = job?.issuerKind;
  if (kind === undefined) return { kind: "acme" };
  if (IMPLEMENTED_ISSUER_KINDS.includes(kind)) return { kind };
  return {
    error: `job names issuer kind ${JSON.stringify(kind)}, which this agent does not implement`,
  };
}

function findOutcomeProblem(value) {
  if (value.evidence !== undefined && !Array.isArray(value.evidence)) {
    return "evidence must be an array";
  }
  switch (value.outcome) {
    case "issued":
      return isNonEmptyString(value.certificatePem) ? null : "certificatePem is required";
    case "pending":
      return Number.isInteger(value.requestId) &&
        value.requestId >= 1 &&
        value.requestId <= MAX_REQUEST_ID
        ? null
        : "requestId must be an integer from 1 to 4294967295";
    case "refused":
      if (!isNonEmptyString(value.rejectionReason)) return "rejectionReason is required";
      return isNonEmptyString(value.detail) ? null : "detail is required";
    default:
      return isNonEmptyString(value.detail) ? null : "detail is required";
  }
}

/**
 * Checks an issuer outcome before an executor acts on it. A malformed
 * outcome throws instead of being read as anything, least of all issued.
 *
 * @param {unknown} value
 * @returns {object} the same outcome
 */
function assertIssuanceOutcome(value) {
  if (value === null || typeof value !== "object" || !ISSUANCE_OUTCOMES.includes(value.outcome)) {
    throw new TypeError(
      `issuer returned an unknown outcome: ${JSON.stringify(value?.outcome ?? null)}`,
    );
  }
  const problem = findOutcomeProblem(value);
  if (problem !== null) {
    throw new TypeError(`issuer returned a malformed ${value.outcome} outcome: ${problem}`);
  }
  return value;
}

module.exports = {
  ISSUANCE_OUTCOMES,
  IMPLEMENTED_ISSUER_KINDS,
  resolveJobIssuerKind,
  assertIssuanceOutcome,
  createAcmeIssuer,
};
