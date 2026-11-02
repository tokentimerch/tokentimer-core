"use strict";

/** Local fail-closed safety variants. Template mismatch, allowlist miss,
 * disallowed algorithm, foreign request, and revocation/OCSP disagreement
 * each refuse the operation. This module does not change the authoritative
 * OCSP revoked proof.
 */

const assert = require("node:assert/strict");
const {assessLab, createClosedReport, writeReport} = require("../../../scripts/certops-adcs-lab-contract");

const SUITE = "adcs-safety-variants";
const SOURCE = "tests/e2e/helpers/certops-adcs-safety-variants.js";
const EVIDENCE_LEVEL = "integration";
const SCOPE = "adcs-safety-variant-refusal";
const DEFAULT_REPORT = "qualification-results/adcs-safety-variants.json";
const VARIANTS = Object.freeze([
  "template-mismatch",
  "allowlist-miss",
  "disallowed-algorithm",
  "foreign-request",
  "revocation-ocsp-disagreement",
]);
const ALLOWED_TEMPLATES = Object.freeze(["TTQualificationRSAShort"]);
const ALLOWED_ALGORITHMS = Object.freeze(["rsa-2048"]);
const REQUIRED_SCENARIOS = Object.freeze(VARIANTS.map((variant) => `adcs-safety-${variant}`));
const REQUIRED_CAPABILITIES = Object.freeze(["windows", "domain", "api", "qualifiedBuild"]);
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-adcs-lab-contract.js",
  SOURCE,
  "scripts/certops-adcs-safety-variants.js",
  ".github/workflows/certops-adcs-coverage-variants.yml",
  "tests/e2e/helpers/certops-adcs-ocsp-revoked.js",
]);
const PROOF_KEYS = Object.freeze([
  "scope",
  "evidenceLevel",
  "variant",
  "closed",
  "authoritativeRevokedStatusQualified",
  "disposableForestRan",
  "nativeExecutionQualified",
  "hostCapabilityAbsentIsPass",
]);



function refusal(variant) {
  const proof = {
    scope: SCOPE,
    evidenceLevel: EVIDENCE_LEVEL,
    variant,
    closed: true,
    authoritativeRevokedStatusQualified: false,
    disposableForestRan: false,
    nativeExecutionQualified: false,
    hostCapabilityAbsentIsPass: false,
  };
  verifyProof(proof);
  return { ok: false, proof };
}

function refuseSafety(variant, input) {
  assert.ok(input && typeof input === "object");
  if (variant === "template-mismatch") {
    if (input.requestedTemplate === input.confirmedTemplate) throw new Error("Template mismatch required");
    assert.equal(typeof input.requestedTemplate, "string");
    assert.equal(typeof input.confirmedTemplate, "string");
  } else if (variant === "allowlist-miss") {
    if (ALLOWED_TEMPLATES.includes(input.template)) throw new Error("Allowlist miss required");
    assert.equal(typeof input.template, "string");
  } else if (variant === "disallowed-algorithm") {
    if (ALLOWED_ALGORITHMS.includes(input.algorithm)) throw new Error("Disallowed algorithm required");
    assert.equal(typeof input.algorithm, "string");
  } else if (variant === "foreign-request") {
    if (input.owner === input.ownedOwner) throw new Error("Foreign request required");
    assert.equal(typeof input.owner, "string");
    assert.equal(typeof input.ownedOwner, "string");
  } else if (variant === "revocation-ocsp-disagreement") {
    if (input.crlStatus === input.ocspStatus) throw new Error("Revocation and OCSP disagreement required");
    assert.ok(input.crlStatus === "revoked" || input.crlStatus === "good");
    assert.ok(input.ocspStatus === "revoked" || input.ocspStatus === "good" || input.ocspStatus === "unknown");
  } else {
    throw new Error("Unknown safety variant");
  }
  return refusal(variant);
}

function assertAuthoritativeRevokedIntact(proof, verify) {
  assert.equal(typeof verify, "function");
  assert.equal(proof.authoritativeRevokedStatusQualified, true);
  const checked = verify(proof);
  assert.equal(checked, proof);
  assert.equal(checked.authoritativeRevokedStatusQualified, true);
  assert.throws(() => verify({ ...proof, authoritativeRevokedStatusQualified: false }));
  assert.throws(() => verifyProof({ ...refusal("revocation-ocsp-disagreement").proof, authoritativeRevokedStatusQualified: true }));
  return true;
}

function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...PROOF_KEYS].sort());
  assert.equal(value.scope, SCOPE);
  assert.equal(value.evidenceLevel, EVIDENCE_LEVEL);
  assert.ok(VARIANTS.includes(value.variant), value.variant);
  assert.equal(value.closed, true);
  assert.equal(value.authoritativeRevokedStatusQualified, false);
  assert.equal(value.disposableForestRan, false);
  assert.equal(value.nativeExecutionQualified, false);
  assert.equal(value.hostCapabilityAbsentIsPass, false);
  return true;
}

function qualifySafetyVariants(context = {}) {
  const lab = assessLab(context.env, context.platform);
  if (!lab.ok) throw new Error(`Disposable AD CS forest is required: ${lab.missing.join(",")}`);
  throw new Error("Safety variant markers do not enroll");
}

const buildClosedReport = createClosedReport({SUITE, EVIDENCE_LEVEL, REQUIRED_CAPABILITIES, REQUIRED_SCENARIOS}, {authoritativeRevokedStatusQualified: false}, {});



function dispatch(options = {}) {
  const env = options.env || process.env;
  const platform = options.platform || process.platform;
  const lab = assessLab(env, platform);
  const reportPath = options.reportPath || env.CERTOPS_ADCS_SAFETY_VARIANTS_REPORT || DEFAULT_REPORT;
  const reason = lab.ok
    ? "Safety variant markers do not enroll"
    : `Disposable AD CS forest is required: ${lab.missing.join(",")}`;
  writeReport(reportPath, buildClosedReport(reason));
  console.error(reason);
  return 1;
}

if (require.main === module) process.exitCode = dispatch();

module.exports = {
  SUITE,
  SOURCE,
  SCOPE,
  EVIDENCE_LEVEL,
  VARIANTS,
  ALLOWED_TEMPLATES,
  ALLOWED_ALGORITHMS,
  REQUIRED_SCENARIOS,
  REQUIRED_CAPABILITIES,
  REQUIRED_SOURCES,
  PROOF_KEYS,
  DEFAULT_REPORT,
  assessLab,
  refuseSafety,
  assertAuthoritativeRevokedIntact,
  verifyProof,
  qualifySafetyVariants,
  buildClosedReport,
  dispatch,
};
