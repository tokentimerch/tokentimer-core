"use strict";

/** Local parser for a lost submit response. Zero candidates are a clean miss
 * and do not invent a request id. Two or more candidates are ambiguous and
 * fail closed with no chosen request. Exactly one owned candidate is a local
 * parser result. nativeExecutionQualified stays false.
 */

const assert = require("node:assert/strict");
const {assessLab, createClosedReport, writeReport} = require("../../../scripts/certops-adcs-lab-contract");

const SUITE = "adcs-lost-submit";
const SOURCE = "tests/e2e/helpers/certops-adcs-lost-submit.js";
const EVIDENCE_LEVEL = "integration";
const SCOPE = "deterministic-lost-submit-response";
const DEFAULT_REPORT = "qualification-results/adcs-lost-submit.json";
const REQUEST_ID = /^[1-9][0-9]{0,9}$/;
const REQUIRED_SCENARIOS = Object.freeze([
  "adcs-lost-submit-clean-miss",
  "adcs-lost-submit-ambiguous",
  "adcs-lost-submit-owned-candidate",
]);
const REQUIRED_CAPABILITIES = Object.freeze(["windows", "domain", "api", "qualifiedBuild"]);
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-adcs-lab-contract.js",
  SOURCE,
  "scripts/certops-adcs-lost-submit.js",
  "docs/certops/adcs/lost-submit.md",
  ".github/workflows/certops-adcs-coverage-variants.yml",
]);
const PROOF_KEYS = Object.freeze([
  "scope",
  "evidenceLevel",
  "status",
  "requestId",
  "chosen",
  "candidateCount",
  "localParserResult",
  "disposableForestRan",
  "nativeExecutionQualified",
  "hostCapabilityAbsentIsPass",
]);



function closed(status, requestId, chosen, candidateCount) {
  return {
    scope: SCOPE,
    evidenceLevel: EVIDENCE_LEVEL,
    status,
    requestId,
    chosen,
    candidateCount,
    localParserResult: true,
    disposableForestRan: false,
    nativeExecutionQualified: false,
    hostCapabilityAbsentIsPass: false,
  };
}

function assertOwned(candidate, owned) {
  assert.equal(candidate.owned, true);
  assert.equal(candidate.owner, owned.owner);
  assert.equal(candidate.subject, owned.subject);
  assert.match(owned.csrSha256, /^[a-f0-9]{64}$/);
  assert.equal(candidate.csrSha256, owned.csrSha256);
  const requestId = String(candidate.requestId);
  assert.match(requestId, REQUEST_ID);
  assert.ok(Number(requestId) <= 0xffffffff);
  return requestId;
}

function reconcileLostSubmit(candidates, owned) {
  assert.equal(typeof owned?.owner, "string");
  assert.equal(typeof owned.subject, "string");
  if (!Array.isArray(candidates)) throw new Error("Lost-submit candidates are required");
  if (candidates.length === 0) {
    const proof = closed("clean-miss", null, false, 0);
    verifyProof(proof);
    return { proof, requestId: null, chosen: false };
  }
  if (candidates.length >= 2) {
    const error = new Error("Ambiguous lost-submit candidates");
    error.chosen = false;
    error.requestId = null;
    throw error;
  }
  const requestId = assertOwned(candidates[0], owned);
  const proof = closed("reconciled", requestId, true, 1);
  verifyProof(proof);
  return { proof, requestId, chosen: true };
}

function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...PROOF_KEYS].sort());
  assert.equal(value.scope, SCOPE);
  assert.equal(value.evidenceLevel, EVIDENCE_LEVEL);
  assert.equal(value.localParserResult, true);
  assert.equal(value.disposableForestRan, false);
  assert.equal(value.nativeExecutionQualified, false);
  assert.equal(value.hostCapabilityAbsentIsPass, false);
  if (value.status === "clean-miss") {
    assert.equal(value.requestId, null);
    assert.equal(value.chosen, false);
    assert.equal(value.candidateCount, 0);
  } else if (value.status === "reconciled") {
    assert.match(value.requestId, REQUEST_ID);
    assert.ok(Number(value.requestId) <= 0xffffffff);
    assert.equal(value.chosen, true);
    assert.equal(value.candidateCount, 1);
  } else {
    throw new Error("Ambiguous lost-submit candidates");
  }
  return true;
}

function qualifyLostSubmit(context = {}) {
  const lab = assessLab(context.env, context.platform);
  if (!lab.ok) throw new Error(`Disposable AD CS forest is required: ${lab.missing.join(",")}`);
  throw new Error("Lost-submit markers do not query a CA");
}

const buildClosedReport = createClosedReport({SUITE, EVIDENCE_LEVEL, REQUIRED_CAPABILITIES, REQUIRED_SCENARIOS}, {requestId: null, chosen: false}, {});



function dispatch(options = {}) {
  const env = options.env || process.env;
  const platform = options.platform || process.platform;
  const lab = assessLab(env, platform);
  const reportPath = options.reportPath || env.CERTOPS_ADCS_LOST_SUBMIT_REPORT || DEFAULT_REPORT;
  const reason = lab.ok
    ? "Lost-submit markers do not query a CA"
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
  REQUIRED_SCENARIOS,
  REQUIRED_CAPABILITIES,
  REQUIRED_SOURCES,
  PROOF_KEYS,
  DEFAULT_REPORT,
  assessLab,
  reconcileLostSubmit,
  verifyProof,
  qualifyLostSubmit,
  buildClosedReport,
  dispatch,
};
