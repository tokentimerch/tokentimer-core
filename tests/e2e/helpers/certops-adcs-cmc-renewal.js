"use strict";

/** Local contract for a signature over an owned CMC renewal.
 * Unsigned or foreign CMC fails. A repeated unattended renewal uses the same
 * template and a new request id. Both results keep nativeExecutionQualified false.
 */

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const SUITE = "adcs-cmc-renewal";
const SOURCE = "tests/e2e/helpers/certops-adcs-cmc-renewal.js";
const EVIDENCE_LEVEL = "integration";
const SCOPE = "signed-cmc-renewal";
const DEFAULT_REPORT = "qualification-results/adcs-cmc-renewal.json";
const REQUEST_ID = /^[1-9][0-9]{0,9}$/;
const REQUIRED_SCENARIOS = Object.freeze([
  "adcs-cmc-signed-renewal",
  "adcs-cmc-repeated-unattended-renewal",
]);
const REQUIRED_CAPABILITIES = Object.freeze(["windows", "domain", "api", "qualifiedBuild"]);
const REQUIRED_SOURCES = Object.freeze([
  SOURCE,
  "scripts/certops-adcs-cmc-renewal.js",
  "docs/certops/adcs/cmc-renewal.md",
  ".github/workflows/certops-adcs-coverage-variants.yml",
]);
const PROOF_KEYS = Object.freeze([
  "scope",
  "evidenceLevel",
  "case",
  "template",
  "requestId",
  "priorRequestId",
  "signatureVerified",
  "ownerMatched",
  "consumedRequestReused",
  "disposableForestRan",
  "nativeExecutionQualified",
  "hostCapabilityAbsentIsPass",
]);

function assessLab(env = process.env, platform = process.platform) {
  const missing = [];
  if (platform !== "win32") missing.push("win32");
  if (env.CERTOPS_ADCS_DISPOSABLE_LAB !== "1") missing.push("CERTOPS_ADCS_DISPOSABLE_LAB");
  try {
    if (new URL(env.CERTOPS_ADCS_API_URL || "").protocol !== "https:") missing.push("CERTOPS_ADCS_API_URL");
  } catch {
    missing.push("CERTOPS_ADCS_API_URL");
  }
  return {
    ok: missing.length === 0,
    missing,
    passed: false,
    nativeQualified: false,
    hostCapabilityAbsentIsPass: false,
  };
}

function canonicalRenewal(renewal) {
  return Buffer.from(JSON.stringify({
    kind: "cmc-renewal",
    owner: renewal.owner,
    template: renewal.template,
    requestId: String(renewal.requestId),
  }));
}

function assertRenewalShape(renewal) {
  assert.equal(typeof renewal?.owner, "string");
  assert.ok(renewal.owner.length > 0);
  assert.equal(typeof renewal.template, "string");
  assert.ok(renewal.template.length > 0);
  assert.match(String(renewal.requestId), REQUEST_ID);
  assert.ok(Number(renewal.requestId) <= 0xffffffff);
}

function signOwnedRenewal(renewal, privateKey) {
  assertRenewalShape(renewal);
  const signature = crypto.sign("sha256", canonicalRenewal(renewal), privateKey).toString("base64");
  return { ...renewal, requestId: String(renewal.requestId), signature, algorithm: "sha256" };
}

function proofFor(renewalCase, renewal, priorRequestId) {
  return {
    scope: SCOPE,
    evidenceLevel: EVIDENCE_LEVEL,
    case: renewalCase,
    template: renewal.template,
    requestId: String(renewal.requestId),
    priorRequestId,
    signatureVerified: true,
    ownerMatched: true,
    consumedRequestReused: false,
    disposableForestRan: false,
    nativeExecutionQualified: false,
    hostCapabilityAbsentIsPass: false,
  };
}

function acceptSignedRenewal(renewal, publicKey, owner) {
  assertRenewalShape(renewal);
  if (typeof renewal.signature !== "string" || renewal.signature.length === 0) {
    throw new Error("Unsigned CMC renewal");
  }
  if (renewal.owner !== owner) throw new Error("Foreign CMC renewal");
  const verified = crypto.verify(
    "sha256",
    canonicalRenewal(renewal),
    publicKey,
    Buffer.from(renewal.signature, "base64"),
  );
  if (!verified) throw new Error("CMC renewal signature rejected");
  const proof = proofFor("signed-renewal", renewal, null);
  verifyProof(proof);
  return proof;
}

function acceptRepeatedRenewal(first, second, publicKey, owner) {
  acceptSignedRenewal(first, publicKey, owner);
  if (first.consumed !== true) throw new Error("Repeated renewal requires a consumed request");
  const secondProof = acceptSignedRenewal(second, publicKey, owner);
  if (second.template !== first.template) throw new Error("Repeated renewal template changed");
  if (String(second.requestId) === String(first.requestId)) throw new Error("Consumed request id reused");
  const proof = proofFor("repeated-unattended", second, String(first.requestId));
  verifyProof(proof);
  return { first: secondProof, proof };
}

function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...PROOF_KEYS].sort());
  assert.equal(value.scope, SCOPE);
  assert.equal(value.evidenceLevel, EVIDENCE_LEVEL);
  assert.equal(typeof value.template, "string");
  assert.ok(value.template.length > 0);
  assert.match(value.requestId, REQUEST_ID);
  assert.ok(Number(value.requestId) <= 0xffffffff);
  assert.equal(value.signatureVerified, true);
  assert.equal(value.ownerMatched, true);
  assert.equal(value.consumedRequestReused, false);
  assert.equal(value.disposableForestRan, false);
  assert.equal(value.nativeExecutionQualified, false);
  assert.equal(value.hostCapabilityAbsentIsPass, false);
  if (value.case === "signed-renewal") {
    assert.equal(value.priorRequestId, null);
  } else if (value.case === "repeated-unattended") {
    assert.match(value.priorRequestId, REQUEST_ID);
    assert.notEqual(value.priorRequestId, value.requestId);
  } else {
    throw new Error("CMC renewal case required");
  }
  return true;
}

function qualifyCmcRenewal(context = {}) {
  const lab = assessLab(context.env, context.platform);
  if (!lab.ok) throw new Error(`Disposable AD CS forest is required: ${lab.missing.join(",")}`);
  throw new Error("CMC renewal markers do not submit a renewal");
}

function buildClosedReport(reason) {
  const now = new Date().toISOString();
  const candidate = process.env.GITHUB_SHA;
  return {
    schemaVersion: 1,
    suite: SUITE,
    strict: true,
    evidenceLevel: EVIDENCE_LEVEL,
    status: "failed",
    nativeExecutionQualified: false,
    hostCapabilityAbsentIsPass: false,
    disposableForestRan: false,
    startedAt: now,
    finishedAt: now,
    candidateSha: /^[a-f0-9]{40}$/i.test(candidate || "") ? candidate : "0".repeat(40),
    requiredCapabilities: [...REQUIRED_CAPABILITIES],
    capabilities: {},
    requiredScenarios: [...REQUIRED_SCENARIOS],
    missingScenarios: [...REQUIRED_SCENARIOS],
    missingCapabilities: [...REQUIRED_CAPABILITIES],
    scenarios: [],
    cleanup: { status: "failed", summary: String(reason).slice(0, 512) },
    fixturePrerequisite: "No disposable forest executed this journey. A failed report is not native qualification.",
  };
}

function writeReport(reportPath, report) {
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
}

function dispatch(options = {}) {
  const env = options.env || process.env;
  const platform = options.platform || process.platform;
  const lab = assessLab(env, platform);
  const reportPath = options.reportPath || env.CERTOPS_ADCS_CMC_RENEWAL_REPORT || DEFAULT_REPORT;
  const reason = lab.ok
    ? "CMC renewal markers do not submit a renewal"
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
  signOwnedRenewal,
  acceptSignedRenewal,
  acceptRepeatedRenewal,
  verifyProof,
  qualifyCmcRenewal,
  buildClosedReport,
  dispatch,
};
