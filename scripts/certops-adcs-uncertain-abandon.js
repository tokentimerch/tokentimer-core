"use strict";

/** Local contract for a successful uncertain-state abandonment.
 * Abandon only when the state is uncertain, no in-use key is deleted, and no
 * foreign request is touched. A successful abandon keeps nativeExecutionQualified false.
 * The forest journey remains in tests/e2e/helpers/certops-adcs-uncertain-abandon.js.
 */

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const SUITE = "adcs-uncertain-abandon";
const SOURCE = "scripts/certops-adcs-uncertain-abandon.js";
const EVIDENCE_LEVEL = "integration";
const SCOPE = "uncertain-state-abandon-local-contract";
const DEFAULT_REPORT = "qualification-results/adcs-uncertain-abandon.json";
const REQUIRED_SCENARIOS = Object.freeze(["adcs-uncertain-abandon-accepted"]);
const REQUIRED_CAPABILITIES = Object.freeze(["windows", "domain", "api", "qualifiedBuild"]);
const REQUIRED_SOURCES = Object.freeze([
  SOURCE,
  "tests/e2e/helpers/certops-adcs-uncertain-abandon.js",
  "docs/certops/adcs/uncertain-abandon.md",
  ".github/workflows/certops-adcs-coverage-variants.yml",
]);
const PROOF_KEYS = Object.freeze([
  "scope",
  "evidenceLevel",
  "state",
  "abandoned",
  "inUseKeyDeleted",
  "foreignRequestTouched",
  "disposableForestRan",
  "nativeExecutionQualified",
  "hostCapabilityAbsentIsPass",
]);
const KEY_DELETE = /delkey|certutil|cngkey|remove-item/i;

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

function abandonUncertain(action) {
  assert.ok(action && typeof action === "object" && !Array.isArray(action));
  if (action.state !== "submission_uncertain") throw new Error("Abandon requires an uncertain state");
  if (action.inUseKeyDeleted === true) throw new Error("Refusing to delete an in-use key");
  if (action.foreignRequestTouched === true) throw new Error("Refusing to touch a foreign request");
  if (action.key && action.key.inUse === true && action.deleteKey === true) {
    throw new Error("Refusing to delete an in-use key");
  }
  const commands = Array.isArray(action.commands) ? action.commands : [];
  for (const command of commands) {
    const joined = [command.file, ...(command.args || [])].join(" ");
    if (KEY_DELETE.test(joined)) throw new Error("Refusing to delete an in-use key");
    if (action.key?.container && /delete/i.test(joined) && joined.includes(action.key.container)) {
      throw new Error("Refusing to delete an in-use key");
    }
    if (action.foreignRequestId && joined.includes(String(action.foreignRequestId))) {
      throw new Error("Refusing to touch a foreign request");
    }
  }
  if (action.requestId && action.ownedRequestId && String(action.requestId) !== String(action.ownedRequestId)) {
    throw new Error("Refusing to touch a foreign request");
  }
  const proof = {
    scope: SCOPE,
    evidenceLevel: EVIDENCE_LEVEL,
    state: "submission_uncertain",
    abandoned: true,
    inUseKeyDeleted: false,
    foreignRequestTouched: false,
    disposableForestRan: false,
    nativeExecutionQualified: false,
    hostCapabilityAbsentIsPass: false,
  };
  verifyProof(proof);
  return { abandoned: true, proof };
}

function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...PROOF_KEYS].sort());
  assert.equal(value.scope, SCOPE);
  assert.equal(value.evidenceLevel, EVIDENCE_LEVEL);
  assert.equal(value.state, "submission_uncertain");
  assert.equal(value.abandoned, true);
  assert.equal(value.inUseKeyDeleted, false);
  assert.equal(value.foreignRequestTouched, false);
  assert.equal(value.disposableForestRan, false);
  assert.equal(value.nativeExecutionQualified, false);
  assert.equal(value.hostCapabilityAbsentIsPass, false);
  return true;
}

function qualifyUncertainAbandon(context = {}) {
  const lab = assessLab(context.env, context.platform);
  if (!lab.ok) throw new Error(`Disposable AD CS forest is required: ${lab.missing.join(",")}`);
  throw new Error("Uncertain abandon markers do not abandon an enrollment");
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
    inUseKeyDeleted: false,
    foreignRequestTouched: false,
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
  const reportPath = options.reportPath || env.CERTOPS_ADCS_UNCERTAIN_ABANDON_REPORT || DEFAULT_REPORT;
  const reason = lab.ok
    ? "Uncertain abandon markers do not abandon an enrollment"
    : `Disposable AD CS forest is required: ${lab.missing.join(",")}`;
  writeReport(reportPath, buildClosedReport(reason));
  console.error(reason);
  return 1;
}

function main() {
  return dispatch();
}

if (require.main === module) process.exit(main());

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
  abandonUncertain,
  verifyProof,
  qualifyUncertainAbandon,
  buildClosedReport,
  dispatch,
  main,
};
