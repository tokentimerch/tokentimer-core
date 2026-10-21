"use strict";

/** Local records for response-loss, journal-phase, and key-generation crash
 * experiments. verifyProof requires releaseQualificationSatisfied false.
 * Treating a report as qualified throws. These experiments do not satisfy
 * release qualification.
 */

const assert = require("node:assert/strict");
const {assessLab, createClosedReport, writeReport} = require("../../../scripts/certops-adcs-lab-contract");

const SUITE = "adcs-crash-experiments";
const SOURCE = "tests/e2e/helpers/certops-adcs-crash-experiments.js";
const EVIDENCE_LEVEL = "integration";
const SCOPE = "adcs-crash-experiment";
const DEFAULT_REPORT = "qualification-results/adcs-crash-experiments.json";
const EXPERIMENTS = Object.freeze(["response-loss", "journal-phase", "key-generation"]);
const REQUIRED_SCENARIOS = Object.freeze([
  "adcs-crash-response-loss",
  "adcs-crash-journal-phase",
  "adcs-crash-key-generation",
]);
const REQUIRED_CAPABILITIES = Object.freeze(["windows", "domain", "api", "qualifiedBuild"]);
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-adcs-lab-contract.js",
  SOURCE,
  "scripts/certops-adcs-crash-experiments.js",
  ".github/workflows/certops-adcs-coverage-variants.yml",
]);
const PROOF_KEYS = Object.freeze([
  "scope",
  "evidenceLevel",
  "experiment",
  "releaseQualificationSatisfied",
  "disposableForestRan",
  "nativeExecutionQualified",
  "hostCapabilityAbsentIsPass",
]);
const REJECTED = "Experimental crash report cannot satisfy release qualification";



function buildExperimentProof(experiment) {
  assert.ok(EXPERIMENTS.includes(experiment), "crash experiment required");
  const proof = {
    scope: SCOPE,
    evidenceLevel: EVIDENCE_LEVEL,
    experiment,
    releaseQualificationSatisfied: false,
    disposableForestRan: false,
    nativeExecutionQualified: false,
    hostCapabilityAbsentIsPass: false,
  };
  verifyProof(proof);
  return proof;
}

function verifyProof(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(REJECTED);
  if (value.releaseQualificationSatisfied !== false || value.nativeExecutionQualified === true || value.qualified === true || value.status === "qualified") {
    throw new Error(REJECTED);
  }
  assert.deepEqual(Object.keys(value).sort(), [...PROOF_KEYS].sort());
  assert.equal(value.scope, SCOPE);
  assert.equal(value.evidenceLevel, EVIDENCE_LEVEL);
  assert.ok(EXPERIMENTS.includes(value.experiment));
  assert.equal(value.releaseQualificationSatisfied, false);
  assert.equal(value.disposableForestRan, false);
  assert.equal(value.nativeExecutionQualified, false);
  assert.equal(value.hostCapabilityAbsentIsPass, false);
  return true;
}

function treatAsQualified() {
  throw new Error(REJECTED);
}

function qualifyCrashExperiment(context = {}) {
  const lab = assessLab(context.env, context.platform);
  if (!lab.ok) throw new Error(`Disposable AD CS forest is required: ${lab.missing.join(",")}`);
  throw new Error(REJECTED);
}

const buildClosedReport = createClosedReport({SUITE, EVIDENCE_LEVEL, REQUIRED_CAPABILITIES, REQUIRED_SCENARIOS}, {}, {releaseQualificationSatisfied: false});



function dispatch(options = {}) {
  const env = options.env || process.env;
  const platform = options.platform || process.platform;
  const lab = assessLab(env, platform);
  const reportPath = options.reportPath || env.CERTOPS_ADCS_CRASH_EXPERIMENTS_REPORT || DEFAULT_REPORT;
  const reason = lab.ok
    ? "Crash experiment markers do not satisfy release qualification"
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
  EXPERIMENTS,
  REQUIRED_SCENARIOS,
  REQUIRED_CAPABILITIES,
  REQUIRED_SOURCES,
  PROOF_KEYS,
  DEFAULT_REPORT,
  REJECTED,
  assessLab,
  buildExperimentProof,
  verifyProof,
  treatAsQualified,
  qualifyCrashExperiment,
  buildClosedReport,
  dispatch,
};
