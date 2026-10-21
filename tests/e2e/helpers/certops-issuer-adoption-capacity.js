/**
 * Qualification: local issuer capacity and adoption
 *
 * Refuse a sixth shared-cap reservation without eviction and adoption outside the owned
 * issuer set. Missing forests fail closed with hostCapabilityAbsentIsPass false.
 * nativeCell remains pending; native-adcs-issuer-reassignment is the separate forest
 * journey, and these catalog annotations cannot qualify that native cell.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";

/** Adoption and capacity remainder for issuer switch. The native forest
 * journey stays in the issuer-reassignment cell. Capacity exhaustion and a
 * foreign issuer fail closed, and nativeCell stays pending. */

const assert = require("node:assert/strict");
const {pendingFacts} = require("../../../scripts/certops-qualification-report");
const fs = require("node:fs");
const path = require("node:path");

const SCOPE = "issuer-adoption-and-capacity-remainder";
const SUITE = "issuer-adoption-capacity";
const SUITE_LEVEL = "integration";
const PROOF_LEVEL = "script";
const REPORT_FILE = "issuer-adoption-capacity.json";
const REPORT_ENV = "CERTOPS_ISSUER_ADOPTION_CAPACITY_REPORT";
const CAPACITY = 5;
const SCENARIOS = Object.freeze([
  "issuer-capacity-exhausted",
  "issuer-foreign-adoption-refused",
]);
const CATALOG_IDS = Object.freeze([
  "renewal.ca-capacity",
  "renewal.issuer-switch",
]);
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-qualification-report.js",
  "tests/e2e/helpers/certops-issuer-adoption-capacity.js",
  "scripts/certops-issuer-adoption-capacity.js",
  "scripts/certops-issuer-adoption-capacity.test.js",
  "scripts/_registration/cross-coverage.json",
  ".github/workflows/certops-cross-coverage-variants.yml",
]);

function createState(ownedIssuers) {
  assert.ok(Array.isArray(ownedIssuers) && ownedIssuers.length > 0);
  return {
    ownedIssuers: [...ownedIssuers],
    reservations: [],
    adopted: null,
    nativeCell: "pending",
    nativeCellQualified: false,
  };
}

function seal(state) {
  if (state.nativeCell !== "pending" || state.nativeCellQualified !== false) {
    throw Object.assign(new Error("native cell cannot be marked qualified"), {
      code: "NATIVE_CELL_PENDING",
    });
  }
  state.nativeCell = "pending";
  state.nativeCellQualified = false;
  return state;
}

function reserve(state, subject) {
  seal(state);
  assert.equal(typeof subject, "string");
  assert.ok(subject.length > 0);
  if (state.reservations.length >= CAPACITY) {
    throw Object.assign(new Error("capacity exhausted"), {
      code: "CAPACITY_EXHAUSTED",
      nativeCell: "pending",
    });
  }
  state.reservations.push(subject);
  return seal(state);
}

function adopt(state, issuerId) {
  seal(state);
  if (!state.ownedIssuers.includes(issuerId)) {
    throw Object.assign(new Error("foreign issuer adoption refused"), {
      code: "FOREIGN_ISSUER",
      nativeCell: "pending",
    });
  }
  state.adopted = issuerId;
  return seal(state);
}

function verifyProof(proof) {
  assert.equal(proof.scope, SCOPE);
  assert.equal(proof.evidenceLevel, PROOF_LEVEL);
  assert.equal(proof.nativeCell, "pending");
  assert.equal(proof.nativeCellQualified, false);
  assert.equal(proof.capacityExhausted, true);
  assert.equal(proof.foreignIssuerRefused, true);
  assert.equal(proof.hostCapabilityAbsentIsPass, false);
  assert.equal(proof.qualified, false);
  assert.equal(proof.inUseKeyDeleted, false);
  assert.equal(proof.blanketNetshReset, false);
  return true;
}

function localProof() {
  const proof = {
    scope: SCOPE,
    evidenceLevel: PROOF_LEVEL,
    nativeCell: "pending",
    nativeCellQualified: false,
    capacityExhausted: true,
    foreignIssuerRefused: true,
    hostCapabilityAbsentIsPass: false,
    qualified: false,
    inUseKeyDeleted: false,
    blanketNetshReset: false,
  };
  verifyProof(proof);
  return proof;
}

function assessLab(env = process.env) {
  const missing = [];
  if (env.CERTOPS_ADCS_DISPOSABLE_LAB !== "1") missing.push("CERTOPS_ADCS_DISPOSABLE_LAB");
  return { ok: missing.length === 0, missing };
}

function closedReport(reason, env = process.env) {
  const lab = assessLab(env);
  const now = new Date().toISOString();
  return {...pendingFacts({SUITE, SUITE_LEVEL, PROOF_LEVEL, SCENARIOS, REQUIRED_SOURCES, CATALOG_IDS, now}),
nativeCell: "pending",
nativeCellQualified: false,
separateSuite: "native-adcs-issuer-reassignment",
reason: lab.ok
      ? "Lab markers do not qualify native issuer adoption"
      : String(reason || `lab absent: ${lab.missing.join(",")}`),
cleanup: {
      status: "failed",
      summary: "No forest enrollment or issuer confirmation was started",
    }};
}

function writeReport(reportPath, report) {
  assert.equal(report.nativeCell, "pending");
  assert.equal(report.nativeCellQualified, false);
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
}

function run(options = {}) {
  const env = options.env || process.env;
  const report = closedReport(options.reason, env);
  const reportPath = options.reportPath || env[REPORT_ENV] || path.join("qualification-results", REPORT_FILE);
  if (options.write !== false) writeReport(reportPath, report);
  return report;
}

module.exports = {
  SCOPE,
  SUITE,
  SUITE_LEVEL,
  PROOF_LEVEL,
  REPORT_FILE,
  REPORT_ENV,
  CAPACITY,
  SCENARIOS,
  CATALOG_IDS,
  REQUIRED_SOURCES,
  createState,
  seal,
  reserve,
  adopt,
  verifyProof,
  localProof,
  assessLab,
  closedReport,
  writeReport,
  run,
};
