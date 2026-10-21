/**
 * Qualification: local Kubernetes outage contract
 *
 * API timeout, missed watches and missing RBAC fail closed without opening a socket. A
 * supplied cluster probe cannot set kubernetesQualified. The real-host suite stays
 * pending until a live cluster executes; absent capabilities are not passes and
 * controller catalog mappings remain annotations.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";

/** Local Kubernetes outage, watch, and RBAC contract. Each fault fails
 * closed. This file does not open a socket or talk to a cluster. */

const assert = require("node:assert/strict");
const {pendingFacts} = require("../../../scripts/certops-qualification-report");
const fs = require("node:fs");
const path = require("node:path");

const SCOPE = "kubernetes-outage-watch-and-rbac";
const SUITE = "k8s-rbac-outage";
const SUITE_LEVEL = "real-host";
const PROOF_LEVEL = "script";
const SUITE_STATUS = "pending";
const REPORT_FILE = "k8s-rbac-outage.json";
const REPORT_ENV = "CERTOPS_K8S_RBAC_OUTAGE_REPORT";
const SCENARIOS = Object.freeze([
  "k8s-api-timeout-closed",
  "k8s-missed-watch-closed",
  "k8s-missing-rbac-closed",
]);
const CATALOG_IDS = Object.freeze([
  "controller.restart-watch",
  "controller.rbac-boundary",
  "controller.observe",
]);
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-qualification-report.js",
  "tests/e2e/helpers/certops-k8s-rbac-outage.js",
  "scripts/certops-k8s-rbac-outage.js",
  "scripts/certops-k8s-rbac-outage.test.js",
  "scripts/_registration/cross-coverage.json",
  ".github/workflows/certops-cross-coverage-variants.yml",
]);
const FAULTS = Object.freeze({
  timeout: "API_TIMEOUT",
  watch: "MISSED_WATCH",
  rbac: "MISSING_RBAC",
});

function observe(kind) {
  const code = FAULTS[kind];
  assert.equal(typeof code, "string");
  const result = {
    status: "failed",
    code,
    kubernetesQualified: false,
    talkedToCluster: false,
    hostCapabilityAbsentIsPass: false,
  };
  throw Object.assign(new Error(code), { code, result });
}

function verifyProof(proof) {
  assert.equal(proof.scope, SCOPE);
  assert.equal(proof.evidenceLevel, PROOF_LEVEL);
  assert.equal(proof.kubernetesQualified, false);
  assert.equal(proof.talkedToCluster, false);
  assert.equal(proof.apiTimeoutClosed, true);
  assert.equal(proof.missedWatchClosed, true);
  assert.equal(proof.missingRbacClosed, true);
  assert.equal(proof.hostCapabilityAbsentIsPass, false);
  assert.equal(proof.inUseKeyDeleted, false);
  assert.equal(proof.blanketNetshReset, false);
  return true;
}

function localProof() {
  const proof = {
    scope: SCOPE,
    evidenceLevel: PROOF_LEVEL,
    kubernetesQualified: false,
    talkedToCluster: false,
    apiTimeoutClosed: true,
    missedWatchClosed: true,
    missingRbacClosed: true,
    hostCapabilityAbsentIsPass: false,
    inUseKeyDeleted: false,
    blanketNetshReset: false,
  };
  verifyProof(proof);
  return proof;
}

function assessCluster(probe) {
  const present = Boolean(probe && probe.cluster === true);
  return {
    available: false,
    present,
    kubernetesQualified: false,
    talkedToCluster: false,
    reason: present ? "cluster contact is not claimed" : "cluster absent",
  };
}

function assessLab(env = process.env) {
  const missing = [];
  if (env.CERTOPS_K8S_CLUSTER_LAB !== "1") missing.push("CERTOPS_K8S_CLUSTER_LAB");
  return { ok: false, missing, pending: true };
}

function closedReport(reason, env = process.env) {
  const lab = assessLab(env);
  const now = new Date().toISOString();
  return {...pendingFacts({SUITE, SUITE_LEVEL, PROOF_LEVEL, SCENARIOS, REQUIRED_SOURCES, CATALOG_IDS, now}),
suiteStatus: SUITE_STATUS,
kubernetesQualified: false,
talkedToCluster: false,
reason: String(reason || `lab absent: ${lab.missing.join(",")}`),
cleanup: { status: "failed", summary: "No cluster client was opened" }};
}

function writeReport(reportPath, report) {
  assert.equal(report.kubernetesQualified, false);
  assert.equal(report.talkedToCluster, false);
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
}

function run(options = {}) {
  const env = options.env || process.env;
  const cluster = assessCluster(options.probe);
  const report = closedReport(cluster.reason, env);
  report.kubernetesQualified = false;
  report.talkedToCluster = false;
  const reportPath = options.reportPath || env[REPORT_ENV] || path.join("qualification-results", REPORT_FILE);
  if (options.write !== false) writeReport(reportPath, report);
  return report;
}

module.exports = {
  SCOPE,
  SUITE,
  SUITE_LEVEL,
  PROOF_LEVEL,
  SUITE_STATUS,
  REPORT_FILE,
  REPORT_ENV,
  SCENARIOS,
  CATALOG_IDS,
  REQUIRED_SOURCES,
  FAULTS,
  observe,
  verifyProof,
  localProof,
  assessCluster,
  assessLab,
  closedReport,
  writeReport,
  run,
};
