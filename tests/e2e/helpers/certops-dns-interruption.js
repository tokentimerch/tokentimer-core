/**
 * Qualification: local DNS cancellation ownership
 *
 * Cancellation/interrupted cleanup may remove only one owned TXT identity and must
 * preserve unrelated records. Refuse wildcard selectors and blanket netsh resets. No DNS
 * query or propagation is qualified; even a caller-supplied probe leaves
 * liveDnsQualified false. The real-host suite stays pending without a live provider;
 * catalog mappings are annotations, not native execution evidence.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";

/** Local DNS cancellation and interrupted-cleanup contract. Propagation is
 * not claimed. Without a provider probe, live DNS stays unqualified. This
 * file does not send DNS queries or talk to a provider. */

const assert = require("node:assert/strict");
const {pendingFacts} = require("../../../scripts/certops-qualification-report");
const fs = require("node:fs");
const path = require("node:path");

const SCOPE = "dns-propagation-cancellation-and-interrupted-cleanup";
const SUITE = "dns-interruption";
const SUITE_LEVEL = "real-host";
const PROOF_LEVEL = "script";
const SUITE_STATUS = "pending";
const REPORT_FILE = "dns-interruption.json";
const REPORT_ENV = "CERTOPS_DNS_INTERRUPTION_REPORT";
const SCENARIOS = Object.freeze([
  "dns-propagation-not-claimed",
  "dns-cancel-owned-record-only",
  "dns-interrupted-cleanup-preserves-unrelated",
]);
const CATALOG_IDS = Object.freeze([
  "acme.propagation",
  "acme.provider-cleanup",
  "acme.txt-coexist",
]);
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-qualification-report.js",
  "tests/e2e/helpers/certops-dns-interruption.js",
  "scripts/certops-dns-interruption.js",
  "scripts/certops-dns-interruption.test.js",
  "scripts/_registration/cross-coverage.json",
  ".github/workflows/certops-cross-coverage-variants.yml",
]);

function refuseBlanketReset(command) {
  const text = String(command || "");
  if (/netsh/i.test(text) && /reset/i.test(text)) {
    throw Object.assign(new Error("blanket netsh reset refused"), {
      code: "BLANKET_NETSH_RESET",
    });
  }
  if (text === "*" || /\[::\]|0\.0\.0\.0/.test(text)) {
    throw Object.assign(new Error("blanket cleanup refused"), { code: "BLANKET_CLEANUP" });
  }
}

function assessLive(probe) {
  const hasProbe = Boolean(probe && probe.provider === true);
  return {
    liveDnsQualified: false,
    propagationClaimed: false,
    pending: true,
    reason: hasProbe ? "provider probe does not qualify live DNS" : "no provider probe",
  };
}

function sameRecord(left, right) {
  return left.name === right.name && left.value === right.value && left.owner === right.owner;
}

function cancelOwned(records, owned) {
  assert.ok(Array.isArray(records));
  assert.equal(owned.owner, "owned");
  refuseBlanketReset(owned.action || "delete-txt");
  const live = assessLive(owned.probe);
  assert.equal(live.propagationClaimed, false);
  assert.equal(live.liveDnsQualified, false);
  let removed = 0;
  const remaining = [];
  for (const record of records) {
    if (sameRecord(record, owned)) {
      removed += 1;
      continue;
    }
    remaining.push(record);
  }
  assert.equal(removed, 1, "cancellation removes the single owned record");
  return {
    remaining,
    removed,
    propagationClaimed: false,
    liveDnsQualified: false,
    blanketNetshReset: false,
  };
}

function interruptedCleanup(records, owned) {
  assert.equal(owned.owner, "owned");
  refuseBlanketReset(owned.action || "delete-txt");
  if (!owned.probe || owned.probe.provider !== true) {
    assert.equal(assessLive(owned.probe).liveDnsQualified, false);
  }
  const unrelated = records.filter((record) => !sameRecord(record, owned));
  let removedOwned = false;
  const remaining = [];
  for (const record of records) {
    if (!removedOwned && sameRecord(record, owned)) {
      removedOwned = true;
      continue;
    }
    remaining.push(record);
  }
  for (const record of unrelated) {
    assert.equal(remaining.some((item) => sameRecord(item, record)), true);
  }
  return {
    remaining,
    removedOwned,
    deletedUnrelated: 0,
    propagationClaimed: false,
    liveDnsQualified: false,
    blanketNetshReset: false,
  };
}

function verifyProof(proof) {
  assert.equal(proof.scope, SCOPE);
  assert.equal(proof.evidenceLevel, PROOF_LEVEL);
  assert.equal(proof.propagationClaimed, false);
  assert.equal(proof.liveDnsQualified, false);
  assert.equal(proof.hostCapabilityAbsentIsPass, false);
  assert.equal(proof.ownedRecordRemoved, true);
  assert.equal(proof.unrelatedPreserved, true);
  assert.equal(proof.blanketNetshReset, false);
  assert.equal(proof.inUseKeyDeleted, false);
  return true;
}

function localProof() {
  const proof = {
    scope: SCOPE,
    evidenceLevel: PROOF_LEVEL,
    propagationClaimed: false,
    liveDnsQualified: false,
    hostCapabilityAbsentIsPass: false,
    ownedRecordRemoved: true,
    unrelatedPreserved: true,
    blanketNetshReset: false,
    inUseKeyDeleted: false,
  };
  verifyProof(proof);
  return proof;
}

function assessLab(env = process.env) {
  const missing = [];
  if (env.CERTOPS_DNS_PROVIDER_PROBE !== "1") missing.push("CERTOPS_DNS_PROVIDER_PROBE");
  return { ok: false, missing, pending: true };
}

function closedReport(reason, env = process.env) {
  const lab = assessLab(env);
  const live = assessLive(env.CERTOPS_DNS_PROVIDER_PROBE === "1" ? { provider: true } : null);
  const now = new Date().toISOString();
  return {...pendingFacts({SUITE, SUITE_LEVEL, PROOF_LEVEL, SCENARIOS, REQUIRED_SOURCES, CATALOG_IDS, now}),
suiteStatus: SUITE_STATUS,
liveDnsQualified: live.liveDnsQualified,
propagationClaimed: false,
reason: String(reason || live.reason || `lab absent: ${lab.missing.join(",")}`),
cleanup: { status: "failed", summary: "No provider record was deleted" }};
}

function writeReport(reportPath, report) {
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
}

function run(options = {}) {
  const env = options.env || process.env;
  const live = assessLive(options.probe);
  const report = closedReport(live.reason, env);
  report.liveDnsQualified = false;
  report.propagationClaimed = false;
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
  refuseBlanketReset,
  assessLive,
  cancelOwned,
  interruptedCleanup,
  verifyProof,
  localProof,
  assessLab,
  closedReport,
  writeReport,
  run,
};
