"use strict";
/** Experimental post-cutover recovery. The product journals bind before its
 * internal TLS check, and has no initial-install post-bind/pre-verify marker.
 * This variant therefore proves only a new trusted binding before durable
 * completion, recording actual retention state rather than inventing absence. */
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const base = require("./certops-adcs-accepted-install-recovery");
const PHASE = "bound-before-complete";
const FLAGS = [...base.FLAGS.filter(flag => flag !== "oldTrustedBindingAtFault"), "newTrustedBindingAtFault", "claimBoundRecoveryVerification", "idempotentNativeCutoverCompletion", "exactSingleRetentionRow", "retentionCompletionIdempotent", "predecessorCustodyPreserved"];
const REQUIRED_SOURCES = [...new Set([...base.REQUIRED_SOURCES, "tests/e2e/helpers/certops-adcs-bound-install-recovery.js", "infra/certops-adcs/bound-install-phase-fault.ps1", "packages/agent/src/windows-retention/index.js"])];
function verifyFault(value) {
  assert.equal(Object.prototype.hasOwnProperty.call(value, "predecessorIisUnchanged"), false);
  const translated = { ...value, phase: base.PHASE, predecessorIisUnchanged: value.newIisLeafBound }; delete translated.newIisLeafBound;
  assert.equal(value.phase, PHASE); assert.equal(value.newIisLeafBound, true); return base.verifyFault(translated);
}
function verifyReport(report, root = path.resolve(__dirname, "../../..")) {
  assert.deepEqual(Object.keys(report).sort(), ["schemaVersion", "scope", "phase", "qualificationStatus", "experimental", "status", "candidateSha", "fixtureSource", "fixtureSources", "fault", "leaseRemainingAtFaultMs", "recoveryWaitBudgetMs", "actualLeaseWaitMs", "caRequestsAtFault", "caRequestsAfterRecovery", "retentionAtFault", "preVerificationWindowClaimed", ...FLAGS].sort());
  assert.equal(report.schemaVersion, 1); assert.equal(report.scope, "enterprise-adcs-journal-phase-experimental"); assert.equal(report.phase, PHASE); assert.equal(report.qualificationStatus, "not-qualified"); assert.equal(report.experimental, true); assert.equal(report.status, "passed");
  assert.match(report.candidateSha, /^[a-f0-9]{40}$/i); verifyFault(report.fault);
  for (const flag of FLAGS) assert.equal(report[flag], true, flag);
  assert.ok(["absent", "matching-existing-row"].includes(report.retentionAtFault)); assert.equal(report.preVerificationWindowClaimed, false);
  for (const name of ["caRequestsAtFault", "caRequestsAfterRecovery"]) assert.ok(Number.isInteger(report[name]) && report[name] >= 1 && report[name] <= 1000);
  assert.equal(report.caRequestsAfterRecovery, report.caRequestsAtFault);
  for (const name of ["leaseRemainingAtFaultMs", "recoveryWaitBudgetMs", "actualLeaseWaitMs"]) assert.ok(Number.isInteger(report[name]) && report[name] >= 0 && report[name] <= 900000);
  assert.equal(report.recoveryWaitBudgetMs, report.leaseRemainingAtFaultMs + 90000); assert.ok(report.actualLeaseWaitMs + 1000 >= report.leaseRemainingAtFaultMs + 60000); assert.ok(report.actualLeaseWaitMs <= report.recoveryWaitBudgetMs + 1000);
  const digest = file => crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex");
  assert.deepEqual(report.fixtureSource, { file: "tests/e2e/helpers/certops-adcs-bound-install-recovery.js", sha256: digest("tests/e2e/helpers/certops-adcs-bound-install-recovery.js") });
  assert.ok(Array.isArray(report.fixtureSources)); assert.equal(report.fixtureSources.length, REQUIRED_SOURCES.length);
  for (const file of REQUIRED_SOURCES) { const rows = report.fixtureSources.filter(row => row.file === file); assert.equal(rows.length, 1); assert.deepEqual(rows[0], { file, sha256: digest(file) }); }
  return true;
}
function qualifyBoundInstallRecovery(context) {
  return base.qualifyObservedInstallRecovery(context, PHASE);
}
module.exports = { PHASE, FLAGS, REQUIRED_SOURCES, verifyFault, verifyReport, qualifyBoundInstallRecovery };
