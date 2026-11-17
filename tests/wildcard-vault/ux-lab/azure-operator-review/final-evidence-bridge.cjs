"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
// Loaded from the trusted workflow checkout. Reports are never trusted
// solely because the local writer validated their content.
const contract = require("../../../../scripts/certops-final-package-evidence.cjs");
const { verifyIdentity } = require("../../../../scripts/certops-azure-keyvault-package.cjs");
const { beginNativeServiceObservation } = require("./native-service-observation.cjs");
const CONTRACT_SOURCE_COMMIT = "5ac8b05578a0d48c917dc1cc4ffeb1c0eed5e19a";
const TEARDOWN = "owned-teardown";

function validateObservedEvidence({ profile, report, context }) {
  assert.ok(Object.hasOwn(contract.PROFILES, profile), "profile not provided by candidate validator");
  assert.ok(report && context, "observed report and provenance context required");
  assert.equal(contract.verify(profile, report, context), true, "candidate validator refused evidence");
}

// The workflow owns the live observations and an independently verified
// cleanup. Run the latter even if the former fails. This is not an adapter
// that upgrades the existing supporting container/UX report.
async function runOperatorQualification({ profile, context, outputDirectory, observe, teardown }) {
  assert.ok(["azure-operator-http-real-ca", "openbao-operator-http-real-ca"].includes(profile));
  const { sourceSha, runId, packageIdentity } = context;
  assert.match(sourceSha, /^[a-f0-9]{40}$/);
  assert.match(runId, /^[1-9][0-9]{0,15}$/);
  verifyIdentity(packageIdentity);
  assert.ok(path.isAbsolute(outputDirectory) && fs.lstatSync(outputDirectory).isDirectory(), "owned output directory required");
  const specification = contract.PROFILES[profile];
  const file = path.join(outputDirectory, specification.file);
  assert.equal(fs.lstatSync(file, { throwIfNoEntry: false }), undefined, "reuse of prior evidence refused");
  assert.equal(typeof observe, "function");
  assert.equal(typeof teardown, "function");
  let observed, failure, closed;
  try { observed = await observe(); }
  catch (error) { failure = error; }
  try { closed = await teardown(); }
  catch (error) {
    if (failure) throw new AggregateError([failure, error], "operator scenario and teardown both failed");
    throw error;
  }
  if (failure) throw failure;

  assert.deepEqual(observed.packageArtifact, packageIdentity, "operator did not use the selected archive");
  assert.equal(closed.sourceSha, sourceSha);
  assert.equal(closed.runId, runId);
  assert.deepEqual(closed.packageArtifact, packageIdentity, "teardown receipt belongs to a different archive");
  assert.equal(specification.scenarios.at(-1), TEARDOWN);
  const scenarios = [...observed.scenarios, { id: TEARDOWN, status: "passed" }];
  const report = { schemaVersion: 1, profile, sourceSha, runId, packageArtifact: packageIdentity,
    status: "passed", productionQualified: false, fullOperatorE2e: true,
    counts: { passed: scenarios.length, failed: 0, pending: 0, skipped: 0 }, scenarios,
    cleanup: closed.cleanup, facts: observed.facts, nativeService: observed.nativeService };
  validateObservedEvidence({ profile, report, context });
  const json = JSON.stringify(report) + "\n";
  assert.ok(Buffer.byteLength(json) < 131072, "operator evidence exceeds collector bound");
  fs.writeFileSync(file, json, { flag: "wx", mode: 0o600 });
  return report;
}

module.exports = { CONTRACT_SOURCE_COMMIT, validateObservedEvidence, beginNativeServiceObservation, runOperatorQualification };
