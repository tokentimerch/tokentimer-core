"use strict";
/** Supporting report/oracle tests; these do not run or qualify native jobs. */
const { test } = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), os = require("node:os");
const { scope, trueFields, verifyFacts, snapshotTree } = require("../tests/e2e/helpers/certops-native-certificate-dry-run");
function facts() { return { scope, admission: "production-service-explicit-mode", dryRunOperations: 2, deployPlanSteps: 3, renewPlanSteps: 6, validateCalls: 1, reloadCalls: 1, caSentinelCalls: 1, dnsSentinelCalls: 1, ...Object.fromEntries(trueFields.map(field => [field, true])) }; }
test("native certificate dry-run proof requires every independent fact", () => {
  assert.equal(verifyFacts(facts()), true);
  for (const field of trueFields) { const missing = facts(); delete missing[field]; assert.throws(() => verifyFacts(missing)); assert.throws(() => verifyFacts({ ...facts(), [field]: false })); }
});
test("native certificate dry-run proof refuses wrong counts, scope and private additions", () => {
  for (const field of ["dryRunOperations", "deployPlanSteps", "renewPlanSteps", "validateCalls", "reloadCalls", "caSentinelCalls", "dnsSentinelCalls"]) assert.throws(() => verifyFacts({ ...facts(), [field]: 0 }));
  assert.throws(() => verifyFacts({ ...facts(), scope: "real-acme-qualified" }));
  assert.throws(() => verifyFacts({ ...facts(), admission: "public-route-mode" }));
  assert.throws(() => verifyFacts({ ...facts(), privateKey: "fixture-secret" }));
});
test("exact dry-run file inventory detects changed key bytes and new staging artifacts", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "certops-dry-run-oracle-"));
  try {
    const key = path.join(directory, "owned.key"); fs.writeFileSync(key, "local fixture bytes", { mode: 0o600 }); const original = snapshotTree(directory);
    fs.writeFileSync(key, "changed fixture bytes"); assert.notDeepEqual(snapshotTree(directory), original);
    fs.writeFileSync(key, "local fixture bytes"); assert.deepEqual(snapshotTree(directory), original);
    fs.writeFileSync(path.join(directory, "unexpected.stage"), "fixture"); assert.notDeepEqual(snapshotTree(directory), original);
  } finally { assert.equal(path.dirname(path.resolve(directory)), path.resolve(os.tmpdir())); assert.ok(path.basename(directory).startsWith("certops-dry-run-oracle-")); fs.rmSync(directory, { recursive: true, force: true }); }
});
