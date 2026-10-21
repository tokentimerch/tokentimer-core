"use strict";
/** Pure adverse proof contracts; never executes native Windows operations. */
const assert = require("node:assert/strict"), test = require("node:test");
const fixture = require("../tests/e2e/helpers/certops-windows-certificate-dry-run");
const proof = () => ({ scope: fixture.scope, admission: "production-service-explicit-mode", deployPlanSteps: 3, renewPlanSteps: 6, ...Object.fromEntries(fixture.fields.map(field => [field, true])) });
test("Windows certificate dry-run proof rejects every missing or false native observation", () => {
  assert.equal(fixture.verifyProof(proof()), true);
  for (const field of fixture.fields) { const missing = proof(); delete missing[field]; assert.throws(() => fixture.verifyProof(missing)); assert.throws(() => fixture.verifyProof({ ...proof(), [field]: false })); }
  for (const change of [{ privateKey: "forbidden" }, { scope: "full-native-execution" }, { admission: "public-route" }, { renewPlanSteps: 0 }]) assert.throws(() => fixture.verifyProof({ ...proof(), ...change }));
});
test("persisted Windows dry-run plan requires authentic mode, action and unique complete step set", () => {
  const rows = () => Array.from({ length: 3 }, (_, index) => ({ evidence_type: "policy.checked", summary: "Dry run plan for deploy fixture", metadata: { dryRun: true, jobMode: "dry_run", action: "deploy", planStep: index + 1 } }));
  fixture.verifyPlan(rows(), "deploy", 3);
  const arrayMetadata = rows().map(row => ({ ...row, metadata: Object.entries(row.metadata).map(([name, value]) => ({ name, value })) })); fixture.verifyPlan(arrayMetadata, "deploy", 3);
  assert.throws(() => fixture.verifyPlan(rows().slice(1), "deploy", 3));
  for (const [field, value] of [["dryRun", false], ["jobMode", "real"], ["action", "renew"], ["planStep", 3]]) { const changed = rows(); changed[0].metadata[field] = value; assert.throws(() => fixture.verifyPlan(changed, "deploy", 3)); }
  assert.throws(() => fixture.verifyPlan([...rows(), { evidence_type: "deployment.updated" }], "deploy", 3));
});
