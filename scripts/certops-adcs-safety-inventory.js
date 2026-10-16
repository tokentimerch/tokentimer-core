"use strict";
/**
 * Validates the committed unsafe-template, key-constraint and CA-flag fixture inventory.
 * Invoked before disposable AD CS provisioning to catch missing boundary cases; inventory
 * validation alone is not a native CA execution or qualification result.
 */
const assert = require("node:assert/strict");
const cases = require("../infra/certops-adcs/safety-cases.json");
function validate(definition = cases) {
  assert.equal(definition.schemaVersion, 1);
  const server = "1.3.6.1.5.5.7.3.1";
  const badEkus = ["2.5.29.37.0", "1.3.6.1.4.1.311.20.2.1", "1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.2.3.4"];
  assert.equal(new Set(definition.templateCases.map(item => item.name)).size, definition.templateCases.length);
  for (const item of definition.templateCases) {
    assert.match(item.name, /^TTQualification[A-Za-z0-9]{1,45}$/);
    assert.ok([1, 2].includes(item.schema));
    for (const oid of [...item.eku, ...item.applicationPolicies]) assert.match(oid, /^[0-2](?:\.[0-9]+)+$/);
  }
  const exact = (a, b) => JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
  assert.ok(definition.templateCases.some(item => item.eku.length === 0 && item.reason === "eku_not_server_auth_only"), "Absent EKU refusal fixture is required");
  for (const oid of badEkus) for (const eku of [[oid], [server, oid]]) {
    assert.ok(definition.templateCases.some(item => exact(item.eku, eku) && item.reason === "eku_not_server_auth_only"), "Every prohibited EKU needs standalone and mixed actual template fixtures");
  }
  assert.ok(definition.templateCases.some(item => item.schema === 1 && exact(item.eku, [server]) && item.reason === "schema_version_1"));
  for (const policy of [[badEkus[2]], [server, badEkus[2]]]) {
    assert.ok(definition.templateCases.some(item => exact(item.eku, [server]) && exact(item.applicationPolicies, policy) && item.reason === "application_policy_not_server_auth_only"));
  }
  const requiredKeys = [
    ["rsa-below-template-minimum", "rsa", 2048, 2], ["ec-on-schema-two", "ecdsa", 256, 2],
    ["ec-curve-on-schema-three", "ecdsa", 384, 3], ["rsa-on-ec-schema-three", "rsa", 2048, 3],
    ["ec-curve-on-schema-four", "ecdsa", 384, 4], ["rsa-on-ec-schema-four", "rsa", 2048, 4],
    ["rsa2048-below-template3072", "rsa", 2048, 2], ["rsa3072-below-template4096", "rsa", 3072, 2],
    ["ec256-on-p384-schema-three", "ecdsa", 256, 3], ["ec256-on-p384-schema-four", "ecdsa", 256, 4],
  ];
  for (const [id, algorithm, size, schema] of requiredKeys) assert.equal(definition.keyConstraintCases.filter(item => item.id === id && item.algorithm === algorithm && item.size === size && item.schema === schema).length, 1, `Missing or misclassified snapshot key boundary ${id}`);
  for (const item of definition.keyConstraintCases) { assert.ok([2, 3, 4].includes(item.schema)); assert.ok(["rsa", "ecdsa"].includes(item.algorithm)); assert.ok([256, 384, 2048, 3072].includes(item.size)); }
  for (const [edit, clear] of [[0x40000, 0], [0, 0x200], [0x40000, 0x200]]) {
    assert.equal(definition.caFlagCases.filter(item => item.editFlagsSet === edit && item.interfaceFlagsClear === clear).length, 1, "Each native unsafe CA flag combination is mandatory");
  }
  return { template: definition.templateCases.length, snapshotKey: definition.keyConstraintCases.length, caFlags: definition.caFlagCases.length };
}
module.exports = { validate };
if (require.main === module) console.log(`Validated AD CS native safety fixture inventory ${JSON.stringify(validate())}; native execution is a separate qualification requirement`);
