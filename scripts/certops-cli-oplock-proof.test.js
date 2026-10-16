"use strict";
/** Synthetic bounded-proof refusal tests; actual native mechanics are exercised
 * separately by certops-cli-oplock-support.js and do not qualify installation. */
const test = require("node:test"), assert = require("node:assert/strict");
const { fields, verifyMechanics } = require("../tests/e2e/helpers/certops-windows-cli-oplock");
const { drainInOrder, assertCleanupSafe, cleanupGuardName } = require("../tests/e2e/helpers/certops-windows-cli-oplock");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
test("native oplock mechanics require every exact public fact", () => {
  const facts = Object.fromEntries(fields.map(field => [field, true])); assert.equal(verifyMechanics(facts), true);
  for (const field of fields) { for (const value of [false, null, 1, "true"]) assert.throws(() => verifyMechanics({ ...facts, [field]: value })); const missing = { ...facts }; delete missing[field]; assert.throws(() => verifyMechanics(missing)); }
  assert.throws(() => verifyMechanics({ ...facts, fullInstallerQualified: true }));
  assert.throws(() => verifyMechanics({ ...facts, rawProcessCommand: "private" }));
});
test("failed installer identity/termination/drain never enters holder release", async () => {
  for (const reason of ["identity changed", "kill refused", "close missing", "process still present"]) {
    let released = false;
    await assert.rejects(drainInOrder({ drainInstaller: async () => { throw new Error(reason); }, drainHolder: async () => { released = true; } }), new RegExp(reason));
    assert.equal(released, false);
  }
  const events = []; await drainInOrder({ drainInstaller: async () => events.push("installer-closed-and-absent"), drainHolder: async () => events.push("holder-closed-and-absent") });
  assert.deepEqual(events, ["installer-closed-and-absent", "holder-closed-and-absent"]);
});
test("parent cleanup guard refuses active or incomplete drain receipts", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "certops-oplock-guard-test-"));
  try {
    assertCleanupSafe(directory);
    const file = path.join(directory, cleanupGuardName);
    for (const receipt of [{ phase: "active" }, { phase: "drained", installerAbsent: true }, { phase: "drained", installerAbsent: false, driverAbsent: true }]) {
      fs.writeFileSync(file, JSON.stringify(receipt)); assert.throws(() => assertCleanupSafe(directory));
    }
    fs.writeFileSync(file, JSON.stringify({ phase: "drained", installerAbsent: true, driverAbsent: true })); assertCleanupSafe(directory);
  } finally { assert.equal(path.dirname(directory), os.tmpdir()); assert.match(path.basename(directory), /^certops-oplock-guard-test-/); fs.rmSync(directory, { recursive: true }); }
});
test("endpoint cleanup refuses changed hash/store/appid and absent ownership without exposing identities", () => {
  const { assertEndpointOwned } = require("../tests/e2e/helpers/certops-windows-cli-second-rename");
  const identity = { hash: "owned-public-hash", store: "My", appid: "owned-public-appid" }, expected = JSON.stringify(identity);
  assert.equal(assertEndpointOwned(JSON.stringify({ appid: identity.appid.toUpperCase(), store: "my", hash: identity.hash }), expected), true);
  assert.equal(assertEndpointOwned("absent", undefined), false);
  assert.throws(() => assertEndpointOwned(expected, undefined));
  for (const field of ["hash", "store", "appid"]) assert.throws(() => assertEndpointOwned(JSON.stringify({ ...identity, [field]: "foreign" }), expected), error => !error.message.includes("owned-public"));
});
test("certificate cleanup requires exact readable native CNG association before deletion", () => {
  const { assertCertificateCustodyOwned } = require("../tests/e2e/helpers/certops-windows-cli-second-rename");
  const facts = { container: "owned-container", provider: "Microsoft Software Key Storage Provider", machine: true, exportPolicy: 0, bits: 2048, thumbprint: "A".repeat(40), der: "owned-public-der" };
  const expected = { containerName: facts.container, thumbprint: facts.thumbprint, der: facts.der };
  assertCertificateCustodyOwned(facts, expected);
  // Partial-create recovery may not know DER beforehand, but still requires
  // an actual readable RSA association to the exact owned machine container.
  assertCertificateCustodyOwned(facts, { containerName: facts.container });
  for (const changed of [null, { ...facts, container: "foreign" }, { ...facts, provider: "foreign" }, { ...facts, machine: false }, { ...facts, exportPolicy: 1 }, { ...facts, thumbprint: "B".repeat(40) }, { ...facts, der: "foreign-public-der" }]) assert.throws(() => assertCertificateCustodyOwned(changed, expected));
  for (const field of Object.keys(facts)) { const missing = { ...facts }; delete missing[field]; assert.throws(() => assertCertificateCustodyOwned(missing, expected)); }
});
