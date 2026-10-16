"use strict";
/** Pure native-state proof refusals; no ACL or service operations execute. */
const test = require("node:test"), assert = require("node:assert/strict"), fixture = require("../packages/agent/scripts/host/state-read-refusal-fixture");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
test("state read-denial proof refuses missing facts and installed-service promotion", () => {
  const proof = { scope: "native-temporary-state-read-denials-production-readers", installedServiceStartupQualified: false, ...Object.fromEntries(fixture.fields.map(field => [field, true])) }; fixture.verifyProof(proof);
  for (const field of fixture.fields) { const missing = { ...proof }; delete missing[field]; assert.throws(() => fixture.verifyProof(missing)); for (const value of [false, null, 1, "true"]) assert.throws(() => fixture.verifyProof({ ...proof, [field]: value })); }
  assert.throws(() => fixture.verifyProof({ ...proof, installedServiceStartupQualified: true })); assert.throws(() => fixture.verifyProof({ ...proof, rawCredential: "forbidden" }));
});
test("unproven state ACL restoration preserves owned evidence instead of permitting parent deletion", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "certops-state-read-guard-test-"));
  try {
    fixture.assertCleanupSafe(directory); fs.writeFileSync(path.join(directory, fixture.preserveGuardName), JSON.stringify({ reason: "exact-acl-restoration-unproven" }));
    assert.throws(() => fixture.assertCleanupSafe(directory)); fs.writeFileSync(path.join(directory, fixture.preserveGuardName), "malformed"); assert.throws(() => fixture.assertCleanupSafe(directory));
  } finally { assert.equal(path.dirname(directory), os.tmpdir()); assert.match(path.basename(directory), /^certops-state-read-guard-test-/); fs.rmSync(directory, { recursive: true }); }
});
