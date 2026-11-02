"use strict";
/** Pure proof/source and owned temporary path controls. This file never calls
 * the native qualifier, changes ACLs or creates machine keys/certificates. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path"),
  h = require("../packages/agent/scripts/host/journal-read-refusal-fixture");
const proof = () => ({
  scope: h.scope,
  installedServiceQualified: false,
  nativeCngQualified: false,
  ...Object.fromEntries(h.fields.map((field) => [field, true])),
});
test("journal ACL proof requires all measured native controls and cannot promote installed enrollment", () => {
  assert.equal(h.verifyProof(proof()), true);
  for (const key of Object.keys(proof())) {
    const missing = proof();
    delete missing[key];
    assert.throws(() => h.verifyProof(missing), key);
    const invalid = proof();
    invalid[key] =
      typeof invalid[key] === "boolean" ? !invalid[key] : "foreign";
    assert.throws(() => h.verifyProof(invalid), key);
  }
  assert.throws(() =>
    h.verifyProof({ ...proof(), privateJournal: "forbidden" }),
  );
});
test("journal ACL restoration guard preserves owned state and replaced roots are refused", () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "journal-acl-pure-")),
    a = path.join(parent, "owned"),
    b = path.join(parent, "replacement");
  try {
    fs.mkdirSync(a);
    fs.mkdirSync(b);
    const original = h.identity(a),
      replacement = h.identity(b);
    assert.notEqual(original, replacement);
    h.assertCleanupSafe(parent);
    fs.writeFileSync(path.join(parent, h.preserveGuardName), "malformed");
    assert.throws(() => h.assertCleanupSafe(parent), /Preserve journal/);
    fs.rmdirSync(a);
    fs.renameSync(b, a);
    assert.throws(() => h.assertIdentity(a, original), /identity changed/);
    assert.equal(fs.existsSync(a), true);
  } finally {
    assert.equal(path.dirname(parent), os.tmpdir());
    assert.match(path.basename(parent), /^journal-acl-pure-/);
    fs.rmSync(parent, { recursive: true });
  }
});
test("ACL scripts target only one explicit native right and exact restore descriptor", () => {
  const file = h.aclScripts("C:\\owned\\journal.json", "D:PAI(A;;FA;;;SY)"),
    directory = h.aclScripts(
      "C:\\owned\\adcs-enrollments",
      "D:PAI(A;;FA;;;SY)",
      true,
    );
  assert.match(file.deny, /FileSystemRights\]::ReadData/);
  assert.match(directory.deny, /FileSystemRights\]::ListDirectory/);
  assert.match(file.restore, /FileSecurity/);
  assert.match(directory.restore, /DirectorySecurity/);
  for (const script of [file.restore, directory.restore])
    assert.equal(script.includes("AddAccessRule"), false);
  assert.throws(() => h.aclScripts("owned", "bad'quote"));
});
test("journal native source fingerprints are unique and bind production readers and genuine software CSR", () => {
  assert.equal(new Set(h.requiredSources).size, h.requiredSources.length);
  for (const file of h.requiredSources)
    assert.ok(fs.statSync(path.resolve(__dirname, "..", file)).isFile());
  const source = fs.readFileSync(
    path.resolve(
      __dirname,
      "../packages/agent/scripts/host/journal-read-refusal-fixture.js",
    ),
    "utf8",
  );
  for (const token of [
    "keys.generateCsr",
    "journal.writeEnrollmentJournal",
    "journal.listProtectedEnrollmentContainers",
    '"EACCES", "EPERM"',
  ])
    assert.ok(source.includes(token));
  assert.equal(h.scenarios.length, 2);
});
