"use strict";
/** Offline public proof and real software signature controls only. They do not
 * execute PowerShell, native CNG, CertOps services or the native qualification. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  crypto = require("node:crypto"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const helper = require("../packages/agent/scripts/host/orphan-journal-fixture");
function proof() {
  return {
    scope: helper.scope,
    installedServiceQualified: false,
    caEnrollmentQualified: false,
    orphanAgePolicyQualified: false,
    ...Object.fromEntries(helper.fields.map((key) => [key, true])),
  };
}
test("native orphan journal proof is closed and cannot promote explicit local prerequisites into CA, installed or age coverage", () => {
  assert.equal(helper.verifyProof(proof()), true);
  for (const field of helper.fields) {
    for (const value of [false, undefined]) {
      const bad = proof();
      if (value === undefined) delete bad[field];
      else bad[field] = value;
      assert.throws(() => helper.verifyProof(bad), field);
    }
  }
  for (const change of [
    (v) => (v.scope = "installed-agent"),
    (v) => (v.installedServiceQualified = true),
    (v) => (v.caEnrollmentQualified = true),
    (v) => (v.orphanAgePolicyQualified = true),
    (v) => (v.privateCsr = "private"),
  ]) {
    const bad = proof();
    change(bad);
    assert.throws(() => helper.verifyProof(bad));
  }
});
test("native custody observation requires genuine private possession and exact nonexportable machine provider metadata", () => {
  const nonce = "a".repeat(32),
    pair = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }),
    jwk = pair.publicKey.export({ format: "jwk" });
  const value = {
    uniqueSha256: "b".repeat(64),
    machine: true,
    provider: "Microsoft Software Key Storage Provider",
    exportPolicy: 0,
    bits: 2048,
    modulus: Buffer.from(jwk.n, "base64url").toString("base64"),
    exponent: Buffer.from(jwk.e, "base64url").toString("base64"),
    signature: crypto
      .sign("sha256", Buffer.from(nonce), pair.privateKey)
      .toString("base64"),
  };
  const result = helper.verifyObservation(value, nonce);
  assert.equal(
    result.spkiSha256,
    crypto
      .createHash("sha256")
      .update(pair.publicKey.export({ type: "spki", format: "der" }))
      .digest("hex"),
  );
  for (const patch of [
    { machine: false },
    { provider: "foreign" },
    { exportPolicy: 1 },
    { bits: 4096 },
    { signature: Buffer.alloc(256).toString("base64") },
  ])
    assert.throws(() =>
      helper.verifyObservation({ ...value, ...patch }, nonce),
    );
  assert.throws(() => helper.keyScript("container';Remove-Item", nonce));
  assert.throws(() => helper.keyScript("valid", "not-a-nonce"));
});
test("owned fixture guard preserves state on uncertainty and only regular trees pass cleanup preflight", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-orphan-proof-"));
  try {
    fs.mkdirSync(path.join(root, "state"));
    fs.writeFileSync(path.join(root, "state", "owned.json"), "{}");
    helper.assertFixtureTreeRegular(root);
    helper.assertCleanupSafe(root);
    const guard = path.join(root, helper.preserveGuardName);
    fs.writeFileSync(guard, "owned", { flag: "wx" });
    assert.throws(() => helper.assertCleanupSafe(root));
    assert.equal(fs.readFileSync(guard, "utf8"), "owned");
    assert.equal(fs.existsSync(path.join(root, "state", "owned.json")), true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("all fixture keys use deterministic product enrollment names eligible for production survivor-safe cleanup", () => {
  const store = require("../packages/agent/src/windows-cert-store"),
    ids = [crypto.randomUUID(), crypto.randomUUID(), crypto.randomUUID()],
    first = helper.fixtureContainerNames(...ids);
  assert.deepEqual(first, helper.fixtureContainerNames(...ids));
  assert.equal(new Set(Object.values(first)).size, 3);
  Object.values(first).forEach((name, index) => {
    assert.equal(name, store.buildEnrollmentContainerName(ids[index]));
    assert.equal(store.isAgentOwnedContainerName(name), true);
  });
  assert.throws(() => helper.fixtureContainerNames(ids[0], ids[0], ids[2]));
});

test("native absence requires an exact successful boolean, never missing or diagnostic output", () => {
  assert.equal(helper.parseNativeExists("True"), true);
  assert.equal(helper.parseNativeExists("False"), false);
  for (const value of ["", undefined, "false", "warning\nFalse", false])
    assert.throws(() => helper.parseNativeExists(value));
});

test("ownership rejects unavailable or zero native filesystem identities", () => {
  assert.equal(helper.validateFileId(123n), "123");
  for (const value of [0n, -1n, undefined, null, 0, "123"])
    assert.throws(() => helper.validateFileId(value));
});
