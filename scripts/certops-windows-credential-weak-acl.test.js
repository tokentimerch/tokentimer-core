"use strict";
/** Public proof, retained public-file and policy controls only. No native ACL
 * or installed service/certificate is changed by these supporting checks. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const h = require("../packages/agent/scripts/host/credential-weak-acl-fixture");
function fixture() {
  return {
    scope: h.SCOPE,
    installedServiceStartupQualified: false,
    nativeCertificateQualified: false,
    untrustedProcessReadQualified: false,
    ...Object.fromEntries(h.FLAGS.map((f) => [f, true])),
  };
}
test("weak ACL proof requires actual native observations without claiming installed startup or exfiltration", () => {
  h.verifyProof(fixture());
  for (const k of Object.keys(fixture())) {
    const p = fixture();
    delete p[k];
    assert.throws(() => h.verifyProof(p));
  }
  for (const k of h.FLAGS)
    assert.throws(() => h.verifyProof({ ...fixture(), [k]: false }));
  for (const patch of [
    { installedServiceStartupQualified: true },
    { nativeCertificateQualified: true },
    { untrustedProcessReadQualified: true },
    { rawCredential: "private" },
  ])
    assert.throws(() => h.verifyProof({ ...fixture(), ...patch }));
});
test("native ready receipt binds original file and actual protected untrusted ACE", () => {
  const p = {
    schemaVersion: 1,
    nonce: "a".repeat(64),
    fileId: "12:34",
    originalDacl: "D:P(A;;FA;;;SY)",
    appliedDacl: "D:P(A;;FA;;;SY)(A;;CC;;;WD)",
    untrustedSid: "S-1-1-0",
    readMask: 1,
    retainedOriginalHandle: true,
  };
  h.verifyReady(p, p.nonce, p.fileId);
  for (const patch of [
    { nonce: "b".repeat(64) },
    { fileId: "12:35" },
    { untrustedSid: "S-1-5-18" },
    { readMask: 2 },
    { retainedOriginalHandle: false },
    { appliedDacl: p.originalDacl },
    { appliedDacl: "D:(A;;CC;;;WD)" },
    { rawCredential: "secret" },
  ])
    assert.throws(() => h.verifyReady({ ...p, ...patch }, p.nonce, p.fileId));
});
test("lost or same-byte replaced guard cannot clear pending ACL ownership", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "weak-acl-guard-")),
    guard = path.join(root, h.GUARD),
    saved = path.join(root, "saved.guard");
  try {
    const owner = h.beginGuard(root),
      bytes = fs.readFileSync(guard);
    assert.throws(() => h.assertCleanupSafe(root));
    fs.renameSync(guard, saved);
    assert.throws(() => owner.release());
    assert.throws(() => h.assertCleanupSafe(root));
    fs.writeFileSync(guard, bytes, { flag: "wx" });
    assert.throws(() => owner.release());
    assert.ok(fs.readFileSync(guard).equals(bytes));
    fs.unlinkSync(guard);
    fs.renameSync(saved, guard);
    owner.release();
    h.assertCleanupSafe(root);
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});
test("bounded control reader refuses oversized files and holders inherit no unrelated secrets", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "weak-acl-reader-")),
    file = path.join(root, "public");
  try {
    fs.writeFileSync(file, "public");
    assert.equal(h.read(file, 6).toString(), "public");
    assert.throws(() => h.read(file, 5));
    assert.deepEqual(
      h.holderEnvironment({
        Path: "public-path",
        SystemRoot: "C:\\Windows",
        TEMP: "owned",
        PSModulePath: "foreign",
        GITHUB_TOKEN: "secret",
        DATABASE_URL: "secret",
        CERTOPS_ADCS_OFFICER_PASSWORD: "secret",
      }),
      { Path: "public-path", SystemRoot: "C:\\Windows", TEMP: "owned" },
    );
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});

test("cleanup preserves same-byte replacements of every original protocol file", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "weak-acl-original-"));
  try {
    for (const name of [
      "credential",
      "context.json",
      "release",
      "ready.json",
      "restored.json",
    ]) {
      const file = path.join(root, name),
        saved = file + ".original";
      fs.writeFileSync(file, "public-control", { flag: "wx" });
      const original = h.readRecord(file);
      fs.renameSync(file, saved);
      fs.writeFileSync(file, original.bytes, { flag: "wx" });
      assert.throws(
        () => h.removeOriginal(file, original),
        /preserve replacement/,
      );
      assert.ok(fs.readFileSync(file).equals(original.bytes));
      assert.ok(fs.existsSync(saved));
      fs.unlinkSync(file);
      fs.renameSync(saved, file);
      h.removeOriginal(file, original);
      assert.equal(fs.existsSync(file), false);
    }
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});
