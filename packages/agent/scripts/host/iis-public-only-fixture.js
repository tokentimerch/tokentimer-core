/*
 * Qualification notes: native-iis-public-only-association
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Exercise actual native IIS certificate lookup when a public store context lacks its expected
 * private-key association. Independently prove original protected key/certificate and trusted endpoint
 * facts; production must refuse unsafe deployment rather than infer possession from public bytes.
 * Exact owned public copy cleanup preserves genuine key and unrelated endpoint. This narrow supporting
 * association control is not installed issuance, export-policy qualification or a CA journey.
 */
"use strict";
/** Supporting native IIS association refusal, not an installed/API journey.
 * Reuses a fixture leaf only AFTER its original key is genuinely absent. Owns
 * one exact public My-store copy and never deletes or recreates a native key.
 * The caller must check assertCleanupSafe before broader fixture cleanup. */
const assert = require("node:assert/strict"),
  crypto = require("node:crypto"),
  fs = require("node:fs"),
  path = require("node:path");
const { deployIisBinding } = require("../../src/windows-iis");
const MARKER = ".iis-public-only-pending.json";
const active = new Set(),
  SCOPE = "native-iis-public-only-certificate-association-refusal",
  SCENARIO = "windows-iis-public-only-association-refusal";
const REQUIRED_SOURCES = Object.freeze([
  "packages/agent/scripts/host/iis-public-only-fixture.js",
  "packages/agent/scripts/host/iis-fixture.js",
  "packages/agent/scripts/host/windows-host.test.js",
  "packages/agent/src/windows-iis/index.js",
  "packages/agent/src/windows-discovery/index.js",
]);
const FLAGS = Object.freeze([
  "actualPublicOnlyMyCertificate",
  "originalNativeKeyAbsent",
  "actualProductionDeploymentRefused",
  "actualRollbackSucceeded",
  "predecessorBindingAndTrustedTlsPreserved",
  "unrelatedBindingAndTrustedTlsPreserved",
  "exactOwnedPublicCopyRemoved",
]);
function verifyProof(p) {
  assert.ok(p && typeof p === "object" && !Array.isArray(p));
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "scope",
      "refusalCode",
      "installedSignedJobQualified",
      "candidateFingerprint",
      "predecessorFingerprint",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(p.scope, SCOPE);
  assert.ok(["BIND_FAILED", "VERIFY_FAILED"].includes(p.refusalCode));
  assert.equal(p.installedSignedJobQualified, false);
  for (const k of FLAGS) assert.equal(p[k], true);
  for (const k of ["candidateFingerprint", "predecessorFingerprint"])
    assert.match(p[k], /^[a-f0-9]{64}$/);
  assert.notEqual(p.candidateFingerprint, p.predecessorFingerprint);
  return p;
}
const q = (s) => s.replace(/'/g, "''");
function scripts({ thumbprint, der, containerName }) {
  assert.match(thumbprint, /^[A-F0-9]{40}$/);
  assert.match(containerName, /^[A-Za-z0-9_.{}-]{1,256}$/);
  assert.match(der, /^[A-Za-z0-9+/]+={0,2}$/);
  const check = `$ErrorActionPreference='Stop';$provider=[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider;$options=[Security.Cryptography.CngKeyOpenOptions]::MachineKey;if([Security.Cryptography.CngKey]::Exists('${q(containerName)}',$provider,$options)){throw 'Original fixture key must remain absent'};$p='Cert:\\LocalMachine\\My\\${thumbprint}';`,
    exact = `$c=Get-Item -LiteralPath $p -ErrorAction Stop;try{if($c.Thumbprint-cne'${thumbprint}'-or$c.HasPrivateKey-or[Convert]::ToBase64String($c.RawData)-cne'${der}'){throw 'Changed public-only certificate must be preserved'}}finally{$c.Dispose()};`;
  return {
    create:
      check +
      `if(Test-Path -LiteralPath $p){throw 'Refusing preexisting public certificate'};$c=[Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String('${der}'));$s=[Security.Cryptography.X509Certificates.X509Store]::new('My','LocalMachine');try{if($c.HasPrivateKey-or$c.Thumbprint-cne'${thumbprint}'){throw 'Exact public-only input required'};$s.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite);$s.Add($c)}finally{$s.Dispose();$c.Dispose()};` +
      exact +
      "'public-only'",
    observe: check + exact + "'public-only'",
    remove:
      check +
      exact +
      "Remove-Item -LiteralPath $p -ErrorAction Stop;if(Test-Path -LiteralPath $p){throw 'Owned public copy remains'};'removed'",
  };
}
function assertCleanupSafe(root) {
  assert.ok(
    !active.has(path.resolve(root)) &&
      !fs.existsSync(path.join(path.resolve(root), MARKER)),
    "Preserve unresolved public-only association fixture",
  );
}
function assertOriginalMarker(file, original, expected) {
  const fd = fs.openSync(file, "r");
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    assert.ok(
      before.isFile() &&
        !before.isSymbolicLink() &&
        before.dev === original.dev &&
        before.ino === original.ino &&
        before.size === BigInt(expected.length),
      "Preserve changed association marker",
    );
    const buffer = Buffer.alloc(expected.length + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = fs.readSync(
        fd,
        buffer,
        length,
        buffer.length - length,
        length,
      );
      if (!count) break;
      length += count;
    }
    const after = fs.fstatSync(fd, { bigint: true }),
      current = fs.lstatSync(file, { bigint: true });
    for (const row of [after, current])
      assert.ok(
        row.isFile() &&
          !row.isSymbolicLink() &&
          row.dev === before.dev &&
          row.ino === before.ino &&
          row.size === before.size &&
          row.mtimeNs === before.mtimeNs &&
          row.ctimeNs === before.ctimeNs,
        "Preserve changed association marker",
      );
    assert.ok(
      length === expected.length && buffer.subarray(0, length).equals(expected),
      "Preserve changed association marker",
    );
  } finally {
    fs.closeSync(fd);
  }
}
async function qualify({
  workDir,
  certificate,
  containerName,
  predecessor,
  binding,
  powershell,
  readPrimary,
  assertPrimaryTls,
  assertSibling,
}) {
  assert.equal(process.platform, "win32");
  for (const fn of [powershell, readPrimary, assertPrimaryTls, assertSibling])
    assert.equal(typeof fn, "function");
  const root = path.resolve(workDir),
    original = fs.lstatSync(root, { bigint: true });
  assert.ok(
    original.isDirectory() && !original.isSymbolicLink() && original.ino > 0n,
  );
  assert.equal(fs.realpathSync.native(root), root);
  assertCleanupSafe(root);
  active.add(root);
  const marker = path.join(root, MARKER),
    markerBytes = Buffer.from(JSON.stringify({ nonce: crypto.randomUUID() }));
  fs.writeFileSync(marker, markerBytes, { flag: "wx", mode: 0o600 });
  const markerStat = fs.lstatSync(marker, { bigint: true });
  const owned = () => {
    const now = fs.lstatSync(root, { bigint: true });
    assert.ok(
      now.isDirectory() &&
        !now.isSymbolicLink() &&
        now.dev === original.dev &&
        now.ino === original.ino,
      "Preserve replaced native fixture root",
    );
    assertOriginalMarker(marker, markerStat, markerBytes);
  };
  const candidate = new crypto.X509Certificate(
      Buffer.from(certificate.der, "base64"),
    ),
    old = new crypto.X509Certificate(Buffer.from(predecessor.der, "base64"));
  assert.equal(
    candidate.fingerprint.replaceAll(":", ""),
    certificate.thumbprint,
  );
  assert.notEqual(candidate.fingerprint256, old.fingerprint256);
  const before = await readPrimary();
  assert.equal(before.thumb, predecessor.thumbprint);
  assert.equal(before.nativeThumb, predecessor.thumbprint);
  assert.equal(String(before.store).toLowerCase(), "my");
  assert.equal(String(before.nativeStore).toLowerCase(), "my");
  await assertPrimaryTls();
  await assertSibling();
  const native = scripts({
    thumbprint: certificate.thumbprint,
    der: certificate.der,
    containerName,
  });
  owned();
  assert.equal(powershell(native.create), "public-only");
  owned();
  assert.equal(powershell(native.observe), "public-only");
  const pem =
    "-----BEGIN CERTIFICATE-----\n" +
    certificate.der +
    "\n-----END CERTIFICATE-----\n";
  const result = await deployIisBinding({
    binding,
    certificatePem: pem,
    verifyTimeoutMs: 5000,
  });
  assert.equal(
    result.ok,
    false,
    "An unusable public-only association must never succeed",
  );
  assert.ok(
    ["BIND_FAILED", "VERIFY_FAILED"].includes(result.code),
    "Real binding or live verification refusal required",
  );
  assert.equal(
    result.rolledBack,
    true,
    "Actual outgoing endpoint restoration required",
  );
  assert.deepEqual(await readPrimary(), before);
  await assertPrimaryTls();
  await assertSibling();
  owned();
  assert.equal(powershell(native.observe), "public-only");
  owned();
  assert.equal(powershell(native.remove), "removed");
  assert.deepEqual(await readPrimary(), before);
  await assertPrimaryTls();
  await assertSibling();
  owned();
  fs.unlinkSync(marker);
  active.delete(root);
  return verifyProof({
    scope: SCOPE,
    refusalCode: result.code,
    installedSignedJobQualified: false,
    candidateFingerprint: crypto
      .createHash("sha256")
      .update(candidate.raw)
      .digest("hex"),
    predecessorFingerprint: crypto
      .createHash("sha256")
      .update(old.raw)
      .digest("hex"),
    ...Object.fromEntries(FLAGS.map((k) => [k, true])),
  });
}
module.exports = {
  SCOPE,
  SCENARIO,
  REQUIRED_SOURCES,
  FLAGS,
  verifyProof,
  scripts,
  qualify,
  assertCleanupSafe,
  assertOriginalMarker,
};
