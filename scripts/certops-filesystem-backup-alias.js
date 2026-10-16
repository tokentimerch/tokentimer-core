"use strict";
/** Real native filesystem qualification for an explicit backup directory alias.
 * Called only by the disposable filesystem host harness with genuine matching
 * fixtures. It never exposes local key bytes/paths and does not qualify API or
 * service admission. Unknown directory/receipt replacement preserves the root. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { isDeepStrictEqual } = require("node:util");
const deploy = require("../packages/agent/src/deploy");
const policy = require("../packages/agent/src/policy");
const common = require("./certops-filesystem-concurrent");
const SCENARIO = "filesystem-backup-directory-alias-refusal";
const SCOPE = "native-filesystem-explicit-backup-directory-alias-refusal";
const PREFIX = ".preserve-filesystem-backup-alias-";
const FLAGS = [
  "actualInitialPairAndChain",
  "actualNativeDirectoryAlias",
  "lexicalAliasAllowed",
  "canonicalOutsideRefused",
  "productionRealpathPolicyRefusal",
  "predecessorBytesAndIdentityPreserved",
  "noOutsideBackupCreated",
  "sourceKeyPreserved",
  "actualAllowedDirectoryRecovery",
  "threePredecessorBackupsVerified",
  "privateKeyPermissionsVerified",
  "ownedCleanupCompleted",
];
const REQUIRED_SOURCES = [
  ...common.REQUIRED_SOURCES,
  "scripts/certops-filesystem-backup-alias.js",
];
const digest = (value) =>
  crypto.createHash("sha256").update(value).digest("hex");
function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "schemaVersion",
      "scope",
      "aliasKind",
      "refusalStage",
      "fingerprints",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.scope, SCOPE);
  assert.ok(["symlink", "junction"].includes(value.aliasKind));
  assert.equal(value.refusalStage, "realpath-policy");
  assert.ok(
    Array.isArray(value.fingerprints) &&
      value.fingerprints.length === 2 &&
      value.fingerprints.every(
        (v) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v),
      ) &&
      new Set(value.fingerprints).size === 2,
  );
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  return true;
}
function identity(file, directory = false) {
  const st = fs.lstatSync(file, { bigint: true });
  assert.ok(
    !st.isSymbolicLink() &&
      (directory ? st.isDirectory() : st.isFile()) &&
      st.ino > 0n,
    "Owned native file identity required",
  );
  assert.equal(path.resolve(fs.realpathSync.native(file)), path.resolve(file));
  return `${st.dev}:${st.ino}`;
}
function observe(file) {
  const st = fs.lstatSync(file, { bigint: true });
  return {
    identity: identity(file),
    sha256: digest(fs.readFileSync(file)),
    mode: String(st.mode),
    uid: String(st.uid),
    gid: String(st.gid),
  };
}
function assertPreserved(file, before) {
  assert.ok(
    isDeepStrictEqual(observe(file), before),
    "Owned file bytes, inode or permissions changed",
  );
}
function assertCleanupSafe(root) {
  assert.ok(
    !fs
      .readdirSync(common.canonicalDirectory(root))
      .some((name) => name.startsWith(PREFIX)),
    "Preserve unresolved backup-directory ownership",
  );
}
async function qualifyBackupDirectoryAlias({
  workDir,
  materials,
  independentlyCheckKeyPermissions,
}) {
  assert.ok(["linux", "win32"].includes(process.platform));
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
  assert.equal(process.env.CERTOPS_FILESYSTEM_DISPOSABLE_HOST, "1");
  assert.ok(Array.isArray(materials) && materials.length === 2);
  assert.equal(typeof independentlyCheckKeyPermissions, "function");
  const root = common.canonicalDirectory(workDir),
    rootId = identity(root, true);
  const dir = fs.mkdtempSync(path.join(root, "backup-alias-")),
    dirId = identity(dir, true);
  const allowed = path.join(dir, "allowed"),
    outside = path.join(dir, "outside");
  fs.mkdirSync(allowed, { mode: 0o700 });
  fs.mkdirSync(outside, { mode: 0o700 });
  const allowedId = identity(allowed, true),
    outsideId = identity(outside, true);
  const marker = path.join(outside, "sentinel");
  fs.writeFileSync(marker, "owned-outside-preserved", {
    flag: "wx",
    mode: 0o600,
  });
  const sentinel = observe(marker);
  const receipt = path.join(root, PREFIX + crypto.randomUUID() + ".json");
  const receiptBytes = Buffer.from(
    JSON.stringify({
      schemaVersion: 1,
      directory: dir,
      token: crypto.randomUUID(),
    }),
  );
  fs.writeFileSync(receipt, receiptBytes, { flag: "wx", mode: 0o600 });
  const receiptId = identity(receipt),
    receiptSha = digest(receiptBytes);
  let clean = false,
    proof;
  function owned() {
    assert.equal(identity(root, true), rootId);
    assert.equal(identity(dir, true), dirId);
    assert.equal(identity(allowed, true), allowedId);
    assert.equal(identity(outside, true), outsideId);
    assert.equal(identity(receipt), receiptId);
    assert.ok(
      digest(fs.readFileSync(receipt)) === receiptSha,
      "Backup directory owner receipt changed",
    );
  }
  try {
    const target = {
      type: "domain",
      reference: "filesystem.example.test",
      certPath: path.join(allowed, "leaf.pem"),
      keyPath: path.join(allowed, "key.pem"),
      chainPath: path.join(allowed, "chain.pem"),
    };
    const checkPath = policy.createPolicyEngine(
      policy.loadPolicyConfig({ allowedPaths: [allowed] }),
    ).checkPath;
    const input = (material) => ({
      certificatePem: material.certificatePem,
      privateKeyPath: material.privateKeyPath,
      chainPem: material.chainPem,
      retainPrivateKeyStaging: true,
    });
    const sourceKeys = materials.map((item) => {
      assert.equal(path.dirname(path.resolve(item.privateKeyPath)), root);
      return observe(item.privateKeyPath);
    });
    const fingerprints = materials.map((item) =>
      digest(new crypto.X509Certificate(item.certificatePem).raw),
    );
    assert.equal(new Set(fingerprints).size, 2);
    function pair(material, files) {
      const leaf = new crypto.X509Certificate(fs.readFileSync(files.cert));
      assert.ok(
        digest(leaf.raw) ===
          digest(new crypto.X509Certificate(material.certificatePem).raw),
        "Actual deployed leaf differs",
      );
      assert.ok(
        leaf.checkPrivateKey(
          crypto.createPrivateKey(fs.readFileSync(files.key)),
        ),
        "Actual native key differs",
      );
      assert.equal(leaf.checkHost(target.reference), target.reference);
      assert.ok(
        digest(fs.readFileSync(files.key)) ===
          sourceKeys[materials.indexOf(material)].sha256,
        "Actual key bytes differ",
      );
      assert.ok(
        digest(fs.readFileSync(files.chain)) === digest(material.chainPem),
        "Actual chain differs",
      );
      assert.ok(
        leaf.verify(new crypto.X509Certificate(material.chainPem).publicKey),
        "Actual CA signature differs",
      );
      independentlyCheckKeyPermissions(files.key);
    }
    const initial = await deploy.deployCertificateAndKey({
      target,
      ...input(materials[0]),
      checkPath,
    });
    assert.equal(initial.deployed, true);
    assert.equal(initial.firstDeploy, true);
    const files = {
      cert: target.certPath,
      key: target.keyPath,
      chain: target.chainPath,
    };
    pair(materials[0], files);
    const before = Object.values(files).map(observe);
    const alias = path.join(allowed, "backups");
    fs.symlinkSync(
      outside,
      alias,
      process.platform === "win32" ? "junction" : "dir",
    );
    const aliasSt = fs.lstatSync(alias, { bigint: true });
    assert.ok(
      aliasSt.isSymbolicLink() && aliasSt.ino > 0n,
      "Actual native directory alias required",
    );
    assert.equal(path.resolve(fs.realpathSync.native(alias)), outside);
    assert.equal(checkPath(alias).allowed, true);
    assert.notEqual(checkPath(outside).allowed, true);
    const refusal = await deploy.deployCertificateAndKey({
      target: { ...target, backupDir: alias },
      ...input(materials[1]),
      checkPath,
    });
    assert.equal(refusal.deployed, false);
    assert.equal(refusal.skipped, false);
    assert.equal(refusal.stage, "realpath-policy");
    assert.equal(refusal.backupPaths, undefined);
    Object.values(files).forEach((file, index) =>
      assertPreserved(file, before[index]),
    );
    assert.deepEqual(fs.readdirSync(outside), ["sentinel"]);
    assertPreserved(marker, sentinel);
    materials.forEach((item, index) =>
      assertPreserved(item.privateKeyPath, sourceKeys[index]),
    );
    pair(materials[0], files);
    owned();
    const currentAlias = fs.lstatSync(alias, { bigint: true });
    assert.ok(
      currentAlias.isSymbolicLink() &&
        currentAlias.dev === aliasSt.dev &&
        currentAlias.ino === aliasSt.ino &&
        path.resolve(fs.realpathSync.native(alias)) === outside,
      "Refuse foreign alias replacement",
    );
    fs.unlinkSync(alias);
    fs.mkdirSync(alias, { mode: 0o700 });
    const backupId = identity(alias, true);
    const recovered = await deploy.deployCertificateAndKey({
      target: { ...target, backupDir: alias },
      ...input(materials[1]),
      checkPath,
    });
    assert.equal(recovered.deployed, true);
    assert.equal(recovered.skipped, false);
    assert.equal(recovered.firstDeploy, false);
    assert.equal(identity(alias, true), backupId);
    assert.equal(new Set(Object.values(recovered.backupPaths)).size, 3);
    for (const file of Object.values(recovered.backupPaths)) {
      assert.equal(path.dirname(file), alias);
      identity(file);
    }
    pair(materials[0], recovered.backupPaths);
    pair(materials[1], files);
    assert.deepEqual(fs.readdirSync(outside), ["sentinel"]);
    assertPreserved(marker, sentinel);
    materials.forEach((item, index) =>
      assertPreserved(item.privateKeyPath, sourceKeys[index]),
    );
    owned();
    clean = true;
    proof = {
      schemaVersion: 1,
      scope: SCOPE,
      aliasKind: process.platform === "win32" ? "junction" : "symlink",
      refusalStage: "realpath-policy",
      fingerprints,
      ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
    };
  } finally {
    // No broad cleanup on failure: retain the exact receipt and owned root for
    // diagnosis; parent must stop before deleting any staged private material.
    if (clean) {
      owned();
      fs.rmSync(dir, { recursive: true });
      fs.unlinkSync(receipt);
    }
  }
  verifyProof(proof);
  return proof;
}
module.exports = {
  SCENARIO,
  SCOPE,
  FLAGS,
  REQUIRED_SOURCES,
  verifyProof,
  observe,
  assertPreserved,
  assertCleanupSafe,
  qualifyBackupDirectoryAlias,
};
