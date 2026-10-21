/**
 * Qualification: native destination-scoped backup retention
 *
 * Use production filesystem deployment with backupRetentionCount:1, three genuine pairs
 * and real clock. Two destinations share basenames and an explicit backup directory;
 * deploy+rotate both, then rotate only the first twice more. Each step must retain that
 * destination's newest three rollback files and delete its older generation while
 * preserving the other's exact backups, inodes, modes, legacy timestamp backup, operator
 * file and outside sentinel. Independently verify predecessor leaf,
 * key/chain/CA/DNS/permissions plus final target/staging pairs; public proof keeps only
 * public fingerprints, fixed counts/flags. Legacy files remain operator-owned. Register
 * durable receipt before mutations; unresolved ownership blocks recursive cleanup.
 * Recheck original directory/receipt/sentinel identities before release. This proves
 * generation-count retention, not elapsed-age expiry or cross-process locking. All four
 * host slots require strict proof/current critical sources; pure temporary-file/proof
 * checks are not protected native execution.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";
/** Native source for bounded destination-scoped backup retention. Called by a
 * disposable host harness with three genuine matching certificate/key fixtures.
 * Uses real production clocks and files; private material never enters proof. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const deploy = require("../packages/agent/src/deploy");
const policy = require("../packages/agent/src/policy");
const common = require("./certops-filesystem-concurrent");
const observation = require("./certops-filesystem-backup-alias");
const SCENARIO = "filesystem-backup-retention-destination-isolation";
const SCOPE =
  "native-filesystem-bounded-backup-retention-destination-isolation";
const PREFIX = ".preserve-filesystem-backup-retention-";
const FLAGS = [
  "twoActualInitialDeployments",
  "twoActualIndependentRotations",
  "sameBasenamesAndBackupDirectory",
  "olderOwnedGenerationPruned",
  "currentRollbackGenerationPreserved",
  "otherDestinationBackupsPreserved",
  "legacyAndOperatorFilesPreserved",
  "outsideSentinelPreserved",
  "threePredecessorPairsVerified",
  "finalCertificateKeyAndChainVerified",
  "nativePrivateKeyPermissionsVerified",
  "privateStagingPreserved",
  "ownedCleanupCompleted",
];
const REQUIRED_SOURCES = [
  ...observation.REQUIRED_SOURCES,
  "scripts/certops-filesystem-backup-retention.js",
];
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "schemaVersion",
      "scope",
      "retentionCount",
      "targetCount",
      "actualRotations",
      "fingerprints",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.scope, SCOPE);
  assert.equal(value.retentionCount, 1);
  assert.equal(value.targetCount, 2);
  assert.equal(value.actualRotations, 4);
  assert.ok(
    Array.isArray(value.fingerprints) &&
      value.fingerprints.length === 3 &&
      value.fingerprints.every(
        (v) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v),
      ) &&
      new Set(value.fingerprints).size === 3,
  );
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  return true;
}
function dirIdentity(file) {
  const st = fs.lstatSync(file, { bigint: true });
  assert.ok(st.isDirectory() && !st.isSymbolicLink() && st.ino > 0n);
  assert.equal(fs.realpathSync.native(file), file);
  return `${st.dev}:${st.ino}`;
}
function assertCleanupSafe(root) {
  assert.ok(
    !fs
      .readdirSync(common.canonicalDirectory(root))
      .some((file) => file.startsWith(PREFIX)),
    "Preserve unresolved backup retention ownership",
  );
}
async function qualifyBackupRetention({
  workDir,
  materials,
  independentlyCheckKeyPermissions,
}) {
  assert.ok(["linux", "win32"].includes(process.platform));
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
  assert.equal(process.env.CERTOPS_FILESYSTEM_DISPOSABLE_HOST, "1");
  assert.ok(Array.isArray(materials) && materials.length === 3);
  assert.equal(typeof independentlyCheckKeyPermissions, "function");
  const root = common.canonicalDirectory(workDir),
    rootId = dirIdentity(root);
  const directory = fs.mkdtempSync(path.join(root, "backup-retention-")),
    directoryId = dirIdentity(directory);
  const dirs = ["one", "two", "backups"].map((name) =>
    path.join(directory, name),
  );
  dirs.forEach((dir) => fs.mkdirSync(dir, { mode: 0o700 }));
  const directoryIds = dirs.map(dirIdentity),
    backups = dirs[2];
  const receipt = path.join(root, PREFIX + crypto.randomUUID() + ".json");
  fs.writeFileSync(
    receipt,
    JSON.stringify({ schemaVersion: 1, token: crypto.randomUUID(), directory }),
    { flag: "wx", mode: 0o600 },
  );
  const receiptBefore = observation.observe(receipt);
  const outside = path.join(
    root,
    `retention-outside-${crypto.randomUUID()}.txt`,
  );
  fs.writeFileSync(outside, "owned outside public sentinel", {
    flag: "wx",
    mode: 0o600,
  });
  const outsideBefore = observation.observe(outside);
  const owned = () => {
    assert.equal(dirIdentity(root), rootId);
    assert.equal(dirIdentity(directory), directoryId);
    dirs.forEach((dir, index) =>
      assert.equal(dirIdentity(dir), directoryIds[index]),
    );
    observation.assertPreserved(receipt, receiptBefore);
  };
  let complete = false,
    proof;
  try {
    const fingerprints = materials.map((item) =>
      sha(new crypto.X509Certificate(item.certificatePem).raw),
    );
    assert.equal(new Set(fingerprints).size, 3);
    const staging = materials.map((item) => {
      assert.equal(path.dirname(path.resolve(item.privateKeyPath)), root);
      return observation.observe(item.privateKeyPath);
    });
    const targets = dirs
      .slice(0, 2)
      .map((dir) => ({
        type: "domain",
        reference: "filesystem.example.test",
        certPath: path.join(dir, "leaf.pem"),
        keyPath: path.join(dir, "key.pem"),
        chainPath: path.join(dir, "chain.pem"),
        backupDir: backups,
        backupRetentionCount: 1,
      }));
    const checkPath = policy.createPolicyEngine(
      policy.loadPolicyConfig({ allowedPaths: [directory] }),
    ).checkPath;
    const input = (index) => ({
      certificatePem: materials[index].certificatePem,
      privateKeyPath: materials[index].privateKeyPath,
      chainPem: materials[index].chainPem,
      retainPrivateKeyStaging: true,
    });
    const paths = (target) => ({
      cert: target.certPath,
      key: target.keyPath,
      chain: target.chainPath,
    });
    function verifyPair(files, index) {
      const leaf = new crypto.X509Certificate(fs.readFileSync(files.cert));
      assert.ok(
        sha(leaf.raw) === fingerprints[index],
        "Actual predecessor leaf differs",
      );
      assert.ok(
        leaf.checkPrivateKey(
          crypto.createPrivateKey(fs.readFileSync(files.key)),
        ),
        "Actual predecessor private key differs",
      );
      assert.ok(
        sha(fs.readFileSync(files.key)) === staging[index].sha256,
        "Actual predecessor key bytes differ",
      );
      assert.equal(leaf.checkHost(targets[0].reference), targets[0].reference);
      assert.ok(
        sha(fs.readFileSync(files.chain)) === sha(materials[index].chainPem),
        "Actual predecessor chain differs",
      );
      assert.ok(
        leaf.verify(
          new crypto.X509Certificate(materials[index].chainPem).publicKey,
        ),
        "Actual native CA signature differs",
      );
      Object.values(files).forEach((file) => observation.observe(file));
      independentlyCheckKeyPermissions(files.key);
    }
    for (const target of targets) {
      const result = await deploy.deployCertificateAndKey({
        target,
        ...input(0),
        checkPath,
      });
      assert.equal(result.deployed, true);
      assert.equal(result.firstDeploy, true);
      verifyPair(paths(target), 0);
    }
    const legacy = path.join(backups, "leaf.pem.2020-01-01T00-00-00.000Z.bak"),
      operator = path.join(backups, "operator-owned.txt");
    fs.writeFileSync(legacy, "owned legacy public sentinel", {
      flag: "wx",
      mode: 0o600,
    });
    fs.writeFileSync(operator, "owned operator public sentinel", {
      flag: "wx",
      mode: 0o600,
    });
    const legacyBefore = observation.observe(legacy),
      operatorBefore = observation.observe(operator);
    const rotate = async (target, index) => {
      const result = await deploy.deployCertificateAndKey({
        target,
        ...input(index),
        checkPath,
      });
      assert.equal(result.deployed, true);
      assert.equal(result.skipped, false);
      assert.equal(result.firstDeploy, false);
      for (const file of Object.values(result.backupPaths))
        assert.equal(path.dirname(file), backups);
      verifyPair(paths(target), index);
      return result.backupPaths;
    };
    const first = await rotate(targets[0], 1),
      second = await rotate(targets[1], 1);
    assert.equal(
      new Set([...Object.values(first), ...Object.values(second)]).size,
      6,
    );
    verifyPair(first, 0);
    verifyPair(second, 0);
    const secondBefore = Object.values(second).map(observation.observe);
    const third = await rotate(targets[0], 2);
    for (const file of Object.values(first))
      assert.equal(
        fs.existsSync(file),
        false,
        "Older exact destination generation must be pruned",
      );
    verifyPair(third, 1);
    Object.values(second).forEach((file, index) =>
      observation.assertPreserved(file, secondBefore[index]),
    );
    const fourth = await rotate(targets[0], 0);
    for (const file of Object.values(third))
      assert.equal(fs.existsSync(file), false);
    verifyPair(fourth, 2);
    verifyPair(paths(targets[0]), 0);
    verifyPair(paths(targets[1]), 1);
    Object.values(second).forEach((file, index) =>
      observation.assertPreserved(file, secondBefore[index]),
    );
    observation.assertPreserved(legacy, legacyBefore);
    observation.assertPreserved(operator, operatorBefore);
    observation.assertPreserved(outside, outsideBefore);
    assert.equal(
      fs.readdirSync(backups).length,
      8,
      "Only two retained destination generations and public sentinels may remain",
    );
    materials.forEach((item, index) =>
      observation.assertPreserved(item.privateKeyPath, staging[index]),
    );
    owned();
    complete = true;
    proof = {
      schemaVersion: 1,
      scope: SCOPE,
      retentionCount: 1,
      targetCount: 2,
      actualRotations: 4,
      fingerprints,
      ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
    };
  } finally {
    if (complete) {
      owned();
      observation.assertPreserved(outside, outsideBefore);
      fs.rmSync(directory, { recursive: true });
      fs.unlinkSync(outside);
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
  assertCleanupSafe,
  qualifyBackupRetention,
};
