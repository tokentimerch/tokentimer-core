"use strict";
/** Short native expiry fixture child custody. Creation is suspended inside a
 * retained JobObject; only its independently observed current runner SID is used.
 * A failed/unknown drain retains a durable receipt and blocks host cleanup.
 * This supplies no native certificate, policy-window or installed-service proof. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const contained = require("../../../../tests/e2e/helpers/certops-windows-contained-process");
const platform = require("../../src/platform");
const owners = new Map(),
  prefix = ".preserve-short-retention-";
const REQUIRED_SOURCES = Object.freeze([
  "packages/agent/scripts/host/retention-interrupted-process.js",
  ...contained.REQUIRED_SOURCES,
  "packages/agent/src/platform/index.js",
]);
const digest = (bytes) =>
  crypto.createHash("sha256").update(bytes).digest("hex");
function id(file) {
  const stat = fs.lstatSync(file, { bigint: true });
  assert.ok(stat.ino > 0n && !stat.isSymbolicLink());
  assert.equal(
    fs.realpathSync(file).toLowerCase(),
    path.resolve(file).toLowerCase(),
  );
  return String(stat.ino);
}
function verifyProof(p) {
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "scope",
      "assignedBeforeResume",
      "rootExit86",
      "nativeActiveZero",
      "nativeHandlesClosed",
      "wrapperClosed",
    ].sort(),
  );
  assert.equal(p.scope, "owned-short-retention-native-interruption-drain");
  for (const flag of [
    "assignedBeforeResume",
    "rootExit86",
    "nativeActiveZero",
    "nativeHandlesClosed",
    "wrapperClosed",
  ])
    assert.equal(p[flag], true, flag);
  return true;
}
function assertCleanupSafe(workDir) {
  const root = path.resolve(workDir);
  assert.equal(
    [...owners.values()].some((owner) => owner.root === root),
    false,
    "Retain short-retention fixture while process custody is unresolved",
  );
  assert.equal(
    fs.readdirSync(root).some((name) => name.startsWith(prefix)),
    false,
    "Retain durable short-retention process receipt",
  );
  contained.assertCleanupSafe(root);
}
function release(owner) {
  assert.equal(id(owner.root), owner.rootId);
  assert.equal(id(owner.directory), owner.directoryId);
  assert.equal(id(owner.guard), owner.guardId);
  assert.equal(digest(fs.readFileSync(owner.guard)), owner.guardDigest);
  fs.unlinkSync(owner.guard);
  owners.delete(owner.guard);
}
async function drainBeforeCleanup(workDir) {
  const root = path.resolve(workDir);
  for (const owner of [...owners.values()].filter(
    (value) => value.root === root,
  )) {
    assert.ok(
      owner.resource,
      "No retained native ownership receipt; preserve fixture",
    );
    const proof = await owner.resource.stopAndDrain();
    assert.equal(proof.activeNativeProcesses, 0);
    assert.equal(owner.resource.hasLiveChild(), false);
    assert.equal(owner.resource.hasOwnershipReceipt(), false);
    release(owner);
  }
  assertCleanupSafe(root);
}
async function interruptOwnedCollector({
  workDir,
  stateDir,
  thumbprint,
  containerName,
  retentionHours,
  store = "My",
}) {
  assert.ok(["My", "WebHosting"].includes(store));
  assert.ok(store === "My" || retentionHours === 24);
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_HOST_TESTS, "1");
  assert.ok([24, 168, 720].includes(retentionHours));
  assert.match(thumbprint, /^[A-F0-9]{40}$/);
  assert.match(
    containerName,
    /^tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/,
  );
  const root = path.resolve(workDir),
    directory = path.dirname(path.resolve(stateDir));
  assert.equal(path.basename(stateDir), "state");
  assert.equal(path.dirname(directory), root);
  assert.match(path.basename(directory), /^elapsed-retention-[a-f0-9-]{36}$/);
  const token = crypto.randomUUID(),
    guard = path.join(root, prefix + token + ".json"),
    go = path.join(directory, "interrupted-native-go");
  assert.equal(fs.existsSync(go), false);
  const bytes = Buffer.from(
    JSON.stringify({ schemaVersion: 1, token, directory }),
  );
  fs.writeFileSync(guard, bytes, { flag: "wx", mode: 0o600 });
  platform.applyRestrictivePermissions(guard, { kind: "file" });
  const owner = {
    root,
    directory,
    guard,
    rootId: id(root),
    directoryId: id(directory),
    guardId: id(guard),
    guardDigest: digest(bytes),
    resource: null,
  };
  owners.set(guard, owner);
  let wrapperExit;
  try {
    const resource = await contained.startContainedNativeProcess({
      executable: process.execPath,
      args: [
        path.join(__dirname, "retention-interrupted-child.js"),
        stateDir,
        thumbprint,
        containerName,
        ...(retentionHours === 24
          ? []
          : [`--retention-hours=${retentionHours}`]),
        ...(store === "My" ? [] : [`--store=${store}`]),
        `--owned-go=${go}`,
      ],
      environment: {
        ...Object.fromEntries(
          [
            "SystemRoot",
            "WINDIR",
            "ComSpec",
            "PATH",
            "PATHEXT",
            "TEMP",
            "TMP",
            "SystemDrive",
            "ProgramFiles",
            "ProgramData",
            "USERPROFILE",
          ]
            .filter((key) => process.env[key] !== undefined)
            .map((key) => [key, process.env[key]]),
        ),
        CERTOPS_HOST_TESTS: "1",
      },
      workDir: root,
      maxLifetimeMs: 120000,
      onCreated(value) {
        owner.resource = value;
        wrapperExit = new Promise((resolve) =>
          value.wrapper.once("close", resolve),
        );
      },
    });
    assert.equal(id(root), owner.rootId);
    assert.equal(id(directory), owner.directoryId);
    assert.equal(id(guard), owner.guardId);
    assert.equal(digest(fs.readFileSync(guard)), owner.guardDigest);
    const temporary = go + ".tmp";
    fs.writeFileSync(temporary, "1", { flag: "wx" });
    try {
      fs.linkSync(temporary, go);
    } finally {
      fs.unlinkSync(temporary);
    }
    let timer;
    try {
      await Promise.race([
        wrapperExit,
        new Promise((_, reject) => {
          timer = setTimeout(
            () =>
              reject(new Error("Owned short-retention child did not close")),
            130000,
          );
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
    const closed = await resource.stopAndDrain();
    assert.equal(closed.rootExitCode, 86);
    assert.equal(closed.activeNativeProcesses, 0);
    assert.equal(closed.nativeHandlesClosed, true);
    assert.equal(resource.hasLiveChild(), false);
    assert.equal(resource.hasOwnershipReceipt(), false);
    const receiptFile = path.join(stateDir, "interrupted-native-delete.json"),
      stat = fs.lstatSync(receiptFile);
    assert.ok(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 8192);
    const receipt = JSON.parse(fs.readFileSync(receiptFile, "utf8"));
    assert.equal(
      receipt.fault,
      "process-exit-after-native-delstore-before-delkey",
    );
    assert.equal(receipt.nativeCommandSucceeded, true);
    assert.equal(receipt.thumbprint, thumbprint);
    assert.equal(receipt.containerName, containerName);
    assert.equal(receipt.pid, resource.rootIdentity.pid);
    const proof = {
      scope: "owned-short-retention-native-interruption-drain",
      assignedBeforeResume: true,
      rootExit86: true,
      nativeActiveZero: true,
      nativeHandlesClosed: true,
      wrapperClosed: true,
    };
    verifyProof(proof);
    return { receipt, proof };
  } finally {
    await drainBeforeCleanup(root);
  }
}
module.exports = {
  REQUIRED_SOURCES,
  verifyProof,
  assertCleanupSafe,
  drainBeforeCleanup,
  interruptOwnedCollector,
};
