"use strict";
/** Qualification-only public-certificate association custody. The actual key
 * stays in CNG, and the paired SYSTEM holder retains its original certificate
 * context while the public store entry is absent. This is not key recovery.
 * Unknown restoration or process drainage preserves every ownership receipt. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const contained = require("./certops-windows-contained-process");
const { readOwned } = require("./certops-windows-installed-verify-rollback");
const active = new Set();
const PREFIX = ".failed-rollback-holder-";
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-windows-predecessor-holder.js",
  "tests/e2e/helpers/certops-windows-predecessor-holder.ps1",
  ...contained.REQUIRED_SOURCES,
]);
function directoryIdentity(directory) {
  const stat = fs.lstatSync(directory, { bigint: true });
  assert.ok(stat.isDirectory() && !stat.isSymbolicLink() && stat.ino > 0n);
  assert.equal(
    fs.realpathSync.native(directory).toLowerCase(),
    path.resolve(directory).toLowerCase(),
  );
  return { dev: String(stat.dev), ino: String(stat.ino) };
}
function assertCleanupSafe(root) {
  root = path.resolve(root);
  assert.ok(
    !active.has(root),
    "Unresolved predecessor association preserves fixture",
  );
  assert.ok(
    !fs.readdirSync(root).some((name) => name.startsWith(PREFIX)),
    "Predecessor association receipt preserves fixture",
  );
}
function verifyReceipt(value, phase, { token, leaf, challenge }) {
  assert.ok(["ready", "removed", "restored"].includes(phase));
  const flag =
    phase === "removed"
      ? "publicEntryAbsent"
      : phase === "restored"
        ? "originalPublicAssociationRestored"
        : null;
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "token",
      "phase",
      "fingerprint",
      "signature",
      ...(flag ? [flag] : []),
    ].sort(),
  );
  assert.equal(value.token, token);
  assert.equal(value.phase, phase);
  assert.equal(value.fingerprint, sha(leaf.raw));
  if (flag) assert.equal(value[flag], true);
  assert.ok(
    typeof value.signature === "string" &&
      /^[A-Za-z0-9+/]+={0,2}$/.test(value.signature),
  );
  const signature = Buffer.from(value.signature, "base64");
  assert.equal(signature.toString("base64"), value.signature);
  assert.equal(signature.length, 256);
  assert.ok(
    crypto.verify(
      "sha256",
      challenge,
      { key: leaf.publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
      signature,
    ),
    "Original CNG possession signature required",
  );
  return true;
}
async function start({
  root,
  powershell,
  thumbprint,
  derBase64,
  containerName,
  uniqueName,
  registry,
}) {
  assert.equal(process.platform, "win32");
  root = path.resolve(root);
  assert.ok(Array.isArray(registry));
  assertCleanupSafe(root);
  const originalRoot = directoryIdentity(root);
  const leaf = new crypto.X509Certificate(Buffer.from(derBase64, "base64"));
  assert.equal(leaf.raw.toString("base64"), derBase64);
  assert.equal(
    crypto.createHash("sha1").update(leaf.raw).digest("hex").toUpperCase(),
    thumbprint,
  );
  assert.equal(leaf.publicKey.asymmetricKeyType, "rsa");
  assert.equal(leaf.publicKey.asymmetricKeyDetails.modulusLength, 2048);
  for (const value of [containerName, uniqueName])
    assert.ok(
      typeof value === "string" &&
        value.length > 0 &&
        value.length <= 1024 &&
        !/[\x00-\x1f]/.test(value),
    );
  const token = crypto.randomBytes(32).toString("hex");
  const directory = path.join(root, PREFIX + token);
  const challenge = crypto.randomBytes(32);
  let resource, wrapperClosed;
  const row = {
    root,
    cleanupCompleted: false,
    async emergencyDrain() {
      if (resource) await resource.stopAndDrain();
      // Drainage alone does not prove the original association was restored.
    },
  };
  registry.push(row);
  active.add(root); // Before the first publication; missing markers cannot clear it.
  fs.mkdirSync(directory, { mode: 0o700 });
  const originalDirectory = directoryIdentity(directory);
  const originals = new Map();
  const check = () => {
    assert.deepEqual(directoryIdentity(root), originalRoot);
    assert.deepEqual(directoryIdentity(directory), originalDirectory);
  };
  function remember(name, bytes) {
    const item = readOwned(path.join(directory, name), 65536);
    if (bytes)
      assert.ok(
        item.bytes.equals(bytes),
        "Original predecessor protocol bytes required",
      );
    const prior = originals.get(name);
    if (prior)
      assert.ok(
        item.stat.dev === prior.stat.dev &&
          item.stat.ino === prior.stat.ino &&
          item.bytes.equals(prior.bytes),
        "Changed predecessor protocol preserved",
      );
    else originals.set(name, item);
    return item;
  }
  function publish(name, bytes) {
    check();
    fs.writeFileSync(path.join(directory, name), bytes, {
      flag: "wx",
      mode: 0o600,
    });
    remember(name, bytes);
  }
  const context = {
    schemaVersion: 1,
    token,
    root,
    rootDev: originalRoot.dev,
    rootIno: originalRoot.ino,
    directory,
    directoryDev: originalDirectory.dev,
    directoryIno: originalDirectory.ino,
    thumbprint,
    derBase64,
    containerName,
    uniqueName,
    challengeBase64: challenge.toString("base64"),
  };
  const bytes = Buffer.from(JSON.stringify(context));
  assert.ok(bytes.length <= 65536);
  publish("context.json", bytes);
  const driver = path.resolve(
    __dirname,
    "certops-windows-predecessor-holder.ps1",
  );
  const originalDriver = readOwned(driver, 65536);
  const deadline = Date.now() + 15 * 60000;
  async function receipt(phase) {
    const file = phase + ".json";
    while (!fs.existsSync(path.join(directory, file))) {
      check();
      assert.ok(
        Date.now() < deadline && resource?.hasLiveChild(),
        "Predecessor holder did not publish an owned phase",
      );
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    const observed = remember(file);
    verifyReceipt(JSON.parse(observed.bytes), phase, {
      token,
      leaf,
      challenge,
    });
    check();
  }
  resource = await contained.startContainedNativeProcess({
    executable: powershell,
    args: [
      "-NoProfile",
      "-NonInteractive",
      "-File",
      driver,
      "-ContextPath",
      path.join(directory, "context.json"),
      "-ContextSha256",
      sha(bytes),
    ],
    workDir: root,
    maxLifetimeMs: 15 * 60000,
    expectedSid: "S-1-5-18",
    onCreated(created) {
      resource = created;
      wrapperClosed = new Promise((resolve) =>
        created.wrapper.once("close", (code, signal) =>
          resolve({ code, signal }),
        ),
      );
    },
  });
  const currentDriver = readOwned(driver, 65536);
  assert.ok(
    currentDriver.stat.dev === originalDriver.stat.dev &&
      currentDriver.stat.ino === originalDriver.stat.ino &&
      currentDriver.bytes.equals(originalDriver.bytes),
    "Original predecessor holder source required",
  );
  await receipt("ready");
  let removed = false,
    restored = false;
  return {
    async remove() {
      assert.equal(removed, false);
      publish("remove", Buffer.from(token));
      await receipt("removed");
      removed = true;
    },
    async restoreAndDrain() {
      assert.equal(removed, true);
      assert.equal(restored, false);
      publish("restore", Buffer.from(token));
      await receipt("restored");
      let timer;
      let closed;
      try {
        closed = await Promise.race([
          wrapperClosed,
          new Promise((_, reject) => {
            timer = setTimeout(
              () =>
                reject(new Error("Predecessor holder natural close missing")),
              45000,
            );
          }),
        ]);
      } finally {
        clearTimeout(timer);
      }
      assert.deepEqual(closed, { code: 0, signal: null });
      const proof = await resource.stopAndDrain();
      assert.equal(proof.rootExitCode, 0);
      assert.equal(proof.activeNativeProcesses, 0);
      assert.equal(proof.nativeHandlesClosed, true);
      check();
      assert.deepEqual(
        fs.readdirSync(directory).sort(),
        [...originals.keys()].sort(),
      );
      for (const name of originals.keys()) remember(name);
      for (const name of originals.keys())
        fs.unlinkSync(path.join(directory, name));
      fs.rmdirSync(directory);
      active.delete(root);
      row.cleanupCompleted = true;
      restored = true;
      return proof;
    },
    async emergencyDrain() {
      await row.emergencyDrain(); // The unresolved association keeps its guard.
    },
  };
}
module.exports = {
  REQUIRED_SOURCES,
  PREFIX,
  verifyReceipt,
  directoryIdentity,
  assertCleanupSafe,
  start,
};
