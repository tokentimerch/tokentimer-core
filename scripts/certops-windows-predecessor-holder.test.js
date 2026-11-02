"use strict";
/** Software signatures and owned temporary directory controls only; this does
 * not load PowerShell, access a certificate store or run a native process. */
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const holder = require("../tests/e2e/helpers/certops-windows-predecessor-holder");

test("holder phase receipts require exact predecessor possession and closed phase facts", () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const leaf = {
    raw: Buffer.from("software-only predecessor identity"),
    publicKey,
  };
  const challenge = crypto.randomBytes(32),
    token = "a".repeat(64);
  const signature = crypto
    .sign("sha256", challenge, {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    })
    .toString("base64");
  const fingerprint = crypto
    .createHash("sha256")
    .update(leaf.raw)
    .digest("hex");
  for (const phase of ["ready", "removed", "restored"]) {
    const flag =
      phase === "removed"
        ? "publicEntryAbsent"
        : phase === "restored"
          ? "originalPublicAssociationRestored"
          : null;
    const value = {
      token,
      phase,
      fingerprint,
      signature,
      ...(flag ? { [flag]: true } : {}),
    };
    const expected = { token, leaf, challenge };
    assert.equal(holder.verifyReceipt(value, phase, expected), true);
    for (const key of Object.keys(value)) {
      const bad = { ...value };
      delete bad[key];
      assert.throws(() => holder.verifyReceipt(bad, phase, expected));
    }
    for (const patch of [
      { token: "b".repeat(64) },
      { fingerprint: "b".repeat(64) },
      { signature: Buffer.alloc(256).toString("base64") },
      { unknown: true },
      ...(flag ? [{ [flag]: false }] : []),
    ])
      assert.throws(() =>
        holder.verifyReceipt({ ...value, ...patch }, phase, expected),
      );
    assert.throws(() =>
      holder.verifyReceipt(value, phase, {
        ...expected,
        challenge: crypto.randomBytes(32),
      }),
    );
  }
  assert.throws(() =>
    holder.verifyReceipt({}, "unknown", { token, leaf, challenge }),
  );
});

test("an unresolved holder directory blocks fixture cleanup even without phase receipts", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "predecessor-holder-"));
  try {
    holder.assertCleanupSafe(root);
    const directory = path.join(root, holder.PREFIX + "a".repeat(64));
    fs.mkdirSync(directory);
    const identity = holder.directoryIdentity(directory);
    assert.match(identity.ino, /^[1-9][0-9]*$/);
    assert.throws(() => holder.assertCleanupSafe(root));
    fs.rmdirSync(directory);
    holder.assertCleanupSafe(root);
    const file = path.join(root, "not-directory");
    fs.writeFileSync(file, "public fixture");
    assert.throws(() => holder.directoryIdentity(file));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("failed startup exposes the original contained resource for drain while preserving association custody", async () => {
  const vm = require("node:vm");
  const { createRequire } = require("node:module");
  const { EventEmitter } = require("node:events");
  const file = path.resolve(
    __dirname,
    "../tests/e2e/helpers/certops-windows-predecessor-holder.js",
  );
  const actualRequire = createRequire(file);
  let drains = 0;
  const module = { exports: {} };
  const source = fs.readFileSync(file, "utf8");
  vm.runInNewContext(
    source,
    {
      module,
      exports: module.exports,
      __dirname: path.dirname(file),
      Buffer,
      process: { platform: "win32" },
      setTimeout,
      clearTimeout,
      require(name) {
        if (name !== "./certops-windows-contained-process")
          return actualRequire(name);
        return {
          REQUIRED_SOURCES: [],
          startContainedNativeProcess(options) {
            options.onCreated({
              wrapper: new EventEmitter(),
              stopAndDrain() {
                drains++;
                return Promise.resolve();
              },
            });
            throw new Error(
              "controlled startup failure before native execution",
            );
          },
        };
      },
    },
    { filename: file },
  );
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "predecessor-startup-"));
  try {
    const leaf = new crypto.X509Certificate(
      fs.readFileSync(
        path.resolve(
          __dirname,
          "../packages/agent/src/verify/fixtures/leaf.crt.pem",
        ),
      ),
    );
    const registry = [];
    await assert.rejects(
      module.exports.start({
        root,
        powershell: path.resolve(root, "never-executed.exe"),
        thumbprint: leaf.fingerprint.replaceAll(":", ""),
        derBase64: leaf.raw.toString("base64"),
        containerName: "software-fixture-container",
        uniqueName: "software-fixture-unique",
        registry,
      }),
      /controlled startup failure/,
    );
    assert.equal(registry.length, 1);
    assert.equal(registry[0].cleanupCompleted, false);
    await registry[0].emergencyDrain();
    assert.equal(drains, 1);
    assert.throws(() => module.exports.assertCleanupSafe(root));
    for (const name of fs.readdirSync(root))
      fs.rmSync(path.join(root, name), { recursive: true });
    assert.throws(
      () => module.exports.assertCleanupSafe(root),
      "Missing durable receipt cannot clear in-memory ownership",
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
