"use strict";
/** Filesystem regressions for backup identity and retention. Fixed timestamps
 * reproduce coarse-clock collisions; these controls do not qualify native TLS,
 * installed agents or elapsed retention. All writes stay in owned temp roots. */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  deployCertificate,
  deployCertificateAndKey,
} = require("../../packages/agent/src/deploy");
const vectors = path.resolve(
  __dirname,
  "../../packages/agent/src/verify/fixtures",
);
const leaf = (name) => fs.readFileSync(path.join(vectors, name), "utf8");
const first = leaf("selfsigned.crt.pem"),
  second = leaf("wrong-san.crt.pem");
const now = () => new Date("2026-10-15T12:00:00.000Z");
async function owned(execute) {
  const directory = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "certops-backup-generation-")),
  );
  try {
    await execute(directory);
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
}
function options(directory, target) {
  return {
    target,
    now,
    checkPath: (file) => ({
      allowed: path.resolve(file).startsWith(directory + path.sep),
    }),
  };
}
function target(directory, name = "one") {
  const destination = path.join(directory, name);
  fs.mkdirSync(destination);
  const backupDir = path.join(directory, "backups");
  fs.mkdirSync(backupDir, { recursive: true });
  return {
    type: "domain",
    reference: "backup.example.test",
    certPath: path.join(destination, "server.crt"),
    backupDir,
  };
}
test("equal-clock deployments retain both distinct predecessor backups", () =>
  owned(async (directory) => {
    const input = options(directory, target(directory));
    assert.equal(
      (await deployCertificate({ ...input, certificatePem: first })).deployed,
      true,
    );
    const a = await deployCertificate({ ...input, certificatePem: second });
    const b = await deployCertificate({ ...input, certificatePem: first });
    assert.equal(a.deployed, true);
    assert.equal(b.deployed, true);
    assert.notEqual(a.backupPath, b.backupPath);
    assert.equal(fs.readFileSync(a.backupPath, "utf8"), first);
    assert.equal(fs.readFileSync(b.backupPath, "utf8"), second);
  }));
test("certificate and key with the same basename cannot overwrite each other's backup", () =>
  owned(async (directory) => {
    const certDir = path.join(directory, "cert"),
      keyDir = path.join(directory, "key"),
      backups = path.join(directory, "backups");
    for (const dir of [certDir, keyDir, backups]) fs.mkdirSync(dir);
    const certPath = path.join(certDir, "server.pem"),
      keyPath = path.join(keyDir, "server.pem"),
      staged = path.join(directory, "staged.key");
    const oldKey = leaf("wrong-san.key.pem");
    fs.writeFileSync(certPath, second, { mode: 0o600 });
    fs.writeFileSync(keyPath, oldKey, { mode: 0o600 });
    fs.writeFileSync(staged, leaf("leaf.key.pem"), { mode: 0o600 });
    const result = await deployCertificateAndKey({
      ...options(directory, {
        type: "domain",
        reference: "backup.example.test",
        certPath,
        keyPath,
        backupDir: backups,
      }),
      certificatePem: first,
      privateKeyPath: staged,
    });
    assert.equal(result.deployed, true);
    assert.notEqual(result.backupPaths.cert, result.backupPaths.key);
    assert.equal(fs.readFileSync(result.backupPaths.cert, "utf8"), second);
    assert.ok(
      fs.readFileSync(result.backupPaths.key).equals(Buffer.from(oldKey)),
      "Original private backup must remain unchanged",
    );
  }));
test("retention scopes same-basename backups to their destination and preserves the current generation", () =>
  owned(async (directory) => {
    const a = options(directory, target(directory, "one")),
      b = options(directory, target(directory, "two"));
    a.target.backupRetentionCount = 1;
    b.target.backupRetentionCount = 1;
    for (const input of [a, b])
      assert.equal(
        (await deployCertificate({ ...input, certificatePem: first })).deployed,
        true,
      );
    const a1 = await deployCertificate({ ...a, certificatePem: second });
    const b1 = await deployCertificate({ ...b, certificatePem: second });
    const a2 = await deployCertificate({ ...a, certificatePem: first });
    assert.equal(a1.deployed, true);
    assert.equal(b1.deployed, true);
    assert.equal(a2.deployed, true);
    assert.notEqual(a1.backupPath, a2.backupPath);
    assert.equal(fs.existsSync(a1.backupPath), false);
    assert.equal(fs.readFileSync(a2.backupPath, "utf8"), second);
    assert.equal(fs.readFileSync(b1.backupPath, "utf8"), first);
  }));
test("retention leaves unrelated and unscoped historical backup files untouched", () =>
  owned(async (directory) => {
    const input = options(directory, target(directory));
    input.target.backupRetentionCount = 1;
    const names = [
      "server.crt.operator.bak",
      "server.crt.2020-01-01T00-00-00.000Z.bak",
    ];
    for (const name of names)
      fs.writeFileSync(
        path.join(input.target.backupDir, name),
        "operator-owned",
      );
    for (const certificatePem of [first, second, first])
      assert.equal(
        (await deployCertificate({ ...input, certificatePem })).deployed,
        true,
      );
    for (const name of names)
      assert.equal(
        fs.readFileSync(path.join(input.target.backupDir, name), "utf8"),
        "operator-owned",
      );
  }));

test("first installation preserves the existing refusal of a missing backup directory", () =>
  owned(async (directory) => {
    const backupDir = path.join(directory, "not-created-yet");
    const certPath = path.join(directory, "first.crt");
    const result = await deployCertificate({
      ...options(directory, {
        type: "domain",
        reference: "backup.example.test",
        certPath,
        backupDir,
      }),
      certificatePem: first,
    });
    assert.equal(result.deployed, false);
    assert.equal(result.stage, "validate");
    assert.equal(fs.existsSync(certPath), false);
    assert.equal(fs.existsSync(backupDir), false);
  }));

test("an allowed backup directory alias keeps real predecessor backups inside the allowlist", () =>
  owned(async (directory) => {
    const real = path.join(directory, "real-backups"),
      alias = path.join(directory, "backup-alias");
    fs.mkdirSync(real);
    fs.symlinkSync(
      real,
      alias,
      process.platform === "win32" ? "junction" : "dir",
    );
    const certPath = path.join(directory, "server.crt");
    fs.writeFileSync(certPath, second);
    const result = await deployCertificate({
      ...options(directory, {
        type: "domain",
        reference: "backup.example.test",
        certPath,
        backupDir: alias,
      }),
      certificatePem: first,
    });
    assert.equal(result.deployed, true);
    assert.equal(path.dirname(result.backupPath), fs.realpathSync.native(real));
    assert.equal(fs.readFileSync(result.backupPath, "utf8"), second);
  }));

for (const paired of [false, true]) {
  test(`resolved backup directory escape refuses ${paired ? "certificate/key" : "certificate-only"} deployment before backup or replacement`, () =>
    owned(async (directory) => {
      const allowed = path.join(directory, "allowed"),
        outside = path.join(directory, "outside");
      fs.mkdirSync(allowed);
      fs.mkdirSync(outside);
      fs.writeFileSync(path.join(outside, "sentinel"), "unchanged");
      const backupDir = path.join(allowed, "backup-link");
      fs.symlinkSync(
        outside,
        backupDir,
        process.platform === "win32" ? "junction" : "dir",
      );
      const certPath = path.join(allowed, "server.crt");
      fs.writeFileSync(certPath, second, { mode: 0o600 });
      const input = {
        ...options(allowed, {
          type: "domain",
          reference: "backup.example.test",
          certPath,
          backupDir,
        }),
        certificatePem: first,
      };
      let result;
      if (paired) {
        const keyPath = path.join(allowed, "server.key"),
          staged = path.join(allowed, "staged.key");
        const oldKey = leaf("wrong-san.key.pem");
        fs.writeFileSync(keyPath, oldKey, { mode: 0o600 });
        fs.writeFileSync(staged, leaf("leaf.key.pem"), { mode: 0o600 });
        result = await deployCertificateAndKey({
          ...input,
          target: { ...input.target, keyPath },
          privateKeyPath: staged,
        });
        assert.ok(
          fs.readFileSync(keyPath).equals(Buffer.from(oldKey)),
          "Existing key must remain unchanged",
        );
        assert.ok(
          fs.existsSync(staged),
          "Refused deployment must preserve private staging",
        );
      } else result = await deployCertificate(input);
      assert.equal(result.deployed, false);
      assert.equal(result.stage, "realpath-policy");
      assert.equal(fs.readFileSync(certPath, "utf8"), second);
      assert.deepEqual(fs.readdirSync(outside), ["sentinel"]);
      assert.equal(
        fs.readFileSync(path.join(outside, "sentinel"), "utf8"),
        "unchanged",
      );
    }));
}
