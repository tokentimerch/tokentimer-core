"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  validateTargetConfig,
  deployCertificate,
  deployCertificateAndKey,
  discardDeployBackups,
  removeDeployedArtifacts,
  parseDeployFileMode,
  getDeployMetrics,
  resetDeployMetrics,
} = require("./index.js");

// Real X.509 fixtures (shared with verify/); fake PEM strings are rejected
// by pre-deploy validation and must not be used here either.
const FIXTURES_DIR = path.join(__dirname, "..", "verify", "fixtures");
const CERT_PEM = fs.readFileSync(path.join(FIXTURES_DIR, "selfsigned.crt.pem"), "utf8");
const OTHER_CERT_PEM = fs.readFileSync(path.join(FIXTURES_DIR, "wrong-san.crt.pem"), "utf8");
const MATCHING_KEY_PEM = fs.readFileSync(path.join(FIXTURES_DIR, "leaf.key.pem"), "utf8");
const OTHER_KEY_PEM = fs.readFileSync(path.join(FIXTURES_DIR, "wrong-san.key.pem"), "utf8");
const PRIVATE_KEY_PEM =
  "-----BEGIN PRIVATE KEY-----\nMIIEfake-key-body\n-----END PRIVATE KEY-----\n";

const tempDirs = [];

function makeTempDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-agent-deploy-test-"));
  tempDirs.push(dir);
  return dir;
}

/**
 * A checkPath stub that allows anything under `allowedRoot` (segment-aware,
 * like the real policy engine) and rejects everything else.
 */
function makeCheckPath(allowedRoot) {
  const normalizedRoot = path.normalize(path.resolve(allowedRoot));
  return (candidate) => {
    const normalized = path.normalize(path.resolve(candidate));
    const relative = path.relative(normalizedRoot, normalized);
    const contained =
      normalized === normalizedRoot ||
      (relative !== "" &&
        !relative.startsWith("..") &&
        !path.isAbsolute(relative));
    if (!contained) {
      return {
        allowed: false,
        rejectionReason: "path_not_allowlisted",
        detail: `test: "${candidate}" outside "${allowedRoot}"`,
      };
    }
    return { allowed: true };
  };
}

function makeTarget(dir, overrides = {}) {
  return {
    type: "endpoint",
    reference: "test-endpoint",
    certPath: path.join(dir, "server.crt"),
    ...overrides,
  };
}

// Symlink creation on win32 requires elevation or Developer Mode; probe
// once and skip symlink tests when unavailable (same approach as the
// discovery tests take for openssl availability).
function canCreateSymlinks() {
  const dir = makeTempDir();
  const targetFile = path.join(dir, "probe-target");
  const linkPath = path.join(dir, "probe-link");
  fs.writeFileSync(targetFile, "probe", "utf8");
  try {
    fs.symlinkSync(targetFile, linkPath);
    return true;
  } catch (_err) {
    return false;
  }
}

const SYMLINKS_AVAILABLE = canCreateSymlinks();
const SYMLINK_SKIP = SYMLINKS_AVAILABLE
  ? false
  : "symlink creation is not permitted on this machine (win32 without privilege)";

beforeEach(() => {
  resetDeployMetrics();
});

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (_err) {
      // best-effort cleanup
    }
  }
});

describe("validateTargetConfig", () => {
  it("accepts a well-formed target with existing parent dir and allowed path", () => {
    const dir = makeTempDir();
    const result = validateTargetConfig(makeTarget(dir), {
      checkPath: makeCheckPath(dir),
    });
    assert.deepEqual(result, { valid: true });
  });

  it("rejects a non-object target", () => {
    const dir = makeTempDir();
    const result = validateTargetConfig(null, { checkPath: makeCheckPath(dir) });
    assert.equal(result.valid, false);
    assert.match(result.detail, /must be an object/);
  });

  it("rejects an unknown target.type", () => {
    const dir = makeTempDir();
    const result = validateTargetConfig(
      makeTarget(dir, { type: "mainframe" }),
      { checkPath: makeCheckPath(dir) },
    );
    assert.equal(result.valid, false);
    assert.match(result.detail, /target\.type/);
  });

  it("rejects a relative certPath", () => {
    const dir = makeTempDir();
    const result = validateTargetConfig(
      makeTarget(dir, { certPath: "relative/server.crt" }),
      { checkPath: makeCheckPath(dir) },
    );
    assert.equal(result.valid, false);
    assert.match(result.detail, /absolute path/);
  });

  it("rejects a certPath whose parent directory does not exist", () => {
    const dir = makeTempDir();
    const result = validateTargetConfig(
      makeTarget(dir, { certPath: path.join(dir, "missing-subdir", "server.crt") }),
      { checkPath: makeCheckPath(dir) },
    );
    assert.equal(result.valid, false);
    assert.match(result.detail, /parent directory does not exist/);
  });

  it("rejects a certPath the checkPath callback disallows", () => {
    const dir = makeTempDir();
    const otherDir = makeTempDir();
    const result = validateTargetConfig(makeTarget(otherDir), {
      checkPath: makeCheckPath(dir),
    });
    assert.equal(result.valid, false);
    assert.match(result.detail, /rejected by policy/);
    assert.match(result.detail, /path_not_allowlisted/);
  });

  it("validates optional backupDir as an existing, policy-allowed directory", () => {
    const dir = makeTempDir();
    const result = validateTargetConfig(
      makeTarget(dir, { backupDir: path.join(dir, "does-not-exist") }),
      { checkPath: makeCheckPath(dir) },
    );
    assert.equal(result.valid, false);
    assert.match(result.detail, /backupDir/);
  });

  it("throws (programmer error) when no checkPath callback is provided", () => {
    const dir = makeTempDir();
    assert.throws(
      () => validateTargetConfig(makeTarget(dir), {}),
      /checkPath callback is required/,
    );
  });
});

describe("deployCertificate", () => {
  it("happy path: writes content atomically with a restrictive mode", async () => {
    const dir = makeTempDir();
    const target = makeTarget(dir);

    const result = await deployCertificate({
      target,
      certificatePem: CERT_PEM,
      checkPath: makeCheckPath(dir),
    });

    assert.equal(result.deployed, true);
    assert.equal(result.skipped, false);
    assert.equal(result.backupPath, null);
    assert.equal(fs.readFileSync(target.certPath, "utf8"), CERT_PEM);

    if (process.platform !== "win32") {
      const mode = fs.statSync(target.certPath).mode & 0o777;
      assert.equal(mode, 0o600);
    }

    // No temp files may be left behind.
    const leftovers = fs.readdirSync(dir).filter((name) => name.endsWith(".tmp"));
    assert.deepEqual(leftovers, []);
  });

  it("records an idempotent skip when the destination already has identical bytes", async () => {
    const dir = makeTempDir();
    const target = makeTarget(dir);
    const checkPath = makeCheckPath(dir);

    const first = await deployCertificate({ target, certificatePem: CERT_PEM, checkPath });
    assert.equal(first.deployed, true);
    const mtimeAfterFirst = fs.statSync(target.certPath).mtimeMs;

    const second = await deployCertificate({ target, certificatePem: CERT_PEM, checkPath });

    assert.equal(second.deployed, false);
    assert.equal(second.skipped, true);
    assert.equal(second.reason, "idempotent");
    // The file must not have been touched at all.
    assert.equal(fs.statSync(target.certPath).mtimeMs, mtimeAfterFirst);
    // And no backup may have been created for a skip.
    const backups = fs.readdirSync(dir).filter((name) => name.endsWith(".bak"));
    assert.deepEqual(backups, []);
  });

  it("creates a timestamped backup when overwriting different content", async () => {
    const dir = makeTempDir();
    const target = makeTarget(dir);
    const checkPath = makeCheckPath(dir);
    const fixedNow = new Date("2026-07-22T05:00:00.000Z");

    await deployCertificate({ target, certificatePem: CERT_PEM, checkPath });
    const result = await deployCertificate({
      target,
      certificatePem: OTHER_CERT_PEM,
      checkPath,
      now: () => fixedNow,
    });

    assert.equal(result.deployed, true);
    assert.ok(result.backupPath, "expected a backupPath in the result");
    assert.equal(
      path.basename(result.backupPath),
      "server.crt.2026-07-22T05-00-00.000Z.bak",
    );
    assert.equal(fs.readFileSync(result.backupPath, "utf8"), CERT_PEM);
    assert.equal(fs.readFileSync(target.certPath, "utf8"), OTHER_CERT_PEM);
  });

  it("honors target.backupDir for the backup location", async () => {
    const dir = makeTempDir();
    const backupDir = path.join(dir, "backups");
    fs.mkdirSync(backupDir);
    const target = makeTarget(dir, { backupDir });
    const checkPath = makeCheckPath(dir);

    await deployCertificate({ target, certificatePem: CERT_PEM, checkPath });
    const result = await deployCertificate({
      target,
      certificatePem: OTHER_CERT_PEM,
      checkPath,
    });

    assert.equal(result.deployed, true);
    assert.equal(path.dirname(result.backupPath), backupDir);
  });

  it("prunes old backups down to target.backupRetentionCount after a successful deploy", async () => {
    const dir = makeTempDir();
    const backupDir = path.join(dir, "backups");
    fs.mkdirSync(backupDir);
    const target = makeTarget(dir, { backupDir, backupRetentionCount: 2 });
    const checkPath = makeCheckPath(dir);

    // Four successive deploys with alternating content create three
    // timestamped backups (the first deploy has nothing to back up);
    // retention of 2 must prune down to the 2 most recent after the last.
    await deployCertificate({ target, certificatePem: CERT_PEM, checkPath });
    await new Promise((resolve) => setTimeout(resolve, 5));
    await deployCertificate({ target, certificatePem: OTHER_CERT_PEM, checkPath });
    await new Promise((resolve) => setTimeout(resolve, 5));
    await deployCertificate({ target, certificatePem: CERT_PEM, checkPath });
    await new Promise((resolve) => setTimeout(resolve, 5));
    const fourth = await deployCertificate({ target, certificatePem: OTHER_CERT_PEM, checkPath });

    assert.equal(fourth.deployed, true);
    const backupFiles = fs
      .readdirSync(backupDir)
      .filter((name) => name.startsWith("server.crt.") && name.endsWith(".bak"));
    assert.equal(backupFiles.length, 2, "must retain only the 2 most recent backups");
    // The most recent backup (from the fourth deploy) survives.
    assert.equal(fs.existsSync(fourth.backupPath), true);
  });

  it("does not prune backups when target.backupRetentionCount is absent (unbounded, pre-existing default)", async () => {
    const dir = makeTempDir();
    const backupDir = path.join(dir, "backups");
    fs.mkdirSync(backupDir);
    const target = makeTarget(dir, { backupDir });
    const checkPath = makeCheckPath(dir);

    await deployCertificate({ target, certificatePem: CERT_PEM, checkPath });
    await new Promise((resolve) => setTimeout(resolve, 5));
    await deployCertificate({ target, certificatePem: OTHER_CERT_PEM, checkPath });
    await new Promise((resolve) => setTimeout(resolve, 5));
    await deployCertificate({ target, certificatePem: CERT_PEM, checkPath });
    await new Promise((resolve) => setTimeout(resolve, 5));
    await deployCertificate({ target, certificatePem: OTHER_CERT_PEM, checkPath });

    const backupFiles = fs
      .readdirSync(backupDir)
      .filter((name) => name.startsWith("server.crt.") && name.endsWith(".bak"));
    assert.equal(backupFiles.length, 3, "no retentionCount configured: all backups kept");
  });

  it("rolls back from the backup when the atomic write fails", async () => {
    const dir = makeTempDir();
    const target = makeTarget(dir);
    const checkPath = makeCheckPath(dir);

    await deployCertificate({ target, certificatePem: CERT_PEM, checkPath });

    const result = await deployCertificate({
      target,
      certificatePem: OTHER_CERT_PEM,
      checkPath,
      // TEST-ONLY fs override: force the final rename to fail after the
      // backup has been taken, exercising the rollback path.
      _fsOverrides: {
        rename: () => Promise.reject(new Error("injected rename failure")),
      },
    });

    assert.equal(result.deployed, false);
    assert.equal(result.rolledBack, true);
    assert.equal(result.stage, "write");
    assert.match(result.error, /injected rename failure/);
    // Original content restored.
    assert.equal(fs.readFileSync(target.certPath, "utf8"), CERT_PEM);
  });

  it("refuses (throws) a payload containing a private-key PEM marker", async () => {
    const dir = makeTempDir();
    const target = makeTarget(dir);

    await assert.rejects(
      deployCertificate({
        target,
        certificatePem: CERT_PEM + PRIVATE_KEY_PEM,
        checkPath: makeCheckPath(dir),
      }),
      /private-key PEM marker/,
    );
    // Nothing may have been written.
    assert.equal(fs.existsSync(target.certPath), false);
  });

  it("returns a validate-stage failure (not a throw) for a policy-rejected target", async () => {
    const dir = makeTempDir();
    const otherDir = makeTempDir();
    const target = makeTarget(otherDir);

    const result = await deployCertificate({
      target,
      certificatePem: CERT_PEM,
      checkPath: makeCheckPath(dir),
    });

    assert.equal(result.deployed, false);
    assert.equal(result.stage, "validate");
    assert.match(result.error, /rejected by policy/);
  });

  it(
    "rejects a symlinked destination escaping the allowed root (realpath re-check)",
    { skip: SYMLINK_SKIP },
    async () => {
      const allowedRoot = makeTempDir();
      const outsideDir = makeTempDir();
      const outsideFile = path.join(outsideDir, "victim.crt");
      fs.writeFileSync(outsideFile, "outside content\n", "utf8");

      // Lexically inside allowedRoot, but actually a symlink escaping it.
      const linkPath = path.join(allowedRoot, "server.crt");
      fs.symlinkSync(outsideFile, linkPath);

      const result = await deployCertificate({
        target: makeTarget(allowedRoot),
        certificatePem: CERT_PEM,
        checkPath: makeCheckPath(allowedRoot),
      });

      assert.equal(result.deployed, false);
      assert.equal(result.stage, "realpath-policy");
      assert.match(result.error, /escapes the allowlisted roots/);
      // The outside file must be untouched.
      assert.equal(fs.readFileSync(outsideFile, "utf8"), "outside content\n");
    },
  );

  it(
    "rejects a symlinked parent directory escaping the allowed root",
    { skip: SYMLINK_SKIP },
    async () => {
      const allowedRoot = makeTempDir();
      const outsideDir = makeTempDir();

      const linkedSubdir = path.join(allowedRoot, "tls");
      fs.symlinkSync(outsideDir, linkedSubdir, "dir");

      const result = await deployCertificate({
        target: makeTarget(allowedRoot, {
          certPath: path.join(linkedSubdir, "server.crt"),
        }),
        certificatePem: CERT_PEM,
        checkPath: makeCheckPath(allowedRoot),
      });

      assert.equal(result.deployed, false);
      assert.equal(result.stage, "realpath-policy");
      assert.deepEqual(fs.readdirSync(outsideDir), []);
    },
  );
});

describe("deployCertificate per-destination mutex", () => {
  it("serializes two concurrent deploys to the same destination in call order", async () => {
    const dir = makeTempDir();
    const target = makeTarget(dir);
    const checkPath = makeCheckPath(dir);
    const events = [];

    // Slow down the first deploy's realpath so, without a mutex, the second
    // deploy would interleave with (and finish before) the first.
    const realFsp = require("node:fs/promises");
    let firstCall = true;
    const slowRealpath = async (p) => {
      const isFirst = firstCall;
      firstCall = false;
      if (isFirst) {
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      return realFsp.realpath(p);
    };

    const first = deployCertificate({
      target,
      certificatePem: CERT_PEM,
      checkPath,
      _fsOverrides: { realpath: slowRealpath },
    }).then((result) => {
      events.push("first-done");
      return result;
    });
    const second = deployCertificate({
      target,
      certificatePem: OTHER_CERT_PEM,
      checkPath,
      _fsOverrides: { realpath: slowRealpath },
    }).then((result) => {
      events.push("second-done");
      return result;
    });

    const [firstResult, secondResult] = await Promise.all([first, second]);

    assert.deepEqual(events, ["first-done", "second-done"]);
    assert.equal(firstResult.deployed, true);
    assert.equal(secondResult.deployed, true);
    // The second deploy ran after the first completed, so it saw the first
    // deploy's content on disk and backed it up before overwriting.
    assert.ok(secondResult.backupPath);
    assert.equal(fs.readFileSync(secondResult.backupPath, "utf8"), CERT_PEM);
    assert.equal(fs.readFileSync(target.certPath, "utf8"), OTHER_CERT_PEM);
  });

  it("lets deploys to different destinations proceed independently", async () => {
    const dirA = makeTempDir();
    const dirB = makeTempDir();

    const [resultA, resultB] = await Promise.all([
      deployCertificate({
        target: makeTarget(dirA),
        certificatePem: CERT_PEM,
        checkPath: makeCheckPath(dirA),
      }),
      deployCertificate({
        target: makeTarget(dirB),
        certificatePem: OTHER_CERT_PEM,
        checkPath: makeCheckPath(dirB),
      }),
    ]);

    assert.equal(resultA.deployed, true);
    assert.equal(resultB.deployed, true);
  });
});

describe("deploy metrics", () => {
  it("increments per-target-type counters across outcomes", async () => {
    const dir = makeTempDir();
    const checkPath = makeCheckPath(dir);
    const endpointTarget = makeTarget(dir);
    const applianceTarget = makeTarget(dir, {
      type: "appliance",
      certPath: path.join(dir, "appliance.crt"),
    });

    // endpoint: success, then idempotent skip, then a rollback failure.
    await deployCertificate({ target: endpointTarget, certificatePem: CERT_PEM, checkPath });
    await deployCertificate({ target: endpointTarget, certificatePem: CERT_PEM, checkPath });
    await deployCertificate({
      target: endpointTarget,
      certificatePem: OTHER_CERT_PEM,
      checkPath,
      _fsOverrides: {
        rename: () => Promise.reject(new Error("injected rename failure")),
      },
    });
    // appliance: one success.
    await deployCertificate({ target: applianceTarget, certificatePem: CERT_PEM, checkPath });

    const metrics = getDeployMetrics();

    assert.deepEqual(metrics.endpoint, {
      attempts: 3,
      succeeded: 1,
      idempotentSkips: 1,
      rollbacks: 1,
      failures: 1,
    });
    assert.deepEqual(metrics.appliance, {
      attempts: 1,
      succeeded: 1,
      idempotentSkips: 0,
      rollbacks: 0,
      failures: 0,
    });
  });

  it("resetDeployMetrics clears all counters", async () => {
    const dir = makeTempDir();
    await deployCertificate({
      target: makeTarget(dir),
      certificatePem: CERT_PEM,
      checkPath: makeCheckPath(dir),
    });
    assert.ok(getDeployMetrics().endpoint);

    resetDeployMetrics();

    assert.deepEqual(getDeployMetrics(), {});
  });

  it("returns snapshots that do not leak internal state (mutation-safe)", async () => {
    const dir = makeTempDir();
    await deployCertificate({
      target: makeTarget(dir),
      certificatePem: CERT_PEM,
      checkPath: makeCheckPath(dir),
    });

    const snapshot = getDeployMetrics();
    snapshot.endpoint.attempts = 999;

    assert.equal(getDeployMetrics().endpoint.attempts, 1);
  });
});

describe("deployCertificateAndKey", () => {
  it("atomically installs a matched key+certificate pair and retains backups until discarded", async () => {
    const dir = makeTempDir();
    const certPath = path.join(dir, "server.crt");
    const keyPath = path.join(dir, "server.key");
    const stagedKeyPath = path.join(dir, ".server.key.staging-test");
    fs.writeFileSync(certPath, OTHER_CERT_PEM, { mode: 0o600 });
    fs.writeFileSync(keyPath, OTHER_KEY_PEM, { mode: 0o600 });
    fs.writeFileSync(stagedKeyPath, MATCHING_KEY_PEM, { mode: 0o600 });

    const result = await deployCertificateAndKey({
      target: {
        type: "endpoint",
        reference: "pair",
        certPath,
        keyPath,
      },
      certificatePem: CERT_PEM,
      privateKeyPath: stagedKeyPath,
      checkPath: makeCheckPath(dir),
    });

    assert.equal(result.deployed, true);
    assert.equal(fs.readFileSync(certPath, "utf8"), CERT_PEM);
    assert.equal(fs.readFileSync(keyPath, "utf8"), MATCHING_KEY_PEM);
    assert.ok(result.backupPaths.cert);
    assert.ok(result.backupPaths.key);
    assert.equal(fs.readFileSync(result.backupPaths.cert, "utf8"), OTHER_CERT_PEM);
    assert.equal(fs.readFileSync(result.backupPaths.key, "utf8"), OTHER_KEY_PEM);
    // Staging key consumed after successful promote.
    assert.equal(fs.existsSync(stagedKeyPath), false);

    // Backups survive until explicit discard (post-verify).
    const discarded = await discardDeployBackups({ backupPaths: result.backupPaths });
    assert.equal(discarded.discarded.length, 2);
    assert.equal(fs.existsSync(result.backupPaths.cert), false);
    assert.equal(fs.existsSync(result.backupPaths.key), false);
    // Live pair untouched.
    assert.equal(fs.readFileSync(certPath, "utf8"), CERT_PEM);
    assert.equal(fs.readFileSync(keyPath, "utf8"), MATCHING_KEY_PEM);
  });

  it("rolls back BOTH key and cert when the key write fails after cert write", async () => {
    const dir = makeTempDir();
    const certPath = path.join(dir, "server.crt");
    const keyPath = path.join(dir, "server.key");
    const stagedKeyPath = path.join(dir, "staged.key");
    fs.writeFileSync(certPath, OTHER_CERT_PEM, { mode: 0o600 });
    fs.writeFileSync(keyPath, OTHER_KEY_PEM, { mode: 0o600 });
    fs.writeFileSync(stagedKeyPath, MATCHING_KEY_PEM, { mode: 0o600 });

    let renameCount = 0;
    const realRename = require("node:fs/promises").rename;
    const result = await deployCertificateAndKey({
      target: {
        type: "endpoint",
        reference: "pair",
        certPath,
        keyPath,
      },
      certificatePem: CERT_PEM,
      privateKeyPath: stagedKeyPath,
      checkPath: makeCheckPath(dir),
      _fsOverrides: {
        rename: (from, to) => {
          renameCount += 1;
          // First rename is the cert temp→live; second is the key. Fail the key.
          if (renameCount >= 2) {
            return Promise.reject(new Error("injected key rename failure"));
          }
          return realRename(from, to);
        },
      },
    });

    assert.equal(result.deployed, false);
    assert.equal(result.rolledBack, true);
    assert.equal(result.stage, "write");
    assert.equal(fs.readFileSync(certPath, "utf8"), OTHER_CERT_PEM);
    assert.equal(fs.readFileSync(keyPath, "utf8"), OTHER_KEY_PEM);
  });

  it("leaves the live key untouched when only a staged key exists and write fails before swap", async () => {
    const dir = makeTempDir();
    const certPath = path.join(dir, "server.crt");
    const keyPath = path.join(dir, "server.key");
    const stagedKeyPath = path.join(dir, "staged.key");
    fs.writeFileSync(keyPath, OTHER_KEY_PEM, { mode: 0o600 });
    fs.writeFileSync(stagedKeyPath, MATCHING_KEY_PEM, { mode: 0o600 });

    const result = await deployCertificateAndKey({
      target: {
        type: "endpoint",
        reference: "pair",
        certPath,
        keyPath,
      },
      certificatePem: CERT_PEM,
      privateKeyPath: stagedKeyPath,
      checkPath: makeCheckPath(dir),
      _fsOverrides: {
        rename: () => Promise.reject(new Error("injected rename failure")),
      },
    });

    assert.equal(result.deployed, false);
    assert.equal(fs.readFileSync(keyPath, "utf8"), OTHER_KEY_PEM);
    assert.equal(fs.existsSync(certPath), false);
  });
});

describe("deployCertificate chainPath", () => {
  const FULLCHAIN_PEM = fs.readFileSync(
    path.join(FIXTURES_DIR, "leaf-fullchain.crt.pem"),
    "utf8",
  );
  const LEAF_PEM = fs.readFileSync(path.join(FIXTURES_DIR, "leaf.crt.pem"), "utf8");
  const INTERMEDIATE_PEM = fs.readFileSync(
    path.join(FIXTURES_DIR, "intermediate.crt.pem"),
    "utf8",
  );

  it("writes leaf and chain atomically when chainPath is configured", async () => {
    const dir = makeTempDir();
    const certPath = path.join(dir, "cert.pem");
    const chainPath = path.join(dir, "chain.pem");
    const result = await deployCertificate({
      target: {
        type: "endpoint",
        reference: "chain-test",
        certPath,
        chainPath,
      },
      certificatePem: LEAF_PEM,
      chainPem: INTERMEDIATE_PEM,
      checkPath: makeCheckPath(dir),
    });
    assert.equal(result.deployed, true);
    assert.equal(fs.readFileSync(certPath, "utf8"), LEAF_PEM);
    assert.equal(fs.readFileSync(chainPath, "utf8"), INTERMEDIATE_PEM);
    assert.equal(result.chainDestination, path.resolve(chainPath));
  });

  it("fails when chainPath is configured but chainPem is missing", async () => {
    const dir = makeTempDir();
    const result = await deployCertificate({
      target: {
        type: "endpoint",
        reference: "chain-missing",
        certPath: path.join(dir, "cert.pem"),
        chainPath: path.join(dir, "chain.pem"),
      },
      certificatePem: FULLCHAIN_PEM,
      checkPath: makeCheckPath(dir),
    });
    assert.equal(result.deployed, false);
    assert.equal(result.stage, "validate");
    assert.match(result.error, /no chain PEM content/);
  });

  it("rolls back cert and chain together on write failure", async () => {
    const dir = makeTempDir();
    const certPath = path.join(dir, "cert.pem");
    const chainPath = path.join(dir, "chain.pem");
    fs.writeFileSync(certPath, OTHER_CERT_PEM, { mode: 0o600 });
    fs.writeFileSync(chainPath, INTERMEDIATE_PEM, { mode: 0o600 });

    let renameCount = 0;
    const result = await deployCertificate({
      target: {
        type: "endpoint",
        reference: "chain-rollback",
        certPath,
        chainPath,
      },
      certificatePem: LEAF_PEM,
      chainPem: `${INTERMEDIATE_PEM}\n`,
      checkPath: makeCheckPath(dir),
      _fsOverrides: {
        rename: async (...args) => {
          renameCount += 1;
          if (renameCount >= 2) {
            throw new Error("injected chain rename failure");
          }
          return fs.promises.rename(...args);
        },
      },
    });

    assert.equal(result.deployed, false);
    assert.equal(result.rolledBack, true);
    assert.equal(fs.readFileSync(certPath, "utf8"), OTHER_CERT_PEM);
    assert.equal(fs.readFileSync(chainPath, "utf8"), INTERMEDIATE_PEM);
  });
});

describe("deploy modes, ownership metadata, and first-deploy removal", () => {
  it("rejects world-writable certMode", () => {
    const parsed = parseDeployFileMode("0666", "certMode");
    assert.equal(parsed.ok, false);
    assert.match(parsed.detail, /world-writable/);
  });

  it("rejects unsafe owner names", () => {
    const dir = makeTempDir();
    const result = validateTargetConfig(
      makeTarget(dir, { owner: "root;rm -rf /" }),
      { checkPath: makeCheckPath(dir) },
    );
    assert.equal(result.valid, false);
    assert.match(result.detail, /owner/);
  });

  it("applies an explicit certMode on atomic write", async () => {
    const dir = makeTempDir();
    const certPath = path.join(dir, "mode.pem");
    const result = await deployCertificate({
      target: makeTarget(dir, { certPath, certMode: "0644" }),
      certificatePem: CERT_PEM,
      checkPath: makeCheckPath(dir),
    });
    assert.equal(result.deployed, true);
    if (process.platform !== "win32") {
      const mode = fs.statSync(certPath).mode & 0o777;
      assert.equal(mode, 0o644);
    }
  });

  it("removeDeployedArtifacts unlinks first-deploy destinations", async () => {
    const dir = makeTempDir();
    const certPath = path.join(dir, "new.pem");
    const keyPath = path.join(dir, "new.key");
    fs.writeFileSync(certPath, CERT_PEM, { mode: 0o600 });
    fs.writeFileSync(keyPath, MATCHING_KEY_PEM, { mode: 0o600 });
    const removal = await removeDeployedArtifacts({
      destinations: [certPath, keyPath],
      checkPath: makeCheckPath(dir),
    });
    assert.deepEqual(removal.failed, []);
    assert.equal(fs.existsSync(certPath), false);
    assert.equal(fs.existsSync(keyPath), false);
  });

  it("never returns private key bytes from deployCertificateAndKey", async () => {
    const dir = makeTempDir();
    const certPath = path.join(dir, "pair.crt");
    const keyPath = path.join(dir, "pair.key");
    const staged = path.join(dir, "staged.key");
    fs.writeFileSync(staged, MATCHING_KEY_PEM, { mode: 0o600 });
    const result = await deployCertificateAndKey({
      target: makeTarget(dir, { certPath, keyPath }),
      certificatePem: CERT_PEM,
      privateKeyPath: staged,
      checkPath: makeCheckPath(dir),
    });
    assert.equal(result.deployed, true);
    assert.doesNotMatch(JSON.stringify(result), /BEGIN [A-Z0-9 ]*PRIVATE KEY/);
  });
});
