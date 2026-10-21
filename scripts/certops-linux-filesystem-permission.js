/**
 * Qualification: native backup-directory DAC refusal
 *
 * The disposable GitHub-hosted Linux/root fixture resolves actual nobody UID/GID,
 * executes original production deployer under that identity and independently checks
 * zero effective capabilities. First deploy+rotate must match cert/key/DNS/chain, native
 * OpenSSL verification, owner/group/mode 0600. Set only owned backup directory to mode
 * 0500; independent exclusive write must return real EACCES and rotation refuse at
 * backup before live replacement. Preserve predecessor bytes/inodes/modes/owner, outside
 * sentinel and both staging keys. Restore exact directory identity/mode and require
 * genuine same-identity success. This is pre-mutation refusal, not rollback.
 * qualifyBackupDirectoryDac({first, second}) needs distinct genuine fixtures.
 * Standalone:
 * node scripts/certops-linux-filesystem-permission.js --report qualification-results/filesystem-linux-dac.json.
 * The filesystem workflow runs selected absolute Node 24 under sudo with only its four
 * declared nonsecret environment variables; verify/upload this separate report alongside
 * original filesystem JSON only. Ubuntu 22.04/24.04 require their own proofs. Child
 * input travels stdin; key files 0600. Raw errors/private bytes/local hashes are never
 * artifacts. Failed permission restoration preserves private root; pure checks do not
 * qualify signed API, installed service, daemon reload or serving cutover.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";
/** Direct production deployer qualification on a disposable root-owned Linux
 * host. Drops to an independently resolved nonroot account with no effective
 * capabilities; real DAC denial blocks backup BEFORE any target replacement.
 * Never run on a production host. Private fixture files and snapshots stay local. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { isDeepStrictEqual } = require("node:util");
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-linux-filesystem-permission.js",
  "scripts/certops-linux-filesystem-permission-child.js",
  "packages/agent/src/deploy/index.js",
  "packages/agent/src/platform/durability.js",
  "packages/agent/src/platform/index.js",
  "packages/agent/src/policy/index.js",
  "packages/agent/scripts/host-gate.js",
  ".github/workflows/certops-filesystem-qualification.yml",
]);
const FLAGS = Object.freeze([
  "nonrootWithoutCapabilities",
  "actualInitialDeployment",
  "actualRotationDeployment",
  "independentWriteEacces",
  "productionBackupRefused",
  "predecessorIdentityPreserved",
  "outsideSentinelPreserved",
  "backupDirectoryRestored",
  "actualRecoveryDeployment",
  "ownedCleanupCompleted",
]);
function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(
    Object.keys(value).sort(),
    ["schemaVersion", "scope", "uid", "gid", ...FLAGS].sort(),
  );
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.scope, "native-linux-nonroot-backup-dac-refusal");
  assert.ok(
    Number.isSafeInteger(value.uid) &&
      value.uid > 0 &&
      Number.isSafeInteger(value.gid) &&
      value.gid > 0,
  );
  for (const name of FLAGS)
    assert.equal(value[name], true, `Missing DAC proof: ${name}`);
  return true;
}
function snapshot(file) {
  const stat = fs.lstatSync(file, { bigint: true });
  assert.ok(stat.isFile() && !stat.isSymbolicLink() && stat.ino > 0n);
  return {
    identity: `${stat.dev}:${stat.ino}`,
    mode: Number(stat.mode & 0o777n),
    uid: Number(stat.uid),
    gid: Number(stat.gid),
    sha256: crypto
      .createHash("sha256")
      .update(fs.readFileSync(file))
      .digest("hex"),
  };
}
function assertUnchanged(files, before) {
  assert.ok(
    isDeepStrictEqual(files.map(snapshot), before),
    "Owned predecessor file identity changed; private details withheld",
  );
}
function qualifyBackupDirectoryDac({ first, second }) {
  assert.equal(process.platform, "linux");
  assert.equal(process.getuid(), 0);
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
  assert.equal(process.env.CERTOPS_FILESYSTEM_DISPOSABLE_HOST, "1");
  const account = spawnSync("getent", ["passwd", "nobody"], {
    encoding: "utf8",
    timeout: 10000,
    maxBuffer: 4096,
  });
  assert.equal(account.status, 0, "Native nonroot identity is required");
  const fields = account.stdout.trim().split(":");
  const uid = Number(fields[2]),
    gid = Number(fields[3]);
  assert.equal(fields[0], "nobody");
  assert.ok(
    Number.isSafeInteger(uid) &&
      uid > 0 &&
      Number.isSafeInteger(gid) &&
      gid > 0,
  );
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-dac-"));
  const rootStat = fs.lstatSync(root, { bigint: true });
  assert.ok(
    rootStat.isDirectory() && !rootStat.isSymbolicLink() && rootStat.ino > 0n,
  );
  const rootIdentity = `${rootStat.dev}:${rootStat.ino}`;
  const backup = path.join(root, "backups"),
    destination = path.join(root, "deployed"),
    staging = path.join(root, "staging"),
    sentinel = path.join(root, "outside-sentinel");
  let restored = true,
    complete = false;
  const proof = {
    schemaVersion: 1,
    scope: "native-linux-nonroot-backup-dac-refusal",
    uid,
    gid,
  };
  const rootOwned = () => {
    const stat = fs.lstatSync(root, { bigint: true });
    assert.ok(
      stat.isDirectory() &&
        !stat.isSymbolicLink() &&
        `${stat.dev}:${stat.ino}` === rootIdentity,
      "Owned DAC root changed; preserve state",
    );
  };
  function run(deployment, expectDenied = false) {
    const payload = {
      root,
      uid,
      gid,
      deployment,
      expectDenied,
      probe: path.join(backup, "must-not-be-created"),
    };
    const result = spawnSync(
      process.execPath,
      [path.join(__dirname, "certops-linux-filesystem-permission-child.js")],
      {
        uid,
        gid,
        env: { PATH: process.env.PATH, LANG: "C.UTF-8" },
        input: JSON.stringify(payload),
        encoding: "utf8",
        timeout: 60000,
        maxBuffer: 8192,
        windowsHide: true,
      },
    );
    assert.ifError(result.error);
    assert.equal(
      result.status,
      0,
      "Nonroot production deployment child failed; raw output withheld",
    );
    const observed = JSON.parse(result.stdout);
    assert.equal(observed.uid, uid);
    assert.equal(observed.gid, gid);
    assert.equal(observed.effectiveCapabilitiesZero, true);
    return observed;
  }
  try {
    fs.chmodSync(root, 0o700);
    fs.chownSync(root, uid, gid);
    for (const directory of [backup, destination, staging]) {
      fs.mkdirSync(directory, { mode: 0o700 });
      fs.chownSync(directory, uid, gid);
    }
    fs.writeFileSync(sentinel, crypto.randomBytes(64), {
      mode: 0o600,
      flag: "wx",
    });
    const sentinelBefore = snapshot(sentinel);
    const target = {
      type: "domain",
      reference: "filesystem.example.test",
      certPath: path.join(destination, "server.crt"),
      keyPath: path.join(destination, "server.key"),
      chainPath: path.join(destination, "chain.pem"),
      backupDir: backup,
    };
    function material(value, name) {
      assert.ok(
        value &&
          typeof value.certificatePem === "string" &&
          typeof value.chainPem === "string",
      );
      const key = path.join(staging, `${name}.key`);
      fs.copyFileSync(value.privateKeyPath, key, fs.constants.COPYFILE_EXCL);
      fs.chmodSync(key, 0o600);
      fs.chownSync(key, uid, gid);
      return {
        target,
        certificatePem: value.certificatePem,
        chainPem: value.chainPem,
        privateKeyPath: key,
      };
    }
    const a = material(first, "first"),
      b = material(second, "second");
    assert.notEqual(
      new crypto.X509Certificate(a.certificatePem).fingerprint256,
      new crypto.X509Certificate(b.certificatePem).fingerprint256,
    );
    function observeDeployment(deployment) {
      const certificate = new crypto.X509Certificate(
        fs.readFileSync(target.certPath),
      );
      assert.equal(
        certificate.fingerprint256,
        new crypto.X509Certificate(deployment.certificatePem).fingerprint256,
      );
      assert.equal(certificate.checkHost(target.reference), target.reference);
      assert.equal(
        certificate.verify(
          new crypto.X509Certificate(deployment.chainPem).publicKey,
        ),
        true,
        "Native leaf must be signed by the fixture CA",
      );
      assert.ok(
        certificate.checkPrivateKey(
          crypto.createPrivateKey(fs.readFileSync(target.keyPath)),
        ),
        "Native deployment certificate/key mismatch",
      );
      assert.equal(
        fs.readFileSync(target.chainPath, "utf8"),
        deployment.chainPem,
      );
      for (const file of [target.certPath, target.keyPath, target.chainPath]) {
        const observed = snapshot(file);
        assert.equal(observed.uid, uid);
        assert.equal(observed.gid, gid);
        assert.equal(observed.mode, 0o600);
      }
    }
    for (const deployment of [a, b]) {
      const observed = run(deployment);
      assert.equal(observed.deployed, true);
      assert.equal(observed.deployedChainVerified, true);
      assert.equal(observed.stage, null);
      observeDeployment(deployment);
    }
    proof.nonrootWithoutCapabilities = true;
    proof.actualInitialDeployment = true;
    proof.actualRotationDeployment = true;
    const files = [target.certPath, target.keyPath, target.chainPath];
    const before = files.map(snapshot);
    const backupStat = fs.lstatSync(backup, { bigint: true });
    const backupIdentity = `${backupStat.dev}:${backupStat.ino}`;
    const originalMode = Number(backupStat.mode & 0o777n);
    const backupNames = fs.readdirSync(backup).sort();
    const backupBefore = backupNames.map((name) =>
      snapshot(path.join(backup, name)),
    );
    fs.chmodSync(backup, 0o500);
    restored = false;
    try {
      const refused = run(a, true);
      assert.equal(refused.osDenied, true);
      assert.equal(refused.backupRefusal, true);
      assert.equal(refused.stage, "backup");
      assert.equal(refused.deployed, false);
      assertUnchanged(files, before);
      assertUnchanged([sentinel], [sentinelBefore]);
      assert.deepEqual(fs.readdirSync(backup).sort(), backupNames);
      assertUnchanged(
        backupNames.map((name) => path.join(backup, name)),
        backupBefore,
      );
      proof.independentWriteEacces = true;
      proof.productionBackupRefused = true;
      proof.predecessorIdentityPreserved = true;
      proof.outsideSentinelPreserved = true;
    } finally {
      rootOwned();
      const stat = fs.lstatSync(backup, { bigint: true });
      assert.ok(
        stat.isDirectory() &&
          !stat.isSymbolicLink() &&
          `${stat.dev}:${stat.ino}` === backupIdentity,
        "Backup directory changed; preserve state",
      );
      fs.chmodSync(backup, originalMode);
      const after = fs.lstatSync(backup, { bigint: true });
      assert.equal(Number(after.mode & 0o777n), originalMode);
      assert.equal(Number(after.uid), uid);
      assert.equal(Number(after.gid), gid);
      restored = true;
    }
    proof.backupDirectoryRestored = true;
    const recovered = run(a);
    assert.equal(recovered.deployed, true);
    assert.equal(recovered.deployedChainVerified, true);
    assert.equal(recovered.stage, null);
    observeDeployment(a);
    assert.ok(
      new crypto.X509Certificate(
        fs.readFileSync(target.certPath),
      ).checkPrivateKey(
        crypto.createPrivateKey(fs.readFileSync(target.keyPath)),
      ),
      "Recovered local key/certificate must match",
    );
    assert.equal(fs.readFileSync(target.chainPath, "utf8"), a.chainPem);
    assertUnchanged([sentinel], [sentinelBefore]);
    proof.actualRecoveryDeployment = true;
    complete = true;
  } finally {
    // A failed restoration keeps the exact owned root for independent recovery;
    // private fixture material must never be included in diagnostic artifacts.
    if (restored) {
      rootOwned();
      fs.rmSync(root, { recursive: true });
      assert.equal(fs.existsSync(root), false);
    }
  }
  assert.equal(complete, true);
  proof.ownedCleanupCompleted = true;
  verifyProof(proof);
  return proof;
}
async function main() {
  assert.equal(process.platform, "linux");
  assert.equal(process.getuid(), 0);
  assert.equal(process.versions.node.split(".")[0], "24");
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
  assert.equal(process.env.CERTOPS_FILESYSTEM_DISPOSABLE_HOST, "1");
  assert.equal(process.argv[2], "--report");
  const reportPath = path.resolve(process.argv[3] || "");
  assert.equal(
    reportPath,
    path.resolve("qualification-results/filesystem-linux-dac.json"),
  );
  const { createHostGate } = require("../packages/agent/scripts/host-gate");
  const native = (args) => {
    const result = spawnSync("openssl", args, {
      encoding: "utf8",
      timeout: 30000,
      maxBuffer: 8192,
    });
    assert.ifError(result.error);
    assert.equal(
      result.status,
      0,
      "Native fixture OpenSSL failed; raw output withheld",
    );
    return result;
  };
  const gate = createHostGate({
    suite: "filesystem-linux-backup-dac-host",
    strict: true,
    reportPath,
    requiredCapabilities: ["native-linux-nonroot-dac", "openssl-key-oracle"],
    fixtureSource: {
      file: "scripts/certops-linux-filesystem-permission.js",
      sha256: crypto
        .createHash("sha256")
        .update(fs.readFileSync(__filename))
        .digest("hex"),
    },
    probeCapabilities: () => ({
      "native-linux-nonroot-dac": {
        available:
          process.platform === "linux" &&
          process.getuid() === 0 &&
          fs.existsSync("/proc/self/status"),
      },
      "openssl-key-oracle": { available: native(["version"]).status === 0 },
    }),
  });
  gate.report.fixtureSources = REQUIRED_SOURCES.map((file) => ({
    file,
    sha256: crypto
      .createHash("sha256")
      .update(fs.readFileSync(path.resolve(__dirname, "..", file)))
      .digest("hex"),
  }));
  const release = fs.readFileSync("/etc/os-release", "utf8");
  const distribution = release.match(/^ID="?([^"\n]+)/m)?.[1],
    version = release.match(/^VERSION_ID="?([^"\n]+)/m)?.[1];
  assert.equal(
    fs.existsSync("/.dockerenv") || fs.existsSync("/run/.containerenv"),
    false,
    "A container cannot qualify the native Ubuntu host slot",
  );
  assert.equal(distribution, "ubuntu");
  assert.ok(["22.04", "24.04"].includes(version));
  gate.report.qualificationEnvironment = {
    ...gate.report.qualificationEnvironment,
    distributionVersion: version,
    distribution,
    measurement: "native",
    executionSurface: "disposable-vm",
  };
  let fixtureRoot,
    fixtureIdentity,
    failure,
    cleanup = "failed",
    ready = false;
  try {
    await gate.preflight();
    ready = true;
    fixtureRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), "certops-dac-material-"),
    );
    fs.chmodSync(fixtureRoot, 0o700);
    const stat = fs.lstatSync(fixtureRoot, { bigint: true });
    assert.ok(stat.ino > 0n && !stat.isSymbolicLink());
    fixtureIdentity = `${stat.dev}:${stat.ino}`;
    const ca = path.join(fixtureRoot, "ca.crt"),
      caKey = path.join(fixtureRoot, "ca.key");
    native([
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      caKey,
      "-out",
      ca,
      "-days",
      "2",
      "-subj",
      `/CN=CertOps-DAC-${crypto.randomUUID()}`,
      "-addext",
      "basicConstraints=critical,CA:TRUE",
      "-addext",
      "keyUsage=critical,keyCertSign,cRLSign",
    ]);
    fs.chmodSync(caKey, 0o600);
    function certificate(name) {
      const key = path.join(fixtureRoot, name + ".key"),
        csr = path.join(fixtureRoot, name + ".csr"),
        pem = path.join(fixtureRoot, name + ".crt"),
        ext = path.join(fixtureRoot, name + ".ext");
      native([
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        key,
        "-out",
        csr,
        "-subj",
        "/CN=filesystem.example.test",
      ]);
      fs.chmodSync(key, 0o600);
      fs.writeFileSync(
        ext,
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:filesystem.example.test\n",
        { flag: "wx", mode: 0o600 },
      );
      native([
        "x509",
        "-req",
        "-in",
        csr,
        "-CA",
        ca,
        "-CAkey",
        caKey,
        "-set_serial",
        "0x" + crypto.randomUUID().replaceAll("-", ""),
        "-days",
        "2",
        "-extfile",
        ext,
        "-out",
        pem,
      ]);
      native([
        "verify",
        "-CAfile",
        ca,
        "-verify_hostname",
        "filesystem.example.test",
        pem,
      ]);
      return {
        certificatePem: fs.readFileSync(pem, "utf8"),
        chainPem: fs.readFileSync(ca, "utf8"),
        privateKeyPath: key,
      };
    }
    const first = certificate("first"),
      second = certificate("second");
    await gate.scenario(
      "filesystem-linux-nonroot-backup-dac-refusal",
      async () => {
        gate.report.nativeLinuxBackupDac = await qualifyBackupDirectoryDac({
          first,
          second,
        });
      },
      {
        oracle:
          "Actual nonroot capability-free positive deployments, independent EACCES and production pre-mutation backup refusal, exact native predecessor preservation and restored-permission recovery",
      },
    );
  } catch (error) {
    failure = error;
  } finally {
    const clean = () => {
      if (fixtureRoot) {
        const stat = fs.lstatSync(fixtureRoot, { bigint: true });
        assert.ok(
          stat.isDirectory() &&
            !stat.isSymbolicLink() &&
            `${stat.dev}:${stat.ino}` === fixtureIdentity,
          "Owned DAC fixture root changed; preserve state",
        );
        fs.rmSync(fixtureRoot, { recursive: true });
        assert.equal(fs.existsSync(fixtureRoot), false);
      }
    };
    try {
      if (ready)
        await gate.scenario("filesystem-linux-backup-dac-cleanup", clean);
      else clean();
      cleanup = "passed";
    } catch (error) {
      failure ||= error;
    }
    try {
      await gate.finish({
        requiredScenarios: [
          "filesystem-linux-nonroot-backup-dac-refusal",
          "filesystem-linux-backup-dac-cleanup",
        ],
        cleanup: { status: cleanup },
      });
    } catch (error) {
      failure ||= error;
    }
  }
  if (failure) throw failure;
}
module.exports = {
  qualifyBackupDirectoryDac,
  verifyProof,
  snapshot,
  assertUnchanged,
  FLAGS,
  REQUIRED_SOURCES,
  main,
};
if (require.main === module)
  main().catch(() => {
    console.error(
      "Native Linux backup DAC qualification failed; inspect sanitized report",
    );
    process.exitCode = 1;
  });
