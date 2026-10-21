/**
 * Qualification: installed nonroot file discovery and restoration
 *
 * The Ubuntu 22.04/24.04 systemd and published-upgrade workflows require a separate
 * linux-installed-file-discovery report after installation, reapplication or upgrade,
 * using the original service and registration. All real, effective, saved and filesystem
 * UID/GID values must match the nonroot account, with zero effective capabilities and
 * the candidate discovery module. Create an owned public certificate and genuine
 * private-key decoys within the existing installer write path. Change only discovery
 * configuration. Retain the original mode-0600 configuration descriptor and bytes, plus
 * a root-owned local backup. Two distinct authenticated post-start scans and a complete
 * public inventory page must identify the exact public leaf, path, agent and host,
 * report adjacent-key presence and contain no private decoy material. To restore, stop
 * the exact unit and prove its cgroup empty and original process birth absent before
 * deleting unchanged inputs or restoring configuration. The restarted original
 * configuration must authenticate after an independent database cutoff with changed
 * heartbeat uptime; polling alone is insufficient. Credential and signing-pin bytes must
 * remain unchanged. The installation receipt binds mandatory discovery, a fresh nonce
 * and completion path. Cleanup requires the matching closed receipt, original
 * configuration identity and restored digest, proven process drainage and input absence.
 * A missing or deleted guard never grants cleanup. Unknown setup or restoration
 * preserves host and database ownership. Independent always-run host cleanup must
 * succeed, and the original receipt (including dangling links) must be absent before
 * volume destruction. Run only on disposable hosts. Published upgrade still requires its
 * authenticated predecessor and separate upgrade report. Supporting checks:
 * node --test scripts/certops-linux-installed-discovery.test.js scripts/certops-linux-installed-discovery-release.test.js
 * python scripts/certops-linux-installed-discovery-collector.test.py
 * Configuration, keys, backups, credentials and raw process output are not artifacts.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";
/** Installed-systemd discovery qualification. Private configuration stays on the
 * disposable VM. Retained descriptors refuse replacement instead of adopting a
 * byte-identical foreign config; callers must preserve the durable guard on any
 * unresolved restoration. Native orchestration is added with the parent hook. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const crypto = require("node:crypto");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const discovery = require("./certops-native-file-discovery");
const UNIT = "tokentimer-agent.service";
const STATE = "/opt/tokentimer-agent/state";
const COMPLETION_NAME = "certops-linux-systemd-discovery-completed.json";
const GUARD_NAME = "certops-linux-systemd-discovery-active.json";
const REQUIRED_SOURCES = Object.freeze([
  ...new Set([
    ...discovery.REQUIRED_SOURCES,
    "tests/e2e/helpers/certops-linux-installed-discovery.js",
    "tests/e2e/linux-systemd-real-journey.js",
    "tests/e2e/helpers/certops-api-fixture.js",
    "scripts/certops-linux-systemd.js",
    "scripts/certops-linux-systemd-cleanup.js",
    "scripts/certops-linux-systemd-ownership.js",
    "scripts/certops_linux_installed_discovery_proof.py",
    "packages/agent/scripts/install-agent.sh",
    "packages/agent/scripts/host-gate.js",
    "packages/agent/src/config/index.js",
    "packages/agent/src/evidence/index.js",
    "packages/agent/src/protocol/index.js",
    "packages/agent/vendor/log-scrub/secret-material.js",
    "apps/api/services/certops/agentRegistry.js",
    "apps/api/services/certops/agentDispatch.js",
    "apps/api/services/certops/csrWorkflow.js",
    "apps/api/services/certops/renewalProfile.js",
    "apps/api/services/certops/parser.js",
    "apps/api/services/certops/inventory.js",
    "apps/api/services/certops/evidence.js",
    "apps/api/utils/secretMaterial.js",
    ".github/workflows/certops-linux-systemd.yml",
    ".github/workflows/certops-linux-published-upgrade.yml",
  ]),
]);
const COMPLETION_FIELDS = [
  "schemaVersion",
  "nonce",
  "originalConfigSha256",
  "restoredConfigSha256",
  "configDev",
  "configIno",
  "originalDiscoveryProcessDrained",
  "ownedDiscoveryInputsRemoved",
  "credentialAndPinPreserved",
];
function hash(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}
function completionPath(runnerTemp) {
  return path.join(runnerTemp, COMPLETION_NAME);
}
function guardPath(runnerTemp) {
  return path.join(runnerTemp, GUARD_NAME);
}
function assertReceiptPlan(receipt, runnerTemp) {
  assert.equal(receipt.installedDiscoveryRequired, true);
  assert.match(receipt.installedDiscoveryNonce, /^[a-f0-9]{64}$/);
  assert.equal(
    receipt.installedDiscoveryCompletion,
    completionPath(runnerTemp),
  );
}
function assertCompletion(receipt, runnerTemp) {
  assertReceiptPlan(receipt, runnerTemp);
  assert.equal(
    fs.lstatSync(guardPath(runnerTemp), { throwIfNoEntry: false }),
    undefined,
    "Active discovery guard preserves installed state",
  );
  const file = completionPath(runnerTemp),
    stat = fs.lstatSync(file, { bigint: true });
  assert.ok(
    stat.isFile() &&
      !stat.isSymbolicLink() &&
      stat.uid === 0n &&
      (stat.mode & 0o777n) === 0o600n &&
      stat.nlink === 1n &&
      stat.size > 0n &&
      stat.size <= 4096n,
  );
  const held = retainOwnedFile(file, {
    uid: 0,
    gid: Number(stat.gid),
    mode: 0o600,
  });
  let value;
  try {
    value = JSON.parse(held.original.toString("utf8"));
    held.close();
  } catch (error) {
    held.disposeHandle();
    throw error;
  }
  assert.deepEqual(Object.keys(value).sort(), [...COMPLETION_FIELDS].sort());
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.nonce, receipt.installedDiscoveryNonce);
  for (const field of [
    "originalDiscoveryProcessDrained",
    "ownedDiscoveryInputsRemoved",
    "credentialAndPinPreserved",
  ])
    assert.equal(value[field], true);
  for (const field of ["originalConfigSha256", "restoredConfigSha256"])
    assert.match(value[field], /^[a-f0-9]{64}$/);
  assert.equal(value.originalConfigSha256, value.restoredConfigSha256);
  const config = fs.lstatSync(path.join(STATE, "config.json"), {
    bigint: true,
  });
  assert.ok(
    config.isFile() &&
      !config.isSymbolicLink() &&
      config.dev.toString() === value.configDev &&
      config.ino.toString() === value.configIno,
    "Restored installed config identity is mandatory for cleanup",
  );
  assert.ok(config.uid > 0n && config.gid > 0n);
  const configHeld = retainOwnedConfig(path.join(STATE, "config.json"), {
    uid: Number(config.uid),
    gid: Number(config.gid),
  });
  try {
    assert.equal(hash(configHeld.original), value.restoredConfigSha256);
    configHeld.close();
  } catch (error) {
    configHeld.disposeHandle();
    throw error;
  }
  return value;
}

function retainOwnedFile(file, { uid, gid, mode }) {
  assert.equal(
    fs.realpathSync.native(file),
    path.resolve(file),
    "Retained file ancestors must not be aliases",
  );
  const before = fs.lstatSync(file, { bigint: true });
  assert.ok(
    before.isFile() &&
      !before.isSymbolicLink() &&
      before.ino > 0n &&
      before.nlink === 1n,
  );
  assert.equal(before.uid, BigInt(uid));
  assert.equal(before.gid, BigInt(gid));
  assert.equal(before.mode & 0o777n, BigInt(mode));
  const fd = fs.openSync(
    file,
    fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW || 0),
  );
  let expected,
    closed = false;
  function read() {
    assert.equal(closed, false);
    assert.equal(
      fs.realpathSync.native(file),
      path.resolve(file),
      "Retained file ancestor changed",
    );
    const opened = fs.fstatSync(fd, { bigint: true }),
      current = fs.lstatSync(file, { bigint: true });
    for (const item of [opened, current]) {
      assert.ok(
        item.isFile() &&
          !item.isSymbolicLink() &&
          item.ino === before.ino &&
          item.dev === before.dev &&
          item.nlink === 1n,
        "Original installed config identity changed",
      );
      assert.ok(
        item.uid === before.uid &&
          item.gid === before.gid &&
          item.mode === before.mode,
        "Original installed config permissions changed",
      );
      assert.ok(
        item.size > 0n && item.size <= 262144n,
        "Installed config exceeds fixture read bound",
      );
    }
    const bytes = Buffer.alloc(Number(opened.size) + 1);
    const count = fs.readSync(fd, bytes, 0, bytes.length, 0);
    const after = fs.fstatSync(fd, { bigint: true });
    assert.ok(
      count === Number(opened.size) &&
        after.size === opened.size &&
        after.mtimeNs === opened.mtimeNs &&
        after.ctimeNs === opened.ctimeNs,
      "Installed config changed during bounded read",
    );
    const result = bytes.subarray(0, count);
    if (expected)
      assert.ok(
        result.equals(expected),
        "Unexpected installed config bytes; preserve ownership state",
      );
    return Buffer.from(result);
  }
  let original;
  try {
    original = read();
    expected = original;
  } catch (error) {
    fs.closeSync(fd);
    throw error;
  }
  function write(bytes) {
    assert.ok(
      Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 262144,
    );
    read();
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.writeSync(
        fd,
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
      assert.ok(count > 0, "Installed config write made no progress");
      offset += count;
    }
    fs.ftruncateSync(fd, bytes.length);
    fs.fsyncSync(fd);
    expected = Buffer.from(bytes);
    read();
  }
  return {
    original: Buffer.from(original),
    originalSha256: crypto.createHash("sha256").update(original).digest("hex"),
    assertUnchanged: read,
    write,
    restore() {
      write(original);
    },
    close() {
      if (!closed) {
        read();
        fs.closeSync(fd);
        closed = true;
      }
    },
    // Handle disposal alone never authorizes state cleanup or clears a guard.
    disposeHandle() {
      if (!closed) {
        fs.closeSync(fd);
        closed = true;
      }
    },
  };
}

function retainOwnedConfig(file, { uid, gid }) {
  return retainOwnedFile(file, { uid, gid, mode: 0o600 });
}
const SCOPE = "actual-installed-systemd-public-file-discovery";
const FLAGS = Object.freeze([
  "actualInstalledCandidate",
  "actualSystemdService",
  "actualUnprivilegedProcess",
  "twoGenuinePublicScans",
  "publicInventoryExactLocation",
  "privateDecoysNeverPersisted",
  "credentialAndPinPreserved",
  "originalConfigIdentityRestored",
  "discoveryProcessDrained",
  "restoredServiceAuthenticatedHeartbeat",
  "ownedInputsRemoved",
]);
function verifyProof(value) {
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "scope",
      "uid",
      "gid",
      "fingerprint",
      "positiveScanCount",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.scope, SCOPE);
  for (const flag of FLAGS) assert.equal(value[flag], true);
  for (const field of ["uid", "gid"])
    assert.ok(Number.isSafeInteger(value[field]) && value[field] > 0);
  assert.match(value.fingerprint, /^[a-f0-9]{64}$/);
  assert.ok(
    Number.isSafeInteger(value.positiveScanCount) &&
      value.positiveScanCount >= 2 &&
      value.positiveScanCount <= 10000,
  );
  return true;
}
function processBirth(pid) {
  const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
  const birth = stat.slice(stat.lastIndexOf(")") + 2).split(/\s+/)[19];
  assert.match(birth, /^[1-9][0-9]*$/);
  return birth;
}
function freshAuthenticatedHeartbeat(before, row) {
  return Boolean(
    before &&
    row &&
    before.uptime_seconds !== null &&
    row.uptime_seconds !== null &&
    Number.isFinite(Number(before.uptime_seconds)) &&
    Number.isFinite(Number(row.uptime_seconds)) &&
    Number(row.uptime_seconds) > 0 &&
    Date.parse(row.last_seen_at) > Date.parse(before.checked_at) &&
    Number(row.uptime_seconds) !== Number(before.uptime_seconds),
  );
}
async function qualifyInstalledDiscovery(context) {
  const {
    pool,
    workspaceId,
    agentId,
    baseUrl,
    repoRoot,
    writeFixture,
    uid,
    gid,
    command,
    waitFor,
    mainPid,
    identity,
    serviceProperty,
    registerResource,
  } = context;
  let complete = false;
  const resource = {
    hasOwnershipReceipt: () =>
      !complete || fs.existsSync(guardPath(process.env.RUNNER_TEMP)),
    assertCleanupSafe() {
      assert.equal(
        complete,
        true,
        "Installed discovery recovery remains unresolved",
      );
    },
  };
  registerResource(resource);
  assert.equal(process.platform, "linux");
  assert.equal(process.getuid(), 0);
  const runnerTemp = fs.realpathSync.native(process.env.RUNNER_TEMP);
  assert.equal(runnerTemp, path.resolve(process.env.RUNNER_TEMP));
  const ownershipFile = path.join(
    runnerTemp,
    "certops-linux-systemd-owned.json",
  );
  const receiptStat = fs.lstatSync(ownershipFile);
  const receiptHeld = retainOwnedFile(ownershipFile, {
    uid: 0,
    gid: receiptStat.gid,
    mode: 0o600,
  });
  let receipt;
  try {
    receipt = JSON.parse(receiptHeld.original);
    receiptHeld.close();
  } catch (error) {
    receiptHeld.disposeHandle();
    throw error;
  }
  assertReceiptPlan(receipt, runnerTemp);
  for (const file of [guardPath(runnerTemp), completionPath(runnerTemp)])
    assert.equal(
      fs.lstatSync(file, { throwIfNoEntry: false }),
      undefined,
      "Discovery receipt must not be adopted",
    );
  const guardBytes = Buffer.from(
    JSON.stringify({
      schemaVersion: 1,
      nonce: receipt.installedDiscoveryNonce,
      ownerPid: process.pid,
    }),
  );
  fs.writeFileSync(guardPath(runnerTemp), guardBytes, {
    flag: "wx",
    mode: 0o600,
  });
  const guardStat = fs.lstatSync(guardPath(runnerTemp), { bigint: true });
  const {
    createHostGate,
  } = require("../../../packages/agent/scripts/host-gate");
  const fingerprint = (file) => ({
    file,
    sha256: hash(fs.readFileSync(path.join(repoRoot, file))),
  });
  const gate = createHostGate({
    suite: "linux-installed-file-discovery",
    strict: true,
    evidenceLevel: "real-host",
    reportPath: path.join(
      repoRoot,
      "qualification-results/linux-installed-file-discovery.json",
    ),
    fixtureSource: fingerprint(
      "tests/e2e/helpers/certops-linux-installed-discovery.js",
    ),
    requiredCapabilities: ["linux", "systemd", "api", "openssl"],
    probeCapabilities: () => ({
      linux: { available: process.platform === "linux" },
      systemd: { available: serviceProperty("ActiveState") === "active" },
      api: { available: typeof pool.query === "function" },
      openssl: {
        available:
          spawnSync("openssl", ["version"], { stdio: "ignore", timeout: 10000 })
            .status === 0,
      },
    }),
  });
  let held,
    backup,
    fixtureDir,
    session,
    originalStat,
    fixtureStat,
    backupStat,
    proof,
    primary,
    scanCount = 0,
    leafFingerprint,
    drained = false,
    inputsRemoved = false,
    preserved = false;
  const files = [];
  const configFile = path.join(STATE, "config.json");
  const credential = path.join(STATE, "credential"),
    pin = path.join(STATE, "signing-key-pin.json");
  let originalCredential, originalPin;
  const readPrivateDigest = (file) => {
    const current = retainOwnedConfig(file, { uid, gid });
    try {
      const value = hash(current.original);
      current.close();
      return value;
    } catch (error) {
      current.disposeHandle();
      throw error;
    }
  };
  const checkProcess = () => {
    const pid = identity();
    discovery.parseUnprivilegedIdentity(
      fs.readFileSync(`/proc/${pid}/status`, "utf8"),
      uid,
      gid,
    );
    assert.equal(serviceProperty("User"), "tokentimer-agent");
    assert.equal(serviceProperty("KillMode"), "control-group");
    assert.equal(serviceProperty("ControlGroup"), `/system.slice/${UNIT}`);
    assert.equal(
      fs.realpathSync.native(
        path.join("/opt/tokentimer-agent/app/src/discovery/index.js"),
      ),
      "/opt/tokentimer-agent/app/src/discovery/index.js",
    );
    assert.equal(
      hash(fs.readFileSync("/opt/tokentimer-agent/app/src/discovery/index.js")),
      hash(
        fs.readFileSync(
          path.join(repoRoot, "packages/agent/src/discovery/index.js"),
        ),
      ),
    );
    return { pid, birth: processBirth(pid) };
  };
  const stopAndDrain = () => {
    let original = null;
    if (mainPid() > 0) original = checkProcess();
    command("systemctl", ["stop", UNIT]);
    assert.equal(mainPid(), 0);
    const members = path.join(
      "/sys/fs/cgroup/system.slice",
      UNIT,
      "cgroup.procs",
    );
    if (fs.existsSync(members))
      assert.equal(
        fs.readFileSync(members, "utf8").trim(),
        "",
        "Owned systemd cgroup must be empty before restoring config",
      );
    if (original && fs.existsSync(`/proc/${original.pid}/stat`))
      assert.notEqual(
        processBirth(original.pid),
        original.birth,
        "Original installed process remains alive",
      );
    drained = true;
  };
  const remember = (file) => {
    const stat = fs.lstatSync(file, { bigint: true });
    assert.ok(
      stat.isFile() &&
        !stat.isSymbolicLink() &&
        stat.ino > 0n &&
        stat.nlink === 1n,
    );
    files.push({
      file,
      dev: stat.dev,
      ino: stat.ino,
      sha256: readPrivateDigest(file),
    });
  };
  const assertFiles = () => {
    assert.ok(fixtureDir && fs.realpathSync.native(fixtureDir) === fixtureDir);
    const directory = fs.lstatSync(fixtureDir, { bigint: true });
    assert.ok(
      directory.isDirectory() &&
        !directory.isSymbolicLink() &&
        directory.dev === fixtureStat.dev &&
        directory.ino === fixtureStat.ino,
      "Original discovery directory identity changed",
    );
    assert.deepEqual(
      fs.readdirSync(fixtureDir).sort(),
      files.map((item) => path.basename(item.file)).sort(),
      "Unknown discovery-directory entries must be preserved",
    );
    for (const item of files) {
      const stat = fs.lstatSync(item.file, { bigint: true });
      assert.ok(
        stat.isFile() &&
          !stat.isSymbolicLink() &&
          stat.dev === item.dev &&
          stat.ino === item.ino &&
          stat.nlink === 1n,
        "Owned discovery fixture identity changed",
      );
      assert.equal(readPrivateDigest(item.file), item.sha256);
    }
  };
  try {
    await gate.preflight();
    checkProcess();
    originalStat = fs.lstatSync(configFile, { bigint: true });
    held = retainOwnedConfig(configFile, { uid, gid });
    originalCredential = readPrivateDigest(credential);
    originalPin = readPrivateDigest(pin);
    backup = path.join(
      STATE,
      `.qualification-discovery-${receipt.installedDiscoveryNonce}.original`,
    );
    fs.writeFileSync(backup, held.original, { flag: "wx", mode: 0o600 });
    backupStat = fs.lstatSync(backup, { bigint: true });
    const saved = retainOwnedFile(backup, {
      uid: 0,
      gid: fs.statSync(backup).gid,
      mode: 0o600,
    });
    try {
      assert.ok(saved.original.equals(held.original));
      saved.close();
    } catch (error) {
      saved.disposeHandle();
      throw error;
    }
    fixtureDir = fs.realpathSync.native(
      fs.mkdtempSync(path.join(writeFixture.allowed, "installed-discovery-")),
    );
    fixtureStat = fs.lstatSync(fixtureDir, { bigint: true });
    const cert = path.join(fixtureDir, "server.crt"),
      key = path.join(fixtureDir, "server.key");
    const generated = spawnSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "2",
        "-subj",
        "/CN=installed-discovery.example.test",
        "-addext",
        "subjectAltName=DNS:installed-discovery.example.test",
        "-keyout",
        key,
        "-out",
        cert,
      ],
      { stdio: "ignore", timeout: 20000 },
    );
    assert.equal(
      generated.status,
      0,
      "Owned installed-discovery fixture generation failed",
    );
    fs.chmodSync(key, 0o600);
    const privateBytes = fs.readFileSync(key),
      publicBytes = fs.readFileSync(cert);
    leafFingerprint = new crypto.X509Certificate(publicBytes).fingerprint256
      .replaceAll(":", "")
      .toLowerCase();
    fs.writeFileSync(path.join(fixtureDir, "disguised.crt"), privateBytes, {
      flag: "wx",
      mode: 0o600,
    });
    fs.writeFileSync(
      path.join(fixtureDir, "mixed.pem"),
      Buffer.concat([publicBytes, privateBytes]),
      { flag: "wx", mode: 0o600 },
    );
    fs.chownSync(fixtureDir, uid, gid);
    fs.chmodSync(fixtureDir, 0o700);
    for (const file of [
      cert,
      key,
      path.join(fixtureDir, "disguised.crt"),
      path.join(fixtureDir, "mixed.pem"),
    ]) {
      fs.chownSync(file, uid, gid);
      fs.chmodSync(file, 0o600);
      remember(file);
    }
    session = await require("./certops-api-fixture").createApiFixture(baseUrl);
    await pool.query(
      "INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'admin')",
      [workspaceId, session.userId],
    );
    await gate.scenario(
      "linux-installed-systemd-public-discovery",
      async () => {
        stopAndDrain();
        let changed;
        try {
          changed = JSON.parse(held.original);
        } catch {
          throw new Error(
            "Installed discovery requires valid owned configuration",
          );
        }
        changed.discovery = { directories: [fixtureDir], intervalMs: 1000 };
        held.write(Buffer.from(JSON.stringify(changed)));
        const cutoff = (await pool.query("SELECT clock_timestamp() AS now"))
          .rows[0].now;
        command("systemctl", ["start", UNIT]);
        await waitFor(
          () => mainPid() > 0,
          "installed discovery service starts",
        );
        checkProcess();
        await waitFor(
          async () => {
            checkProcess();
            assertFiles();
            const rows = (
              await pool.query(
                "SELECT metadata,observed_at,redacted_output FROM certificate_evidence WHERE workspace_id=$1 AND metadata->>'agentId'=$2 AND metadata->>'eventType'='certificate.observed' AND observed_at >= $3::timestamptz",
                [workspaceId, agentId, cutoff],
              )
            ).rows;
            if (
              new Set(
                rows.map((row) => new Date(row.observed_at).toISOString()),
              ).size < 2
            )
              return false;
            assert.ok(
              rows.every(
                (row) =>
                  row.metadata.filePath === cert &&
                  row.metadata.targetHost === require("node:os").hostname() &&
                  row.metadata.fingerprintSha256 === leafFingerprint,
              ),
              "Installed discovery must report only the real public certificate",
            );
            assert.ok(
              rows.some((row) => row.metadata.coLocatedKeyDetected === true),
            );
            const serialized = JSON.stringify(rows);
            assert.ok(
              !serialized.includes(privateBytes.toString()) &&
                !serialized.includes(privateBytes.toString("base64")) &&
                !serialized.includes("PRIVATE KEY-----"),
              "Private discovery input must not persist",
            );
            const inventory = await session.request(
              `/api/v1/workspaces/${workspaceId}/certops/certificate-identities?limit=100&offset=0`,
              "GET",
            );
            assert.equal(inventory.status, 200);
            assert.ok(
              inventory.body.pagination &&
                inventory.body.pagination.offset === 0 &&
                inventory.body.pagination.total === inventory.body.items.length,
              "Complete public inventory page is required for installed-discovery observation",
            );
            const expected = inventory.body.items.filter(
              (item) => item.fingerprintSha256 === leafFingerprint,
            );
            assert.equal(expected.length, 1);
            assert.ok(
              expected[0].locations.some(
                (location) =>
                  location.locationKind === "filesystem" &&
                  location.sourceRef ===
                    `${agentId}/${require("node:os").hostname()}/${cert}`,
              ),
            );
            scanCount = new Set(
              rows.map((row) => new Date(row.observed_at).toISOString()),
            ).size;
            return true;
          },
          "two actual installed-service observations and public inventory",
          40000,
        );
      },
    );
  } catch (error) {
    primary = error;
  } finally {
    try {
      if (held) {
        stopAndDrain();
        held.restore();
        assert.ok(held.assertUnchanged().equals(held.original));
        if (fixtureDir) {
          assertFiles();
          for (const item of files) fs.unlinkSync(item.file);
          fs.rmdirSync(fixtureDir);
          inputsRemoved = true;
        } else inputsRemoved = true;
        const before = (
          await pool.query(
            "SELECT last_seen_at,uptime_seconds,clock_timestamp() AS checked_at FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
            [workspaceId, agentId],
          )
        ).rows[0];
        assert.ok(before);
        command("systemctl", ["start", UNIT]);
        await waitFor(() => mainPid() > 0, "restored installed service starts");
        const restoredProcess = checkProcess();
        await waitFor(async () => {
          assert.equal(mainPid(), restoredProcess.pid);
          assert.equal(
            processBirth(restoredProcess.pid),
            restoredProcess.birth,
          );
          const row = (
            await pool.query(
              "SELECT last_seen_at,uptime_seconds FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
              [workspaceId, agentId],
            )
          ).rows[0];
          return freshAuthenticatedHeartbeat(before, row);
        }, "restored installed service authenticates genuine heartbeat");
        assert.equal(readPrivateDigest(credential), originalCredential);
        assert.equal(readPrivateDigest(pin), originalPin);
        preserved = true;
        const completion = {
          schemaVersion: 1,
          nonce: receipt.installedDiscoveryNonce,
          originalConfigSha256: held.originalSha256,
          restoredConfigSha256: hash(held.assertUnchanged()),
          configDev: originalStat.dev.toString(),
          configIno: originalStat.ino.toString(),
          originalDiscoveryProcessDrained: drained,
          ownedDiscoveryInputsRemoved: inputsRemoved,
          credentialAndPinPreserved: preserved,
        };
        held.close();
        held = null;
        if (backup) {
          const backupCurrent = fs.lstatSync(backup, { bigint: true });
          assert.ok(
            backupCurrent.ino === backupStat.ino &&
              backupCurrent.dev === backupStat.dev,
            "Private original-config backup must not be adopted after replacement",
          );
          const saved = retainOwnedFile(backup, {
            uid: 0,
            gid: fs.statSync(backup).gid,
            mode: 0o600,
          });
          try {
            assert.equal(hash(saved.original), completion.originalConfigSha256);
            saved.close();
          } catch (error) {
            saved.disposeHandle();
            throw error;
          }
          fs.unlinkSync(backup);
          backup = null;
        }
        const currentGuard = fs.lstatSync(guardPath(runnerTemp), {
          bigint: true,
        });
        assert.ok(
          currentGuard.ino === guardStat.ino &&
            currentGuard.dev === guardStat.dev &&
            fs.readFileSync(guardPath(runnerTemp)).equals(guardBytes),
        );
        fs.unlinkSync(guardPath(runnerTemp));
        fs.writeFileSync(
          completionPath(runnerTemp),
          JSON.stringify(completion),
          { flag: "wx", mode: 0o600 },
        );
        assertCompletion(receipt, runnerTemp);
        complete = true;
      }
    } catch {
      primary = new Error(
        "Installed discovery restoration unknown; preserve configuration, guard and owned inputs",
      );
    }
    if (held) held.disposeHandle();
    if (complete && session)
      try {
        await session.cleanup();
      } catch {
        primary = new Error("Installed discovery API fixture cleanup failed");
      }
  }
  if (!primary) {
    proof = {
      scope: SCOPE,
      uid,
      gid,
      fingerprint: leafFingerprint,
      positiveScanCount: scanCount,
      ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
    };
    verifyProof(proof);
    gate.report.nativeInstalledFileDiscovery = proof;
  }
  if (primary) {
    gate.report.status = "failed";
    gate.report.failure = "Installed discovery or owned restoration failed";
  }
  gate.report.fixtureSources = REQUIRED_SOURCES.map(fingerprint);
  await gate.finish({
    requiredScenarios: ["linux-installed-systemd-public-discovery"],
    cleanup: { status: complete ? "passed" : "failed" },
  });
  if (primary) throw new Error("Installed discovery qualification failed");
  return resource;
}
module.exports = {
  retainOwnedConfig,
  retainOwnedFile,
  assertReceiptPlan,
  assertCompletion,
  completionPath,
  guardPath,
  SCOPE,
  FLAGS,
  verifyProof,
  qualifyInstalledDiscovery,
  REQUIRED_SOURCES,
  freshAuthenticatedHeartbeat,
};
