"use strict";
/** Native Ubuntu discovery refusal fixture. Only public certificates enter this
 * fixture. The real foreground agent and public API remain owned by the caller.
 * Keep unreadable inputs unreadable until that agent has positively drained. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const os = require("node:os");
const SCOPE = "actual-unprivileged-linux-file-discovery-refusals";
const FLAGS = Object.freeze([
  "actualUnprivilegedAgent",
  "noEffectiveCapabilities",
  "actualOsEacces",
  "fileAndDirectorySymlinksUnfollowed",
  "twoActualPositiveScans",
  "publicInventoryRegularLocation",
  "negativeFingerprintAbsent",
  "outsidePublicBytesUnchanged",
  "exactAgentClosed",
  "ownedInputsRemoved",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-native-file-discovery.js",
  "packages/agent/src/discovery/index.js",
  "packages/agent/src/index.js",
  "apps/api/routes/certops-agent.js",
  "apps/api/services/certops/agentObservations.js",
  "apps/api/services/certops/certificateIdentity.js",
  "apps/api/routes/certops.js",
]);

function verifyProof(value) {
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "scope",
      "uid",
      "gid",
      "positiveFingerprint",
      "negativeFingerprint",
      "positiveScanCount",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.scope, SCOPE);
  for (const flag of FLAGS)
    assert.equal(
      value[flag],
      true,
      "Native discovery proof requires every actual observation",
    );
  for (const field of ["uid", "gid"])
    assert.ok(Number.isSafeInteger(value[field]) && value[field] > 0);
  for (const field of ["positiveFingerprint", "negativeFingerprint"])
    assert.match(value[field], /^[a-f0-9]{64}$/);
  assert.notEqual(value.positiveFingerprint, value.negativeFingerprint);
  assert.ok(
    Number.isSafeInteger(value.positiveScanCount) &&
      value.positiveScanCount >= 2 &&
      value.positiveScanCount <= 10000,
  );
  return true;
}

function parseUnprivilegedIdentity(status, expectedUid, expectedGid) {
  assert.ok(Number.isSafeInteger(expectedUid) && expectedUid > 0);
  assert.ok(Number.isSafeInteger(expectedGid) && expectedGid > 0);
  for (const [field, expected] of [
    ["Uid", expectedUid],
    ["Gid", expectedGid],
  ]) {
    const matches = [
      ...status.matchAll(
        new RegExp(
          `^${field}:\\s+([0-9]+)\\s+([0-9]+)\\s+([0-9]+)\\s+([0-9]+)\\s*$`,
          "gm",
        ),
      ),
    ];
    assert.equal(
      matches.length,
      1,
      "Native identity must be independently readable",
    );
    assert.ok(
      matches[0].slice(1).every((value) => Number(value) === expected),
      "Every real/effective/saved/filesystem identity must match the unprivileged owner",
    );
  }
  const capabilities = [...status.matchAll(/^CapEff:\s+([0-9a-f]+)\s*$/gm)];
  assert.equal(capabilities.length, 1);
  assert.equal(
    BigInt(`0x${capabilities[0][1]}`),
    0n,
    "Native discovery must have no effective capabilities",
  );
  return { uid: expectedUid, gid: expectedGid, effectiveCapabilities: "0" };
}

function createRefusalFixture({ workDir, discoveryDir, publicCertificate }) {
  assert.equal(process.platform, "linux");
  const uid = process.getuid(),
    gid = process.getgid();
  parseUnprivilegedIdentity(
    fs.readFileSync("/proc/self/status", "utf8"),
    uid,
    gid,
  );
  const root = fs.realpathSync.native(workDir);
  assert.equal(root, path.resolve(workDir));
  assert.equal(
    fs.realpathSync.native(discoveryDir),
    path.resolve(discoveryDir),
  );
  assert.ok(discoveryDir.startsWith(root + path.sep));
  const certificate = new crypto.X509Certificate(publicCertificate);
  assert.doesNotMatch(
    Buffer.from(publicCertificate).toString("utf8"),
    /PRIVATE KEY/,
  );
  const fingerprint = certificate.fingerprint256
    .replaceAll(":", "")
    .toLowerCase();
  const outside = path.join(root, "discovery-refusal-public");
  const target = path.join(outside, "outside.crt");
  const denied = path.join(discoveryDir, "denied-public.crt");
  const fileAlias = path.join(discoveryDir, "public-file-alias.crt");
  const directoryAlias = path.join(discoveryDir, "public-directory-alias");
  const owned = [];
  let released = false;
  let agent = null,
    agentClosed = false;
  let deniedFd = null;
  let verifiedScans = null;
  function remember(file) {
    const stat = fs.lstatSync(file, { bigint: true });
    assert.ok(stat.ino > 0n);
    owned.push({ file, ino: stat.ino, dev: stat.dev, mode: stat.mode });
  }
  function assertUnchanged() {
    assert.equal(fs.realpathSync.native(root), root);
    assert.equal(fs.realpathSync.native(discoveryDir), discoveryDir);
    for (const entry of owned) {
      const stat = fs.lstatSync(entry.file, { bigint: true });
      assert.ok(
        stat.ino === entry.ino &&
          stat.dev === entry.dev &&
          stat.mode === entry.mode,
        "Discovery refusal fixture ownership changed",
      );
    }
    assert.equal(fs.readlinkSync(fileAlias), target);
    assert.equal(fs.readlinkSync(directoryAlias), outside);
    assert.ok(
      fs.readFileSync(target).equals(Buffer.from(publicCertificate)),
      "Owned outside public certificate changed",
    );
    assert.ok(deniedFd !== null);
    const opened = fs.fstatSync(deniedFd, { bigint: true });
    const original = owned.find((entry) => entry.file === denied);
    assert.ok(opened.ino === original.ino && opened.dev === original.dev);
    const expected = Buffer.from(publicCertificate),
      actual = Buffer.alloc(expected.length + 1);
    const count = fs.readSync(deniedFd, actual, 0, actual.length, 0);
    assert.ok(
      count === expected.length && actual.subarray(0, count).equals(expected),
      "Retained public-only denied file bytes changed",
    );
  }
  // Register this resource before preparation. A partial setup must never look
  // released merely because a later alias creation or permission probe failed.
  const resource = {
    hasOwnershipReceipt: () => !released,
    assertCleanupSafe: () =>
      assert.equal(
        released,
        true,
        "Native discovery fixtures require exact agent drainage before cleanup",
      ),
  };
  function prepare() {
    remember(root);
    remember(discoveryDir);
    fs.mkdirSync(outside, { mode: 0o700 });
    remember(outside);
    fs.writeFileSync(target, publicCertificate, { flag: "wx", mode: 0o600 });
    remember(target);
    fs.writeFileSync(denied, publicCertificate, { flag: "wx", mode: 0o600 });
    deniedFd = fs.openSync(
      denied,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
    );
    fs.chmodSync(denied, 0o000);
    remember(denied);
    fs.symlinkSync(target, fileAlias);
    remember(fileAlias);
    fs.symlinkSync(outside, directoryAlias, "dir");
    remember(directoryAlias);
    assert.throws(
      () => fs.readFileSync(denied),
      (error) => error.code === "EACCES",
      "Actual OS DAC refusal is mandatory before starting the agent",
    );
    assertUnchanged();
  }
  function observeAgent(child) {
    assert.equal(
      agent,
      null,
      "Only the originally retained foreground agent may own discovery",
    );
    const pid = child.pid;
    assert.ok(Number.isSafeInteger(pid) && pid > 0);
    assert.equal(child.exitCode, null);
    assert.equal(child.signalCode, null);
    agent = child;
    child.once("close", () => {
      agentClosed = true;
    });
    return parseUnprivilegedIdentity(
      fs.readFileSync(`/proc/${pid}/status`, "utf8"),
      uid,
      gid,
    );
  }
  async function finishAfterAgentDrain() {
    if (agent && !agentClosed)
      await new Promise((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error("Exact discovery agent close unconfirmed")),
          10000,
        );
        agent.once("close", () => {
          clearTimeout(timer);
          resolve();
        });
      });
    assert.ok(
      agent &&
        agentClosed &&
        (agent.exitCode !== null || agent.signalCode !== null),
      "Exact retained discovery agent must close before fixture cleanup",
    );
    assertUnchanged();
    fs.closeSync(deniedFd);
    deniedFd = null;
    for (const file of [fileAlias, directoryAlias, denied, target])
      fs.unlinkSync(file);
    fs.rmdirSync(outside);
    released = true;
    if (!verifiedScans) return null;
    const proof = {
      scope: SCOPE,
      uid,
      gid,
      positiveFingerprint: verifiedScans.positiveFingerprint,
      negativeFingerprint: fingerprint,
      positiveScanCount: verifiedScans.positiveScanCount,
      ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
    };
    verifyProof(proof);
    return proof;
  }
  return {
    resource,
    prepare,
    observeAgent,
    assertUnchanged,
    finishAfterAgentDrain,
    recordScans(value) {
      assert.equal(value.negativeFingerprint, fingerprint);
      verifiedScans = {
        ...verifyObservedScans({ ...value, targetHost: os.hostname() }),
        positiveFingerprint: value.positiveFingerprint,
      };
    },
    fingerprint,
    paths: { denied, fileAlias, directoryAlias, target },
  };
}

function verifyObservedScans({
  rows,
  inventory,
  positiveFingerprint,
  negativeFingerprint,
  positivePath,
  agentId,
  targetHost = os.hostname(),
  preparedAt,
}) {
  for (const fingerprint of [positiveFingerprint, negativeFingerprint])
    assert.match(fingerprint, /^[a-f0-9]{64}$/);
  assert.notEqual(positiveFingerprint, negativeFingerprint);
  assert.ok(Number.isFinite(Date.parse(preparedAt)));
  assert.ok(Array.isArray(rows) && rows.length > 0);
  const positive = rows.filter(
    (row) => row.metadata?.fingerprintSha256 === positiveFingerprint,
  );
  const times = new Set(
    positive.map((row) => new Date(row.observed_at).toISOString()),
  );
  assert.ok(
    times.size >= 2,
    "Two genuine post-setup discovery scans must have persisted",
  );
  assert.ok(
    positive.every(
      (row) =>
        row.metadata.agentId === agentId &&
        row.metadata.targetHost === targetHost &&
        row.metadata.filePath === positivePath &&
        Date.parse(row.observed_at) >= Date.parse(preparedAt),
    ),
    "Actual discovery evidence must bind the owned regular file and agent",
  );
  assert.ok(
    rows.every(
      (row) => row.metadata?.fingerprintSha256 !== negativeFingerprint,
    ),
    "Denied or aliased public certificate must never be ingested",
  );
  assert.ok(Array.isArray(inventory.items));
  assert.ok(
    inventory.pagination &&
      inventory.pagination.offset === 0 &&
      inventory.pagination.total === inventory.items.length,
    "Complete owned public inventory page is required for absence proof",
  );
  const matching = inventory.items.filter(
    (item) => item.fingerprintSha256 === positiveFingerprint,
  );
  assert.equal(
    matching.length,
    1,
    "Actual public inventory must contain the independently fingerprinted regular certificate",
  );
  assert.ok(
    matching[0].locations.some(
      (location) =>
        location.locationKind === "filesystem" &&
        location.sourceRef === `${agentId}/${targetHost}/${positivePath}`,
    ),
    "Actual inventory location must bind the agent and regular path",
  );
  assert.ok(
    inventory.items.every(
      (item) => item.fingerprintSha256 !== negativeFingerprint,
    ),
  );
  return {
    positiveScanCount: times.size,
    regularInventoryPresent: true,
    deniedFingerprintAbsent: true,
  };
}
module.exports = {
  SCOPE,
  FLAGS,
  REQUIRED_SOURCES,
  verifyProof,
  parseUnprivilegedIdentity,
  createRefusalFixture,
  verifyObservedScans,
};
