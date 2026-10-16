"use strict";
/** Real-day fault composition only. The parent must first measure a genuine day
 * in one resident process. No clock, ledger, transport or key deletion is faked.
 * Existing native fault child delegates actual execution, exits after delstore,
 * and is contained before product code starts. Unknown drainage preserves state. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  { isDeepStrictEqual } = require("node:util");
const retention = require("../../../packages/agent/src/windows-retention");
const contained = require("./certops-windows-contained-process");
const { DAY, HOUR } = require("../../../scripts/certops-retention24h-contract");
const platform = require("../../../packages/agent/src/platform");
const SCOPE =
  "actual-day-native-delstore-interruption-and-default-clock-resume";
const FLAGS = Object.freeze([
  "actualDayBeforeNativeMutation",
  "sameOriginalProductionLedger",
  "ownedChildExit86",
  "containedNativeTreeDrained",
  "nativeCertificateAbsentBeforeResume",
  "nativeKeyPossessionRetainedBeforeResume",
  "incompleteLedgerUnchanged",
  "replacementCustodyAndTrustedTlsPreserved",
  "ordinaryDefaultClockResumeCompleted",
  "nativeCertificateAndKeyAbsentAfterResume",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-retention24h-interrupted.js",
  "packages/agent/scripts/host/retention-interrupted-child.js",
  "packages/agent/src/platform/index.js",
  ...contained.REQUIRED_SOURCES,
]);
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
function verifyTiming({ monotonicElapsedMs, observedAt, cleanupDeadline }) {
  assert.ok(
    Number.isFinite(monotonicElapsedMs) &&
      monotonicElapsedMs >= DAY &&
      monotonicElapsedMs <= DAY + HOUR,
  );
  for (const value of [observedAt, cleanupDeadline]) {
    assert.match(value, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    assert.ok(Number.isFinite(Date.parse(value)));
  }
  assert.ok(Date.parse(observedAt) > Date.parse(cleanupDeadline));
  return true;
}
function verifyProof(p) {
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "scope",
      ...FLAGS,
      "monotonicElapsedBeforeCrashMs",
      "interruptedAt",
      "resumedAt",
      "cleanupDeadline",
      "productionSixHourCadenceQualified",
      "full168HourRetentionQualified",
    ].sort(),
  );
  assert.equal(p.scope, SCOPE);
  assert.ok(Number.isInteger(p.monotonicElapsedBeforeCrashMs));
  assert.match(p.resumedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  for (const flag of FLAGS) assert.equal(p[flag], true, flag);
  assert.equal(p.productionSixHourCadenceQualified, false);
  assert.equal(p.full168HourRetentionQualified, false);
  verifyTiming({
    monotonicElapsedMs: p.monotonicElapsedBeforeCrashMs,
    observedAt: p.interruptedAt,
    cleanupDeadline: p.cleanupDeadline,
  });
  assert.ok(Date.parse(p.resumedAt) >= Date.parse(p.interruptedAt));
  return true;
}
function verifyReceipt(
  receipt,
  { thumbprint, containerName, childPid, cleanupDeadline },
) {
  assert.deepEqual(
    Object.keys(receipt).sort(),
    [
      "fault",
      "thumbprint",
      "containerName",
      "nativeCommandSucceeded",
      "pid",
      "observedAt",
    ].sort(),
  );
  assert.equal(
    receipt.fault,
    "process-exit-after-native-delstore-before-delkey",
  );
  assert.equal(receipt.thumbprint, thumbprint);
  assert.equal(receipt.containerName, containerName);
  assert.ok(
    Number.isInteger(childPid) && childPid > 0 && childPid <= 0xffffffff,
  );
  assert.equal(receipt.pid, childPid);
  assert.equal(receipt.nativeCommandSucceeded, true);
  assert.match(
    receipt.observedAt,
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
  );
  assert.ok(
    Number.isFinite(Date.parse(receipt.observedAt)) &&
      Date.parse(receipt.observedAt) > Date.parse(cleanupDeadline),
  );
  return true;
}
function assertCleanupSafe(configPath) {
  const directory = path.dirname(configPath);
  assert.equal(
    fs.existsSync(path.join(directory, "interrupted-delete-owner.json")),
    false,
    "Preserve unresolved resident interruption ownership",
  );
  contained.assertCleanupSafe(directory);
}
async function interruptAfterRealDay({
  configPath,
  configSha256,
  timing,
  verifyIntermediate,
}) {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  assert.equal(typeof verifyIntermediate, "function");
  verifyTiming(timing);
  const bytes = fs.readFileSync(configPath);
  assert.equal(hash(bytes), configSha256);
  const config = JSON.parse(bytes);
  for (const file of REQUIRED_SOURCES)
    assert.ok(
      config.requiredSources.some((row) => row.file === file),
      "Missing interruption source fingerprint",
    );
  require("../../../scripts/certops-retention24h-runtime").verifyConfig(
    config,
    configPath,
  );
  assert.equal(timing.cleanupDeadline, config.cleanupDeadline);
  assert.ok(Date.now() > Date.parse(config.cleanupDeadline));
  const directory = path.dirname(configPath),
    guard = path.join(directory, "interrupted-delete-owner.json"),
    go = path.join(directory, "interrupted-delete-go"),
    receiptFile = path.join(config.stateDir, "interrupted-native-delete.json");
  for (const file of [guard, go, receiptFile])
    assert.equal(
      fs.existsSync(file),
      false,
      "Refuse prior interruption ownership",
    );
  const rowPath = retention.ledgerRowPath(
      path.join(config.stateDir, "windows-retention"),
      config.predecessor.thumbprint,
    ),
    before = fs.readFileSync(rowPath),
    rowIdentity = fs.lstatSync(rowPath, { bigint: true }),
    row = retention.readLedgerRow(
      path.dirname(rowPath),
      config.predecessor.thumbprint,
    );
  assert.ok(
    rowIdentity.isFile() &&
      !rowIdentity.isSymbolicLink() &&
      rowIdentity.ino > 0n,
  );
  assert.ok(row && row.lifecycleState !== "removed");
  const guardBytes = Buffer.from(
    JSON.stringify({
      schemaVersion: 1,
      configSha256,
      nonce: config.lease.nonce,
    }),
  );
  fs.writeFileSync(guard, guardBytes, { flag: "wx", mode: 0o600 });
  platform.applyRestrictivePermissions(guard, { kind: "file" });
  const guardId = fs.lstatSync(guard, { bigint: true }).ino;
  assert.ok(guardId > 0n);
  const resources = [];
  let wrapperExit;
  let resource;
  try {
    resource = await contained.startContainedNativeProcess({
      executable: process.execPath,
      args: [
        path.resolve(
          __dirname,
          "../../../packages/agent/scripts/host/retention-interrupted-child.js",
        ),
        config.stateDir,
        config.predecessor.thumbprint,
        config.predecessor.containerName,
        configPath,
        configSha256,
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
        CERTOPS_ADCS_DISPOSABLE_LAB: "1",
      },
      workDir: directory,
      maxLifetimeMs: 180000,
      expectedSid: "S-1-5-18",
      onCreated(value) {
        resources.push(value);
        wrapperExit = new Promise((resolve) =>
          value.wrapper.once("close", resolve),
        );
      },
    });
    assert.equal(hash(fs.readFileSync(configPath)), configSha256);
    const tmp = go + ".tmp";
    fs.writeFileSync(tmp, "1", { flag: "wx" });
    try {
      fs.linkSync(tmp, go);
    } finally {
      fs.unlinkSync(tmp);
    }
    let timer;
    try {
      await Promise.race([
        wrapperExit,
        new Promise((_, reject) => {
          timer = setTimeout(
            () => reject(new Error("Owned native interruption did not exit")),
            190000,
          );
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
    const closed = await resource.stopAndDrain();
    assert.equal(closed.rootExitCode, 86);
    assert.equal(closed.activeNativeProcesses, 0);
    contained.assertCleanupSafe(directory);
    const stat = fs.lstatSync(receiptFile);
    assert.ok(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 8192);
    const receipt = JSON.parse(fs.readFileSync(receiptFile, "utf8"));
    verifyReceipt(receipt, {
      ...config.predecessor,
      childPid: resource.rootIdentity.pid,
      cleanupDeadline: config.cleanupDeadline,
    });
    assert.ok(
      Date.parse(receipt.observedAt) >= Date.parse(timing.observedAt) &&
        Date.parse(receipt.observedAt) <= Date.now(),
    );
    assert.equal(fs.lstatSync(rowPath, { bigint: true }).ino, rowIdentity.ino);
    assert.ok(
      fs.readFileSync(rowPath).equals(before),
      "Native interruption changed incomplete ledger bytes",
    );
    assert.ok(
      isDeepStrictEqual(
        retention.readLedgerRow(
          path.dirname(rowPath),
          config.predecessor.thumbprint,
        ),
        row,
      ),
      "Incomplete ledger identity changed",
    );
    const native = await verifyIntermediate();
    for (const flag of [
      "predecessorCertificateAbsent",
      "predecessorKeyPossessionVerified",
      "replacementCustodyVerified",
      "replacementTrustedTlsVerified",
    ])
      assert.equal(native[flag], true, flag);
    return {
      finish({ ordinarySweepSummary, finalNative }) {
        for (const flag of [
          "predecessorCertificateAbsent",
          "predecessorKeyAbsent",
          "replacementCustodyVerified",
          "replacementTrustedTlsVerified",
        ])
          assert.equal(finalNative[flag], true, flag);
        assert.deepEqual(ordinarySweepSummary.removed, [
          config.predecessor.thumbprint,
        ]);
        assert.deepEqual(ordinarySweepSummary.deferred, []);
        assert.equal(
          retention.readLedgerRow(
            path.dirname(rowPath),
            config.predecessor.thumbprint,
          ).lifecycleState,
          "removed",
        );
        assert.equal(fs.lstatSync(guard, { bigint: true }).ino, guardId);
        assert.ok(fs.readFileSync(guard).equals(guardBytes));
        contained.assertCleanupSafe(directory);
        const proof = {
          scope: SCOPE,
          ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
          monotonicElapsedBeforeCrashMs: Math.floor(timing.monotonicElapsedMs),
          interruptedAt: receipt.observedAt,
          resumedAt: new Date().toISOString(),
          cleanupDeadline: config.cleanupDeadline,
          productionSixHourCadenceQualified: false,
          full168HourRetentionQualified: false,
        };
        verifyProof(proof);
        fs.unlinkSync(guard);
        return proof;
      },
    };
  } finally {
    for (const owned of resources) await owned.stopAndDrain();
  }
}
module.exports = {
  SCOPE,
  FLAGS,
  REQUIRED_SOURCES,
  verifyTiming,
  verifyProof,
  verifyReceipt,
  interruptAfterRealDay,
  assertCleanupSafe,
};
