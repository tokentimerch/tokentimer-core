"use strict";
/* Compose two real native prerequisites: an already prepared machine CNG key
 * from the owned orphan fixture, and an independently demonstrated filesystem
 * denial. No CA request, installed agent, journal state or clock is synthesized.
 * The original fixture retains key cleanup; unknown ACL/child ownership blocks it.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { isDeepStrictEqual } = require("node:util");
const journal = require("../../src/issuers/adcs-enrollment-journal");
const { applyRestrictivePermissions } = require("../../src/platform");
const contained = require("../../../../tests/e2e/helpers/certops-windows-contained-process");
const acl = require("./retention-ledger-read-refusal-fixture");
const SCOPE = "native-prepared-cng-preserved-through-unreadable-adcs-journal";
const SCENARIOS = Object.freeze([
  "windows-native-cng-journal-read-denied-protected",
  "windows-native-cng-journal-root-list-denied-protected",
]);
const FLAGS = Object.freeze([
  "actualPreparedNativeKeyPrerequisite",
  "actualFreshOsReadAndListDenied",
  "productionJournalNotAbsent",
  "actualOrphanReconciliationDeferred",
  "sameNativePrivateKeyPossession",
  "sameJournalBytesAndFileIdentities",
  "exactRetainedHandleAclsRestored",
  "ownedNativeChildrenDrained",
  "productionJournalReadersRecovered",
]);
const REQUIRED_SOURCES = Object.freeze([
  "packages/agent/scripts/host/orphan-journal-acl-fixture.js",
  "packages/agent/scripts/host/orphan-journal-fixture.js",
  "packages/agent/scripts/host/retention-ledger-read-refusal-fixture.js",
  "packages/agent/scripts/host/retention-ledger-acl-hold.ps1",
  "packages/agent/src/index.js",
  "packages/agent/src/issuers/adcs-enrollment-journal.js",
  "packages/agent/src/platform/index.js",
  ...contained.REQUIRED_SOURCES,
]);
const GUARD = ".preserve-native-cng-journal-acl.json";
const active = new Set();
const owner = (directory) => path.resolve(directory).toLowerCase();
function verifyProof(proof) {
  assert.deepEqual(
    Object.keys(proof).sort(),
    [
      "scope",
      "caEnrollmentQualified",
      "installedServiceQualified",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(proof.scope, SCOPE);
  assert.equal(proof.caEnrollmentQualified, false);
  assert.equal(proof.installedServiceQualified, false);
  for (const flag of FLAGS) assert.equal(proof[flag], true, flag);
  return proof;
}
function assertCleanupSafe(workDir) {
  assert.equal(
    active.has(owner(workDir)),
    false,
    "Preserve native CNG while journal ACL recovery remains unresolved",
  );
  assert.equal(
    fs.existsSync(path.join(workDir, GUARD)),
    false,
    "Preserve native CNG journal ACL guard",
  );
  contained.assertCleanupSafe(workDir);
}
async function until(check) {
  const deadline = performance.now() + 60000;
  while (performance.now() < deadline) {
    const result = check();
    if (result) return result;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("Owned native CNG journal ACL protocol exceeded deadline");
}
function validatePrepared(read, containerName) {
  assert.equal(read.kind, "valid");
  assert.equal(read.journal.state, "prepared");
  assert.ok(
    read.journal.containerName === containerName,
    "Prepared native journal belongs to another key",
  );
  assert.ok(
    /^tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(
      containerName,
    ),
    "Canonical enrollment-owned native key required",
  );
}
function assertOwnedBytes(file, expected, expectedId) {
  assert.equal(acl.identity(file), expectedId);
  const fd = fs.openSync(file, "r");
  try {
    const stat = fs.fstatSync(fd, { bigint: true });
    assert.ok(
      stat.isFile() &&
        `${stat.dev}:${stat.ino}` === expectedId &&
        stat.size === BigInt(expected.length),
    );
    const buffer = Buffer.alloc(expected.length + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = fs.readSync(
        fd,
        buffer,
        length,
        buffer.length - length,
        null,
      );
      if (!count) break;
      length += count;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    assert.ok(
      length === expected.length &&
        buffer.subarray(0, length).equals(expected) &&
        after.size === stat.size &&
        after.mtimeNs === stat.mtimeNs,
      "Exact private ownership bytes changed",
    );
    assert.equal(acl.identity(file), expectedId);
  } finally {
    fs.closeSync(fd);
  }
}
function readJournalBytes(file) {
  const id = acl.identity(file),
    fd = fs.openSync(file, "r");
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    assert.ok(
      before.isFile() &&
        before.size > 0n &&
        before.size <= 65536n &&
        `${before.dev}:${before.ino}` === id,
    );
    const bytes = Buffer.alloc(65537);
    let length = 0;
    while (length < bytes.length) {
      const count = fs.readSync(fd, bytes, length, bytes.length - length, null);
      if (!count) break;
      length += count;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    assert.ok(
      length <= 65536 &&
        after.size === BigInt(length) &&
        after.size === before.size &&
        after.mtimeNs === before.mtimeNs,
    );
    assert.equal(acl.identity(file), id);
    return bytes.subarray(0, length);
  } finally {
    fs.closeSync(fd);
  }
}
async function qualifyPreparedKeyJournalAcl(c) {
  const {
    gate,
    workDir,
    stateDir,
    enrollmentId,
    containerName,
    observeKey,
    sweep,
    assertFixtureOwned,
    powershell: ps,
  } = c;
  assert.equal(process.platform, "win32");
  assertCleanupSafe(workDir);
  assert.equal(
    path.dirname(path.resolve(stateDir)).toLowerCase(),
    path.resolve(workDir).toLowerCase(),
    "Native journal state must be the original owned fixture's direct child",
  );
  assert.match(path.basename(stateDir), /^native-orphan-journal-/);
  for (const callback of [observeKey, sweep, assertFixtureOwned, ps])
    assert.equal(typeof callback, "function");
  assertFixtureOwned();
  validatePrepared(
    journal.readEnrollmentJournal(stateDir, enrollmentId),
    containerName,
  );
  const file = journal.journalV2Path(stateDir, enrollmentId),
    enrollmentDirectory = path.dirname(file),
    tree = path.dirname(enrollmentDirectory);
  const identities = [workDir, stateDir, enrollmentDirectory, tree, file].map(
    (target) => ({ target, identity: acl.identity(target) }),
  );
  const originalBytes = readJournalBytes(file),
    nativeBefore = observeKey(containerName);
  assert.ok(originalBytes.length > 0 && originalBytes.length <= 65536);
  const principalSid = ps(
    "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
  );
  assert.match(principalSid, /^S-1-[0-9-]+$/);
  const guard = path.join(workDir, GUARD);
  const unchanged = () => {
    assertFixtureOwned();
    for (const value of identities)
      assert.equal(acl.identity(value.target), value.identity);
    assertOwnedBytes(
      file,
      originalBytes,
      identities.find((value) => value.target === file).identity,
    );
    validatePrepared(
      journal.readEnrollmentJournal(stateDir, enrollmentId),
      containerName,
    );
    assert.ok(
      isDeepStrictEqual(observeKey(containerName), nativeBefore),
      "Actual protected native key possession changed",
    );
  };
  for (const [index, target] of [
    { file, directory: false },
    { file: tree, directory: true },
  ].entries()) {
    await gate.scenario(
      SCENARIOS[index],
      async () => {
        unchanged();
        const nonce = crypto.randomBytes(32).toString("hex");
        const protocol = fs.mkdtempSync(
          path.join(workDir, "native-cng-journal-acl-"),
        );
        applyRestrictivePermissions(protocol, { kind: "directory" });
        const protocolId = acl.identity(protocol),
          targetId = acl.identity(target.file),
          stat = fs.lstatSync(target.file, { bigint: true });
        const originalSddl = ps(
          `(Get-Acl -LiteralPath '${target.file.replace(/'/g, "''")}').GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)`,
        );
        const context = {
          schemaVersion: 1,
          nonce,
          target: target.file,
          targetInode: stat.ino.toString(),
          targetVolume: stat.dev.toString(),
          directory: target.directory,
          ready: path.join(protocol, "ready.json"),
          release: path.join(protocol, "release"),
          restored: path.join(protocol, "restored.json"),
        };
        const contextPath = path.join(protocol, "context.json"),
          bytes = Buffer.from(JSON.stringify(context));
        fs.writeFileSync(contextPath, bytes, { flag: "wx", mode: 0o600 });
        applyRestrictivePermissions(contextPath);
        const contextId = acl.identity(contextPath);
        active.add(owner(workDir));
        fs.writeFileSync(guard, nonce, { flag: "wx", mode: 0o600 });
        applyRestrictivePermissions(guard);
        const guardId = acl.identity(guard);
        let resource,
          ready,
          closed,
          wrapperClosed = false,
          restoredVerified = false;
        try {
          resource = await contained.startContainedNativeProcess({
            executable: path.join(
              process.env.SystemRoot,
              "System32/WindowsPowerShell/v1.0/powershell.exe",
            ),
            args: [
              "-NoProfile",
              "-NonInteractive",
              "-ExecutionPolicy",
              "Bypass",
              "-File",
              path.join(__dirname, "retention-ledger-acl-hold.ps1"),
              "-ContextPath",
              contextPath,
              "-ContextSha256",
              crypto.createHash("sha256").update(bytes).digest("hex"),
            ],
            environment: Object.fromEntries(
              Object.entries(process.env).filter(([name]) =>
                ["systemroot", "windir", "temp", "tmp", "path"].includes(
                  name.toLowerCase(),
                ),
              ),
            ),
            workDir,
            expectedSid: principalSid,
            maxLifetimeMs: 180000,
            onCreated(value) {
              resource = value;
              closed = new Promise((resolve) =>
                value.wrapper.once("close", () => {
                  wrapperClosed = true;
                  resolve();
                }),
              );
            },
          });
          ready = await until(
            () =>
              fs.existsSync(context.ready) &&
              acl.readReceipt(context.ready, "ready"),
          );
          assert.equal(ready.nonce, nonce);
          assert.equal(ready.denied, true);
          assert.equal(ready.fileId, targetId);
          assert.equal(ready.principalSid, principalSid);
          assert.equal(ready.processId, resource.rootIdentity.pid);
          assert.equal(
            ready.processCreatedAt,
            resource.rootIdentity.creationTime,
          );
          assert.throws(
            () =>
              target.directory
                ? fs.readdirSync(target.file)
                : fs.readFileSync(target.file),
            (error) => ["EACCES", "EPERM"].includes(error.code),
            "Independent fresh native OS denial required",
          );
          const scanned = journal.listProtectedEnrollmentContainers(stateDir);
          assert.equal(scanned.ok, false);
          if (!target.directory)
            assert.equal(
              journal.readEnrollmentJournal(stateDir, enrollmentId).kind,
              "corrupt",
            );
          const result = await sweep();
          assert.deepEqual(result.freed, []);
          assert.ok(
            result.skipped.some(
              (row) =>
                row.containerName === containerName &&
                /journal.*scan.*failed|journal.*unreadable|deferred/i.test(
                  row.reason,
                ),
            ),
          );
          assert.ok(
            isDeepStrictEqual(observeKey(containerName), nativeBefore),
            "Production reconciliation changed the real native key under journal denial",
          );
        } finally {
          try {
            if (ready) {
              assert.equal(acl.identity(protocol), protocolId);
              assert.equal(acl.identity(contextPath), contextId);
              assertOwnedBytes(contextPath, bytes, contextId);
              const staging = context.release + ".writing";
              fs.writeFileSync(staging, nonce, { flag: "wx" });
              fs.linkSync(staging, context.release);
              await until(() => fs.existsSync(context.restored));
              await until(() => wrapperClosed);
              const restored = acl.readReceipt(context.restored, "restored");
              assert.equal(restored.nonce, nonce);
              assert.equal(restored.fileId, targetId);
              assert.equal(restored.restored, true);
              assert.equal(acl.identity(target.file), targetId);
              assert.equal(
                ps(
                  `(Get-Acl -LiteralPath '${target.file.replace(/'/g, "''")}').GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)`,
                ),
                originalSddl,
              );
              unchanged();
              restoredVerified = true;
            }
          } finally {
            if (resource) {
              const drain = await resource.stopAndDrain();
              await closed;
              assert.equal(drain.rootExitCode, 0);
            }
            assert.equal(
              restoredVerified,
              true,
              "Preserve actual native key until exact ACL restoration is proven",
            );
            assert.equal(acl.identity(guard), guardId);
            assertOwnedBytes(guard, Buffer.from(nonce), guardId);
            fs.unlinkSync(guard);
            active.delete(owner(workDir));
          }
        }
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "actual prepared machine CNG key and explicit local journal prerequisite, independent native filesystem denial, genuine production orphan deferral, private-key possession and exact retained-handle restoration",
      },
    );
  }
  return verifyProof({
    scope: SCOPE,
    caEnrollmentQualified: false,
    installedServiceQualified: false,
    ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
  });
}
module.exports = {
  SCOPE,
  SCENARIOS,
  FLAGS,
  REQUIRED_SOURCES,
  GUARD,
  verifyProof,
  validatePrepared,
  readJournalBytes,
  assertCleanupSafe,
  qualifyPreparedKeyJournalAcl,
};
