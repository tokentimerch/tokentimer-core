/*
 * Qualification notes: retention-ledger-access-refusal
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Create real production ledger with explicit local prerequisites,no cert/key/service/CA. Suspended
 * current-token retained-Job holder opens exact volume/file identity with
 * READ_CONTROL/WRITE_DAC/metadata and no delete share,refusing reparse. Deny and restore via same
 * handle GetSecurityInfo/SetSecurityInfo,never reopen unverified name; no data/list rights.
 * Independently require actual EACCES/EPERM before production file/directory reader must throw,not
 * treat as missing. Restore original SDDL/bytes/IDs and successful reads,normal holder exit/zero
 * members; bounded nonce receipts guard every failure. Privileged bypass cannot pass. Unknown
 * restore/drain retains durable+memory guard and blocks broad cleanup. Offline proof/C# compile do not
 * qualify actual ACL denial/deletion/retention.
 */
"use strict";
/** Native temporary-ledger permission controls, not installed retention evidence.
 * A retained no-delete-sharing ACL handle and contained child own each deny and
 * exact restoration. Failed ownership/drain/restoration preserves the root.
 */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const { isDeepStrictEqual } = require("node:util");
const retention = require("../../src/windows-retention");
const { applyRestrictivePermissions } = require("../../src/platform");
const contained = require("../../../../tests/e2e/helpers/certops-windows-contained-process");
const scenarios = [
  "windows-retention-ledger-native-read-denied",
  "windows-retention-ledger-root-native-list-denied",
];
const scope =
  "native-temporary-retention-ledger-access-refusal-not-certificate-cleanup";
const fields = [
  "productionLedgerCreated",
  "actualNativeReadDataDenied",
  "actualNativeListDirectoryDenied",
  "productionUnreadableNotAbsent",
  "retainedExactAclHandles",
  "sameOwnedFileIdentitiesAndBytes",
  "exactNativeAclsRestored",
  "productionReadersRecovered",
  "containedChildrenDrained",
  "ownedTemporaryStateRemoved",
];
const requiredSources = [
  "packages/agent/scripts/host-gate.js",
  "packages/agent/scripts/host/retention-ledger-read-refusal-fixture.js",
  "packages/agent/scripts/host/retention-ledger-acl-hold.ps1",
  "packages/agent/src/windows-retention/index.js",
  "packages/agent/src/platform/index.js",
  ...contained.REQUIRED_SOURCES,
];
const preserveGuardName = ".preserve-retention-ledger-acl.json",
  active = new Set();
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const quote = (value) => value.replace(/'/g, "''");
function identity(file) {
  const s = fs.lstatSync(file, { bigint: true });
  assert.equal(s.isSymbolicLink(), false);
  assert.ok(
    s.isFile() || s.isDirectory(),
    "Owned regular file/directory required",
  );
  assert.ok(s.ino > 0n && s.dev > 0n, "Stable native identity required");
  assert.equal(
    path.resolve(fs.realpathSync.native(file)).toLowerCase(),
    path.resolve(file).toLowerCase(),
  );
  return `${s.dev}:${s.ino}`;
}
function ownerKey(workDir) {
  return path.resolve(workDir).toLowerCase();
}
function assertCleanupSafe(workDir) {
  assert.equal(
    active.has(ownerKey(workDir)),
    false,
    "Preserve ledger state until exact native ACL restoration/drain",
  );
  assert.equal(
    fs.existsSync(path.join(workDir, preserveGuardName)),
    false,
    "Preserve unresolved ledger ACL ownership receipt",
  );
  contained.assertCleanupSafe(workDir);
}
function verifyProof(proof) {
  assert.deepEqual(
    Object.keys(proof).sort(),
    [
      "scope",
      ...fields,
      "installedServiceQualified",
      "nativeCertificateCleanupQualified",
      "elapsedRetentionQualified",
    ].sort(),
  );
  assert.equal(proof.scope, scope);
  for (const field of fields) assert.equal(proof[field], true, field);
  for (const field of [
    "installedServiceQualified",
    "nativeCertificateCleanupQualified",
    "elapsedRetentionQualified",
  ])
    assert.equal(proof[field], false, field);
  return true;
}
async function until(check) {
  const end = performance.now() + 60000;
  while (performance.now() < end) {
    const value = check();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("Owned ledger ACL protocol deadline");
}
function readReceipt(file, kind) {
  const stat = fs.lstatSync(file, { bigint: true }),
    original = `${stat.dev}:${stat.ino}`;
  assert.equal(identity(file), original);
  assert.ok(stat.isFile() && stat.size > 0n && stat.size <= 16384n);
  const handle = fs.openSync(
    file,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
  );
  try {
    const opened = fs.fstatSync(handle, { bigint: true });
    assert.ok(opened.isFile());
    assert.equal(`${opened.dev}:${opened.ino}`, original);
    assert.equal(opened.size, stat.size);
    assert.equal(opened.mtimeNs, stat.mtimeNs);
    const buffer = Buffer.alloc(16385);
    let length = 0;
    while (length < buffer.length) {
      const count = fs.readSync(
        handle,
        buffer,
        length,
        buffer.length - length,
        length,
      );
      if (count === 0) break;
      length += count;
    }
    const after = fs.fstatSync(handle, { bigint: true });
    assert.equal(`${after.dev}:${after.ino}`, original);
    assert.equal(after.size, opened.size);
    assert.equal(after.mtimeNs, opened.mtimeNs);
    assert.equal(identity(file), original);
    assert.ok(length > 0 && length <= 16384 && BigInt(length) === opened.size);
    const value = JSON.parse(buffer.subarray(0, length).toString("utf8"));
    const schemas = {
      ready: [
        "schemaVersion",
        "nonce",
        "fileId",
        "principalSid",
        "processId",
        "processCreatedAt",
        "denied",
      ],
      restored: [
        "schemaVersion",
        "nonce",
        "fileId",
        "restored",
        "originalDacl",
      ],
    };
    assert.ok(Object.hasOwn(schemas, kind));
    assert.deepEqual(Object.keys(value).sort(), schemas[kind].sort());
    assert.equal(value.schemaVersion, 1);
    return value;
  } finally {
    fs.closeSync(handle);
  }
}
async function qualifyLedgerReadRefusals({ gate, powershell: ps, workDir }) {
  assert.equal(process.platform, "win32");
  assertCleanupSafe(workDir);
  const rootId = identity(workDir),
    directory = fs.mkdtempSync(path.join(workDir, "ledger-read-refusal-")),
    directoryId = identity(directory),
    guard = path.join(workDir, preserveGuardName);
  applyRestrictivePermissions(directory, { kind: "directory" });
  const ledgerDir = path.join(directory, "windows-retention"),
    thumb = "A".repeat(40);
  const row = retention.createLedgerRow({
    ledgerDir,
    oldThumbprint: thumb,
    replacementThumbprint: "B".repeat(40),
    cngKeyContainerId: `tokentimer-enr-${crypto.randomUUID()}`,
    verifiedCutoverAt: new Date().toISOString(),
    oldNotAfter: new Date(Date.now() + 86400000).toISOString(),
    ownershipProvenance: "tokentimer_installed",
    store: "My",
  });
  // These explicit local row prerequisites create no native key/cert or CA request.
  const file = retention.ledgerRowPath(ledgerDir, thumb),
    tracked = [directory, ledgerDir, file].map((p) => ({
      file: p,
      id: identity(p),
      hash: fs.statSync(p).isFile() ? hash(fs.readFileSync(p)) : null,
    }));
  const assertTracked = () => {
    assert.equal(identity(workDir), rootId);
    assert.equal(identity(directory), directoryId);
    for (const item of tracked) {
      assert.equal(identity(item.file), item.id, "Owned ledger path changed");
      if (item.hash)
        assert.equal(
          hash(fs.readFileSync(item.file)),
          item.hash,
          "Owned ledger bytes changed",
        );
    }
  };
  const readable = () => {
    assert.ok(
      isDeepStrictEqual(retention.readLedgerRow(ledgerDir, thumb), row),
      "Production ledger content changed",
    );
    assert.deepEqual(retention.listLedgerThumbprints(ledgerDir), [thumb]);
  };
  const powershellPath = path.join(
      process.env.SystemRoot,
      "System32",
      "WindowsPowerShell",
      "v1.0",
      "powershell.exe",
    ),
    holderPath = path.join(__dirname, "retention-ledger-acl-hold.ps1");
  const currentSid = ps(
    "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
  );
  assert.match(currentSid, /^S-1-[0-9-]+$/);
  let primary;
  try {
    for (const [index, target] of [
      { file, directory: false },
      { file: ledgerDir, directory: true },
    ].entries())
      await gate.scenario(
        scenarios[index],
        async () => {
          assertTracked();
          readable();
          const nonce = crypto.randomBytes(32).toString("hex"),
            protocol = path.join(directory, `protocol-${index}`);
          fs.mkdirSync(protocol);
          applyRestrictivePermissions(protocol, { kind: "directory" });
          const protocolId = identity(protocol),
            targetId = identity(target.file),
            targetInode = fs
              .lstatSync(target.file, { bigint: true })
              .ino.toString();
          const sddl = ps(
            `(Get-Acl -LiteralPath '${quote(target.file)}').GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)`,
          );
          const context = {
            schemaVersion: 1,
            nonce,
            target: target.file,
            targetInode,
            targetVolume: fs
              .lstatSync(target.file, { bigint: true })
              .dev.toString(),
            directory: target.directory,
            ready: path.join(protocol, "denied.json"),
            release: path.join(protocol, "release"),
            restored: path.join(protocol, "restored.json"),
          };
          const contextPath = path.join(protocol, "context.json"),
            contextBytes = JSON.stringify(context);
          fs.writeFileSync(contextPath, contextBytes, { flag: "wx" });
          applyRestrictivePermissions(contextPath);
          const contextId = identity(contextPath);
          const guardBytes = JSON.stringify({
            scope,
            nonce,
            directory,
            directoryId,
            targetId,
          });
          active.add(ownerKey(workDir));
          fs.writeFileSync(guard, guardBytes, { flag: "wx" });
          applyRestrictivePermissions(guard);
          const guardId = identity(guard);
          let resource,
            ready,
            drain,
            closed,
            wrapperClosed = false;
          try {
            const environment = Object.fromEntries(
              Object.entries(process.env).filter(([name]) =>
                ["systemroot", "windir", "temp", "tmp", "path"].includes(
                  name.toLowerCase(),
                ),
              ),
            );
            resource = await contained.startContainedNativeProcess({
              executable: powershellPath,
              args: [
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                holderPath,
                "-ContextPath",
                contextPath,
                "-ContextSha256",
                hash(Buffer.from(contextBytes)),
              ],
              environment,
              workDir,
              maxLifetimeMs: 180000,
              expectedSid: currentSid,
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
                readReceipt(context.ready, "ready"),
            );
            assert.deepEqual(
              Object.keys(ready).sort(),
              [
                "schemaVersion",
                "nonce",
                "fileId",
                "principalSid",
                "processId",
                "processCreatedAt",
                "denied",
              ].sort(),
            );
            assert.equal(ready.schemaVersion, 1);
            assert.equal(ready.nonce, nonce);
            assert.equal(ready.fileId, targetId);
            assert.equal(ready.denied, true);
            assert.equal(ready.principalSid, currentSid);
            assert.equal(ready.processId, resource.rootIdentity.pid);
            assert.equal(
              ready.processCreatedAt,
              resource.rootIdentity.creationTime,
            );
            const denial = (error) => ["EACCES", "EPERM"].includes(error.code);
            assert.throws(
              () =>
                target.directory
                  ? fs.readdirSync(target.file)
                  : fs.readFileSync(target.file),
              denial,
              "Actual fresh OS access denial required",
            );
            assert.throws(
              () =>
                target.directory
                  ? retention.listLedgerThumbprints(ledgerDir)
                  : retention.readLedgerRow(ledgerDir, thumb),
              denial,
              "Unreadable production ledger must not become absent/empty",
            );
          } finally {
            try {
              let releaseFailed = false;
              try {
                if (ready) {
                  assert.equal(identity(protocol), protocolId);
                  assert.equal(identity(contextPath), contextId);
                  assert.equal(
                    fs.readFileSync(contextPath, "utf8"),
                    contextBytes,
                  );
                  const releaseStaging = context.release + ".writing";
                  fs.writeFileSync(releaseStaging, nonce, { flag: "wx" });
                  fs.linkSync(releaseStaging, context.release);
                  await until(() => fs.existsSync(context.restored));
                  await until(() => wrapperClosed);
                }
              } catch {
                releaseFailed = true;
              } finally {
                // Every startup/release/receipt failure still drains ONLY the
                // retained owned Job. Uncertain ACL restoration keeps the guard.
                if (resource) {
                  try {
                    drain = await resource.stopAndDrain();
                    await closed;
                  } catch {
                    releaseFailed = true;
                  }
                }
              }
              assert.equal(
                releaseFailed,
                false,
                "Owned restoration protocol failed",
              );
              assert.ok(
                ready && drain,
                "Native restoration/drain never established",
              );
              assert.equal(drain.rootExitCode, 0);
              const restored = readReceipt(context.restored, "restored");
              assert.equal(restored.nonce, nonce);
              assert.equal(restored.fileId, targetId);
              assert.equal(restored.restored, true);
              assert.equal(identity(target.file), targetId);
              assert.equal(
                ps(
                  `(Get-Acl -LiteralPath '${quote(target.file)}').GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)`,
                ),
                sddl,
                "Original complete native ACL changed",
              );
              assertTracked();
              readable();
              assert.equal(identity(guard), guardId);
              assert.equal(fs.readFileSync(guard, "utf8"), guardBytes);
              fs.unlinkSync(guard);
              active.delete(ownerKey(workDir));
            } catch {
              throw new Error(
                "Owned ledger ACL restoration/drain incomplete; preserve fixture",
              );
            }
          }
        },
        {
          evidenceLevel: "real-host",
          oracle:
            "Actual selected-token ReadData/ListDirectory denial, production EACCES/EPERM rather than absence, exact native handle/SDDL/bytes restoration and recovered production read; local row prerequisites only",
        },
      );
  } catch (error) {
    primary = error;
  }
  assertCleanupSafe(workDir);
  assertTracked();
  assert.equal(path.dirname(directory), path.resolve(workDir));
  assert.match(path.basename(directory), /^ledger-read-refusal-/);
  fs.rmSync(directory, { recursive: true });
  if (primary) throw primary;
  const proof = {
    scope,
    ...Object.fromEntries(fields.map((field) => [field, true])),
    installedServiceQualified: false,
    nativeCertificateCleanupQualified: false,
    elapsedRetentionQualified: false,
  };
  verifyProof(proof);
  return proof;
}
module.exports = {
  scenarios,
  scope,
  fields,
  requiredSources,
  preserveGuardName,
  identity,
  readReceipt,
  assertCleanupSafe,
  verifyProof,
  qualifyLedgerReadRefusals,
};
