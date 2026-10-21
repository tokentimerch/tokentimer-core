/*
 * Qualification notes: journal-read-refusals
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Deny actual native read/list access to owned journal prerequisites, independently require
 * EACCES/EPERM before asserting production refusal, and preserve bytes/native file identity/key
 * custody. Retained identity-bound ACL holder restores exact original DACL before reader recovery and
 * guarded cleanup; unknown restoration/drain keeps durable state. Supporting host filesystem refusal
 * does not qualify installed startup, CA request, full recovery or elapsed retention.
 */
"use strict";
/** Supporting native Windows ACL controls for production AD CS journal readers.
 * Uses only an owned temporary software CSR/journal. No machine key, certificate,
 * CA, installed service or enrollment request is created. Failed ACL restoration
 * leaves a durable parent guard and preserves the exact owned directory. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const journal = require("../../src/issuers/adcs-enrollment-journal"),
  keys = require("../../src/keys"),
  config = require("../../src/config");
const scenarios = Object.freeze([
  "windows-adcs-v2-journal-native-read-denied",
  "windows-adcs-journal-root-native-list-denied",
]);
const fields = Object.freeze([
  "genuinePreparedPublicCsr",
  "twoActualNativeAccessDenials",
  "journalUnreadableNotAbsent",
  "globalProtectionScanDeferred",
  "exactFileIdentitiesAndBytesPreserved",
  "exactNativeAclsRestored",
  "productionReadersRecovered",
  "ownedTemporaryStateRemoved",
]);
const scope =
  "native-temporary-adcs-journal-acl-refusals-not-installed-enrollment";
const requiredSources = Object.freeze([
  "packages/agent/scripts/host/journal-read-refusal-fixture.js",
  "packages/agent/src/issuers/adcs-enrollment-journal.js",
  "packages/agent/src/keys/index.js",
  "packages/agent/src/config/index.js",
  "packages/agent/src/platform/index.js",
  "packages/agent/vendor/log-scrub/secret-material.js",
]);
const preserveGuardName = ".preserve-adcs-journal-acl.json";
function verifyProof(value) {
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "scope",
      "installedServiceQualified",
      "nativeCngQualified",
      ...fields,
    ].sort(),
  );
  assert.equal(value.scope, scope);
  assert.equal(value.installedServiceQualified, false);
  assert.equal(value.nativeCngQualified, false);
  for (const field of fields) assert.equal(value[field], true, field);
  return true;
}
function assertCleanupSafe(workDir) {
  assert.equal(
    fs.existsSync(path.join(workDir, preserveGuardName)),
    false,
    "Preserve journal fixtures because exact native ACL restoration is unproven",
  );
}
function identity(file) {
  const stat = fs.lstatSync(file, { bigint: true });
  assert.equal(stat.isSymbolicLink(), false);
  assert.equal(
    path.resolve(fs.realpathSync(file)).toLowerCase(),
    path.resolve(file).toLowerCase(),
  );
  return String(stat.ino);
}
function assertIdentity(file, expected) {
  assert.equal(identity(file), expected, "Owned journal path identity changed");
}
const quote = (value) => {
  assert.equal(typeof value, "string");
  return value.replace(/'/g, "''");
};
function aclScripts(file, sddl, directory = false) {
  assert.ok(typeof sddl === "string" && sddl.length > 0 && !sddl.includes("'"));
  const kind = directory ? "Directory" : "File",
    right = directory ? "ListDirectory" : "ReadData",
    native = `[IO.${kind}]::SetAccessControl('${quote(file)}',$a)`,
    init = `$a=[Security.AccessControl.${kind}Security]::new();$a.SetSecurityDescriptorSddlForm('${sddl}',[Security.AccessControl.AccessControlSections]::Access);`;
  return {
    deny: `${init}$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User;$rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::${right},[Security.AccessControl.AccessControlType]::Deny);$a.AddAccessRule($rule);${native}`,
    restore: init + native,
  };
}
async function qualifyJournalReadRefusals({ gate, powershell: ps, workDir }) {
  assert.equal(process.platform, "win32");
  assert.equal(typeof ps, "function");
  assertCleanupSafe(workDir);
  const parentId = identity(workDir),
    directory = fs.mkdtempSync(path.join(workDir, "journal-read-refusal-")),
    directoryId = identity(directory),
    enrollmentId = crypto.randomUUID(),
    containerName = `tokentimer-enr-${enrollmentId}`,
    guard = path.join(workDir, preserveGuardName);
  const digest = (file) =>
      crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex"),
    assertDirectory = () => {
      assertIdentity(workDir, parentId);
      assertIdentity(directory, directoryId);
    };
  let primary,
    preserve = false;
  try {
    config.ensureConfigDir(directory);
    const keyPath = path.join(directory, "temporary-csr.key");
    keys.generateKeyPairToFile({ keyPath, algorithm: "ec-p256" });
    const keyId = identity(keyPath),
      keyHash = digest(keyPath),
      csr = keys.generateCsr({
        keyPath,
        subject: { commonName: "journal-refusal.example.test" },
        altNames: ["journal-refusal.example.test"],
      });
    const spkiSha256 = crypto
      .createHash("sha256")
      .update(
        crypto
          .createPublicKey(csr.publicKeyPem)
          .export({ type: "spki", format: "der" }),
      )
      .digest("hex");
    // No private key is needed by the journal reader; remove the exact owned
    // software key before either access fault. No CNG key exists for this name.
    assertIdentity(keyPath, keyId);
    assert.equal(digest(keyPath), keyHash);
    fs.unlinkSync(keyPath);
    assert.equal(fs.existsSync(keyPath), false);
    const { csrSha256 } = await journal.writeCsrArtifact({
      stateDir: directory,
      enrollmentId,
      csrPem: csr.csrPem,
    });
    await journal.writeEnrollmentJournal(directory, enrollmentId, {
      state: "prepared",
      attempt: 1,
      containerName,
      snapshotSha256: crypto
        .createHash("sha256")
        .update("owned-journal-read-refusal")
        .digest("hex"),
      csrSha256,
      csrSpkiSha256: spkiSha256,
      templateOid: "1.3.6.1.4.1.311.21.8.1",
      jobId: crypto.randomUUID(),
    });
    const journalFile = journal.journalV2Path(directory, enrollmentId),
      csrFile = journal.csrArtifactPath(directory, enrollmentId),
      root = journal.enrollmentsRoot(directory),
      tracked = [directory, root, path.dirname(journalFile), journalFile, csrFile].map((file) => ({
        file,
        id: identity(file),
        hash: fs.statSync(file).isFile() ? digest(file) : null,
      }));
    const assertTracked = () => {
      assertDirectory();
      for (const row of tracked) {
        assertIdentity(row.file, row.id);
        if (row.hash)
          assert.equal(
            digest(row.file),
            row.hash,
            "Owned journal/CSR bytes changed",
          );
      }
    };
    const readable = () => {
      const read = journal.readEnrollmentJournal(directory, enrollmentId);
      assert.equal(read.kind, "valid");
      assert.equal(read.journal.state, "prepared");
      assert.equal(read.journal.csrSpkiSha256, spkiSha256);
      assert.equal(read.artifacts.csrPem, csr.csrPem);
      const protection = journal.listProtectedEnrollmentContainers(directory);
      assert.equal(protection.ok, true);
      assert.equal(protection.containers.has(containerName), true);
      assert.equal(
        journal.isEnrollmentContainerProtected(
          directory,
          enrollmentId,
          containerName,
        ).protected,
        true,
      );
    };
    readable();
    for (const [index, item] of [
      { file: journalFile, directory: false },
      { file: root, directory: true },
    ].entries())
      await gate.scenario(
        scenarios[index],
        () => {
          assertTracked();
          readable();
          const targetId = identity(item.file),
            sddl = ps(
              `(Get-Acl -LiteralPath '${quote(item.file)}').GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)`,
            ),
            scripts = aclScripts(item.file, sddl, item.directory),
            guardBytes = JSON.stringify({
              reason: "journal-native-acl-restoration-unproven",
              token: crypto.randomUUID(),
              directory,
              directoryId,
              target: item.file,
              targetId,
            });
          fs.writeFileSync(guard, guardBytes, { flag: "wx" });
          const guardId = identity(guard);
          let attempted = false;
          try {
            assertIdentity(item.file, targetId);
            attempted = true;
            ps(scripts.deny);
            assert.throws(
              () =>
                item.directory
                  ? fs.readdirSync(item.file)
                  : fs.readFileSync(item.file),
              (error) => ["EACCES", "EPERM"].includes(error.code),
              "Actual native access denial must precede production refusal",
            );
            if (!item.directory) {
              assert.equal(
                journal.readEnrollmentJournal(directory, enrollmentId).kind,
                "corrupt",
              );
              assert.equal(
                journal.isEnrollmentContainerProtected(
                  directory,
                  enrollmentId,
                  containerName,
                ).protected,
                true,
              );
            }
            assert.equal(
              journal.listProtectedEnrollmentContainers(directory).ok,
              false,
              "Unreadable journal inventory must never become an empty protected set",
            );
          } finally {
            try {
              if (attempted) {
                assertIdentity(item.file, targetId);
                ps(scripts.restore);
                assert.equal(
                  ps(
                    `(Get-Acl -LiteralPath '${quote(item.file)}').GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)`,
                  ),
                  sddl,
                  "Exact native ACL must be restored",
                );
              }
              assertTracked();
              readable();
              assertIdentity(guard, guardId);
              assert.equal(
                fs.readFileSync(guard, "utf8") === guardBytes,
                true,
                "Ownership guard bytes changed",
              );
              fs.unlinkSync(guard);
            } catch (error) {
              preserve = true;
              throw error;
            }
          }
        },
        {
          evidenceLevel: "real-host",
          oracle:
            "Actual OS journal ReadData/root ListDirectory denial, production corrupt/global-defer result, exact native identities/bytes/ACL restored and positive read recovered; temporary software CSR only",
        },
      );
  } catch (error) {
    primary = error;
  }
  try {
    assert.equal(preserve, false);
    assertCleanupSafe(workDir);
    assertDirectory();
    assert.equal(path.dirname(directory), path.resolve(workDir));
    assert.match(path.basename(directory), /^journal-read-refusal-/);
    fs.rmSync(directory, { recursive: true });
    assert.equal(fs.existsSync(directory), false);
  } catch (error) {
    throw new AggregateError(
      [...(primary ? [primary] : []), error],
      "Owned journal ACL restoration/cleanup incomplete; preserve state",
    );
  }
  if (primary) throw primary;
  const value = {
    scope,
    installedServiceQualified: false,
    nativeCngQualified: false,
    ...Object.fromEntries(fields.map((field) => [field, true])),
  };
  verifyProof(value);
  return value;
}
module.exports = {
  scenarios,
  fields,
  scope,
  requiredSources,
  preserveGuardName,
  verifyProof,
  assertCleanupSafe,
  identity,
  assertIdentity,
  aclScripts,
  qualifyJournalReadRefusals,
};
