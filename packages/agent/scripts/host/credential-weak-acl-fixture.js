/*
 * Qualification notes: native-credential-weak-acl
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Use actual protected credential reader against owned public temporary control files with real weak
 * Windows ACLs. Independently observe inappropriate access, require exact production refusal instead
 * of accepting unreadable/weak state, restore original DACL/bytes/native identity and reader recovery.
 * Suspended retained holder plus bounded ownership/drain guard confines mutation/cleanup; never
 * publish credential/control contents or raw ACLs. Not installed credential compromise recovery or SCM
 * qualification.
 */
"use strict";
/** Supporting real Windows ACL admission. The credential is a public synthetic
 * control by default. An owned disposable installed journey may supply its
 * synthetic workspace credential and run startup checks while the DACL is held.
 * This holder never starts SCM or touches CNG/CA itself. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  { spawnSync } = require("node:child_process"),
  { isDeepStrictEqual } = require("node:util");
const config = require("../../src/config"),
  platform = require("../../src/platform"),
  contained = require("../../../../tests/e2e/helpers/certops-windows-contained-process");
const SCENARIO = "windows-credential-native-weak-acl-refusal",
  SCOPE = "native-public-control-credential-weak-acl-refusal",
  GUARD = ".preserve-credential-weak-acl.json";
const FLAGS = Object.freeze([
  "actualOriginalCredentialReadable",
  "nativeOriginalHandleAndIdentity",
  "actualExplicitUntrustedReadAce",
  "protectedDaclRemainedReadable",
  "actualProductionAclRefusal",
  "credentialBytesAndIdentityUnchanged",
  "exactOriginalDaclRestored",
  "productionCredentialReaderRecovered",
  "containedHolderDrained",
  "ownedTemporaryStateRemoved",
]);
const REQUIRED_SOURCES = Object.freeze([
  "packages/agent/scripts/host/credential-weak-acl-fixture.js",
  "packages/agent/scripts/host/credential-weak-acl-hold.ps1",
  "packages/agent/src/config/index.js",
  "packages/agent/src/platform/index.js",
  ...contained.REQUIRED_SOURCES,
]);
const active = new Set(),
  hash = (b) => crypto.createHash("sha256").update(b).digest("hex"),
  key = (p) => path.resolve(p).toLowerCase();
function identity(file) {
  const s = fs.lstatSync(file, { bigint: true });
  assert.ok(!s.isSymbolicLink() && s.ino > 0n && s.dev > 0n);
  assert.equal(key(fs.realpathSync(file)), key(file));
  return `${s.dev}:${s.ino}`;
}
function readRecord(file, max = 16384) {
  const before = fs.lstatSync(file, { bigint: true });
  assert.ok(
    before.isFile() &&
      !before.isSymbolicLink() &&
      before.size >= 0n &&
      before.size <= BigInt(max),
  );
  const fd = fs.openSync(
    file,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
  );
  try {
    const a = fs.fstatSync(fd, { bigint: true });
    assert.ok(a.isFile());
    assert.equal(`${a.dev}:${a.ino}`, `${before.dev}:${before.ino}`);
    const b = Buffer.alloc(max + 1);
    let n = 0;
    while (n < b.length) {
      const r = fs.readSync(fd, b, n, b.length - n, null);
      if (!r) break;
      n += r;
    }
    const z = fs.fstatSync(fd, { bigint: true }),
      p = fs.lstatSync(file, { bigint: true });
    for (const x of [before, z, p])
      for (const field of ["dev", "ino", "size", "mtimeNs", "ctimeNs"])
        assert.equal(x[field], a[field]);
    assert.equal(n, Number(a.size));
    assert.ok(n <= max);
    return { bytes: b.subarray(0, n), id: `${a.dev}:${a.ino}` };
  } finally {
    fs.closeSync(fd);
  }
}
function read(file, max = 16384) {
  return readRecord(file, max).bytes;
}
function assertOriginal(file, original, max = 16384) {
  const current = readRecord(file, max);
  assert.ok(
    current.id === original.id && current.bytes.equals(original.bytes),
    "Original protocol file changed; preserve replacement",
  );
  return current.bytes;
}
function removeOriginal(file, original, max = 16384) {
  assertOriginal(file, original, max);
  fs.unlinkSync(file);
}
function assertCleanupSafe(root) {
  assert.ok(
    !active.has(key(root)) && !fs.existsSync(path.join(root, GUARD)),
    "Preserve unresolved weak credential ACL fixture",
  );
  contained.assertCleanupSafe(root);
}
function beginGuard(root) {
  assertCleanupSafe(root);
  const original = identity(root),
    file = path.join(root, GUARD),
    bytes = Buffer.from(crypto.randomBytes(32).toString("hex"));
  active.add(key(root));
  fs.writeFileSync(file, bytes, { flag: "wx", mode: 0o600 });
  const guardId = identity(file);
  const check = () => {
    assert.equal(identity(root), original);
    assert.equal(identity(file), guardId);
    assert.ok(read(file, 128).equals(bytes));
  };
  return {
    check,
    release() {
      check();
      fs.unlinkSync(file);
      active.delete(key(root));
    },
  };
}
function verifyProof(p) {
  assert.ok(p && typeof p === "object" && !Array.isArray(p));
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "scope",
      "installedServiceStartupQualified",
      "nativeCertificateQualified",
      "untrustedProcessReadQualified",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(p.scope, SCOPE);
  for (const k of [
    "installedServiceStartupQualified",
    "nativeCertificateQualified",
    "untrustedProcessReadQualified",
  ])
    assert.equal(p[k], false);
  for (const f of FLAGS) assert.equal(p[f], true);
  return p;
}
function verifyReady(v, nonce, fileId) {
  assert.deepEqual(
    Object.keys(v).sort(),
    [
      "schemaVersion",
      "nonce",
      "fileId",
      "originalDacl",
      "appliedDacl",
      "untrustedSid",
      "readMask",
      "retainedOriginalHandle",
    ].sort(),
  );
  assert.equal(v.schemaVersion, 1);
  assert.equal(v.nonce, nonce);
  assert.equal(v.fileId, fileId);
  assert.equal(v.untrustedSid, "S-1-1-0");
  assert.equal(v.readMask, 1);
  assert.equal(v.retainedOriginalHandle, true);
  for (const name of ["originalDacl", "appliedDacl"])
    assert.ok(
      typeof v[name] === "string" &&
        v[name].length > 0 &&
        v[name].length <= 65536,
    );
  assert.notEqual(v.originalDacl, v.appliedDacl);
  const parsed = platform.parseDaclSddl(v.appliedDacl);
  assert.equal(parsed.protectedDacl, true);
  assert.ok(parsed.aces.some((a) => a.sid === "S-1-1-0"));
  return v;
}
async function until(check) {
  const end = performance.now() + 60000;
  while (performance.now() < end) {
    const value = check();
    if (value) return value;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw Error("Owned weak ACL protocol timed out");
}
function nativeAclScript(file) {
  return `$a=Get-Acl -LiteralPath '${file.replaceAll("'", "''")}';$r=@($a.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier])|Where-Object {$_.IdentityReference.Value -eq 'S-1-1-0' -and $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow});if($r.Count -ne 1 -or [int]$r[0].FileSystemRights -ne 1 -or !$a.AreAccessRulesProtected){throw 'Exact native explicit untrusted ReadData ACE required'};@{protected=$a.AreAccessRulesProtected;explicitAllowCount=$r.Count;readMask=[int]$r[0].FileSystemRights}|ConvertTo-Json -Compress`;
}
function holderEnvironment(source = process.env) {
  const names = new Set([
    "path",
    "systemroot",
    "windir",
    "comspec",
    "temp",
    "tmp",
    "userprofile",
    "appdata",
    "localappdata",
    "programdata",
    "programfiles",
    "programfiles(x86)",
    "systemdrive",
    "pathext",
  ]);
  return Object.fromEntries(
    Object.entries(source).filter(
      ([name, value]) =>
        names.has(name.toLowerCase()) && typeof value === "string",
    ),
  );
}
function qualify({ gate, workDir, installedCredential }) {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST, "1");
  return gate.scenario(
    SCENARIO,
    async () => {
      const owner = beginGuard(workDir),
        directory = fs.mkdtempSync(
          path.join(workDir, "public-credential-acl-"),
        ),
        directoryId = identity(directory);
      platform.applyRestrictivePermissions(directory, { kind: "directory" });
      if(installedCredential){assert.equal(path.resolve(installedCredential.configDir),path.join(path.resolve(workDir),"state"));assert.equal(typeof installedCredential.onWeak,"function");}
      const credentialDirectory=installedCredential?installedCredential.configDir:directory;
      const credential = installedCredential?config.readCredential(credentialDirectory):"ttagent_publiccontrol_publicfixturevalue123456789";
      if(!installedCredential)config.writeCredential(directory, credential);
      assert.ok(
        config.readCredential(credentialDirectory) === credential,
        "Actual public control credential unreadable",
      );
      const file = path.join(credentialDirectory, "credential"),
        fileId = identity(file),
        original = read(file),
        originalDacl = platform.readWindowsSddl(file),
        nonce = crypto.randomBytes(32).toString("hex"),
        context = {
          schemaVersion: 1,
          targetKind:installedCredential?"installed-owned-credential":"public-control",
          nonce,
          target: file,
          volume: fileId.split(":")[0],
          inode: fileId.split(":")[1],
          originalDacl,
          ready: path.join(directory, "ready.json"),
          release: path.join(directory, "release"),
          restored: path.join(directory, "restored.json"),
        },
        input = path.join(directory, "context.json"),
        contextBytes = Buffer.from(JSON.stringify(context));
      fs.writeFileSync(input, contextBytes, { flag: "wx", mode: 0o600 });
      const snapshots = new Map([
        [file, { id: fileId, bytes: original }],
        [input, readRecord(input)],
      ]);
      assertOriginal(input, snapshots.get(input));
      platform.applyRestrictivePermissions(input, { kind: "file" });
      let resource,
        ready,
        failure,
        drained,
        wrapperClosed = false;
      const powershell = path.join(
        process.env.SystemRoot,
        "System32/WindowsPowerShell/v1.0/powershell.exe",
      );
      try {
        resource = await contained.startContainedNativeProcess({
          executable: powershell,
          args: [
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            path.join(__dirname, "credential-weak-acl-hold.ps1"),
            "-ContextPath",
            input,
            "-ContextSha256",
            hash(contextBytes),
          ],
          environment: holderEnvironment(),
          workDir,
          expectedSid: platform.currentUserSid(),
          maxLifetimeMs: 180000,
          onCreated(value) {
            resource = value;
            value.wrapper.once("close", () => {
              wrapperClosed = true;
            });
          },
        });
        ready = verifyReady(
          await until(
            () =>
              fs.existsSync(context.ready) &&
              (() => {
                const snapshot = readRecord(context.ready),
                  value = JSON.parse(snapshot.bytes.toString("utf8"));
                verifyReady(value, nonce, fileId);
                snapshots.set(context.ready, snapshot);
                return value;
              })(),
          ),
          nonce,
          fileId,
        );
        owner.check();
        assert.equal(ready.originalDacl, originalDacl);
        assert.equal(identity(directory), directoryId);
        assert.equal(identity(file), fileId);
        assert.ok(
          read(file).equals(original),
          "Weak ACL must remain actually readable",
        );
        assert.equal(platform.readWindowsSddl(file), ready.appliedDacl);
        const observation = spawnSync(
          powershell,
          [
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            Buffer.from(nativeAclScript(file), "utf16le").toString("base64"),
          ],
          {
            encoding: "utf8",
            windowsHide: true,
            timeout: 30000,
            env: holderEnvironment(),
          },
        );
        assert.ok(
          !observation.error &&
            observation.status === 0 &&
            observation.signal === null,
          "Independent native ACL read failed",
        );
        assert.deepEqual(JSON.parse(observation.stdout.trim()), {
          protected: true,
          explicitAllowCount: 1,
          readMask: 1,
        });
        assert.throws(
          () => config.readCredential(credentialDirectory),
          (error) =>
            error.message.includes(
              "refusing to use credential file: its ACL grants access to",
            ) && error.message.includes("S-1-1-0"),
        );
        if(installedCredential)await installedCredential.onWeak();
      } catch (error) {
        failure = error;
      } finally {
        if (ready) {
          try {
            owner.check();
            const releaseTemporary=context.release+".writing";
            fs.writeFileSync(releaseTemporary,nonce,{flag:"wx",mode:0o600});
            const releaseRecord=readRecord(releaseTemporary);
            fs.linkSync(releaseTemporary,context.release);
            assertOriginal(releaseTemporary,releaseRecord);
            fs.unlinkSync(releaseTemporary);
            snapshots.set(context.release, readRecord(context.release));
            await until(() => {
              if (!fs.existsSync(context.restored)) return false;
              const snapshot = readRecord(context.restored),
                value = JSON.parse(snapshot.bytes.toString("utf8"));
              assert.deepEqual(
                Object.keys(value).sort(),
                [
                  "schemaVersion",
                  "nonce",
                  "fileId",
                  "originalDacl",
                  "restored",
                ].sort(),
              );
              assert.equal(value.schemaVersion, 1);
              assert.equal(value.nonce, nonce);
              assert.equal(value.fileId, fileId);
              assert.equal(value.restored, true);
              assert.equal(value.originalDacl, ready.originalDacl);
              snapshots.set(context.restored, snapshot);
              return true;
            });
            await until(() => wrapperClosed);
          } catch (error) {
            failure ??= error;
          }
        }
        if (resource) {
          try {
            drained = await resource.stopAndDrain();
            assert.equal(drained.rootExitCode, 0);
            assert.equal(drained.activeNativeProcesses, 0);
            assert.equal(drained.nativeHandlesClosed, true);
            assert.equal(resource.hasLiveChild(), false);
            assert.equal(resource.hasOwnershipReceipt(), false);
          } catch (error) {
            failure ??= error;
          }
        }
      }
      if (failure) throw failure;
      assert.ok(ready && drained);
      owner.check();
      assert.equal(identity(directory), directoryId);
      assert.equal(identity(file), fileId);
      assert.ok(read(file).equals(original));
      const restored = JSON.parse(
        assertOriginal(
          context.restored,
          snapshots.get(context.restored),
        ).toString("utf8"),
      );
      assert.deepEqual(
        Object.keys(restored).sort(),
        ["schemaVersion", "nonce", "fileId", "originalDacl", "restored"].sort(),
      );
      assert.equal(restored.schemaVersion, 1);
      assert.equal(restored.nonce, nonce);
      assert.equal(restored.fileId, fileId);
      assert.equal(restored.restored, true);
      assert.equal(restored.originalDacl, ready.originalDacl);
      assert.equal(platform.readWindowsSddl(file), ready.originalDacl);
      assert.ok(
        config.readCredential(credentialDirectory) === credential,
        "Actual production reader did not recover",
      );
      const names = [
        ...(!installedCredential?["credential"]:[]),
        "context.json",
        "ready.json",
        "release",
        "restored.json",
      ];
      assert.ok(
        isDeepStrictEqual(fs.readdirSync(directory).sort(), [...names].sort()),
      );
      assert.equal(snapshots.size, names.length+(installedCredential?1:0));
      for (const [file, snapshot] of snapshots) {
        owner.check();
        if(installedCredential&&file===path.join(credentialDirectory,"credential")){assertOriginal(file,snapshot);continue;}
        removeOriginal(file, snapshot);
      }
      assert.equal(identity(directory), directoryId);
      fs.rmdirSync(directory);
      owner.release();
      if(installedCredential)return {originalHandleRestored:true,exactCredentialBytesPreserved:true,actualWeakAclReadRefused:true};
      const proof = verifyProof({
        scope: SCOPE,
        installedServiceStartupQualified: false,
        nativeCertificateQualified: false,
        untrustedProcessReadQualified: false,
        ...Object.fromEntries(FLAGS.map((f) => [f, true])),
      });
      gate.report.fixtureSources ??= [];
      for (const f of REQUIRED_SOURCES)
        if (!gate.report.fixtureSources.some((x) => x.file === f))
          gate.report.fixtureSources.push({
            file: f,
            sha256: hash(
              fs.readFileSync(path.resolve(__dirname, "../../../..", f)),
            ),
          });
      return proof;
    },
    {
      evidenceLevel: "real-host",
      oracle:
        "actual native protected DACL Everyone ReadData, readable public control, production credential ACL refusal, exact original-handle restoration and reader recovery; no installed or exfiltration claim",
    },
  );
}
module.exports = {
  SCENARIO,
  SCOPE,
  GUARD,
  FLAGS,
  REQUIRED_SOURCES,
  verifyProof,
  verifyReady,
  read,
  readRecord,
  assertOriginal,
  removeOriginal,
  beginGuard,
  assertCleanupSafe,
  nativeAclScript,
  holderEnvironment,
  qualify,
  withInstalledCredential:({workDir,configDir,onWeak})=>qualify({workDir,installedCredential:{configDir,onWeak},gate:{scenario:(_id,run)=>run(),report:{}}}),
};
