"use strict";

// Retain the exact original configuration file, never repair a preexisting ACL
// or overwrite a foreign path/object. This module proves file ownership only;
// its native caller must stop/drain SCM before each write and keep a separate
// operation guard through the final original-API restart and gateway drainage.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const {
  applyRestrictivePermissions,
} = require("../../../packages/agent/src/platform");
const active = new Set();
const GUARD = ".adcs-result-configuration-active.json";
const MAXIMUM = 65536;
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const q = (value) => value.replace(/'/g, "''");
const canonical = (value) =>
  process.platform === "win32"
    ? path.normalize(value).toLowerCase()
    : path.normalize(value);
function id(stat, directory = false) {
  assert.ok(
    (directory ? stat.isDirectory() : stat.isFile()) &&
      !stat.isSymbolicLink() &&
      stat.ino > 0n &&
      stat.dev > 0n,
    "Provable original regular configuration identity required",
  );
  return `${stat.dev}:${stat.ino}`;
}
function assertCleanupSafe(workDir) {
  const root = path.resolve(workDir);
  assert.ok(
    !active.has(root.toLowerCase()) && !fs.existsSync(path.join(root, GUARD)),
    "Unresolved result configuration ownership preserves the fixture",
  );
}
function readHandle(fd, file, expectedId) {
  const before = fs.fstatSync(fd, { bigint: true });
  assert.equal(id(before), expectedId);
  assert.ok(before.size > 0n && before.size <= BigInt(MAXIMUM));
  const bytes = Buffer.alloc(MAXIMUM + 1);
  let length = 0;
  while (length < bytes.length) {
    const n = fs.readSync(fd, bytes, length, bytes.length - length, length);
    if (n === 0) break;
    length += n;
  }
  const after = fs.fstatSync(fd, { bigint: true }),
    current = fs.lstatSync(file, { bigint: true });
  assert.equal(id(after), expectedId);
  assert.equal(id(current), expectedId);
  assert.ok(
    before.size === after.size &&
      after.size === current.size &&
      before.mtimeNs === after.mtimeNs &&
      after.mtimeNs === current.mtimeNs &&
      before.ctimeNs === after.ctimeNs &&
      after.ctimeNs === current.ctimeNs &&
      BigInt(length) === before.size &&
      length <= MAXIMUM,
    "Configuration changed during bounded original-handle read",
  );
  return bytes.subarray(0, length);
}
function permissionsScript(file, directory = false) {
  return `$f=Get-Item -LiteralPath '${q(file)}' -Force;if(($f.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0-or$f.PSIsContainer-ne $${directory ? "true" : "false"}){throw 'Original configuration regular identity required'};$a=Get-Acl -LiteralPath '${q(file)}';if(!$a.AreAccessRulesProtected){throw 'Protected original configuration DACL required'};$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;foreach($r in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($r.IsInherited-or($r.AccessControlType-eq'Allow'-and$r.IdentityReference.Value-notin @($sid,'S-1-5-18','S-1-5-32-544'))){throw 'Foreign configuration ACL refused'}};$a.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)`;
}
function createConfigurationOwner({
  workDir,
  configDir,
  expectedIdentity,
  ps,
  verifyStopped,
}) {
  const root = path.resolve(workDir),
    directory = path.resolve(configDir),
    file = path.join(directory, "config.json");
  assert.equal(directory, path.join(root, "agent"));
  assert.equal(typeof ps, "function");
  assert.equal(typeof verifyStopped, "function");
  assert.match(expectedIdentity, /^[1-9][0-9]*:[1-9][0-9]*$/);
  assertCleanupSafe(root);
  active.add(root.toLowerCase());
  const rootId = id(fs.lstatSync(root, { bigint: true }), true),
    directoryId = id(fs.lstatSync(directory, { bigint: true }), true);
  for (const item of [root, directory, file])
    assert.equal(
      canonical(fs.realpathSync.native(item)),
      canonical(item),
      "Original configuration namespace changed",
    );
  const rootDacl = ps(permissionsScript(root, true)),
    directoryDacl = ps(permissionsScript(directory, true));
  assert.ok(
    typeof rootDacl === "string" &&
      rootDacl.startsWith("D:") &&
      typeof directoryDacl === "string" &&
      directoryDacl.startsWith("D:"),
  );
  const guard = path.join(root, GUARD),
    guardBytes = Buffer.from(
      JSON.stringify({ schemaVersion: 1, nonce: crypto.randomUUID() }),
    );
  fs.writeFileSync(guard, guardBytes, { flag: "wx" });
  applyRestrictivePermissions(guard, { kind: "file" });
  const guardId = id(fs.lstatSync(guard, { bigint: true }));
  assert.ok(
    id(fs.lstatSync(file, { bigint: true })) === expectedIdentity,
    "Original registered configuration file was replaced",
  );
  const fd = fs.openSync(file, "r+");
  let closed = false,
    restored = false;
  try {
    const fileId = id(fs.fstatSync(fd, { bigint: true }));
    assert.ok(
      fileId === expectedIdentity,
      "Original registered configuration handle mismatch",
    );
    const original = readHandle(fd, file, fileId),
      parsed = JSON.parse(original.toString("utf8"));
    assert.ok(parsed && typeof parsed === "object" && !Array.isArray(parsed));
    assert.equal(new URL(parsed.serverUrl).protocol, "https:");
    const originalDacl = ps(permissionsScript(file));
    assert.ok(
      typeof originalDacl === "string" && originalDacl.startsWith("D:"),
    );
    let expected = original;
    const check = () => {
      assert.equal(
        closed,
        false,
        "Original configuration descriptor already closed",
      );
      assert.equal(id(fs.lstatSync(root, { bigint: true }), true), rootId);
      assert.equal(
        id(fs.lstatSync(directory, { bigint: true }), true),
        directoryId,
      );
      for (const item of [root, directory, file])
        assert.equal(
          canonical(fs.realpathSync.native(item)),
          canonical(item),
          "Original configuration namespace changed",
        );
      assert.equal(id(fs.lstatSync(guard, { bigint: true })), guardId);
      const g = fs.openSync(guard, "r");
      try {
        assert.ok(
          readHandle(g, guard, guardId).equals(guardBytes),
          "Original configuration guard changed",
        );
      } finally {
        fs.closeSync(g);
      }
      assert.ok(
        readHandle(fd, file, fileId).equals(expected),
        "Foreign configuration bytes must be preserved",
      );
      assert.ok(
        ps(permissionsScript(file)) === originalDacl,
        "Foreign configuration permissions must be preserved",
      );
      assert.ok(
        ps(permissionsScript(root, true)) === rootDacl &&
          ps(permissionsScript(directory, true)) === directoryDacl,
        "Foreign configuration-directory permissions must be preserved",
      );
    };
    const write = (bytes) => {
      assert.ok(
        Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= MAXIMUM,
      );
      assert.equal(
        verifyStopped(),
        true,
        "Synchronous fresh native stopped/drained verification required",
      );
      check();
      let offset = 0;
      while (offset < bytes.length) {
        const n = fs.writeSync(
          fd,
          bytes,
          offset,
          bytes.length - offset,
          offset,
        );
        assert.ok(n > 0);
        offset += n;
      }
      fs.ftruncateSync(fd, bytes.length);
      fs.fsyncSync(fd);
      expected = bytes;
      check();
      assert.equal(
        verifyStopped(),
        true,
        "Synchronous fresh native stopped/drained verification required",
      );
    };
    return {
      originalSha256: hash(original),
      originalServerUrl: parsed.serverUrl,
      applyGateway(value) {
        assert.ok(
          expected.equals(original) && !restored,
          "Configuration can be applied only once",
        );
        const url = new URL(value);
        assert.equal(url.protocol, "http:");
        assert.equal(url.hostname, "127.0.0.1");
        assert.ok(
          !url.username &&
            !url.password &&
            !url.search &&
            !url.hash &&
            url.pathname === "/" &&
            Number(url.port) > 0,
        );
        const bytes = Buffer.from(
          JSON.stringify({
            ...parsed,
            serverUrl: url.origin,
            allowInsecureLocalHttp: true,
          }),
        );
        write(bytes);
        return hash(bytes);
      },
      restore() {
        assert.equal(restored, false);
        write(original);
        restored = true;
      },
      complete() {
        check();
        assert.equal(restored, true);
        assert.ok(expected.equals(original));
        fs.closeSync(fd);
        closed = true;
        fs.unlinkSync(guard);
        active.delete(root.toLowerCase());
      },
      close() {
        if (!closed) {
          fs.closeSync(fd);
          closed = true;
        }
      },
    };
  } catch {
    if (!closed) fs.closeSync(fd);
    throw new Error(
      "Owned result configuration capture failed; preserve fixture",
    );
  }
}
module.exports = {
  assertCleanupSafe,
  createConfigurationOwner,
  permissionsScript,
  readHandle,
};
