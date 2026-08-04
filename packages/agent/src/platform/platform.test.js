"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { describe, it, beforeEach, afterEach } = require("node:test");

const platform = require("./index.js");
const durability = require("./durability.js");

const IS_WIN32 = process.platform === "win32";
const OWN_SID = "S-1-5-21-1-2-3-1001";

/**
 * Builds a spawn stub. Each entry maps an executable name to a handler that
 * receives the arguments and returns { status, stdout, stderr } or an error.
 * `powershell` defaults to reporting OWN_SID as the owner, since almost every
 * test exercises a path the agent itself created and therefore legitimately
 * owns; tests that care about a different owner override it explicitly.
 */
function fakeSpawn(handlers) {
  const calls = [];
  const merged = { powershell: () => ({ stdout: `${OWN_SID}\r\n` }), ...handlers };
  const spawn = (file, args) => {
    calls.push({ file, args });
    const handler = merged[file];
    if (!handler) return { error: Object.assign(new Error("nope"), { code: "ENOENT" }) };
    return { status: 0, stdout: "", stderr: "", ...handler(args) };
  };
  spawn.calls = calls;
  return spawn;
}

function whoamiHandler() {
  return { stdout: `"host\\agent","${OWN_SID}"\r\n` };
}

/** Writes an icacls /save-shaped UTF-16LE file for the /save target path. */
function icaclsSaveHandler(sddl) {
  return (args) => {
    const saveIndex = args.indexOf("/save");
    if (saveIndex !== -1) {
      fs.writeFileSync(args[saveIndex + 1], Buffer.from(`name\r\n${sddl}\r\n`, "utf16le"));
    }
    return { status: 0 };
  };
}

describe("platform: SDDL parsing", () => {
  it("reads the protected flag, aliases and inherited entries", () => {
    const parsed = platform.parseDaclSddl(
      `D:PAI(A;;FA;;;${OWN_SID})(A;;FA;;;SY)(A;ID;0x1200a9;;;BU)`,
    );
    assert.equal(parsed.protectedDacl, true);
    assert.deepEqual(
      parsed.aces.map((ace) => ace.sid),
      [OWN_SID, platform.SYSTEM_SID, "S-1-5-32-545"],
    );
    assert.deepEqual(
      parsed.aces.map((ace) => ace.inherited),
      [false, false, true],
    );
  });

  it("does not report a protected DACL for an inheriting one", () => {
    const parsed = platform.parseDaclSddl(`D:AI(A;ID;FA;;;${OWN_SID})`);
    assert.equal(parsed.protectedDacl, false);
    assert.equal(parsed.aces.length, 1);
  });

  it("refuses SDDL without a DACL", () => {
    assert.throws(() => platform.parseDaclSddl("O:BAG:BA"), /SDDL has no DACL/);
  });
});

describe("platform: permission application", () => {
  beforeEach(() => platform.resetPlatformCaches());
  afterEach(() => platform.resetPlatformCaches());

  it("chmods on POSIX and never shells out", () => {
    const chmodCalls = [];
    const spawn = fakeSpawn({});
    const result = platform.applyRestrictivePermissions("/state/credential", {
      platform: "linux",
      spawn,
      fsImpl: { chmodSync: (p, mode) => chmodCalls.push([p, mode]) },
    });
    assert.deepEqual(result, { mechanism: "posix-mode", mode: 0o600 });
    assert.deepEqual(chmodCalls, [["/state/credential", 0o600]]);
    assert.equal(spawn.calls.length, 0);
  });

  it("uses 0700 for directories on POSIX", () => {
    const chmodCalls = [];
    platform.applyRestrictivePermissions("/state", {
      kind: "directory",
      platform: "linux",
      fsImpl: { chmodSync: (p, mode) => chmodCalls.push([p, mode]) },
    });
    assert.deepEqual(chmodCalls, [["/state", 0o700]]);
  });

  it("removes inheritance and grants only SYSTEM plus its own identity on win32", () => {
    const spawn = fakeSpawn({
      whoami: whoamiHandler,
      icacls: icaclsSaveHandler(`D:PAI(A;;FA;;;${OWN_SID})(A;;FA;;;SY)`),
    });
    const result = platform.applyRestrictivePermissions("C:\\state\\credential", {
      platform: "win32",
      spawn,
      tmpDir: os.tmpdir(),
    });
    assert.equal(result.mechanism, "windows-acl");
    assert.equal(result.inheritance, "removed");
    assert.deepEqual(result.removed, []);
    const icacls = spawn.calls.find((call) => call.file === "icacls");
    assert.deepEqual(icacls.args, [
      "C:\\state\\credential",
      "/inheritance:r",
      "/grant:r",
      `*${platform.SYSTEM_SID}:(F)`,
      `*${OWN_SID}:(F)`,
    ]);
  });

  it("removes a foreign ACE that survived /grant:r, then re-verifies", () => {
    // icacls /grant:r only replaces the entries of the principals it names, so
    // a pre-existing explicit Everyone ACE survives it.
    const sddls = [
      `D:PAI(A;;FA;;;${OWN_SID})(A;;FA;;;SY)(A;;FA;;;WD)`,
      `D:PAI(A;;FA;;;${OWN_SID})(A;;FA;;;SY)`,
    ];
    let read = 0;
    const spawn = fakeSpawn({
      whoami: whoamiHandler,
      icacls: (args) => {
        const saveIndex = args.indexOf("/save");
        if (saveIndex !== -1) {
          fs.writeFileSync(
            args[saveIndex + 1],
            Buffer.from(`name\r\n${sddls[Math.min(read++, sddls.length - 1)]}\r\n`, "utf16le"),
          );
        }
        return { status: 0 };
      },
    });
    const result = platform.applyRestrictivePermissions("C:\\state\\credential", {
      platform: "win32",
      spawn,
      tmpDir: os.tmpdir(),
    });
    assert.deepEqual(result.removed, ["S-1-1-0"]);
    const removeCall = spawn.calls.find((call) => call.args.includes("/remove:g"));
    assert.deepEqual(removeCall.args, [
      "C:\\state\\credential",
      "/remove:g",
      "*S-1-1-0",
      "/remove:d",
      "*S-1-1-0",
    ]);
  });

  it("fails when a foreign ACE is still present after enforcement", () => {
    const spawn = fakeSpawn({
      whoami: whoamiHandler,
      icacls: icaclsSaveHandler(`D:PAI(A;;FA;;;${OWN_SID})(A;;FA;;;SY)(A;;FA;;;WD)`),
    });
    assert.throws(
      () =>
        platform.applyRestrictivePermissions("C:\\state\\credential", {
          platform: "win32",
          spawn,
          tmpDir: os.tmpdir(),
        }),
      /still grants S-1-1-0 after enforcement/,
    );
  });

  it("grants inheritable rights on a directory so new files start restricted", () => {
    const spawn = fakeSpawn({
      whoami: whoamiHandler,
      icacls: icaclsSaveHandler(`D:PAI(A;OICI;FA;;;${OWN_SID})(A;OICI;FA;;;SY)`),
    });
    platform.applyRestrictivePermissions("C:\\state", {
      kind: "directory",
      platform: "win32",
      spawn,
      tmpDir: os.tmpdir(),
    });
    const icacls = spawn.calls.find((call) => call.file === "icacls");
    assert.ok(icacls.args.includes(`*${platform.SYSTEM_SID}:(OI)(CI)(F)`));
    assert.ok(icacls.args.includes(`*${OWN_SID}:(OI)(CI)(F)`));
  });

  it("collapses the grant list when the agent already runs as SYSTEM", () => {
    const spawn = fakeSpawn({
      whoami: () => ({ stdout: `"nt authority\\system","${platform.SYSTEM_SID}"\r\n` }),
      icacls: icaclsSaveHandler(`D:PAI(A;;FA;;;SY)`),
      powershell: () => ({ stdout: `${platform.SYSTEM_SID}\r\n` }),
    });
    const result = platform.applyRestrictivePermissions("C:\\state\\credential", {
      platform: "win32",
      spawn,
      tmpDir: os.tmpdir(),
    });
    assert.deepEqual(result.principals, [platform.SYSTEM_SID]);
  });

  it("fails instead of continuing when icacls is unavailable", () => {
    const spawn = fakeSpawn({ whoami: whoamiHandler });
    assert.throws(
      () =>
        platform.applyRestrictivePermissions("C:\\state\\credential", {
          platform: "win32",
          spawn,
        }),
      /icacls is not available on this host/,
    );
  });

  it("fails when icacls reports a non-zero exit", () => {
    const spawn = fakeSpawn({
      whoami: whoamiHandler,
      icacls: () => ({ status: 5, stderr: "Access is denied." }),
    });
    assert.throws(
      () =>
        platform.applyRestrictivePermissions("C:\\state\\credential", {
          platform: "win32",
          spawn,
        }),
      /icacls exited 5 .*remains unprotected/s,
    );
  });

  it("fails when the agent's own SID cannot be resolved", () => {
    const spawn = fakeSpawn({ whoami: () => ({ stdout: "no sid here" }) });
    assert.throws(
      () => platform.currentUserSid({ spawn, useCache: false }),
      /could not parse a SID/,
    );
  });

  it("fails closed when the resulting owner is not in the trusted allowlist", () => {
    const spawn = fakeSpawn({
      whoami: whoamiHandler,
      icacls: icaclsSaveHandler(`D:PAI(A;;FA;;;${OWN_SID})(A;;FA;;;SY)`),
      powershell: () => ({ stdout: "S-1-5-21-9-9-9-9999\r\n" }),
    });
    assert.throws(
      () =>
        platform.applyRestrictivePermissions("C:\\state\\credential", {
          platform: "win32",
          spawn,
          tmpDir: os.tmpdir(),
        }),
      /owner is S-1-5-21-9-9-9-9999.*not one of the trusted owners/s,
    );
  });

  it("accepts SYSTEM or Administrators as a trusted owner", () => {
    const spawn = fakeSpawn({
      whoami: whoamiHandler,
      icacls: icaclsSaveHandler(`D:PAI(A;;FA;;;${OWN_SID})(A;;FA;;;SY)`),
      powershell: () => ({ stdout: `${platform.ADMINISTRATORS_SID}\r\n` }),
    });
    const result = platform.applyRestrictivePermissions("C:\\state\\credential", {
      platform: "win32",
      spawn,
      tmpDir: os.tmpdir(),
    });
    assert.equal(result.mechanism, "windows-acl");
  });

  it("fails closed when powershell is unavailable to verify the owner", () => {
    const spawn = fakeSpawn({
      whoami: whoamiHandler,
      icacls: icaclsSaveHandler(`D:PAI(A;;FA;;;${OWN_SID})(A;;FA;;;SY)`),
    });
    const bareSpawn = (file, args) => {
      if (file === "powershell") return { error: Object.assign(new Error("nope"), { code: "ENOENT" }) };
      return spawn(file, args);
    };
    assert.throws(
      () =>
        platform.applyRestrictivePermissions("C:\\state\\credential", {
          platform: "win32",
          spawn: bareSpawn,
          tmpDir: os.tmpdir(),
        }),
      /powershell is not available on this host/,
    );
  });
});

describe("platform: permission verification", () => {
  let tmpDir;

  beforeEach(() => {
    platform.resetPlatformCaches();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-platform-"));
  });

  afterEach(() => {
    platform.resetPlatformCaches();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function targetFile() {
    const filePath = path.join(tmpDir, "credential");
    fs.writeFileSync(filePath, "secret");
    return filePath;
  }

  it("accepts a DACL limited to the agent, SYSTEM and Administrators", () => {
    const spawn = fakeSpawn({
      whoami: whoamiHandler,
      icacls: icaclsSaveHandler(
        `D:PAI(A;;FA;;;${OWN_SID})(A;;FA;;;SY)(A;;FA;;;BA)`,
      ),
    });
    const result = platform.assertRestrictivePermissions(targetFile(), {
      label: "credential file",
      platform: "win32",
      spawn,
      tmpDir,
    });
    assert.equal(result.mechanism, "windows-acl");
  });

  it("refuses a DACL that grants any other principal", () => {
    const spawn = fakeSpawn({
      whoami: whoamiHandler,
      icacls: icaclsSaveHandler(`D:PAI(A;;FA;;;${OWN_SID})(A;;FA;;;WD)`),
    });
    assert.throws(
      () =>
        platform.assertRestrictivePermissions(targetFile(), {
          label: "credential file",
          platform: "win32",
          spawn,
          tmpDir,
        }),
      /grants access to S-1-1-0/,
    );
  });

  it("accepts an inheriting DACL whose inherited entries are all allowlisted", () => {
    const spawn = fakeSpawn({
      whoami: whoamiHandler,
      icacls: icaclsSaveHandler(`D:AI(A;ID;FA;;;${OWN_SID})(A;ID;FA;;;SY)`),
    });
    assert.equal(
      platform.assertRestrictivePermissions(targetFile(), {
        label: "credential file",
        platform: "win32",
        spawn,
        tmpDir,
      }).mechanism,
      "windows-acl",
    );
  });

  it("requires an explicitly protected DACL for state the agent creates itself", () => {
    const spawn = fakeSpawn({
      whoami: whoamiHandler,
      icacls: icaclsSaveHandler(`D:AI(A;ID;FA;;;${OWN_SID})(A;ID;FA;;;SY)`),
    });
    assert.throws(
      () =>
        platform.assertRestrictivePermissions(targetFile(), {
          label: "agent state file",
          requireProtected: true,
          platform: "win32",
          spawn,
          tmpDir,
        }),
      /still inherits from its parent directory/,
    );
  });

  it("refuses an empty DACL rather than reading it as harmless", () => {
    const spawn = fakeSpawn({ whoami: whoamiHandler, icacls: icaclsSaveHandler("D:P") });
    assert.throws(
      () =>
        platform.assertRestrictivePermissions(targetFile(), {
          label: "credential file",
          platform: "win32",
          spawn,
          tmpDir,
        }),
      /DACL is empty or could not be read/,
    );
  });

  it("fails closed when icacls cannot report an ACL at all", () => {
    const spawn = fakeSpawn({
      whoami: whoamiHandler,
      icacls: (args) => {
        const saveIndex = args.indexOf("/save");
        if (saveIndex !== -1) fs.writeFileSync(args[saveIndex + 1], Buffer.from("", "utf16le"));
        return { status: 0 };
      },
    });
    assert.throws(
      () =>
        platform.assertRestrictivePermissions(targetFile(), {
          label: "credential file",
          platform: "win32",
          spawn,
          tmpDir,
        }),
      /did not report a DACL/,
    );
  });

  it("refuses a symlink or non-regular path on every platform", () => {
    assert.throws(
      () =>
        platform.assertRestrictivePermissions(tmpDir, {
          label: "credential file",
          platform: "linux",
        }),
      /must be a regular non-symlink file/,
    );
  });

  it("reports a missing path as a stat failure", () => {
    assert.throws(
      () =>
        platform.assertRestrictivePermissions(path.join(tmpDir, "absent"), {
          label: "credential file",
        }),
      /failed to stat credential file/,
    );
  });

  it("refuses a group/other-readable file on POSIX", { skip: IS_WIN32 }, () => {
    const filePath = targetFile();
    fs.chmodSync(filePath, 0o644);
    assert.throws(
      () =>
        platform.assertRestrictivePermissions(filePath, {
          label: "credential file",
          platform: "linux",
        }),
      /readable by group\/other/,
    );
  });

  it("enforces a real restricted ACL end to end on win32", { skip: !IS_WIN32 }, () => {
    const filePath = targetFile();
    platform.applyRestrictivePermissions(filePath);
    const result = platform.assertRestrictivePermissions(filePath, {
      label: "credential file",
      requireProtected: true,
    });
    assert.equal(result.mechanism, "windows-acl");
    assert.match(platform.readWindowsSddl(filePath), /^D:P/);
  });

  it("refuses a well-formed allowlisted DACL when the owner is untrusted", () => {
    const spawn = fakeSpawn({
      whoami: whoamiHandler,
      icacls: icaclsSaveHandler(`D:PAI(A;;FA;;;${OWN_SID})(A;;FA;;;SY)`),
      powershell: () => ({ stdout: "S-1-5-21-9-9-9-9999\r\n" }),
    });
    assert.throws(
      () =>
        platform.assertRestrictivePermissions(targetFile(), {
          label: "credential file",
          platform: "win32",
          spawn,
          tmpDir,
        }),
      /owner is S-1-5-21-9-9-9-9999.*not one of the trusted owners/s,
    );
  });

  it("reads the owner via .NET's SID-typed GetOwner rather than a localized display name", () => {
    const spawn = fakeSpawn({
      whoami: whoamiHandler,
      icacls: icaclsSaveHandler(`D:PAI(A;;FA;;;${OWN_SID})(A;;FA;;;SY)`),
      powershell: (args) => {
        assert.ok(args.includes("-Command"));
        assert.match(args[args.length - 1], /GetOwner\(\[System\.Security\.Principal\.SecurityIdentifier\]\)/);
        return { stdout: `${OWN_SID}\r\n` };
      },
    });
    const result = platform.assertRestrictivePermissions(targetFile(), {
      label: "credential file",
      platform: "win32",
      spawn,
      tmpDir,
    });
    assert.equal(result.mechanism, "windows-acl");
  });
});

describe("platform: durability limits", () => {
  beforeEach(() => durability.resetDurabilityLimits());
  afterEach(() => durability.resetDurabilityLimits());

  it("reports a successful directory fsync as durable with no limit", () => {
    const result = durability.fsyncDirectorySync("/state", {
      platform: "linux",
      fsImpl: { openSync: () => 7, fsyncSync: () => {}, closeSync: () => {} },
    });
    assert.deepEqual(result, { durable: true, limit: null });
    assert.deepEqual(durability.getDurabilityLimits(), []);
    assert.deepEqual(durability.durabilityMetadataEntries(), []);
  });

  it("records the win32 directory-fsync limitation instead of swallowing it", () => {
    const result = durability.fsyncDirectorySync("C:\\state", {
      platform: "win32",
      fsImpl: {
        openSync: () => {
          throw Object.assign(new Error("EISDIR"), { code: "EISDIR" });
        },
        fsyncSync: () => {},
        closeSync: () => {},
      },
    });
    assert.equal(result.durable, false);
    assert.equal(result.limit.code, durability.DIRECTORY_FSYNC_UNSUPPORTED);
    assert.match(result.limit.detail, /atomic but not power-loss durable/);
    assert.deepEqual(durability.durabilityMetadataEntries(), [
      { name: "durabilityLimit_directory_fsync_unsupported", value: true },
      { name: "durabilityLimit_directory_fsync_unsupported_platform", value: "win32" },
    ]);
  });

  it("counts repeat occurrences of one limitation once in metadata", () => {
    const fsImpl = {
      openSync: () => {
        throw Object.assign(new Error("EPERM"), { code: "EPERM" });
      },
      fsyncSync: () => {},
      closeSync: () => {},
    };
    durability.fsyncDirectorySync("C:\\a", { platform: "win32", fsImpl });
    durability.fsyncDirectorySync("C:\\b", { platform: "win32", fsImpl });
    const limits = durability.getDurabilityLimits();
    assert.equal(limits.length, 1);
    assert.equal(limits[0].occurrences, 2);
  });

  it("records the limitation from the promise-based deploy path too", async () => {
    const result = await durability.fsyncDirectory(
      {
        open: async () => {
          throw Object.assign(new Error("EPERM"), { code: "EPERM" });
        },
      },
      "C:\\state",
      { platform: "win32" },
    );
    assert.equal(result.durable, false);
    assert.equal(result.limit.code, durability.DIRECTORY_FSYNC_UNSUPPORTED);
  });

  it("still closes the handle after a successful promise-based fsync", async () => {
    let closed = false;
    const result = await durability.fsyncDirectory(
      {
        open: async () => ({
          sync: async () => {},
          close: async () => {
            closed = true;
          },
        }),
      },
      "/state",
    );
    assert.deepEqual(result, { durable: true, limit: null });
    assert.equal(closed, true);
  });
});

describe("platform: clearWindowsServiceBootstrapToken", () => {
  const REG_KEY = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent";

  it("is a no-op on a non-Windows platform", () => {
    const spawn = fakeSpawn({});
    const result = platform.clearWindowsServiceBootstrapToken({
      configDir: "/state",
      platform: "linux",
      spawn,
    });
    assert.deepEqual(result, { attempted: false, cleared: false, reason: "not running on Windows" });
    assert.deepEqual(spawn.calls, []);
  });

  it("rewrites the registry Environment value, dropping the token but keeping the config dir", () => {
    const spawn = fakeSpawn({
      "reg.exe": (args) => {
        if (args[0] === "query") {
          assert.deepEqual(args, [
            "query",
            REG_KEY,
            "/v",
            "Environment",
          ]);
          return {
            status: 0,
            stdout:
              "    Environment    REG_MULTI_SZ    TOKENTIMER_AGENT_CONFIG_DIR=C:\\ProgramData\\TokenTimerAgent\\state\\0TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=ttboot_secret",
          };
        }
        if (args[0] === "add") {
          assert.deepEqual(args, [
            "add",
            REG_KEY,
            "/v",
            "Environment",
            "/t",
            "REG_MULTI_SZ",
            "/d",
            "TOKENTIMER_AGENT_CONFIG_DIR=C:\\ProgramData\\TokenTimerAgent\\state",
            "/f",
          ]);
          return { status: 0 };
        }
        throw new Error(`unexpected reg.exe invocation: ${args.join(" ")}`);
      },
    });
    const result = platform.clearWindowsServiceBootstrapToken({
      configDir: "C:\\ProgramData\\TokenTimerAgent\\state",
      platform: "win32",
      spawn,
    });
    assert.deepEqual(result, { attempted: true, cleared: true });
    assert.equal(spawn.calls.length, 2);
  });

  it("does not write anything when the registry value already has no token", () => {
    const spawn = fakeSpawn({
      "reg.exe": (args) => {
        assert.equal(args[0], "query");
        return {
          status: 0,
          stdout: "    Environment    REG_MULTI_SZ    TOKENTIMER_AGENT_CONFIG_DIR=C:\\state",
        };
      },
    });
    const result = platform.clearWindowsServiceBootstrapToken({
      configDir: "C:\\state",
      platform: "win32",
      spawn,
    });
    assert.deepEqual(result, {
      attempted: true,
      cleared: false,
      reason: "registry value already has no token",
    });
    assert.equal(spawn.calls.length, 1);
  });

  it("does not write anything, and does not create the key, when the service is not installed", () => {
    const spawn = fakeSpawn({
      "reg.exe": (args) => {
        assert.equal(args[0], "query");
        return { status: 1, stdout: "", stderr: "ERROR: The system was unable to find the specified registry key." };
      },
    });
    const result = platform.clearWindowsServiceBootstrapToken({
      configDir: "C:\\state",
      platform: "win32",
      spawn,
    });
    assert.deepEqual(result, {
      attempted: true,
      cleared: false,
      reason: "no service Environment registry value is present",
    });
    assert.equal(spawn.calls.length, 1);
    assert.equal(spawn.calls[0].args[0], "query");
  });

  it("reports, rather than throws, when reg.exe is unavailable", () => {
    const spawn = () => ({ error: Object.assign(new Error("nope"), { code: "ENOENT" }) });
    const result = platform.clearWindowsServiceBootstrapToken({
      configDir: "C:\\state",
      platform: "win32",
      spawn,
    });
    assert.deepEqual(result, {
      attempted: true,
      cleared: false,
      reason: "reg.exe is not available on this host",
    });
  });

  it("reports, rather than throws, when the rewrite itself fails", () => {
    const spawn = fakeSpawn({
      "reg.exe": (args) => {
        if (args[0] === "query") {
          return {
            status: 0,
            stdout: "Environment REG_MULTI_SZ TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=ttboot_secret",
          };
        }
        return { status: 1, stderr: "access denied" };
      },
    });
    const result = platform.clearWindowsServiceBootstrapToken({
      configDir: "C:\\state",
      platform: "win32",
      spawn,
    });
    assert.deepEqual(result, {
      attempted: true,
      cleared: false,
      reason: "reg.exe add exited 1",
    });
  });
});
