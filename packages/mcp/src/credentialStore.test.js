"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  CredentialStoreError,
  assertPrivateFile,
  assertDirectoryControl,
  checkDestination,
  defaultCredentialPath,
  windowsAccount,
  writeCredential,
} = require("./credentialStore");

const SECRET = `ttopc_${"0123456789abcdef"}_${"a".repeat(64)}`;
const posix = process.platform !== "win32";
let dir;

beforeEach(() => {
  // Windows Temp/AppData can be delegated to sandbox principals. The native
  // private-directory tests need a parent without those delegation grants.
  dir = fs.mkdtempSync(path.join(posix ? os.tmpdir() : path.resolve(__dirname, "../../.."), ".tt-mcp-store-"));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

const refused = (fn, pattern) => assert.throws(fn, (error) => error instanceof CredentialStoreError && pattern.test(error.message));

describe("credential store: location", () => {
  it("uses the platform's per-user config directory", () => {
    assert.equal(
      defaultCredentialPath({ env: { XDG_CONFIG_HOME: "/x/cfg" }, platform: "linux", home: "/home/a" }),
      path.join("/x/cfg", "tokentimer", "mcp", "credential"),
    );
    assert.equal(
      defaultCredentialPath({ env: {}, platform: "linux", home: "/home/a" }),
      path.join("/home/a", ".config", "tokentimer", "mcp", "credential"),
    );
    assert.equal(
      defaultCredentialPath({ env: { APPDATA: "C:\\Users\\a\\AppData\\Roaming" }, platform: "win32", home: "C:\\Users\\a" }),
      path.join("C:\\Users\\a\\AppData\\Roaming", "TokenTimer", "mcp", "credential"),
    );
  });
});

describe("credential store: directory control", () => {
  const userSid = "S-1-5-21-1-2-3-1001";
  const directory = (rules = [], owner = userSid) => ({ owner, rules, reparse: false });
  const allowed = (sid, rights, inheritOnly = false) => ({ sid, rights, inheritOnly, allow: true });
  const verify = directories => assertDirectoryControl(dir, { platform: "win32", inspectWindows: () => ({ userSid, directories }) });

  it("accepts private Windows parents and ignores inherit-only Creator Owner rules", () => {
    assert.doesNotThrow(() => verify([directory([allowed(userSid, 2032127), allowed("S-1-3-0", 2032127, true)]), directory([allowed("S-1-1-0", 4)], "S-1-5-18")]));
  });
  it("rejects shared parent writes and ancestor delete/control grants", () => {
    for (const rights of [2, 4, 16, 256, 64, 65536, 262144, 524288, 268435456, 1073741824]) {
      refused(() => verify([directory([allowed("S-1-1-0", rights)])]), /private credential directory/);
    }
    for (const rights of [64, 65536, 262144, 524288, 268435456]) {
      refused(() => verify([directory(), directory([allowed("S-1-1-0", rights)])]), /private credential directory/);
    }
    refused(() => verify([directory([], "S-1-5-21-other")]), /private credential directory/);
  });
  it("runs the parent check during destination preflight without writing", () => {
    refused(() => checkDestination(path.join(dir, "new", "credential"), { directoryCheck: () => { throw new CredentialStoreError("Use a private credential directory"); } }), /private credential directory/);
    assert.deepEqual(fs.readdirSync(dir), []);
  });
  // skip-reason: no-host — Native ACL grant evaluation requires Windows.
  it("rejects a real Windows directory granting Everyone modification before writing", { skip: posix }, () => {
    require("node:child_process").execFileSync("icacls", [dir, "/grant", "*S-1-1-0:(OI)(CI)(M)"], { stdio: "ignore", windowsHide: true });
    refused(() => checkDestination(path.join(dir, "credential")), /private credential directory/);
    assert.deepEqual(fs.readdirSync(dir), []);
  });
  // skip-reason: no-host — POSIX ownership/mode checks require POSIX.
  it("rejects a group-writable POSIX destination directory", { skip: !posix }, () => {
    fs.chmodSync(dir, 0o770);
    refused(() => checkDestination(path.join(dir, "credential")), /private credential directory/);
  });
});

describe("credential store: writing", () => {
  it("writes the secret to a new file, creating missing directories, and returns the path", () => {
    const file = path.join(dir, "deep", "er", "credential");
    const written = writeCredential(file, SECRET);
    assert.equal(written, path.resolve(file));
    assert.equal(fs.readFileSync(file, "utf8"), `${SECRET}\n`);
  });

  // skip-reason: no-host — POSIX file modes and symlink permissions require a POSIX host.
  it("creates the file private to the owner (mode 0600) and the directory 0700", { skip: !posix }, () => {
    const file = path.join(dir, "private", "credential");
    writeCredential(file, SECRET);
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    assert.equal(fs.statSync(path.dirname(file)).mode & 0o777, 0o700);
  });

  it("refuses to overwrite an existing file unless told to, and keeps the old one intact", () => {
    const file = path.join(dir, "credential");
    fs.writeFileSync(file, "OLD\n");
    refused(() => writeCredential(file, SECRET), /already exists/);
    assert.equal(fs.readFileSync(file, "utf8"), "OLD\n");
    writeCredential(file, SECRET, { replace: true });
    assert.equal(fs.readFileSync(file, "utf8"), `${SECRET}\n`);
  });

  // skip-reason: no-host — POSIX file modes and symlink permissions require a POSIX host.
  it("refuses to write through a symbolic link, even with replace", { skip: !posix }, () => {
    const target = path.join(dir, "elsewhere");
    fs.writeFileSync(target, "UNTOUCHED\n");
    const link = path.join(dir, "credential");
    fs.symlinkSync(target, link);
    refused(() => writeCredential(link, SECRET, { replace: true }), /symbolic link/);
    assert.equal(fs.readFileSync(target, "utf8"), "UNTOUCHED\n");
  });

  it("leaves no temporary file behind, on success or failure", () => {
    const file = path.join(dir, "credential");
    writeCredential(file, SECRET);
    assert.deepEqual(fs.readdirSync(dir), ["credential"]);

    const blocked = path.join(dir, "blocked");
    fs.mkdirSync(blocked);
    refused(() => writeCredential(blocked, SECRET, { replace: true }), /could not be written/);
    assert.deepEqual(fs.readdirSync(dir).sort(), ["blocked", "credential"], "no .tmp file is left");
  });

  it("removes the file and fails when Windows access cannot be restricted", () => {
    const file = path.join(dir, "credential");
    refused(
      () =>
        writeCredential(file, SECRET, {
          platform: "win32",
          env: { USERNAME: "alice", USERDOMAIN: "CORP" },
          execFileSync() {
            throw new Error("icacls failed");
          },
        }),
      /could not be written safely/,
    );
    assert.deepEqual(fs.readdirSync(dir), [], "a credential others might read must not remain");
  });

  it("restricts Windows access with an argument list, never a shell string", () => {
    const calls = [];
    const file = path.join(dir, "credential");
    writeCredential(file, SECRET, {
      platform: "win32",
      env: { USERNAME: "alice", USERDOMAIN: "CORP" },
      execFileSync: (command, args) => calls.push({ command, args }),
    });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].command, "icacls");
    assert.ok(Array.isArray(calls[0].args));
    assert.deepEqual(calls[0].args.slice(1), ["/inheritance:r", "/grant:r", "CORP\\alice:(R,W)"]);
    assert.ok(calls[0].args[0].endsWith(".tmp") || fs.existsSync(file), "the restriction is applied before the rename");
  });

  // skip-reason: no-host — Real Windows ACL checks require a Windows host.
  it("really restricts the file to the current user on Windows (real icacls, not a mock)", { skip: posix }, () => {
    const file = path.join(dir, "real", "credential");
    writeCredential(file, SECRET);
    const listing = require("node:child_process").execFileSync("icacls", [file], { encoding: "utf8" });
    const user = (process.env.USERNAME || "").toLowerCase();
    const entries = listing
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.includes(":(") )
      .map((line) => line.replace(file, "").trim().toLowerCase());
    assert.ok(entries.length >= 1, `no access entries found in: ${listing}`);
    for (const entry of entries) {
      assert.ok(entry.includes(user), `unexpected principal has access: ${entry}`);
    }
    for (const broad of ["everyone", "authenticated users", "builtin\\users", "builtin\\administrators", "nt authority\\system"]) {
      assert.ok(!listing.toLowerCase().includes(broad), `${broad} must not have access`);
    }
    assert.equal(fs.readFileSync(file, "utf8"), `${SECRET}\n`, "and the owner can still read it");
  });

  // skip-reason: no-host — Real Windows ACL checks require a Windows host.
  it("can replace a restricted file on Windows", { skip: posix }, () => {
    const file = path.join(dir, "again", "credential");
    writeCredential(file, SECRET);
    const next = `ttopc_${"fedcba9876543210"}_${"b".repeat(64)}`;
    writeCredential(file, next, { replace: true });
    assert.equal(fs.readFileSync(file, "utf8"), `${next}\n`);
  });

  it("rejects user names that could be interpreted as extra arguments", () => {
    for (const name of ['evil"; calc', "a\nb", "x:(F)", "a(b)"]) {
      assert.throws(() => windowsAccount({ USERNAME: name }), CredentialStoreError, name);
    }
    assert.equal(windowsAccount({ USERNAME: "alice" }), "alice");
  });

  it("never puts the secret or the path in an error", () => {
    const file = path.join(dir, "sub", "credential");
    fs.mkdirSync(path.join(dir, "sub"));
    fs.mkdirSync(file);
    try {
      writeCredential(file, SECRET, { replace: true });
      assert.fail("expected an error");
    } catch (error) {
      assert.ok(error instanceof CredentialStoreError);
      assert.ok(!error.message.includes(SECRET));
      assert.ok(!error.message.includes(dir));
    }
  });

  it("refuses an empty credential", () => {
    refused(() => writeCredential(path.join(dir, "c"), ""), /no credential/);
    refused(() => writeCredential(path.join(dir, "c"), null), /no credential/);
  });
});

describe("credential store: the server binding and write order", () => {
  const { formatCredentialFile, parseCredentialFile } = require("./credentialStore");
  const REAL = "https://tokentimer.example.com";

  it("refuses a temporary pathname replaced during Windows ACL restriction without leaking the secret", () => {
    const file = path.join(dir, "credential");
    const displaced = path.join(dir, "displaced");
    refused(() => writeCredential(file, SECRET, {
      platform: "win32",
      env: { USERNAME: "alice" },
      execFileSync: (_command, args) => {
        fs.renameSync(args[0], displaced);
        fs.writeFileSync(args[0], "ATTACKER\n");
      },
    }), /could not be written safely/);
    assert.equal(fs.readFileSync(displaced, "utf8"), "", "the displaced inode must remain empty");
    assert.equal(fs.existsSync(file), false, "the replacement must not be published");
    for (const name of fs.readdirSync(dir)) {
      assert.ok(!fs.readFileSync(path.join(dir, name), "utf8").includes(SECRET));
    }
  });

  it("stores the issuing server beside the secret and reads both back", () => {
    const file = path.join(dir, "credential");
    writeCredential(file, SECRET, { binding: REAL });
    assert.equal(fs.readFileSync(file, "utf8"), `${SECRET}\napi=${REAL}\n`);
    assert.deepEqual(parseCredentialFile(fs.readFileSync(file, "utf8")), { credential: SECRET, binding: REAL, valid: true });
  });

  it("round-trips with and without a binding, and tolerates Windows line endings", () => {
    assert.deepEqual(parseCredentialFile(formatCredentialFile(SECRET, null)), { credential: SECRET, binding: null, valid: true });
    assert.deepEqual(parseCredentialFile(`${SECRET}\r\napi=${REAL}\r\n`), { credential: SECRET, binding: REAL, valid: true });
  });

  it("refuses a binding with spaces or line breaks, which could forge a second line", () => {
    for (const binding of ["a b", "x\ny", "x\r\ny", ""]) {
      refused(() => writeCredential(path.join(dir, "c"), SECRET, { binding }), /not valid/);
    }
    assert.equal(fs.existsSync(path.join(dir, "c")), false);
  });

  it("restricts Windows access while the file is still empty, before any secret is written", () => {
    const file = path.join(dir, "credential");
    let sizeWhenRestricted = null;
    let restricted = null;
    writeCredential(file, SECRET, {
      platform: "win32",
      env: { USERNAME: "alice", USERDOMAIN: "CORP" },
      execFileSync: (command, args) => {
        restricted = args[0];
        sizeWhenRestricted = fs.statSync(args[0]).size;
      },
    });
    assert.ok(restricted, "the restriction must run");
    assert.equal(sizeWhenRestricted, 0, "the secret must not exist yet when access is restricted");
    assert.equal(fs.readFileSync(file, "utf8"), `${SECRET}\n`);
  });
});

describe("credential store: checking a destination without writing", () => {
  it("accepts a path whose directories do not exist yet, and writes nothing", () => {
    const file = path.join(dir, "a", "b", "credential");
    assert.equal(checkDestination(file), path.resolve(file));
    assert.deepEqual(fs.readdirSync(dir), [], "the check must not create anything");
  });

  // skip-reason: no-host — POSIX file modes and symlink permissions require a POSIX host.
  it("applies the same refusals as the write", { skip: !posix }, () => {
    const file = path.join(dir, "credential");
    fs.writeFileSync(file, "x");
    refused(() => checkDestination(file), /already exists/);
    assert.equal(checkDestination(file, { replace: true }), path.resolve(file));
    const link = path.join(dir, "link");
    fs.symlinkSync(file, link);
    refused(() => checkDestination(link, { replace: true }), /symbolic link/);
  });

  it("refuses a location under something that is not a directory", () => {
    const blocker = path.join(dir, "file");
    fs.writeFileSync(blocker, "x");
    refused(() => checkDestination(path.join(blocker, "credential")), /not a directory|not writable/);
  });

  // skip-reason: no-host — POSIX file modes and symlink permissions require a POSIX host.
  it("refuses a read-only directory", { skip: !posix || process.getuid?.() === 0 }, () => {
    const ro = path.join(dir, "ro");
    fs.mkdirSync(ro, { mode: 0o500 });
    refused(() => checkDestination(path.join(ro, "credential")), /not writable/);
  });
});

describe("credential store: reading back", () => {
  // skip-reason: no-host — POSIX file modes and symlink permissions require a POSIX host.
  it("accepts an owner-only file and rejects one other users can read", { skip: !posix }, () => {
    const file = path.join(dir, "credential");
    fs.writeFileSync(file, SECRET, { mode: 0o600 });
    fs.chmodSync(file, 0o600);
    assert.doesNotThrow(() => assertPrivateFile(file));
    for (const mode of [0o644, 0o640, 0o604, 0o666]) {
      fs.chmodSync(file, mode);
      refused(() => assertPrivateFile(file), /readable by other users/);
    }
  });

  // skip-reason: no-host — POSIX file modes and symlink permissions require a POSIX host.
  it("rejects a symbolic link and a missing file", { skip: !posix }, () => {
    const real = path.join(dir, "real");
    fs.writeFileSync(real, SECRET, { mode: 0o600 });
    const link = path.join(dir, "link");
    fs.symlinkSync(real, link);
    refused(() => assertPrivateFile(link), /symbolic link/);
    refused(() => assertPrivateFile(path.join(dir, "missing")), /could not be read/);
  });

  it("does not check POSIX modes on Windows, where they mean nothing", () => {
    const file = path.join(dir, "credential");
    fs.writeFileSync(file, SECRET);
    assert.doesNotThrow(() => assertPrivateFile(file, { platform: "win32" }));
  });
});
