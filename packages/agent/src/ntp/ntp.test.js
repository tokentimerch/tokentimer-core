"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  DEFAULT_TIMEOUT_MS,
  NTP_SYNCHRONIZED_ARGV,
  WIN32_NTP_SOURCE_ARGV,
  checkNtpSynced,
} = require("./index.js");

function fakeExecFile({ stdout = "", error = null } = {}) {
  return (file, args, options, callback) => {
    callback(error, stdout, "");
  };
}

describe("checkNtpSynced on linux", () => {
  it("resolves true when timedatectl prints yes", async () => {
    const result = await checkNtpSynced({
      platform: "linux",
      execFileImpl: fakeExecFile({ stdout: "yes\n" }),
    });
    assert.equal(result, true);
  });

  it("resolves false when timedatectl prints no", async () => {
    const result = await checkNtpSynced({
      platform: "linux",
      execFileImpl: fakeExecFile({ stdout: "no\n" }),
    });
    assert.equal(result, false);
  });

  it("is case- and whitespace-insensitive", async () => {
    const result = await checkNtpSynced({
      platform: "linux",
      execFileImpl: fakeExecFile({ stdout: "  YES  \n" }),
    });
    assert.equal(result, true);
  });

  it("resolves null on a missing binary (ENOENT / non-systemd host)", async () => {
    const enoent = new Error("spawn timedatectl ENOENT");
    enoent.code = "ENOENT";
    const result = await checkNtpSynced({
      platform: "linux",
      execFileImpl: fakeExecFile({ error: enoent }),
    });
    assert.equal(result, null);
  });

  it("resolves null on a timeout", async () => {
    const timeoutError = new Error("timeout");
    timeoutError.killed = true;
    timeoutError.signal = "SIGTERM";
    const result = await checkNtpSynced({
      platform: "linux",
      execFileImpl: fakeExecFile({ error: timeoutError }),
    });
    assert.equal(result, null);
  });

  it("resolves null on a nonzero exit", async () => {
    const exitError = new Error("exit 1");
    exitError.code = 1;
    const result = await checkNtpSynced({
      platform: "linux",
      execFileImpl: fakeExecFile({ error: exitError }),
    });
    assert.equal(result, null);
  });

  it("resolves null on unparseable output instead of guessing", async () => {
    const result = await checkNtpSynced({
      platform: "linux",
      execFileImpl: fakeExecFile({ stdout: "unexpected garbage" }),
    });
    assert.equal(result, null);
  });

  it("resolves null instead of rejecting when execFileImpl throws synchronously", async () => {
    const result = await checkNtpSynced({
      platform: "linux",
      execFileImpl: () => {
        throw new Error("boom");
      },
    });
    assert.equal(result, null);
  });

  it("passes the fixed timedatectl argv and default timeout to execFileImpl", async () => {
    let capturedFile;
    let capturedArgs;
    let capturedOptions;
    const result = await checkNtpSynced({
      platform: "linux",
      execFileImpl: (file, args, options, callback) => {
        capturedFile = file;
        capturedArgs = args;
        capturedOptions = options;
        callback(null, "yes", "");
      },
    });
    assert.equal(result, true);
    assert.equal(capturedFile, NTP_SYNCHRONIZED_ARGV[0]);
    assert.deepEqual(capturedArgs, NTP_SYNCHRONIZED_ARGV.slice(1));
    assert.equal(capturedOptions.timeout, DEFAULT_TIMEOUT_MS);
    // No `shell` option: argv must never be interpreted by a shell.
    assert.equal(capturedOptions.shell, undefined);
  });

  it("defaults to process.platform when platform is not passed explicitly", async () => {
    // Regression guard for the option itself: an omitted platform must
    // still resolve to *some* branch deterministically (whichever the
    // real host is), not throw and not silently no-op.
    let called = false;
    await checkNtpSynced({
      execFileImpl: (file, args, options, callback) => {
        called = true;
        callback(null, "", "");
      },
    });
    assert.equal(called, true);
  });

  it("throws on programmer error: bad execFileImpl or timeoutMs", () => {
    assert.throws(
      () => checkNtpSynced({ execFileImpl: "not-a-function" }),
      /execFileImpl/,
    );
    assert.throws(
      () => checkNtpSynced({ timeoutMs: 0 }),
      /timeoutMs/,
    );
    assert.throws(
      () => checkNtpSynced({ timeoutMs: 1.5 }),
      /timeoutMs/,
    );
  });
});

describe("checkNtpSynced on win32", () => {
  // A real-Windows-host pass found ntpSynced always resolved null on
  // Windows: the previous implementation only ever ran timedatectl, which
  // does not exist there. These pin the w32tm-based replacement.

  it("resolves true when w32tm /query /source reports an NTP server", async () => {
    const result = await checkNtpSynced({
      platform: "win32",
      execFileImpl: fakeExecFile({ stdout: "time.windows.com\n" }),
    });
    assert.equal(result, true);
  });

  it("resolves true for the Hyper-V/Azure time-sync integration source", async () => {
    // Real output captured on a Windows Server 2025 VM.
    const result = await checkNtpSynced({
      platform: "win32",
      execFileImpl: fakeExecFile({
        stdout: "VM IC Time Synchronization Provider\r\n",
      }),
    });
    assert.equal(result, true);
  });

  it("resolves false for the unsynced Local CMOS Clock source", async () => {
    const result = await checkNtpSynced({
      platform: "win32",
      execFileImpl: fakeExecFile({ stdout: "Local CMOS Clock\r\n" }),
    });
    assert.equal(result, false);
  });

  it("resolves false for the unsynced Free-running System Clock source", async () => {
    const result = await checkNtpSynced({
      platform: "win32",
      execFileImpl: fakeExecFile({ stdout: "Free-running System Clock\r\n" }),
    });
    assert.equal(result, false);
  });

  it("is case-insensitive on the unsynced-source tokens", async () => {
    const result = await checkNtpSynced({
      platform: "win32",
      execFileImpl: fakeExecFile({ stdout: "local cmos clock\r\n" }),
    });
    assert.equal(result, false);
  });

  it("resolves null when the Windows Time service is stopped (nonzero exit)", async () => {
    // Real repro on the verification VM: `net stop w32time` then
    // `w32tm /query /source` exits non-zero with a localized error instead
    // of printing a source name.
    const stoppedError = new Error("service not started");
    stoppedError.code = 1;
    const result = await checkNtpSynced({
      platform: "win32",
      execFileImpl: fakeExecFile({ error: stoppedError }),
    });
    assert.equal(result, null);
  });

  it("resolves null on a missing w32tm binary", async () => {
    const enoent = new Error("spawn w32tm ENOENT");
    enoent.code = "ENOENT";
    const result = await checkNtpSynced({
      platform: "win32",
      execFileImpl: fakeExecFile({ error: enoent }),
    });
    assert.equal(result, null);
  });

  it("resolves null on empty output instead of guessing", async () => {
    const result = await checkNtpSynced({
      platform: "win32",
      execFileImpl: fakeExecFile({ stdout: "" }),
    });
    assert.equal(result, null);
  });

  it("passes the fixed w32tm argv, not the Linux timedatectl argv", async () => {
    let capturedFile;
    let capturedArgs;
    await checkNtpSynced({
      platform: "win32",
      execFileImpl: (file, args, options, callback) => {
        capturedFile = file;
        capturedArgs = args;
        callback(null, "time.windows.com", "");
      },
    });
    assert.equal(capturedFile, WIN32_NTP_SOURCE_ARGV[0]);
    assert.deepEqual(capturedArgs, WIN32_NTP_SOURCE_ARGV.slice(1));
  });
});
