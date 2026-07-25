"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const { DEFAULT_TIMEOUT_MS, NTP_SYNCHRONIZED_ARGV, checkNtpSynced } = require("./index.js");

function fakeExecFile({ stdout = "", error = null } = {}) {
  return (file, args, options, callback) => {
    callback(error, stdout, "");
  };
}

describe("checkNtpSynced", () => {
  it("resolves true when timedatectl prints yes", async () => {
    const result = await checkNtpSynced({
      execFileImpl: fakeExecFile({ stdout: "yes\n" }),
    });
    assert.equal(result, true);
  });

  it("resolves false when timedatectl prints no", async () => {
    const result = await checkNtpSynced({
      execFileImpl: fakeExecFile({ stdout: "no\n" }),
    });
    assert.equal(result, false);
  });

  it("is case- and whitespace-insensitive", async () => {
    const result = await checkNtpSynced({
      execFileImpl: fakeExecFile({ stdout: "  YES  \n" }),
    });
    assert.equal(result, true);
  });

  it("resolves null on a missing binary (ENOENT / non-systemd host)", async () => {
    const enoent = new Error("spawn timedatectl ENOENT");
    enoent.code = "ENOENT";
    const result = await checkNtpSynced({
      execFileImpl: fakeExecFile({ error: enoent }),
    });
    assert.equal(result, null);
  });

  it("resolves null on a timeout", async () => {
    const timeoutError = new Error("timeout");
    timeoutError.killed = true;
    timeoutError.signal = "SIGTERM";
    const result = await checkNtpSynced({
      execFileImpl: fakeExecFile({ error: timeoutError }),
    });
    assert.equal(result, null);
  });

  it("resolves null on a nonzero exit", async () => {
    const exitError = new Error("exit 1");
    exitError.code = 1;
    const result = await checkNtpSynced({
      execFileImpl: fakeExecFile({ error: exitError }),
    });
    assert.equal(result, null);
  });

  it("resolves null on unparseable output instead of guessing", async () => {
    const result = await checkNtpSynced({
      execFileImpl: fakeExecFile({ stdout: "unexpected garbage" }),
    });
    assert.equal(result, null);
  });

  it("resolves null instead of rejecting when execFileImpl throws synchronously", async () => {
    const result = await checkNtpSynced({
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
