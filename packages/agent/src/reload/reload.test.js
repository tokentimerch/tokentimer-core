"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  reloadService,
  scrubExcerpt,
  SUPPORTED_SERVICES,
  STDERR_EXCERPT_MAX_CHARS,
} = require("./index.js");

const NGINX_PROFILES = Object.freeze({
  validateArgv: ["nginx", "-t"],
  reloadArgv: ["systemctl", "reload", "nginx"],
});

/**
 * Builds an execFile stub. `plan` maps the command binary (argv[0] as
 * passed to execFile) to an outcome:
 *   { exitCode?: number, stdout?: string, stderr?: string, timeout?: boolean, delayMs?: number }
 * Records every call (file, args, options) in `calls`.
 */
function makeExecFileStub(plan) {
  const calls = [];

  function execFileStub(file, args, options, callback) {
    calls.push({ file, args, options });
    const outcome = plan[file] || {};
    const stdout = outcome.stdout || "";
    const stderr = outcome.stderr || "";

    const finish = () => {
      if (outcome.timeout) {
        const error = new Error(`Command timed out: ${file}`);
        error.killed = true;
        error.signal = "SIGTERM";
        callback(error, stdout, stderr);
        return;
      }
      const exitCode = outcome.exitCode ?? 0;
      if (exitCode === 0) {
        callback(null, stdout, stderr);
      } else {
        const error = new Error(`Command failed: ${file} (exit ${exitCode})`);
        error.code = exitCode;
        callback(error, stdout, stderr);
      }
    };

    if (outcome.delayMs) {
      setTimeout(finish, outcome.delayMs);
    } else {
      setImmediate(finish);
    }
  }

  execFileStub.calls = calls;
  return execFileStub;
}

describe("reloadService", () => {
  it("runs validate then reload on success and reports both stages", async () => {
    const stub = makeExecFileStub({});

    const result = await reloadService({
      service: "nginx",
      commandProfiles: NGINX_PROFILES,
      execFileImpl: stub,
    });

    assert.deepEqual(result, {
      reloaded: true,
      service: "nginx",
      stages: [
        { stage: "validate", exitCode: 0 },
        { stage: "reload", exitCode: 0 },
      ],
    });
    assert.equal(stub.calls.length, 2);
    assert.deepEqual(stub.calls[0], {
      file: "nginx",
      args: ["-t"],
      options: stub.calls[0].options,
    });
    assert.deepEqual(stub.calls[1].file, "systemctl");
    assert.deepEqual(stub.calls[1].args, ["reload", "nginx"]);
  });

  it("short-circuits on validate failure: reload is never invoked", async () => {
    const stub = makeExecFileStub({
      nginx: { exitCode: 1, stderr: "nginx: configuration file test failed" },
    });

    const result = await reloadService({
      service: "nginx",
      commandProfiles: NGINX_PROFILES,
      execFileImpl: stub,
    });

    assert.equal(result.reloaded, false);
    assert.equal(result.stage, "validate");
    assert.equal(result.exitCode, 1);
    assert.match(result.stderrExcerpt, /configuration file test failed/);
    // The reload command must never have been run.
    assert.equal(stub.calls.length, 1);
    assert.equal(stub.calls[0].file, "nginx");
  });

  it("reports a reload-stage failure when validate passes but reload fails", async () => {
    const stub = makeExecFileStub({
      systemctl: { exitCode: 5, stderr: "Failed to reload nginx.service" },
    });

    const result = await reloadService({
      service: "nginx",
      commandProfiles: NGINX_PROFILES,
      execFileImpl: stub,
    });

    assert.equal(result.reloaded, false);
    assert.equal(result.stage, "reload");
    assert.equal(result.exitCode, 5);
    assert.match(result.stderrExcerpt, /Failed to reload/);
    assert.equal(stub.calls.length, 2);
  });

  it("surfaces a timeout as a failure result, never a throw", async () => {
    const stub = makeExecFileStub({
      nginx: { timeout: true },
    });

    const result = await reloadService({
      service: "nginx",
      commandProfiles: NGINX_PROFILES,
      execFileImpl: stub,
    });

    assert.equal(result.reloaded, false);
    assert.equal(result.stage, "validate");
    assert.equal(result.timedOut, true);
    assert.equal(stub.calls.length, 1);
  });

  it("passes the timeout option through to execFile", async () => {
    const stub = makeExecFileStub({});

    await reloadService({
      service: "haproxy",
      commandProfiles: {
        validateArgv: ["haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"],
        reloadArgv: ["systemctl", "reload", "haproxy"],
      },
      timeoutMs: 1234,
      execFileImpl: stub,
    });

    assert.equal(stub.calls[0].options.timeout, 1234);
    assert.equal(stub.calls[1].options.timeout, 1234);
  });

  it("never uses a shell: every call passes shell:false explicitly", async () => {
    const stub = makeExecFileStub({});

    await reloadService({
      service: "apache",
      commandProfiles: {
        validateArgv: ["apachectl", "configtest"],
        reloadArgv: ["systemctl", "reload", "httpd"],
      },
      execFileImpl: stub,
    });

    assert.equal(stub.calls.length, 2);
    for (const call of stub.calls) {
      assert.equal(call.options.shell, false);
    }
  });

  it("bounds the stderr excerpt to the documented maximum", async () => {
    const longStderr = "e".repeat(STDERR_EXCERPT_MAX_CHARS * 4);
    const stub = makeExecFileStub({
      nginx: { exitCode: 1, stderr: longStderr },
    });

    const result = await reloadService({
      service: "nginx",
      commandProfiles: NGINX_PROFILES,
      execFileImpl: stub,
    });

    assert.equal(result.stderrExcerpt.length, STDERR_EXCERPT_MAX_CHARS);
  });

  it("redacts the whole excerpt when output contains a PRIVATE KEY marker", async () => {
    const stub = makeExecFileStub({
      nginx: {
        exitCode: 1,
        stderr:
          "error near -----BEGIN PRIVATE KEY----- MIIEsecretbytes -----END PRIVATE KEY-----",
      },
    });

    const result = await reloadService({
      service: "nginx",
      commandProfiles: NGINX_PROFILES,
      execFileImpl: stub,
    });

    assert.equal(result.stderrExcerpt, "[redacted]");
    assert.ok(!JSON.stringify(result).includes("MIIEsecretbytes"));
  });

  it("throws on an unsupported service name", async () => {
    const stub = makeExecFileStub({});
    await assert.rejects(
      reloadService({
        service: "postgres",
        commandProfiles: NGINX_PROFILES,
        execFileImpl: stub,
      }),
      /service must be one of/,
    );
    assert.equal(stub.calls.length, 0);
  });

  it("throws on argv elements containing shell metacharacters", async () => {
    const stub = makeExecFileStub({});
    const badProfiles = {
      validateArgv: ["nginx", "-t; rm -rf /"],
      reloadArgv: ["systemctl", "reload", "nginx"],
    };

    await assert.rejects(
      reloadService({
        service: "nginx",
        commandProfiles: badProfiles,
        execFileImpl: stub,
      }),
      /disallowed shell metacharacter/,
    );
    assert.equal(stub.calls.length, 0);
  });

  it("throws on empty or malformed argv (programmer error)", async () => {
    const stub = makeExecFileStub({});

    await assert.rejects(
      reloadService({
        service: "nginx",
        commandProfiles: { validateArgv: [], reloadArgv: ["systemctl"] },
        execFileImpl: stub,
      }),
      /must be a non-empty array/,
    );
    await assert.rejects(
      reloadService({
        service: "nginx",
        commandProfiles: { validateArgv: ["nginx", 42], reloadArgv: ["systemctl"] },
        execFileImpl: stub,
      }),
      /must be a non-empty string/,
    );
    await assert.rejects(
      reloadService({
        service: "nginx",
        commandProfiles: null,
        execFileImpl: stub,
      }),
      /commandProfiles must be an object/,
    );
    assert.equal(stub.calls.length, 0);
  });
});

describe("scrubExcerpt", () => {
  it("passes short, clean output through unchanged", () => {
    assert.equal(scrubExcerpt("syntax is ok"), "syntax is ok");
  });

  it("truncates output beyond the maximum", () => {
    const long = "x".repeat(STDERR_EXCERPT_MAX_CHARS + 100);
    assert.equal(scrubExcerpt(long).length, STDERR_EXCERPT_MAX_CHARS);
  });

  it("replaces the entire excerpt when a private-key marker appears anywhere", () => {
    assert.equal(
      scrubExcerpt("prefix -----BEGIN RSA PRIVATE KEY----- suffix"),
      "[redacted]",
    );
    assert.equal(scrubExcerpt("mentions private key material"), "[redacted]");
  });

  it("handles null/undefined defensively", () => {
    assert.equal(scrubExcerpt(null), "");
    assert.equal(scrubExcerpt(undefined), "");
  });
});

describe("SUPPORTED_SERVICES", () => {
  it("covers exactly nginx, apache, haproxy", () => {
    assert.deepEqual([...SUPPORTED_SERVICES].sort(), ["apache", "haproxy", "nginx"]);
  });
});
