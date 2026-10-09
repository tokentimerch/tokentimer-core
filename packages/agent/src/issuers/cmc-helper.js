"use strict";

/**
 * JS bridge to tokentimer-adcs-cmc (ADR-0014 decision 9 trust boundary).
 * Argv only, never a shell. stdout is one JSON object.
 */

const { execFile } = require("node:child_process");
const { promisify } = require("node:util");

const execFileAsync = promisify(execFile);

const EXIT_OK = 0;
const EXIT_UNKNOWN = 1;
const EXIT_FAIL = 2;

/**
 * @param {object} params
 * @param {string} params.helperPath absolute path to tokentimer-adcs-cmc[.exe]
 * @param {string} params.responsePath CMC response file
 * @param {string} params.caKeySha256 hex pin
 * @param {string} [params.caCertPath] required when the response omits the cert bag
 * @param {typeof execFileAsync} [params.execFileImpl]
 * @param {number} [params.timeoutMs]
 */
async function decodeCmcResponse({
  helperPath,
  responsePath,
  caKeySha256,
  caCertPath,
  execFileImpl = execFileAsync,
  timeoutMs = 30_000,
}) {
  if (typeof helperPath !== "string" || helperPath.length === 0) {
    throw new TypeError("helperPath is required");
  }
  if (typeof responsePath !== "string" || responsePath.length === 0) {
    throw new TypeError("responsePath is required");
  }
  if (typeof caKeySha256 !== "string" || !/^[a-f0-9]{64}$/.test(caKeySha256)) {
    throw new TypeError("caKeySha256 must be 64 lowercase hex characters");
  }

  const argv = ["--response", responsePath, "--ca-key-sha256", caKeySha256];
  if (typeof caCertPath === "string" && caCertPath.length > 0) {
    argv.push("--ca-cert", caCertPath);
  }

  let stdout = "";
  let stderr = "";
  let exitCode = EXIT_FAIL;
  try {
    const result = await execFileImpl(helperPath, argv, {
      encoding: "utf8",
      timeout: timeoutMs,
      windowsHide: true,
      maxBuffer: 1024 * 1024,
    });
    stdout = result.stdout || "";
    stderr = result.stderr || "";
    exitCode = 0;
  } catch (err) {
    stdout = err.stdout || "";
    stderr = err.stderr || "";
    if (typeof err.code === "number") {
      exitCode = err.code;
    } else if (err.killed || err.signal) {
      return {
        ok: false,
        exitCode: EXIT_FAIL,
        error: `CMC helper timed out or was killed (${err.signal || "timeout"})`,
        stderr,
      };
    } else {
      return {
        ok: false,
        exitCode: EXIT_FAIL,
        error: `CMC helper failed to start: ${err.message}`,
        stderr,
      };
    }
  }

  let parsed;
  try {
    parsed = JSON.parse(String(stdout).trim());
  } catch {
    return {
      ok: false,
      exitCode: EXIT_FAIL,
      error: "CMC helper stdout was not JSON",
      stdout,
      stderr,
    };
  }

  if (exitCode === EXIT_OK) {
    return { ok: true, exitCode, result: parsed };
  }
  if (exitCode === EXIT_UNKNOWN) {
    return {
      ok: true,
      exitCode,
      result: {
        ...parsed,
        disposition: "unknown",
        error: typeof parsed.error === "string" ? parsed.error : "unknown disposition",
      },
    };
  }
  return {
    ok: false,
    exitCode: EXIT_FAIL,
    error: typeof parsed.error === "string" ? parsed.error : "CMC helper hard failure",
    result: parsed,
    stderr,
  };
}

module.exports = {
  decodeCmcResponse,
  EXIT_OK,
  EXIT_UNKNOWN,
  EXIT_FAIL,
};
