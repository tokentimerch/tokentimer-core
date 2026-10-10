"use strict";

/**
 * JS bridge to tokentimer-adcs-chain (ADR-0014 decision 6).
 * Argv only, never a shell. stdout is one JSON object. One process per check.
 */

const fs = require("node:fs");
const path = require("node:path");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");

const execFileAsync = promisify(execFile);

const EXIT_OK = 0;
const EXIT_DEFERRED = 1;
const EXIT_FAIL = 2;

const RECOGNIZED_VERDICTS = new Set(["valid", "invalid", "revocation_unknown", "ca_key_changed"]);

/**
 * @param {object} [opts]
 * @param {string} [opts.overridePath]
 * @param {string} [opts.packageRoot]
 */
function resolveAdcsChainHelperPath({ overridePath, packageRoot } = {}) {
  if (typeof overridePath === "string" && overridePath.length > 0) {
    if (!fs.existsSync(overridePath)) {
      return { error: `AD CS chain helper not found at ${overridePath}` };
    }
    return { path: overridePath };
  }
  const root =
    typeof packageRoot === "string" && packageRoot.length > 0
      ? packageRoot
      : path.join(__dirname, "..", "..");
  const name = process.platform === "win32" ? "tokentimer-adcs-chain.exe" : "tokentimer-adcs-chain";
  const candidates = [
    path.join(root, "reference", "adcs-chain", "dist", name),
    path.join(root, "reference", "adcs-chain", "dist", "tokentimer-adcs-chain-windows-amd64.exe"),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return { path: candidate };
  }
  return {
    error:
      "tokentimer-adcs-chain helper binary is not installed under packages/agent/reference/adcs-chain/dist",
  };
}

function expectedExitForVerdict(verdict) {
  if (verdict === "valid") return EXIT_OK;
  if (verdict === "revocation_unknown") return EXIT_DEFERRED;
  return EXIT_FAIL;
}

/**
 * @param {object} params
 * @param {string} params.helperPath
 * @param {string} params.certPath leaf certificate file (PEM or DER)
 * @param {string} params.caKeySha256
 * @param {"require"|"best-effort"} [params.revocationCheck]
 * @param {string} [params.extraStorePath] optional PKCS#7 / cert bag for intermediates
 * @param {string} [params.caCertPath] pinned CA cert (also used as extra store)
 * @param {typeof execFileAsync} [params.execFileImpl]
 * @param {number} [params.timeoutMs]
 */
async function validateCertificateChain({
  helperPath,
  certPath,
  caKeySha256,
  revocationCheck = "require",
  extraStorePath,
  caCertPath,
  execFileImpl = execFileAsync,
  timeoutMs = 60_000,
}) {
  if (typeof helperPath !== "string" || helperPath.length === 0) {
    throw new TypeError("helperPath is required");
  }
  if (typeof certPath !== "string" || certPath.length === 0) {
    throw new TypeError("certPath is required");
  }
  if (typeof caKeySha256 !== "string" || !/^[a-f0-9]{64}$/.test(caKeySha256)) {
    throw new TypeError("caKeySha256 must be 64 lowercase hex characters");
  }
  if (revocationCheck !== "require" && revocationCheck !== "best-effort") {
    throw new TypeError("revocationCheck must be require or best-effort");
  }

  const argv = [
    "--cert",
    certPath,
    "--ca-key-sha256",
    caKeySha256,
    "--revocation",
    revocationCheck,
  ];
  if (typeof extraStorePath === "string" && extraStorePath.length > 0) {
    argv.push("--extra-store", extraStorePath);
  }
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
        verdict: "invalid",
        detail: `chain helper timed out or was killed (${err.signal || "timeout"})`,
        stderr,
      };
    } else {
      return {
        ok: false,
        exitCode: EXIT_FAIL,
        verdict: "invalid",
        detail: `chain helper failed to start: ${err.message}`,
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
      verdict: "invalid",
      detail: "chain helper stdout was not JSON",
      stdout,
      stderr,
    };
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return {
      ok: false,
      exitCode: EXIT_FAIL,
      verdict: "invalid",
      detail: "chain helper JSON was not an object",
      stdout,
      stderr,
    };
  }

  const verdict = parsed.verdict;
  if (typeof verdict !== "string" || !RECOGNIZED_VERDICTS.has(verdict)) {
    return {
      ok: false,
      exitCode: EXIT_FAIL,
      verdict: "invalid",
      detail: "chain helper response missing a recognized verdict",
      result: parsed,
      stderr,
    };
  }

  const expectedExit = expectedExitForVerdict(verdict);
  if (exitCode !== expectedExit) {
    return {
      ok: false,
      exitCode: EXIT_FAIL,
      verdict: "invalid",
      detail: `chain helper exit ${exitCode} disagrees with verdict ${verdict} (expected exit ${expectedExit})`,
      result: parsed,
      stderr,
    };
  }

  const detail = typeof parsed.error === "string" ? parsed.error : parsed.detail;

  if (verdict === "valid") {
    return { ok: true, exitCode, verdict: "valid", result: parsed };
  }
  if (verdict === "revocation_unknown") {
    return {
      ok: true,
      exitCode: EXIT_DEFERRED,
      verdict: "revocation_unknown",
      detail: detail || "revocation status unknown",
      result: parsed,
    };
  }
  if (verdict === "ca_key_changed") {
    return {
      ok: false,
      exitCode: EXIT_FAIL,
      verdict: "ca_key_changed",
      detail: detail || "issuing CA key does not match pin",
      result: parsed,
    };
  }
  return {
    ok: false,
    exitCode: EXIT_FAIL,
    verdict: "invalid",
    detail: detail || "chain validation failed",
    result: parsed,
    stderr,
  };
}

module.exports = {
  resolveAdcsChainHelperPath,
  validateCertificateChain,
  EXIT_OK,
  EXIT_DEFERRED,
  EXIT_FAIL,
  RECOGNIZED_VERDICTS,
};
