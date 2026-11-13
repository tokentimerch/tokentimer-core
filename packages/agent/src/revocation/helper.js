"use strict";

const path = require("node:path");
const { spawn } = require("node:child_process");
const { X509Certificate } = require("node:crypto");

const MAX_INPUT = 2 * 1024 * 1024;
const MAX_OUTPUT = 16 * 1024;
const VERDICTS = new Set(["good", "revoked", "issuer_revoked", "unknown"]);
const CHAIN_STATES = new Set(["valid", "invalid", "unknown"]);

function resolveHelperPath({ packageRoot = path.resolve(__dirname, "../.."), platform = process.platform, arch = process.arch } = {}) {
  const target = { x64: "amd64", arm64: "arm64" }[arch];
  if (!target || !["win32", "linux"].includes(platform)) return null;
  const suffix = platform === "win32" ? ".exe" : "";
  const os = platform === "win32" ? "windows" : "linux";
  return path.join(packageRoot, "bin", `tokentimer-observed-revocation-${os}-${target}${suffix}`);
}

// Input/output contain public certificate material only. Fail closed on a
// missing executable, timeout, malformed output or an identity mismatch.
function checkObservedCertificate({ helperPath = resolveHelperPath(), certificatePem, fingerprintSha256, roots, intermediates = [], systemRoots = [], systemIntermediates = [], allowedOrigins = [], spawnImpl = spawn, timeoutMs = 65000 } = {}) {
  const unknown = () => ({ verdict: "unknown", chainStatus: "unknown", detail: "verification unavailable" });
  if (!helperPath || !Array.isArray(roots) || !Array.isArray(systemRoots) || roots.length + systemRoots.length === 0 || !Array.isArray(intermediates) || !Array.isArray(systemIntermediates) || !Array.isArray(allowedOrigins) || allowedOrigins.some((value) => typeof value !== "string")) return Promise.resolve(unknown());
  try {
    const cert = new X509Certificate(certificatePem);
    if (cert.fingerprint256.replace(/:/g, "").toLowerCase() !== fingerprintSha256) return Promise.resolve(unknown());
    certificatePem = cert.toString();
    for (const certPem of [...roots, ...intermediates, ...systemRoots, ...systemIntermediates]) {
      if (typeof certPem !== "string" || !/^-----BEGIN CERTIFICATE-----\s*[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*$/.test(certPem)) return Promise.resolve(unknown());
      new X509Certificate(certPem);
    }
  } catch (_) { return Promise.resolve(unknown()); }
  const input = JSON.stringify({ leaf: certificatePem, roots, intermediates, systemRoots, systemIntermediates, allowedOrigins });
  if (Buffer.byteLength(input) > MAX_INPUT || !Number.isInteger(timeoutMs) || timeoutMs <= 0) return Promise.resolve(unknown());
  return new Promise((resolve) => {
    let child, finished = false, output = "", size = 0;
    const finish = (result) => { if (finished) return; finished = true; clearTimeout(timer); resolve(result); };
    const timer = setTimeout(() => { child?.kill(); finish(unknown()); }, timeoutMs);
    try { child = spawnImpl(helperPath, [], { stdio: ["pipe", "pipe", "ignore"], windowsHide: true, shell: false }); }
    catch (_) { finish(unknown()); return; }
    child.on("error", () => finish(unknown()));
    child.stdin.on("error", () => {});
    child.stdout.on("data", (chunk) => { size += chunk.length; if (size > MAX_OUTPUT) { child.kill(); finish(unknown()); return; } output += chunk.toString("utf8"); });
    child.on("close", (code) => {
      if (code !== 0) return finish(unknown());
      try {
        const result = JSON.parse(output);
        if (!VERDICTS.has(result.verdict) || !CHAIN_STATES.has(result.chainStatus) || !Number.isFinite(Date.parse(result.checkedAt))) return finish(unknown());
        if (result.verdict !== "unknown" && (!Number.isFinite(Date.parse(result.validUntil)) || Date.parse(result.validUntil) <= Date.parse(result.checkedAt) || result.chainStatus !== "valid")) return finish(unknown());
        const issuerFingerprint = result.revokedIssuerFingerprintSha256;
        if (issuerFingerprint !== undefined && (result.verdict !== "issuer_revoked" || typeof issuerFingerprint !== "string" || !/^[a-f0-9]{64}$/.test(issuerFingerprint) || ![...intermediates, ...systemIntermediates].some((value) => new X509Certificate(value).fingerprint256.replace(/:/g, "").toLowerCase() === issuerFingerprint))) return finish(unknown());
        return finish({ verdict: result.verdict, chainStatus: result.chainStatus, checkedAt: result.checkedAt, validUntil: result.validUntil || null, detail: typeof result.detail === "string" ? result.detail.slice(0, 256) : null, ...(issuerFingerprint ? { revokedIssuerFingerprintSha256: issuerFingerprint } : {}) });
      } catch (_) { return finish(unknown()); }
    });
    child.stdin.end(input);
  });
}

module.exports = { resolveHelperPath, checkObservedCertificate };
