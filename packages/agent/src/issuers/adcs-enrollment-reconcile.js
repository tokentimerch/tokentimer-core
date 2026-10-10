"use strict";

/**
 * Bounded tier-2 reconciliation for AD CS submission_uncertain enrollments
 * (ADR-0014 decision 10): requester-scoped certreq -retrieve over a window
 * above the per-CA RequestId watermark. Never resubmits.
 */

const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const crypto = require("node:crypto");
const { applyRestrictivePermissions } = require("../platform/index.js");
const WATERMARK_DIR = "adcs-ca-watermarks";
const DEFAULT_RECONCILE_WINDOW = 16;
const FILE_MODE = 0o600;
const DIR_MODE = 0o700;

function leafSpkiSha256Hex(certificatePem) {
  const { X509Certificate } = require("node:crypto");
  const cert = new X509Certificate(certificatePem);
  const spki = cert.publicKey.export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(spki).digest("hex");
}

function caConfigDigest(caConfig) {
  return crypto.createHash("sha256").update(String(caConfig), "utf8").digest("hex");
}

function watermarkPath(stateDir, caConfig) {
  return path.join(stateDir, WATERMARK_DIR, `${caConfigDigest(caConfig)}.json`);
}

function readHighestRequestId(stateDir, caConfig) {
  if (typeof stateDir !== "string" || typeof caConfig !== "string") return 0;
  const filePath = watermarkPath(stateDir, caConfig);
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw);
    if (Number.isInteger(parsed.highestRequestId) && parsed.highestRequestId >= 1) {
      return parsed.highestRequestId;
    }
  } catch (err) {
    if (err && err.code !== "ENOENT") {
      // Fail closed for callers that care; treat as zero watermark.
    }
  }
  return 0;
}

async function recordHighestRequestId(stateDir, caConfig, requestId) {
  if (typeof stateDir !== "string" || typeof caConfig !== "string") return;
  if (!Number.isInteger(requestId) || requestId < 1) return;
  const current = readHighestRequestId(stateDir, caConfig);
  if (requestId <= current) return;
  const dir = path.join(stateDir, WATERMARK_DIR);
  await fsp.mkdir(dir, { recursive: true, mode: DIR_MODE });
  const dest = watermarkPath(stateDir, caConfig);
  const tmp = `${dest}.${process.pid}.${Date.now()}.tmp`;
  const payload = `${JSON.stringify({
    caConfig,
    highestRequestId: requestId,
    updatedAt: new Date().toISOString(),
  })}\n`;
  await fsp.writeFile(tmp, payload, { mode: FILE_MODE });
  try {
    applyRestrictivePermissions(tmp);
  } catch {
    // best-effort ACL
  }
  await fsp.rename(tmp, dest);
}

/**
 * Probe RequestIds (watermark+1 .. watermark+window) via retrieve.
 * Returns issued only when the leaf SPKI matches the journaled CSR SPKI.
 *
 * @returns {Promise<
 *   | { status: "reconciled", requestId: number, certificatePem: string }
 *   | { status: "unresolved", probed: number }
 * >}
 */
async function tryReconcileUncertainSubmission({
  issuer,
  stateDir,
  caConfig,
  csrSpkiSha256,
  windowSize = DEFAULT_RECONCILE_WINDOW,
  assertIssuanceOutcome,
}) {
  if (typeof csrSpkiSha256 !== "string" || !/^[a-f0-9]{64}$/.test(csrSpkiSha256)) {
    return { status: "unresolved", probed: 0 };
  }
  const watermark = readHighestRequestId(stateDir, caConfig);
  const window =
    Number.isInteger(windowSize) && windowSize >= 1 && windowSize <= 64
      ? windowSize
      : DEFAULT_RECONCILE_WINDOW;
  let probed = 0;
  for (let requestId = watermark + 1; requestId <= watermark + window; requestId += 1) {
    probed += 1;
    let issuance;
    try {
      issuance = assertIssuanceOutcome(await issuer.retrieve(requestId));
    } catch {
      continue;
    }
    if (Number.isInteger(issuance.requestId) && issuance.requestId >= 1) {
      await recordHighestRequestId(stateDir, caConfig, issuance.requestId);
    } else {
      await recordHighestRequestId(stateDir, caConfig, requestId);
    }
    if (issuance.outcome !== "issued" || typeof issuance.certificatePem !== "string") {
      continue;
    }
    let leafSpki;
    try {
      leafSpki = leafSpkiSha256Hex(issuance.certificatePem);
    } catch {
      continue;
    }
    if (leafSpki !== csrSpkiSha256) continue;
    return {
      status: "reconciled",
      requestId: Number.isInteger(issuance.requestId) ? issuance.requestId : requestId,
      certificatePem: issuance.certificatePem,
    };
  }
  return { status: "unresolved", probed };
}

module.exports = {
  DEFAULT_RECONCILE_WINDOW,
  readHighestRequestId,
  recordHighestRequestId,
  tryReconcileUncertainSubmission,
  watermarkPath,
};
