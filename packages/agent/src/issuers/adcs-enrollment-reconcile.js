"use strict";

/**
 * Bounded tier-2 reconciliation for AD CS submission_uncertain enrollments
 * (ADR-0014 decision 10): requester-scoped certreq -retrieve over a window.
 * Never resubmits. Never advances the per-CA watermark on unsuccessful probes.
 */

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { durableWriteFile } = require("./adcs-enrollment-journal");

const WATERMARK_DIR = "adcs-ca-watermarks";
const DEFAULT_RECONCILE_WINDOW = 16;
const DIR_MODE = 0o700;

/** Minimal wx lock for per-CA watermark updates (same fail-closed idea as store locks). */
async function withWatermarkLock(stateDir, caConfig, fn) {
  const dir = path.join(stateDir, WATERMARK_DIR);
  fs.mkdirSync(dir, { recursive: true, mode: DIR_MODE });
  const lockPath = watermarkLockPath(stateDir, caConfig);
  let fd;
  try {
    fd = fs.openSync(lockPath, "wx");
  } catch (err) {
    if (err && err.code === "EEXIST") {
      const locked = new Error("CA RequestId watermark is locked by a concurrent update");
      locked.code = "ADCS_WATERMARK_LOCKED";
      throw locked;
    }
    throw err;
  }
  try {
    fs.writeSync(fd, `${process.pid}\n${new Date().toISOString()}\n`);
    return await fn();
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      // ignore
    }
    try {
      fs.unlinkSync(lockPath);
    } catch {
      // ignore
    }
  }
}

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

function watermarkLockPath(stateDir, caConfig) {
  return path.join(stateDir, WATERMARK_DIR, `${caConfigDigest(caConfig)}.lock`);
}

/**
 * @returns {{ ok: true, highestRequestId: number }
 *   | { ok: false, error: string }}
 */
function readWatermark(stateDir, caConfig) {
  if (typeof stateDir !== "string" || stateDir.length === 0) {
    return { ok: false, error: "stateDir is required" };
  }
  if (typeof caConfig !== "string" || caConfig.length === 0) {
    return { ok: false, error: "caConfig is required" };
  }
  const filePath = watermarkPath(stateDir, caConfig);
  let raw;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch (err) {
    if (err && err.code === "ENOENT") {
      return { ok: true, highestRequestId: 0 };
    }
    return { ok: false, error: `cannot read CA RequestId watermark: ${err.message}` };
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return { ok: false, error: `CA RequestId watermark is corrupt: ${err.message}` };
  }
  if (!parsed || typeof parsed !== "object") {
    return { ok: false, error: "CA RequestId watermark is not an object" };
  }
  if (
    !Number.isInteger(parsed.highestRequestId) ||
    parsed.highestRequestId < 0 ||
    parsed.highestRequestId > 0xffffffff
  ) {
    return { ok: false, error: "CA RequestId watermark has an invalid highestRequestId" };
  }
  return { ok: true, highestRequestId: parsed.highestRequestId };
}

/** Compatibility helper: returns 0 when missing; throws on corrupt watermark. */
function readHighestRequestId(stateDir, caConfig) {
  const read = readWatermark(stateDir, caConfig);
  if (!read.ok) {
    const err = new Error(read.error);
    err.code = "ADCS_REQUESTID_WATERMARK_CORRUPT";
    throw err;
  }
  return read.highestRequestId;
}

/**
 * Record a confirmed CA RequestId (pending or issued). Serialized per CA,
 * durable write, never decreases the watermark.
 */
async function recordHighestRequestId(stateDir, caConfig, requestId) {
  if (typeof stateDir !== "string" || typeof caConfig !== "string") {
    throw new TypeError("stateDir and caConfig are required");
  }
  if (!Number.isInteger(requestId) || requestId < 1) {
    throw new TypeError("requestId must be an integer >= 1");
  }
  return await withWatermarkLock(stateDir, caConfig, async () => {
    const current = readWatermark(stateDir, caConfig);
    if (!current.ok) {
      const err = new Error(current.error);
      err.code = "ADCS_REQUESTID_WATERMARK_CORRUPT";
      throw err;
    }
    if (requestId <= current.highestRequestId) return current.highestRequestId;
    const payload = `${JSON.stringify({
      caConfig,
      highestRequestId: requestId,
      updatedAt: new Date().toISOString(),
    })}\n`;
    await durableWriteFile(watermarkPath(stateDir, caConfig), payload);
    return requestId;
  });
}

/**
 * Probe a bounded RequestId window for leaves whose SPKI matches the CSR.
 *
 * Does not advance the per-CA watermark on uncertain/failed probes.
 * Returns a unique candidate only; the caller must run decision-6 before
 * attaching the RequestId to the enrollment journal.
 *
 * @param {number} [params.reconcileSearchFrom] enrollment-specific cursor
 * @returns {Promise<
 *   | { status: "unique_candidate", requestId: number, certificatePem: string, nextSearchFrom: number, probed: number }
 *   | { status: "ambiguous", matchCount: number, nextSearchFrom: number, probed: number }
 *   | { status: "unresolved", probed: number, nextSearchFrom: number }
 *   | { status: "error", error: string }
 * >}
 */
async function tryReconcileUncertainSubmission({
  issuer,
  stateDir,
  caConfig,
  csrSpkiSha256,
  reconcileSearchFrom = null,
  windowSize = DEFAULT_RECONCILE_WINDOW,
  assertIssuanceOutcome,
}) {
  if (typeof csrSpkiSha256 !== "string" || !/^[a-f0-9]{64}$/.test(csrSpkiSha256)) {
    return { status: "error", error: "csrSpkiSha256 is required for tier-2 reconcile" };
  }
  const watermark = readWatermark(stateDir, caConfig);
  if (!watermark.ok) {
    return { status: "error", error: watermark.error };
  }
  const window =
    Number.isInteger(windowSize) && windowSize >= 1 && windowSize <= 64
      ? windowSize
      : DEFAULT_RECONCILE_WINDOW;

  const start =
    Number.isInteger(reconcileSearchFrom) && reconcileSearchFrom >= 1
      ? reconcileSearchFrom
      : watermark.highestRequestId + 1;
  if (start < 1) {
    return { status: "unresolved", probed: 0, nextSearchFrom: 1 };
  }

  const matches = [];
  let firstOpenId = null;
  let probed = 0;

  for (let requestId = start; requestId < start + window; requestId += 1) {
    probed += 1;
    let issuance;
    try {
      issuance = assertIssuanceOutcome(await issuer.retrieve(requestId));
    } catch {
      if (firstOpenId === null) firstOpenId = requestId;
      continue;
    }

    if (issuance.outcome === "issued" && typeof issuance.certificatePem === "string") {
      let leafSpki;
      try {
        leafSpki = leafSpkiSha256Hex(issuance.certificatePem);
      } catch {
        if (firstOpenId === null) firstOpenId = requestId;
        continue;
      }
      if (leafSpki === csrSpkiSha256) {
        matches.push({
          requestId: Number.isInteger(issuance.requestId) ? issuance.requestId : requestId,
          certificatePem: issuance.certificatePem,
        });
        // Matching candidate stays open until decision-6 confirms uniqueness.
        if (firstOpenId === null) firstOpenId = requestId;
        continue;
      }
      // Issued leaf with a different key is not this enrollment; skip past it
      // for the enrollment cursor only. Do not touch the CA watermark.
      continue;
    }

    // pending / denied / uncertain / refused: keep eligible for a later scan.
    if (firstOpenId === null) firstOpenId = requestId;
  }

  const nextSearchFrom = firstOpenId !== null ? firstOpenId : start + window;

  if (matches.length === 1) {
    return {
      status: "unique_candidate",
      requestId: matches[0].requestId,
      certificatePem: matches[0].certificatePem,
      nextSearchFrom,
      probed,
    };
  }
  if (matches.length > 1) {
    return {
      status: "ambiguous",
      matchCount: matches.length,
      nextSearchFrom,
      probed,
    };
  }
  return { status: "unresolved", probed, nextSearchFrom };
}

module.exports = {
  DEFAULT_RECONCILE_WINDOW,
  readWatermark,
  readHighestRequestId,
  recordHighestRequestId,
  tryReconcileUncertainSubmission,
  watermarkPath,
  leafSpkiSha256Hex,
};
