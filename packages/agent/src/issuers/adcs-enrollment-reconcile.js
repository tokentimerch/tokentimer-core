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
const { acquireExclusiveLockFile } = require("../windows-cert-store");

const WATERMARK_DIR = "adcs-ca-watermarks";
const DEFAULT_RECONCILE_WINDOW = 16;
const DIR_MODE = 0o700;
/** E_ACCESSDENIED: RequestId belongs to another requester; never our leaf. */
const RECONCILE_SKIP_CA_HRESULT = new Set(["0x80070005"]);

/**
 * Outcomes that cannot become this enrollment's leaf later. Skip them for
 * attachmentEligible / nextSearchFrom so a later unique SPKI match can attach.
 */
function isSkippableReconcileProbe(issuance) {
  if (issuance.outcome === "denied" || issuance.outcome === "refused") return true;
  if (
    issuance.outcome === "uncertain" &&
    typeof issuance.caHresult === "string" &&
    RECONCILE_SKIP_CA_HRESULT.has(issuance.caHresult)
  ) {
    return true;
  }
  return false;
}

/**
 * Per-CA watermark mutex via the shared exclusive lock helper (kernel
 * IPC listen). Holder crash releases the listen automatically; two
 * processes must never both observe ownership.
 */
async function withWatermarkLock(stateDir, caConfig, fn) {
  const dir = path.join(stateDir, WATERMARK_DIR);
  fs.mkdirSync(dir, { recursive: true, mode: DIR_MODE });
  const lockPath = watermarkLockPath(stateDir, caConfig);
  const lock = acquireExclusiveLockFile(
    lockPath,
    "ADCS_WATERMARK_LOCKED",
    "CA RequestId watermark is locked by a concurrent update",
  );
  try {
    const result = await lock.run(async () => fn(lock));
    lock.assertHeld();
    return result;
  } finally {
    lock.release();
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
  return await withWatermarkLock(stateDir, caConfig, async (lock) => {
    lock.assertHeld();
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
    lock.assertHeld();
    return requestId;
  });
}

/**
 * Enrollment-specific tier-2 start cursor: one past the CA watermark captured
 * before CA contact. Later watermark advances by other enrollments must not
 * move this enrollment's recovery starting point.
 */
function captureEnrollmentReconcileSearchFrom(stateDir, caConfig) {
  const watermark = readWatermark(stateDir, caConfig);
  if (!watermark.ok) {
    const err = new Error(watermark.error);
    err.code = "ADCS_REQUESTID_WATERMARK_CORRUPT";
    throw err;
  }
  return watermark.highestRequestId + 1;
}

/**
 * Probe a bounded RequestId window for leaves whose SPKI matches the CSR.
 *
 * Does not advance the per-CA watermark on uncertain/failed probes.
 * `unique_candidate` means one visible SPKI match in this window only; earlier
 * pending/inaccessible ids may still match later (`attachmentEligible` is
 * false when any earlier open id remains). Caller must run decision-6 before
 * attaching RequestId, and must never advance the enrollment cursor past the
 * earliest unresolved id merely because a candidate failed validation.
 *
 * @param {number} params.reconcileSearchFrom enrollment-specific cursor (required)
 * @returns {Promise<
 *   | { status: "unique_candidate", requestId: number, certificatePem: string, nextSearchFrom: number, probed: number, attachmentEligible: boolean }
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
  reconcileSearchFrom,
  windowSize = DEFAULT_RECONCILE_WINDOW,
  assertIssuanceOutcome,
}) {
  if (typeof csrSpkiSha256 !== "string" || !/^[a-f0-9]{64}$/.test(csrSpkiSha256)) {
    return { status: "error", error: "csrSpkiSha256 is required for tier-2 reconcile" };
  }
  if (!Number.isInteger(reconcileSearchFrom) || reconcileSearchFrom < 1) {
    return {
      status: "error",
      error:
        "reconcileSearchFrom is required; enrollment must capture the CA watermark before submit",
    };
  }
  // Watermark is read only to fail closed on corruption; scan start is enrollment-scoped.
  const watermark = readWatermark(stateDir, caConfig);
  if (!watermark.ok) {
    return { status: "error", error: watermark.error };
  }
  const window =
    Number.isInteger(windowSize) && windowSize >= 1 && windowSize <= 64
      ? windowSize
      : DEFAULT_RECONCILE_WINDOW;

  const start = reconcileSearchFrom;
  // Extend past the live watermark so ids allocated after capture remain reachable.
  const scanEnd = Math.max(start + window, watermark.highestRequestId + 1 + window);
  const matches = [];
  let firstOpenId = null;
  let probed = 0;

  for (let requestId = start; requestId < scanEnd; requestId += 1) {
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
        // Matching candidate stays open until decision-6 confirms attachment.
        if (firstOpenId === null) firstOpenId = requestId;
        continue;
      }
      // Issued leaf with a different key is not this enrollment; skip past it
      // for the enrollment cursor only. Do not touch the CA watermark.
      continue;
    }

    if (isSkippableReconcileProbe(issuance)) {
      continue;
    }

    // pending / PROPERTY_EMPTY / other uncertain: may still become our leaf.
    if (firstOpenId === null) firstOpenId = requestId;
  }

  const nextSearchFrom = firstOpenId !== null ? firstOpenId : scanEnd;

  if (matches.length === 1) {
    const match = matches[0];
    return {
      status: "unique_candidate",
      requestId: match.requestId,
      certificatePem: match.certificatePem,
      nextSearchFrom,
      probed,
      // True only when no earlier unresolved id remains in the scanned range.
      attachmentEligible: firstOpenId === match.requestId,
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
  captureEnrollmentReconcileSearchFrom,
  tryReconcileUncertainSubmission,
  watermarkPath,
  watermarkLockPath,
  leafSpkiSha256Hex,
};
