"use strict";

/**
 * AD CS enrollment helpers for the Windows IIS executor: snapshot decode,
 * helper binary resolution, pinned CA cert cache, and RequestId journal.
 */

const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const crypto = require("node:crypto");
const { X509Certificate } = require("node:crypto");

const ENROLLMENT_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX64 = /^[a-f0-9]{64}$/;

/** Windows rejects `:` in ordinary directory names; jobId allows it. */
function filesystemSafeJobId(jobId) {
  if (typeof jobId !== "string" || jobId.length === 0) {
    throw new TypeError("jobId is required");
  }
  return jobId.replace(/[^A-Za-z0-9_.-]/g, "_").slice(0, 128);
}

function computeSpkiSha256Hex(certBytes) {
  const cert = new X509Certificate(certBytes);
  const spki = cert.publicKey.export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(spki).digest("hex");
}

/**
 * @param {object} job
 * @returns {{ ok: true, enrollmentId: string, attempt: number, snapshot: object, snapshotSha256: string }
 *   | { ok: false, error: string }}
 */
function decodeEnrollmentSnapshot(job) {
  const enrollment = job?.enrollment;
  if (!enrollment || typeof enrollment !== "object") {
    return { ok: false, error: "AD CS job carries no enrollment binding" };
  }
  const enrollmentId = enrollment.enrollmentId;
  if (typeof enrollmentId !== "string" || !ENROLLMENT_ID_PATTERN.test(enrollmentId)) {
    return { ok: false, error: "enrollment.enrollmentId must be a lowercase UUID" };
  }
  const attempt = enrollment.attempt;
  if (!Number.isInteger(attempt) || attempt < 1) {
    return { ok: false, error: "enrollment.attempt must be an integer >= 1" };
  }
  const snapshotB64 = enrollment.snapshotB64;
  const snapshotSha256 = enrollment.snapshotSha256;
  if (typeof snapshotB64 !== "string" || snapshotB64.length === 0) {
    return { ok: false, error: "enrollment.snapshotB64 is required" };
  }
  if (typeof snapshotSha256 !== "string" || !HEX64.test(snapshotSha256)) {
    return { ok: false, error: "enrollment.snapshotSha256 must be 64 lowercase hex characters" };
  }
  let bytes;
  try {
    bytes = Buffer.from(snapshotB64, "base64");
  } catch {
    return { ok: false, error: "enrollment.snapshotB64 is not valid base64" };
  }
  if (bytes.length === 0) {
    return { ok: false, error: "enrollment.snapshotB64 decoded to empty bytes" };
  }
  const digest = crypto.createHash("sha256").update(bytes).digest("hex");
  if (digest !== snapshotSha256) {
    return { ok: false, error: "enrollment.snapshotSha256 does not match snapshotB64" };
  }
  let snapshot;
  try {
    snapshot = JSON.parse(bytes.toString("utf8"));
  } catch {
    return { ok: false, error: "enrollment snapshot is not valid JSON" };
  }
  if (!snapshot || typeof snapshot !== "object" || snapshot.kind !== "adcs") {
    return { ok: false, error: "enrollment snapshot kind must be adcs" };
  }
  return { ok: true, enrollmentId, attempt, snapshot, snapshotSha256 };
}

function mapSnapshotKeyAlgorithm(snapshot) {
  const algorithm = snapshot?.keyAlgorithm;
  const keySize = snapshot?.keySize;
  if (typeof algorithm !== "string" || !Number.isInteger(keySize)) {
    return { error: "enrollment snapshot is missing keyAlgorithm/keySize" };
  }
  const map = {
    "ecdsa:256": "ec-p256",
    "ecdsa:384": "ec-p384",
    "rsa:2048": "rsa-2048",
    "rsa:3072": "rsa-3072",
    "rsa:4096": "rsa-4096",
  };
  const mapped = map[`${algorithm}:${keySize}`];
  if (!mapped) {
    return {
      error: `unsupported snapshot keyAlgorithm/keySize: ${algorithm}/${keySize}`,
    };
  }
  return { algorithm: mapped };
}

/**
 * Resolves tokentimer-adcs-cmc next to this package's reference build output.
 * @param {object} [opts]
 * @param {string} [opts.overridePath]
 * @param {string} [opts.packageRoot] defaults to packages/agent
 */
function resolveAdcsCmcHelperPath({ overridePath, packageRoot } = {}) {
  if (typeof overridePath === "string" && overridePath.length > 0) {
    if (!fs.existsSync(overridePath)) {
      return { error: `AD CS CMC helper not found at ${overridePath}` };
    }
    return { path: overridePath };
  }
  const root =
    typeof packageRoot === "string" && packageRoot.length > 0
      ? packageRoot
      : path.join(__dirname, "..", "..");
  const name = process.platform === "win32" ? "tokentimer-adcs-cmc.exe" : "tokentimer-adcs-cmc";
  const candidates = [
    path.join(root, "reference", "adcs-cmc", "dist", name),
    path.join(root, "reference", "adcs-cmc", "dist", "tokentimer-adcs-cmc-windows-amd64.exe"),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return { path: candidate };
  }
  return {
    error:
      "tokentimer-adcs-cmc helper binary is not installed under packages/agent/reference/adcs-cmc/dist",
  };
}

function pinnedCaCertPath(stateDir, caKeySha256) {
  return path.join(stateDir, "adcs-ca", `${caKeySha256}.cer`);
}

/**
 * Stages or reuses a CA certificate whose SPKI SHA-256 matches the pin.
 * Prefer an explicit path (tests / operator), then the agent cache.
 * @returns {{ ok: true, caCertPath: string }|{ ok: false, error: string, errorCode?: string }}
 */
function resolvePinnedCaCertPath({ stateDir, caKeySha256, caCertPath }) {
  if (typeof caKeySha256 !== "string" || !HEX64.test(caKeySha256)) {
    return { ok: false, error: "caKeySha256 must be 64 lowercase hex characters" };
  }
  const candidates = [];
  if (typeof caCertPath === "string" && caCertPath.length > 0) {
    candidates.push(caCertPath);
  }
  if (typeof stateDir === "string" && stateDir.length > 0) {
    candidates.push(pinnedCaCertPath(stateDir, caKeySha256));
  }
  for (const candidate of candidates) {
    if (!fs.existsSync(candidate)) continue;
    let bytes;
    try {
      bytes = fs.readFileSync(candidate);
    } catch (err) {
      return { ok: false, error: `failed to read CA certificate: ${err.message}` };
    }
    let pin;
    try {
      pin = computeSpkiSha256Hex(bytes);
    } catch (err) {
      return { ok: false, error: `CA certificate is not valid X.509: ${err.message}` };
    }
    if (pin !== caKeySha256) {
      return {
        ok: false,
        errorCode: "ADCS_CA_KEY_UNPINNED",
        error: `CA certificate at ${candidate} does not match caKeySha256`,
      };
    }
    return { ok: true, caCertPath: candidate };
  }
  return {
    ok: false,
    errorCode: "ADCS_CA_KEY_UNPINNED",
    error:
      "no pinned CA certificate is staged for this enrollment; run adcs-preflight and cache the confirmed CA cert under stateDir/adcs-ca/<caKeySha256>.cer",
  };
}

/**
 * Writes a CA cert into the pin cache after verifying SPKI hash.
 */
async function cachePinnedCaCert({ stateDir, caKeySha256, certBytes }) {
  const pin = computeSpkiSha256Hex(certBytes);
  if (pin !== caKeySha256) {
    throw new Error("certificate SPKI does not match caKeySha256");
  }
  const dest = pinnedCaCertPath(stateDir, caKeySha256);
  await fsp.mkdir(path.dirname(dest), { recursive: true });
  await fsp.writeFile(dest, certBytes);
  return dest;
}

function enrollmentJournalPath(stateDir, enrollmentId) {
  return path.join(stateDir, "adcs-enrollments", `${enrollmentId}.json`);
}

async function writeEnrollmentRequestJournal({
  stateDir,
  enrollmentId,
  attempt,
  requestId,
  snapshotSha256,
  jobId,
}) {
  const dest = enrollmentJournalPath(stateDir, enrollmentId);
  await fsp.mkdir(path.dirname(dest), { recursive: true });
  const payload = {
    enrollmentId,
    attempt,
    requestId,
    snapshotSha256,
    jobId,
    updatedAt: new Date().toISOString(),
  };
  const tmp = `${dest}.${process.pid}.tmp`;
  await fsp.writeFile(tmp, `${JSON.stringify(payload)}\n`, "utf8");
  await fsp.rename(tmp, dest);
  return payload;
}

function readEnrollmentRequestJournal(stateDir, enrollmentId) {
  const dest = enrollmentJournalPath(stateDir, enrollmentId);
  try {
    const raw = fs.readFileSync(dest, "utf8");
    const parsed = JSON.parse(raw);
    if (!Number.isInteger(parsed.requestId) || parsed.requestId < 1) return null;
    return parsed;
  } catch {
    return null;
  }
}

module.exports = {
  filesystemSafeJobId,
  computeSpkiSha256Hex,
  decodeEnrollmentSnapshot,
  mapSnapshotKeyAlgorithm,
  resolveAdcsCmcHelperPath,
  pinnedCaCertPath,
  resolvePinnedCaCertPath,
  cachePinnedCaCert,
  writeEnrollmentRequestJournal,
  readEnrollmentRequestJournal,
  enrollmentJournalPath,
};
