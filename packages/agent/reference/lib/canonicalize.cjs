"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

/**
 * tokentimer-protocol reference-client verifier helper.
 *
 * Self-contained against the PUBLISHED CertOps contracts only:
 *   - Canonicalization algorithm copied from
 *     packages/contracts/certops/canonical-json.cjs (ADR-0003). That file is
 *     the published byte-for-byte contract; this helper reimplements it so the
 *     reference client never imports production agent runtime
 *     (packages/agent/src/signing). An integrator reading only the published
 *     contracts can rebuild this helper from those rules alone.
 *   - Ed25519 verification via Node's crypto.createPublicKey +
 *     crypto.verify(null, ...) (PureEdDSA / raw Ed25519).
 *   - Validity-window check matching ADR-0003's [issuedAt, expiresAt]
 *     semantics with a 30s tolerance.
 *
 * Node engines: >=22.0.0 <25.0.0 (same range as @tokentimer/agent).
 *
 * Usage:
 *   node canonicalize.cjs canonicalize <job.json>
 *   node canonicalize.cjs extract-field <job.json> <fieldName>
 *   node canonicalize.cjs verify <job.json> <pubkey.pem> <pinnedSigningKeyId> [--skip-time-window]
 *
 * Exit codes (verify): 0 = allowed; 1 = soft-rejected (JSON on stdout);
 * 2 = usage / programmer error.
 */

const NODE_MAJOR = Number.parseInt(process.versions.node.split(".")[0], 10);
if (!(NODE_MAJOR >= 22 && NODE_MAJOR < 25)) {
  process.stderr.write(
    `canonicalize: Node ${process.versions.node} is outside the required range >=22.0.0 <25.0.0\n`,
  );
  process.exit(2);
}

const DEFAULT_TIME_WINDOW_TOLERANCE_MS = 30000;
const SIGNATURE_LENGTH_MIN = 64;
const SIGNATURE_LENGTH_MAX = 1024;
const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;
const SIGNING_KEY_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
const NONCE_PATTERN = /^[A-Za-z0-9_.:-]{16,128}$/;

const EXTRACTABLE_FIELDS = new Set([
  "jobId",
  "action",
  "mode",
  "keyMode",
  "nonce",
  "issuedAt",
  "expiresAt",
  "signingKeyId",
  "signature",
  "claimId",
  "attemptId",
]);

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null)
  );
}

function serializeCanonical(value, pathLabel) {
  if (value === undefined) {
    throw new Error(
      `canonicalize found undefined at ${pathLabel}; undefined is not representable in JSON`,
    );
  }
  if (value === null) return "null";
  const valueType = typeof value;
  if (valueType === "boolean") return value ? "true" : "false";
  if (valueType === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(`canonicalize found a non-finite number at ${pathLabel}`);
    }
    return JSON.stringify(value);
  }
  if (valueType === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    const items = value.map((item, index) =>
      serializeCanonical(item, `${pathLabel}[${index}]`),
    );
    return `[${items.join(",")}]`;
  }
  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort();
    const entries = keys.map((key) => {
      const serialized = serializeCanonical(value[key], `${pathLabel}.${key}`);
      return `${JSON.stringify(key)}:${serialized}`;
    });
    return `{${entries.join(",")}}`;
  }
  throw new Error(
    `canonicalize cannot serialize type ${valueType} at ${pathLabel}`,
  );
}

function canonicalizeJobPayload(job) {
  if (!isPlainObject(job)) {
    throw new Error("canonicalize requires a plain object job payload");
  }
  const withoutSignature = {};
  for (const key of Object.keys(job)) {
    if (key === "signature") continue;
    withoutSignature[key] = job[key];
  }
  return serializeCanonical(withoutSignature, "$");
}

function reject(rejectionReason, detail) {
  return { allowed: false, rejectionReason, detail };
}

function findSignedFieldProblem(job) {
  if (!isPlainObject(job)) return "job payload must be a plain object";
  if (
    typeof job.signature !== "string" ||
    job.signature.length < SIGNATURE_LENGTH_MIN ||
    job.signature.length > SIGNATURE_LENGTH_MAX ||
    !BASE64_PATTERN.test(job.signature)
  ) {
    return "job signature is missing or not a well-formed base64 string (64-1024 chars)";
  }
  if (
    typeof job.signingKeyId !== "string" ||
    !SIGNING_KEY_ID_PATTERN.test(job.signingKeyId)
  ) {
    return "job signingKeyId is missing or malformed";
  }
  if (typeof job.nonce !== "string" || !NONCE_PATTERN.test(job.nonce)) {
    return "job nonce is missing or malformed (16-128 chars, [A-Za-z0-9_.:-])";
  }
  if (typeof job.issuedAt !== "string" || Number.isNaN(Date.parse(job.issuedAt))) {
    return "job issuedAt is missing or not a parseable date-time";
  }
  if (
    typeof job.expiresAt !== "string" ||
    Number.isNaN(Date.parse(job.expiresAt))
  ) {
    return "job expiresAt is missing or not a parseable date-time";
  }
  return null;
}

function verifyJobSignature({ job, publicKeyPem, pinnedSigningKeyId }) {
  if (typeof publicKeyPem !== "string" || publicKeyPem.length === 0) {
    throw new Error("verify requires a publicKeyPem string");
  }
  if (
    typeof pinnedSigningKeyId !== "string" ||
    pinnedSigningKeyId.length === 0
  ) {
    throw new Error("verify requires a pinnedSigningKeyId string");
  }

  const fieldProblem = findSignedFieldProblem(job);
  if (fieldProblem !== null) {
    return reject("job_integrity_failed", `Signed job field validation failed: ${fieldProblem}.`);
  }
  if (job.signingKeyId !== pinnedSigningKeyId) {
    return reject(
      "job_integrity_failed",
      `Signing key id mismatch: job was signed with key id "${job.signingKeyId}" but pinned key id is "${pinnedSigningKeyId}".`,
    );
  }

  let publicKey;
  try {
    publicKey = crypto.createPublicKey(publicKeyPem);
  } catch (err) {
    throw new Error(`verify was given an unparseable publicKeyPem: ${err.message}`);
  }

  let verified = false;
  try {
    const canonicalBytes = Buffer.from(canonicalizeJobPayload(job), "utf8");
    const signatureBytes = Buffer.from(job.signature, "base64");
    verified = crypto.verify(null, canonicalBytes, publicKey, signatureBytes);
  } catch (err) {
    return reject(
      "job_integrity_failed",
      `Job payload could not be canonically serialized or verified (${err.message}).`,
    );
  }

  if (!verified) {
    return reject(
      "job_integrity_failed",
      "Job signature verification failed: the Ed25519 signature does not match the canonical job payload under the pinned signing key.",
    );
  }
  return { allowed: true };
}

function checkJobTimeWindow({
  job,
  nowMs,
  clockOffsetMs = null,
  toleranceMs = DEFAULT_TIME_WINDOW_TOLERANCE_MS,
}) {
  if (!Number.isFinite(nowMs)) {
    throw new Error("checkJobTimeWindow requires a finite nowMs");
  }
  if (!Number.isFinite(toleranceMs) || toleranceMs < 0) {
    throw new Error("checkJobTimeWindow toleranceMs must be a non-negative finite number");
  }
  if (
    !isPlainObject(job) ||
    typeof job.issuedAt !== "string" ||
    Number.isNaN(Date.parse(job.issuedAt)) ||
    typeof job.expiresAt !== "string" ||
    Number.isNaN(Date.parse(job.expiresAt))
  ) {
    return reject(
      "job_integrity_failed",
      "Job issuedAt/expiresAt missing or unparseable; cannot establish a validity window.",
    );
  }

  const issuedAtMs = Date.parse(job.issuedAt);
  const expiresAtMs = Date.parse(job.expiresAt);
  if (expiresAtMs < issuedAtMs) {
    return reject(
      "job_integrity_failed",
      "Job validity window is malformed: expiresAt precedes issuedAt.",
    );
  }

  const offsetApplies =
    typeof clockOffsetMs === "number" &&
    Number.isFinite(clockOffsetMs) &&
    Number.isInteger(clockOffsetMs);
  const adjustedNowMs = offsetApplies ? nowMs + clockOffsetMs : nowMs;

  if (adjustedNowMs < issuedAtMs - toleranceMs) {
    return reject(
      "clock_drift_suspected",
      `Job issuedAt is ${issuedAtMs - adjustedNowMs}ms in the future (tolerance ${toleranceMs}ms); local clock drift suspected.`,
    );
  }
  if (adjustedNowMs > expiresAtMs + toleranceMs) {
    return reject(
      "clock_drift_suspected",
      `Job expired ${adjustedNowMs - expiresAtMs}ms ago (tolerance ${toleranceMs}ms); stale dispatch or local clock drift.`,
    );
  }
  return { allowed: true };
}

function fail(message) {
  process.stderr.write(`canonicalize: ${message}\n`);
  process.exit(2);
}

function readJobFile(jobFilePath) {
  let raw;
  try {
    raw = fs.readFileSync(jobFilePath, "utf8");
  } catch (err) {
    fail(`could not read job file "${jobFilePath}": ${err.message}`);
  }
  try {
    return JSON.parse(raw);
  } catch (err) {
    fail(`job file "${jobFilePath}" is not valid JSON: ${err.message}`);
  }
}

function readPublicKeyPem(pemPath) {
  try {
    return fs.readFileSync(pemPath, "utf8");
  } catch (err) {
    fail(`could not read public key file "${pemPath}": ${err.message}`);
  }
}

function cmdCanonicalize(args) {
  const [jobFilePath] = args;
  if (!jobFilePath) fail("canonicalize requires <job.json>");
  const job = readJobFile(jobFilePath);
  let canonical;
  try {
    canonical = canonicalizeJobPayload(job);
  } catch (err) {
    fail(`could not canonicalize job payload: ${err.message}`);
  }
  process.stdout.write(canonical);
}

function cmdExtractField(args) {
  const [jobFilePath, fieldName] = args;
  if (!jobFilePath || !fieldName) {
    fail("extract-field requires <job.json> <fieldName>");
  }
  if (!EXTRACTABLE_FIELDS.has(fieldName)) {
    fail(
      `field "${fieldName}" is not extractable (allowed: ${[...EXTRACTABLE_FIELDS].join(", ")})`,
    );
  }
  const job = readJobFile(jobFilePath);
  const value = job?.[fieldName];
  if (typeof value !== "string") {
    fail(`job field "${fieldName}" is missing or not a string`);
  }
  process.stdout.write(value);
}

function cmdVerify(args) {
  const [jobFilePath, pubKeyPath, pinnedSigningKeyId, ...rest] = args;
  if (!jobFilePath || !pubKeyPath || !pinnedSigningKeyId) {
    fail(
      "verify requires <job.json> <pubkey.pem> <pinnedSigningKeyId> [--skip-time-window]",
    );
  }
  const skipTimeWindow = rest.includes("--skip-time-window");
  const job = readJobFile(jobFilePath);
  const publicKeyPem = readPublicKeyPem(pubKeyPath);

  let signatureResult;
  try {
    signatureResult = verifyJobSignature({
      job,
      publicKeyPem,
      pinnedSigningKeyId,
    });
  } catch (err) {
    fail(err.message);
  }

  if (signatureResult.allowed && !skipTimeWindow) {
    const timeWindowResult = checkJobTimeWindow({ job, nowMs: Date.now() });
    if (!timeWindowResult.allowed) {
      process.stdout.write(`${JSON.stringify(timeWindowResult)}\n`);
      process.exit(1);
    }
  }

  process.stdout.write(`${JSON.stringify(signatureResult)}\n`);
  process.exit(signatureResult.allowed ? 0 : 1);
}

function main() {
  const [subcommand, ...rest] = process.argv.slice(2);
  switch (subcommand) {
    case "canonicalize":
      return cmdCanonicalize(rest);
    case "extract-field":
      return cmdExtractField(rest);
    case "verify":
      return cmdVerify(rest);
    default:
      return fail(
        `unknown subcommand "${subcommand ?? ""}" (expected canonicalize | extract-field | verify)`,
      );
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  EXTRACTABLE_FIELDS,
  canonicalizeJobPayload,
  verifyJobSignature,
  checkJobTimeWindow,
  cmdCanonicalize,
  cmdExtractField,
  cmdVerify,
};