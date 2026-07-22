"use strict";

/**
 * Job signature verification and canonicalization (signed-dispatch runtime,
 * ADR-0003).
 *
 * Jobs dispatched by the control plane are signed with an Ed25519 platform
 * operational signing key. The agent pins the corresponding public key
 * (`signingKeyId` + PEM) and verifies every job's signature before any other
 * processing. HMAC is explicitly rejected by ADR-0003 (a shared symmetric
 * secret would let any agent forge jobs for any other agent); only
 * node:crypto Ed25519 is used here.
 *
 * This module is intentionally self-contained: it accepts plain data as
 * function parameters and does not import sibling modules (config, protocol,
 * replay, ...). Wiring is left to src/index.js (dispatch-wiring work, done
 * separately).
 *
 * Rejection results use the exact shape the policy module produces
 * ({ allowed: false, rejectionReason, detail }) so downstream evidence/result
 * reporting handles policy and integrity rejections uniformly.
 *
 * Custody invariant: no function in this module ever places private key
 * material (or the public key PEM) into a returned detail string, error
 * message, or log line. Details reference key IDs and field names only.
 */

const crypto = require("node:crypto");

/**
 * Rejection reasons owned by the signature/time-window runtime,
 * mirroring the subset of agent-protocol.schema.json's
 * resultBody.rejectionReason enum not owned by the policy module.
 * (job_replay_rejected is owned by the sibling replay module.)
 */
const SIGNING_REJECTION_REASONS = Object.freeze({
  JOB_INTEGRITY_FAILED: "job_integrity_failed",
  CLOCK_DRIFT_SUSPECTED: "clock_drift_suspected",
});

/**
 * Default clock tolerance applied to the [issuedAt, expiresAt] window.
 *
 * Why 30000 ms: HTTP Date-based offset estimation (see the clock module) has
 * 1-second granularity, NTP-synced hosts are typically within tens of
 * milliseconds, and non-NTP hosts commonly drift by seconds, not minutes.
 * 30s absorbs realistic residual drift plus network latency between the
 * control plane stamping issuedAt and the agent validating it, while staying
 * far below the 5-minute dispatch validity window, so it never effectively
 * disables expiry.
 */
const DEFAULT_TIME_WINDOW_TOLERANCE_MS = 30000;

// job-payload.schema.json bounds: signature is base64, 64-1024 chars.
const SIGNATURE_LENGTH_MIN = 64;
const SIGNATURE_LENGTH_MAX = 1024;
const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;
const SIGNING_KEY_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
const NONCE_PATTERN = /^[A-Za-z0-9_.:-]{16,128}$/;

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null)
  );
}

/**
 * @param {string} rejectionReason
 * @param {string} detail
 * @returns {{ allowed: false, rejectionReason: string, detail: string }}
 */
function reject(rejectionReason, detail) {
  return { allowed: false, rejectionReason, detail };
}

/**
 * Recursive canonical JSON serializer shared by canonicalizeJobPayload.
 * Kept separate so the top-level signature exclusion (which applies ONLY at
 * depth 0 per ADR-0003) does not leak into nested levels.
 *
 * @param {*} value
 * @param {string} pathLabel JSON-path-ish label for error messages
 * @returns {string}
 */
function serializeCanonical(value, pathLabel) {
  if (value === undefined) {
    throw new Error(
      `signing: canonicalizeJobPayload found an undefined value at ${pathLabel}; ` +
        "undefined is not representable in JSON and would silently diverge " +
        "between implementations, so it is rejected",
    );
  }
  if (value === null) return "null";
  const valueType = typeof value;
  if (valueType === "boolean") return value ? "true" : "false";
  if (valueType === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(
        `signing: canonicalizeJobPayload found a non-finite number at ${pathLabel}`,
      );
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
    `signing: canonicalizeJobPayload cannot serialize value of type ` +
      `${valueType} at ${pathLabel} (only plain objects, arrays, strings, ` +
      "finite numbers, booleans, and null are allowed)",
  );
}

/**
 * Deterministic canonical JSON serialization of a job payload, EXCLUDING the
 * top-level "signature" property. This is the exact byte sequence the
 * control plane signs and the agent verifies (ADR-0003: "the signature must
 * cover a canonical serialization excluding the signature field").
 *
 * CANONICALIZATION ALGORITHM (the control plane MUST implement this
 * identically, byte for byte):
 *
 *   1. Input must be a plain object (prototype Object.prototype or null).
 *      Anything else (array, class instance, Map, primitive, null) throws.
 *   2. The TOP-LEVEL property named "signature" is omitted. Properties named
 *      "signature" at any deeper nesting level are KEPT and serialized
 *      normally; per ADR-0003 only the envelope's own signature field is
 *      excluded from the signed bytes.
 *   3. Object keys are sorted lexicographically by UTF-16 code unit
 *      (JavaScript's default Array.prototype.sort() on strings), recursively
 *      at every nesting level.
 *   4. Arrays keep their original element order.
 *   5. No whitespace anywhere: `{"a":1,"b":[2,3]}` style.
 *   6. Strings and keys are encoded with JSON.stringify's standard JSON
 *      string escaping. Numbers use JSON.stringify's shortest round-trip
 *      form; non-finite numbers (NaN, Infinity) throw.
 *   7. `undefined` anywhere in the tree throws (it is not representable in
 *      JSON and dropping it silently would let two implementations sign
 *      different bytes for the "same" object).
 *   8. The resulting string is UTF-8 encoded to produce the bytes to
 *      sign/verify (Node string -> Buffer.from(str, "utf8")).
 *
 * @param {object} job the job payload (may include the signature field,
 *   which is excluded from the output)
 * @returns {string} canonical JSON string (UTF-8 encode it for signing)
 * @throws {Error} on non-plain-object input or unserializable values
 */
function canonicalizeJobPayload(job) {
  if (!isPlainObject(job)) {
    throw new Error(
      "signing: canonicalizeJobPayload requires a plain object job payload",
    );
  }
  const withoutSignature = {};
  for (const key of Object.keys(job)) {
    if (key === "signature") continue;
    withoutSignature[key] = job[key];
  }
  return serializeCanonical(withoutSignature, "$");
}

/**
 * Structural checks on the signed-dispatch fields of an untrusted job.
 * Returns a human-readable problem string, or null when well-formed.
 * Bounds mirror job-payload.schema.json (nonce 16-128 chars, signingKeyId
 * 1-128 chars, signature base64 64-1024 chars, issuedAt/expiresAt ISO
 * date-time).
 *
 * @param {object} job
 * @returns {string|null}
 */
function findSignedFieldProblem(job) {
  if (!isPlainObject(job)) {
    return "job payload must be a plain object";
  }
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
  if (
    typeof job.issuedAt !== "string" ||
    Number.isNaN(Date.parse(job.issuedAt))
  ) {
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

/**
 * Verifies an untrusted job's Ed25519 signature against the pinned
 * control-plane public key.
 *
 * Checks, in order (first failure wins):
 *   1. signature / signingKeyId / nonce / issuedAt / expiresAt present and
 *      well-formed per job-payload.schema.json bounds.
 *   2. job.signingKeyId === pinnedSigningKeyId (a mismatch means the job was
 *      signed by a key this agent does not pin -- possibly a rotation the
 *      agent has not picked up, possibly forgery; either way integrity
 *      cannot be established).
 *   3. crypto.verify(null, utf8(canonicalizeJobPayload(job)), publicKeyPem,
 *      base64(job.signature)) -- algorithm null selects Ed25519's intrinsic
 *      signing scheme per Node's crypto API.
 *
 * Never throws on untrusted (job) input: any malformed or forged job
 * produces { allowed: false, rejectionReason: "job_integrity_failed",
 * detail }. Throws only on programmer error (missing/invalid publicKeyPem
 * or pinnedSigningKeyId), because running without a pinned verification key
 * is a misconfiguration that must fail loudly, not soft-reject jobs.
 *
 * @param {object} params
 * @param {object} params.job untrusted job payload from a claim response
 * @param {string} params.publicKeyPem pinned Ed25519 public key (SPKI PEM)
 * @param {string} params.pinnedSigningKeyId pinned signing key id
 * @returns {{ allowed: true } | { allowed: false, rejectionReason: string, detail: string }}
 */
function verifyJobSignature({ job, publicKeyPem, pinnedSigningKeyId }) {
  if (typeof publicKeyPem !== "string" || publicKeyPem.length === 0) {
    throw new Error(
      "signing: verifyJobSignature requires a publicKeyPem string (pinned " +
        "control-plane signing public key); refusing to run without one",
    );
  }
  if (
    typeof pinnedSigningKeyId !== "string" ||
    pinnedSigningKeyId.length === 0
  ) {
    throw new Error(
      "signing: verifyJobSignature requires a pinnedSigningKeyId string",
    );
  }

  const fieldProblem = findSignedFieldProblem(job);
  if (fieldProblem !== null) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      `Signed job field validation failed: ${fieldProblem}.`,
    );
  }

  if (job.signingKeyId !== pinnedSigningKeyId) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      `Signing key id mismatch: job was signed with key id ` +
        `"${job.signingKeyId}" but this agent pins key id ` +
        `"${pinnedSigningKeyId}".`,
    );
  }

  // Parsing the *pinned* public key is trusted-local-config territory: a
  // malformed pinned key is operator/programmer error and must fail loudly,
  // not soft-reject every job (which would look like an attack signal).
  let publicKey;
  try {
    publicKey = crypto.createPublicKey(publicKeyPem);
  } catch (err) {
    throw new Error(
      `signing: verifyJobSignature was given an unparseable publicKeyPem: ${err.message}`,
    );
  }

  let verified = false;
  try {
    const canonicalBytes = Buffer.from(canonicalizeJobPayload(job), "utf8");
    const signatureBytes = Buffer.from(job.signature, "base64");
    verified = crypto.verify(null, canonicalBytes, publicKey, signatureBytes);
  } catch (err) {
    // Everything inside this try operates on untrusted job data
    // (canonicalization of a structurally hostile job with undefined values,
    // or a signature buffer crypto.verify cannot process): integrity cannot
    // be established, so soft-reject. Never echo raw job content here.
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      "Job payload could not be canonically serialized or verified " +
        `(${err.message}).`,
    );
  }

  if (!verified) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      "Job signature verification failed: the Ed25519 signature does not " +
        "match the canonical job payload under the pinned signing key.",
    );
  }

  return { allowed: true };
}

/**
 * Validates that the current time falls inside the job's signed validity
 * window [issuedAt - toleranceMs, expiresAt + toleranceMs].
 *
 * The comparison time is `nowMs + clockOffsetMs` when clockOffsetMs is a
 * finite integer (the clock module's serverTime - localTime estimate, so
 * adding it converts local time to estimated server time -- the same clock
 * that stamped issuedAt/expiresAt). When clockOffsetMs is null/undefined/
 * non-finite, nowMs is used unadjusted.
 *
 * Rejection semantics (documented choice):
 *   - expiresAt < issuedAt: the window is malformed regardless of any clock;
 *     no drift could explain it => "job_integrity_failed".
 *   - adjusted now < issuedAt - toleranceMs (job "from the future") or
 *     adjusted now > expiresAt + toleranceMs (job expired): both are
 *     plausibly clock-related -- a skewed agent clock makes fresh jobs look
 *     future-dated or valid jobs look expired -- so both reject with
 *     "clock_drift_suspected". A genuinely replayed old job is also caught
 *     independently by the replay cache, so classifying window failures as
 *     drift keeps the operator signal actionable (check NTP) without
 *     weakening replay defense.
 *
 * @param {object} params
 * @param {object} params.job untrusted job payload (issuedAt/expiresAt)
 * @param {number} params.nowMs current local epoch milliseconds
 * @param {number|null} [params.clockOffsetMs] estimated serverTime - localTime
 * @param {number} [params.toleranceMs] window slack, default 30000 (see
 *   DEFAULT_TIME_WINDOW_TOLERANCE_MS for rationale)
 * @returns {{ allowed: true } | { allowed: false, rejectionReason: string, detail: string }}
 */
function checkJobTimeWindow({
  job,
  nowMs,
  clockOffsetMs = null,
  toleranceMs = DEFAULT_TIME_WINDOW_TOLERANCE_MS,
}) {
  if (!Number.isFinite(nowMs)) {
    throw new Error("signing: checkJobTimeWindow requires a finite nowMs");
  }
  if (!Number.isFinite(toleranceMs) || toleranceMs < 0) {
    throw new Error(
      "signing: checkJobTimeWindow toleranceMs must be a non-negative finite number",
    );
  }

  if (
    !isPlainObject(job) ||
    typeof job.issuedAt !== "string" ||
    Number.isNaN(Date.parse(job.issuedAt)) ||
    typeof job.expiresAt !== "string" ||
    Number.isNaN(Date.parse(job.expiresAt))
  ) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      "Job issuedAt/expiresAt missing or unparseable; cannot establish a validity window.",
    );
  }

  const issuedAtMs = Date.parse(job.issuedAt);
  const expiresAtMs = Date.parse(job.expiresAt);

  if (expiresAtMs < issuedAtMs) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
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
      SIGNING_REJECTION_REASONS.CLOCK_DRIFT_SUSPECTED,
      `Job issuedAt is ${issuedAtMs - adjustedNowMs}ms in the future ` +
        `(tolerance ${toleranceMs}ms); local clock drift suspected.`,
    );
  }

  if (adjustedNowMs > expiresAtMs + toleranceMs) {
    return reject(
      SIGNING_REJECTION_REASONS.CLOCK_DRIFT_SUSPECTED,
      `Job expired ${adjustedNowMs - expiresAtMs}ms ago ` +
        `(tolerance ${toleranceMs}ms); stale dispatch or local clock drift.`,
    );
  }

  return { allowed: true };
}

/**
 * TEST / CONTROL-PLANE-SIDE UTILITY ONLY. The agent itself never generates
 * or holds a signing private key; the private key lives exclusively in the
 * control plane (ADR-0003). This helper exists so the fake control-plane
 * harness (tests/integration/fake-agent.js) and control-plane code can
 * produce keypairs that interoperate with verifyJobSignature.
 *
 * @returns {{ publicKeyPem: string, privateKeyPem: string, signingKeyId: string }}
 */
function generateSigningKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey
      .export({ type: "pkcs8", format: "pem" })
      .toString(),
    signingKeyId: `signing-key-${crypto.randomUUID()}`,
  };
}

/**
 * TEST / CONTROL-PLANE-SIDE UTILITY ONLY (see generateSigningKeyPair).
 * Signs canonicalizeJobPayload(job) with Ed25519 and returns the base64
 * signature. Using this together with verifyJobSignature guarantees both
 * sides run the identical canonicalization algorithm.
 *
 * @param {object} params
 * @param {object} params.job job payload (any existing top-level signature
 *   field is ignored/excluded by canonicalization)
 * @param {string} params.privateKeyPem Ed25519 private key (PKCS8 PEM)
 * @returns {string} base64 signature
 */
function signJobPayload({ job, privateKeyPem }) {
  if (typeof privateKeyPem !== "string" || privateKeyPem.length === 0) {
    throw new Error("signing: signJobPayload requires a privateKeyPem string");
  }
  const canonicalBytes = Buffer.from(canonicalizeJobPayload(job), "utf8");
  return crypto
    .sign(null, canonicalBytes, crypto.createPrivateKey(privateKeyPem))
    .toString("base64");
}

module.exports = {
  SIGNING_REJECTION_REASONS,
  DEFAULT_TIME_WINDOW_TOLERANCE_MS,
  canonicalizeJobPayload,
  verifyJobSignature,
  checkJobTimeWindow,
  generateSigningKeyPair,
  signJobPayload,
};
