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

// Shared canonical-JSON implementation (single source of truth for the
// signed byte contract; the control plane uses packages/contracts/certops/
// canonical-json.cjs). The agent ships a vendored copy so install-agent.sh
// remains self-contained outside the monorepo. Keep in sync via
// scripts/sync-vendor.js.
const {
  isPlainObject,
  canonicalizeJobPayload,
} = require("../../vendor/contracts/canonical-json.cjs");

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
 * ADR-0012 decision 1: "exact-byte signed envelope" capability. An agent
 * that declares this capability receives v2 envelopes ({ envelopeVersion: 2,
 * payloadB64, signatureB64, signingKeyId }) instead of the legacy v1
 * canonical-JSON-signed job object. See verifyJobEnvelope below.
 */
const SIGNED_PAYLOAD_B64_CAPABILITY = "signed-payload-b64-v1";

const ENVELOPE_VERSION_1 = 1;
const ENVELOPE_VERSION_2 = 2;

// ADR-0012 decision 1's pinned numeric limits, stated there so two
// implementations cannot disagree. encoded/decoded are checked in that
// order: the encoded-length bound is enforced BEFORE any base64 decode is
// attempted, so a hostile encoded string never causes an oversized
// allocation; the decoded-byte bound is the actual content-size policy
// (ADR-0012's real "max job payload size" decision). The two bounds are
// deliberately NOT the tightest-possible pair for each other: an earlier
// revision set the encoded bound to the exact floor(chars/4)*3 = bytes
// value for 49152, which made the decoded check mathematically unreachable
// (no string of at most 65536 valid base64 characters can ever decode to
// more than 49152 bytes, so the decoded check could never be the one that
// actually rejects anything). 98304 gives the encoded check real headroom
// -- floor(98304/4)*3 = 73728 bytes, well above 49152 -- so a payload
// between 49153 and 73728 decoded bytes passes the coarse pre-decode gate
// and is then correctly rejected, with the specific "decoded payload too
// large" reason, by the check that actually enforces the ADR's content-size
// policy. Only a payload whose encoded form is implausibly large even for
// an oversized-but-legitimate-looking request is now rejected before decode
// (the allocation-safety purpose the encoded bound alone exists for).
const V2_MAX_ENCODED_PAYLOAD_CHARS = 98304;
const V2_MAX_DECODED_PAYLOAD_BYTES = 49152;
// Ed25519 signatures are exactly 64 bytes; this is not a range like v1's
// SIGNATURE_LENGTH_MIN/MAX (which bounds a base64 STRING length), it is an
// exact decoded-byte-length check performed after base64-decoding.
const V2_SIGNATURE_DECODED_BYTES = 64;

// Standard (unpadded-tolerant but RFC 4648 padded) base64 alphabet only; no
// base64url, no whitespace, per ADR-0012's "standard Base64, padding,
// whitespace" rule. A payload with embedded whitespace or url-safe
// characters is rejected at this pattern check, before any decode attempt.
// Canonicality itself (no non-minimal padding, no non-zero padding bits) is
// NOT provable by pattern alone and is instead enforced by decode-then-
// re-encode-and-compare (ADR-0012 decision 2, step 4; see
// assertCanonicalBase64 below).
const V2_BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;

const UTF8_BOM_BYTES = Buffer.from([0xef, 0xbb, 0xbf]);

/**
 * Decodes a base64 string and verifies it round-trips to the SAME string
 * (ADR-0012 decision 2, step 4: "re-encode and compare, to enforce canonical
 * base64"). This catches non-canonical encodings a naive decoder accepts
 * silently: non-zero padding bits, non-minimal padding, or alternate valid
 * encodings of the same bytes. Two implementations that only agree on "does
 * this decode" can still disagree on WHICH bytes a non-canonical string
 * decodes to being the "real" ones; requiring canonical encoding removes the
 * ambiguity entirely rather than picking a side.
 *
 * @param {string} value already pattern-checked against V2_BASE64_PATTERN
 * @returns {Buffer|null} decoded bytes, or null when not canonical
 */
function decodeCanonicalBase64(value) {
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) return null;
  return decoded;
}

/**
 * Strict single-JSON-value scanner (ADR-0012 decision 2, steps 7-8: "parse
 * exactly one JSON value" + "require end-of-input immediately after that
 * value"). Native JSON.parse tolerates leading/trailing whitespace around a
 * document (valid per RFC 8259) and cannot itself report whether trailing
 * content followed the value it parsed; strict UTF-8 decoding cannot detect
 * trailing content either, because whitespace or a second JSON document are
 * both valid UTF-8. This scanner independently walks the JSON grammar to
 * find exactly where the first value ends, and the caller requires that
 * position to be the exact end of the string -- not even trailing
 * whitespace survives. It is a structural boundary-finder only (JSON.parse
 * still does the real, spec-complete parse); a text this scanner accepts
 * but considers malformed is treated as end-of-input having failed, never
 * silently handed to JSON.parse anyway.
 *
 * @param {string} text
 * @returns {number} index one past the end of the first value, or -1 if the
 *   text does not begin with a structurally well-formed JSON value
 */
function scanSingleJsonValueEnd(text) {
  const len = text.length;
  let i = 0;

  function isWs(ch) {
    return ch === " " || ch === "\t" || ch === "\n" || ch === "\r";
  }
  function skipWs() {
    while (i < len && isWs(text[i])) i++;
  }
  function parseValue() {
    if (i >= len) return false;
    const c = text[i];
    if (c === "{") return parseObject();
    if (c === "[") return parseArray();
    if (c === '"') return parseString();
    if (c === "-" || (c >= "0" && c <= "9")) return parseNumber();
    if (text.startsWith("true", i)) {
      i += 4;
      return true;
    }
    if (text.startsWith("false", i)) {
      i += 5;
      return true;
    }
    if (text.startsWith("null", i)) {
      i += 4;
      return true;
    }
    return false;
  }
  function parseString() {
    // text[i] === '"' on entry
    i++;
    while (i < len) {
      const c = text[i];
      if (c === '"') {
        i++;
        return true;
      }
      if (c === "\\") {
        i += 2;
        continue;
      }
      // Raw control characters (0x00-0x1F) are illegal inside a JSON
      // string; JSON.parse enforces this fully, this scanner only needs to
      // avoid mis-locating the closing quote, which control chars cannot do.
      i++;
    }
    return false;
  }
  function parseNumber() {
    const start = i;
    if (text[i] === "-") i++;
    if (i >= len || text[i] < "0" || text[i] > "9") return false;
    while (i < len && text[i] >= "0" && text[i] <= "9") i++;
    if (i < len && text[i] === ".") {
      i++;
      if (i >= len || text[i] < "0" || text[i] > "9") return false;
      while (i < len && text[i] >= "0" && text[i] <= "9") i++;
    }
    if (i < len && (text[i] === "e" || text[i] === "E")) {
      i++;
      if (i < len && (text[i] === "+" || text[i] === "-")) i++;
      if (i >= len || text[i] < "0" || text[i] > "9") return false;
      while (i < len && text[i] >= "0" && text[i] <= "9") i++;
    }
    return i > start;
  }
  function parseObject() {
    i++; // {
    skipWs();
    if (i < len && text[i] === "}") {
      i++;
      return true;
    }
    // eslint-disable-next-line no-constant-condition
    while (true) {
      skipWs();
      if (i >= len || text[i] !== '"' || !parseString()) return false;
      skipWs();
      if (i >= len || text[i] !== ":") return false;
      i++;
      skipWs();
      if (!parseValue()) return false;
      skipWs();
      if (i >= len) return false;
      if (text[i] === ",") {
        i++;
        continue;
      }
      if (text[i] === "}") {
        i++;
        return true;
      }
      return false;
    }
  }
  function parseArray() {
    i++; // [
    skipWs();
    if (i < len && text[i] === "]") {
      i++;
      return true;
    }
    // eslint-disable-next-line no-constant-condition
    while (true) {
      skipWs();
      if (!parseValue()) return false;
      skipWs();
      if (i >= len) return false;
      if (text[i] === ",") {
        i++;
        continue;
      }
      if (text[i] === "]") {
        i++;
        return true;
      }
      return false;
    }
  }

  return parseValue() ? i : -1;
}

/**
 * Parses `text` as EXACTLY one JSON value with nothing following it, not
 * even whitespace (ADR-0012 decision 2, steps 7-8). Returns the parsed
 * value, or throws when the text is not a single, fully-consumed JSON
 * document.
 *
 * @param {string} text
 * @returns {unknown}
 */
function parseSingleJsonValueStrict(text) {
  const endIndex = scanSingleJsonValueEnd(text);
  if (endIndex !== text.length) {
    throw new Error(
      "payload is not exactly one JSON value with nothing after it " +
        "(trailing content, including whitespace, is rejected)",
    );
  }
  return JSON.parse(text);
}

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

/**
 * @param {string} rejectionReason
 * @param {string} detail
 * @returns {{ allowed: false, rejectionReason: string, detail: string }}
 */
function reject(rejectionReason, detail) {
  return { allowed: false, rejectionReason, detail };
}

/**
 * Deterministic canonical JSON serialization of a job payload, EXCLUDING the
 * top-level "signature" property. This is the exact byte sequence the
 * control plane signs and the agent verifies (ADR-0003).
 *
 * The implementation lives in the SHARED contracts module
 * packages/contracts/certops/canonical-json.cjs (required above), which both
 * the control-plane signer and this verifier load, so the canonical byte
 * contract cannot drift between the two sides. See that file for the full
 * algorithm documentation. Re-exported here so the agent's public API is
 * unchanged.
 */

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
 * Verifies the v2 "exact-byte signed envelope" (ADR-0012 decision 1).
 *
 * STRICT ORDER, never relaxed: base64 shape check -> size-bounded decode ->
 * Ed25519 verify of the RAW DECODED BYTES -> (only once verified) strict
 * UTF-8 decode -> JSON.parse -> the payload's own signingKeyId must equal
 * the wrapper's (ADR-0012 decision 2 step 13 / decision 3). No
 * canonicalization step exists in this path by design: the signed bytes
 * ARE the wire bytes, so there is nothing to re-derive. A verifier in any
 * language needs only "base64-decode, then verify the raw bytes" to
 * interoperate with this contract.
 *
 * Never throws on untrusted (envelope) input for the same reason
 * verifyJobSignature does not: throws only on programmer error (missing/
 * invalid publicKeyPem or pinnedSigningKeyId).
 *
 * @param {object} params
 * @param {object} params.envelope untrusted { envelopeVersion, payloadB64,
 *   signatureB64, signingKeyId } from a claim response
 * @param {string} params.publicKeyPem pinned Ed25519 public key (SPKI PEM)
 * @param {string} params.pinnedSigningKeyId pinned signing key id
 * @returns {{ allowed: true, job: object } | { allowed: false, rejectionReason: string, detail: string }}
 */
function verifyV2Envelope({ envelope, publicKeyPem, pinnedSigningKeyId }) {
  if (typeof publicKeyPem !== "string" || publicKeyPem.length === 0) {
    throw new Error(
      "signing: verifyV2Envelope requires a publicKeyPem string (pinned " +
        "control-plane signing public key); refusing to run without one",
    );
  }
  if (
    typeof pinnedSigningKeyId !== "string" ||
    pinnedSigningKeyId.length === 0
  ) {
    throw new Error(
      "signing: verifyV2Envelope requires a pinnedSigningKeyId string",
    );
  }

  if (!isPlainObject(envelope)) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      "v2 envelope must be a plain object.",
    );
  }
  if (
    typeof envelope.signingKeyId !== "string" ||
    !SIGNING_KEY_ID_PATTERN.test(envelope.signingKeyId)
  ) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      "v2 envelope signingKeyId is missing or malformed.",
    );
  }
  if (envelope.signingKeyId !== pinnedSigningKeyId) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      `Signing key id mismatch: envelope was signed with key id ` +
        `"${envelope.signingKeyId}" but this agent pins key id ` +
        `"${pinnedSigningKeyId}".`,
    );
  }
  if (
    typeof envelope.payloadB64 !== "string" ||
    envelope.payloadB64.length === 0 ||
    envelope.payloadB64.length > V2_MAX_ENCODED_PAYLOAD_CHARS ||
    !V2_BASE64_PATTERN.test(envelope.payloadB64)
  ) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      `v2 envelope payloadB64 is missing, exceeds ${V2_MAX_ENCODED_PAYLOAD_CHARS} ` +
        "encoded chars, or is not well-formed standard base64.",
    );
  }
  if (
    typeof envelope.signatureB64 !== "string" ||
    envelope.signatureB64.length === 0 ||
    !V2_BASE64_PATTERN.test(envelope.signatureB64)
  ) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      "v2 envelope signatureB64 is missing or not well-formed standard base64.",
    );
  }

  // Step 3 (decode) + step 4 (re-encode and compare, to enforce canonical
  // base64) of ADR-0012 decision 2's normative order.
  const payloadBytes = decodeCanonicalBase64(envelope.payloadB64);
  if (payloadBytes === null) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      "v2 envelope payloadB64 is not canonical base64 (decode-then-re-encode " +
        "did not round-trip).",
    );
  }
  const signatureBytes = decodeCanonicalBase64(envelope.signatureB64);
  if (signatureBytes === null) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      "v2 envelope signatureB64 is not canonical base64 (decode-then-re-encode " +
        "did not round-trip).",
    );
  }

  // The encoded-length check above already bounds this decode; this is a
  // second, exact check on the DECODED byte count (ADR-0012's pinned
  // "decoded payload 49,152 bytes" limit), not a re-derivation of the same
  // fact from a different unit.
  if (payloadBytes.length > V2_MAX_DECODED_PAYLOAD_BYTES) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      `v2 envelope payloadB64 decodes to ${payloadBytes.length} bytes, ` +
        `exceeding the maximum of ${V2_MAX_DECODED_PAYLOAD_BYTES}.`,
    );
  }
  // Ed25519 signatures are EXACTLY 64 bytes decoded; not a range.
  if (signatureBytes.length !== V2_SIGNATURE_DECODED_BYTES) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      `v2 envelope signatureB64 decodes to ${signatureBytes.length} bytes; ` +
        `Ed25519 signatures must decode to exactly ${V2_SIGNATURE_DECODED_BYTES}.`,
    );
  }

  let publicKey;
  try {
    publicKey = crypto.createPublicKey(publicKeyPem);
  } catch (err) {
    throw new Error(
      `signing: verifyV2Envelope was given an unparseable publicKeyPem: ${err.message}`,
    );
  }

  // Step 5: verify the exact decoded bytes against the pinned public key.
  // No JSON parsing, no canonicalization: this is the entire point of the
  // v2 envelope.
  let verified = false;
  try {
    verified = crypto.verify(null, payloadBytes, publicKey, signatureBytes);
  } catch (err) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      `v2 envelope signature could not be verified (${err.message}).`,
    );
  }

  if (!verified) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      "v2 envelope signature verification failed: the Ed25519 signature " +
        "does not match payloadB64's decoded bytes under the pinned signing key.",
    );
  }

  // Step 6: decode UTF-8 strictly, rejecting invalid sequences AND a BOM.
  // "fatal: true" makes Node's TextDecoder reject malformed UTF-8 outright
  // rather than silently substituting U+FFFD. A leading BOM is valid UTF-8
  // (it is codepoint U+FEFF) so TextDecoder alone would accept it; it is
  // rejected explicitly because canonical control-plane output never emits
  // one, and a payload that does deviates from what was actually signed in
  // spirit even though the bytes themselves verified -- the BOM is data the
  // signer did not intend, not a decoding nicety.
  if (payloadBytes.length >= 3 && payloadBytes.subarray(0, 3).equals(UTF8_BOM_BYTES)) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      "v2 envelope payload is verified but begins with a UTF-8 BOM, which " +
        "canonical control-plane output never emits.",
    );
  }
  let payloadText;
  try {
    payloadText = new TextDecoder("utf-8", { fatal: true }).decode(
      payloadBytes,
    );
  } catch (err) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      `v2 envelope payload is verified but not valid strict UTF-8 (${err.message}).`,
    );
  }

  // Steps 7-8: parse exactly one JSON value, then require end-of-input
  // immediately after it. Whitespace or a second document after the value
  // are both valid UTF-8 and would survive step 6 alone; this scanner is
  // the dedicated check for that trailing-content case.
  let job;
  try {
    job = parseSingleJsonValueStrict(payloadText);
  } catch (err) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      `v2 envelope payload is verified and valid UTF-8, but not exactly one ` +
        `JSON value with nothing after it (${err.message}).`,
    );
  }
  if (!isPlainObject(job)) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      "v2 envelope payload verified and parsed, but is not a JSON object.",
    );
  }

  // Step 13: the signed payload carries its own signingKeyId (per
  // signed-dispatch-payload.schema.json), distinct from the wrapper's
  // pre-verification selection hint checked above. ADR-0012 decision 3:
  // "the wrapper's copy is the pre-verification selection hint, the
  // payload's copy is the authenticated value, and step 13 requires them
  // to agree." The wrapper hint is already proven equal to
  // pinnedSigningKeyId above, so checking the payload's copy against
  // pinnedSigningKeyId here is equivalent to checking it against the
  // wrapper's copy, and catches a payload whose authenticated content
  // disagrees with (or omits) the key id the wrapper claimed for it, even
  // though the bytes are genuinely signed by the pinned key.
  if (
    typeof job.signingKeyId !== "string" ||
    !SIGNING_KEY_ID_PATTERN.test(job.signingKeyId)
  ) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      "v2 envelope payload verified and parsed, but its signed " +
        "signingKeyId is missing or malformed.",
    );
  }
  if (job.signingKeyId !== pinnedSigningKeyId) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      `Signing key id mismatch: the verified payload's own signingKeyId ` +
        `"${job.signingKeyId}" does not match the wrapper's signingKeyId ` +
        `"${envelope.signingKeyId}" (this agent pins key id ` +
        `"${pinnedSigningKeyId}").`,
    );
  }

  return { allowed: true, job };
}

/**
 * Dual-format entry point: detects whether an untrusted claimed job is a v1
 * job object (legacy canonical-JSON signing) or a v2 envelope
 * ({ envelopeVersion: 2, ... }), and verifies it through the matching path.
 *
 * The `job` returned on success is always the fully-populated, verified job
 * object subsequent steps (checkJobTimeWindow, replay, policy) operate on:
 * for v1 that is the wire object itself; for v2 it is the payload decoded
 * from inside payloadB64 (the wire envelope carries no other usable
 * fields -- ADR-0012 decision 3, "no sibling objects in v2").
 *
 * @param {object} params
 * @param {object} params.claimed untrusted claimed job/envelope from the wire
 * @param {string} params.publicKeyPem pinned Ed25519 public key (SPKI PEM)
 * @param {string} params.pinnedSigningKeyId pinned signing key id
 * @returns {{ allowed: true, job: object } | { allowed: false, rejectionReason: string, detail: string }}
 */
function verifyJobEnvelope({ claimed, publicKeyPem, pinnedSigningKeyId }) {
  const isV2 =
    isPlainObject(claimed) && claimed.envelopeVersion === ENVELOPE_VERSION_2;
  if (isV2) {
    return verifyV2Envelope({
      envelope: claimed,
      publicKeyPem,
      pinnedSigningKeyId,
    });
  }

  // v1: an explicit envelopeVersion of 1, or (the common legacy case) no
  // envelopeVersion field at all, both take the canonical-JSON path. Any
  // other envelopeVersion value (unknown future version) is NOT silently
  // treated as v1: falling through to canonical-JSON verification of an
  // object shaped like a v2 envelope would fail signature verification
  // anyway, but failing on the explicit "unrecognized version" reason is
  // clearer for operators than a generic integrity failure.
  if (
    isPlainObject(claimed) &&
    claimed.envelopeVersion !== undefined &&
    claimed.envelopeVersion !== ENVELOPE_VERSION_1
  ) {
    return reject(
      SIGNING_REJECTION_REASONS.JOB_INTEGRITY_FAILED,
      `Unrecognized envelopeVersion "${claimed.envelopeVersion}"; this agent ` +
        `understands ${ENVELOPE_VERSION_1} and ${ENVELOPE_VERSION_2}.`,
    );
  }

  const verdict = verifyJobSignature({
    job: claimed,
    publicKeyPem,
    pinnedSigningKeyId,
  });
  if (!verdict.allowed) return verdict;
  return { allowed: true, job: claimed };
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
  SIGNED_PAYLOAD_B64_CAPABILITY,
  ENVELOPE_VERSION_1,
  ENVELOPE_VERSION_2,
  V2_MAX_ENCODED_PAYLOAD_CHARS,
  V2_MAX_DECODED_PAYLOAD_BYTES,
  V2_SIGNATURE_DECODED_BYTES,
  canonicalizeJobPayload,
  verifyJobSignature,
  verifyV2Envelope,
  verifyJobEnvelope,
  checkJobTimeWindow,
  generateSigningKeyPair,
  signJobPayload,
  _test: {
    decodeCanonicalBase64,
    scanSingleJsonValueEnd,
    parseSingleJsonValueStrict,
  },
};
