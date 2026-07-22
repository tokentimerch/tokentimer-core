"use strict";

/**
 * Control-plane Ed25519 job-signing service (CertOps M4/M5, ADR-0003).
 *
 * Server-side counterpart of the agent verifier
 * (packages/agent/src/signing/index.js). Both sides require the SAME
 * canonical-JSON module (packages/contracts/certops/canonical-json.cjs), so
 * the signed byte contract cannot drift.
 *
 * Key custody: the Ed25519 private signing key lives ONLY in
 * certops_signing_keys.private_key_encrypted, wrapped in a versioned
 * AES-256-GCM envelope (same iv:tag:ciphertext hex format as
 * apps/api/services/systemSettings.js). The wrap key comes from
 * CERTOPS_SIGNING_ENCRYPTION_KEY (64 hex chars = 32 bytes). FAIL-CLOSED:
 * any operation that needs the private key (key generation, signing) throws
 * CERTOPS_SIGNING_ENCRYPTION_KEY_MISSING when the env key is unset or
 * malformed. Public-key reads never require the env key.
 *
 * No function in this module ever logs or returns private key material.
 */

const crypto = require("node:crypto");

const { pool } = require("../../db/database");
const {
  canonicalizeJobPayload,
} = require("../../../../packages/contracts/certops/canonical-json.cjs");

const CERTOPS_SIGNING_ENCRYPTION_KEY_MISSING =
  "CERTOPS_SIGNING_ENCRYPTION_KEY_MISSING";
const CERTOPS_SIGNING_KEY_UNAVAILABLE = "CERTOPS_SIGNING_KEY_UNAVAILABLE";
const CERTOPS_SIGNING_PAYLOAD_INVALID = "CERTOPS_SIGNING_PAYLOAD_INVALID";
const CERTOPS_NONCE_REPLAYED = "CERTOPS_NONCE_REPLAYED";
const CERTOPS_NONCE_UNKNOWN_OR_EXPIRED = "CERTOPS_NONCE_UNKNOWN_OR_EXPIRED";

const ENV_KEY_NAME = "CERTOPS_SIGNING_ENCRYPTION_KEY";
const ENV_KEY_PATTERN = /^[a-fA-F0-9]{64}$/;
const ENCRYPTION_VERSION = 1;

const SIGNING_KEY_ID_PREFIX = "ttsk_";
const SIGNING_KEY_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
// base64url of 24 random bytes = 32 chars; matches the DB CHECK and the
// agent-side nonce pattern (^[A-Za-z0-9_.:-]{16,128}$ is a superset).
const NONCE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const NONCE_RANDOM_BYTES = 24;
const DEFAULT_NONCE_TTL_SECONDS = 300;
// Expired nonces stay queryable for one extra hour so late result ingestion
// can still distinguish "replayed" from "never issued".
const SWEEP_GRACE_SECONDS = 3600;

function serviceError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

// --- AES-256-GCM envelope (systemSettings.js format: ivHex:tagHex:cipherHex)

function getEncryptionKey() {
  const raw = process.env[ENV_KEY_NAME];
  if (typeof raw !== "string" || !ENV_KEY_PATTERN.test(raw.trim())) {
    throw serviceError(
      `${ENV_KEY_NAME} is not set or malformed (expected 64 hex chars = ` +
        "32 bytes); refusing to handle the job-signing private key",
      CERTOPS_SIGNING_ENCRYPTION_KEY_MISSING,
    );
  }
  return Buffer.from(raw.trim(), "hex");
}

function encryptPrivateKeyPem(plaintextPem) {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  let encrypted = cipher.update(plaintextPem, "utf8", "hex");
  encrypted += cipher.final("hex");
  const tag = cipher.getAuthTag().toString("hex");
  return `${iv.toString("hex")}:${tag}:${encrypted}`;
}

function decryptPrivateKeyPem(ciphertext, encryptionVersion) {
  if (Number(encryptionVersion) !== ENCRYPTION_VERSION) {
    throw serviceError(
      `Unsupported signing-key encryption version ${encryptionVersion}`,
      CERTOPS_SIGNING_KEY_UNAVAILABLE,
    );
  }
  const key = getEncryptionKey();
  const parts = String(ciphertext || "").split(":");
  if (parts.length !== 3) {
    throw serviceError(
      "Stored signing key envelope is malformed",
      CERTOPS_SIGNING_KEY_UNAVAILABLE,
    );
  }
  try {
    const iv = Buffer.from(parts[0], "hex");
    const tag = Buffer.from(parts[1], "hex");
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(parts[2], "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (_error) {
    // Never chain the original error: it could echo buffer contents.
    throw serviceError(
      "Failed to unwrap the job-signing private key (wrong " +
        `${ENV_KEY_NAME} or corrupted envelope)`,
      CERTOPS_SIGNING_KEY_UNAVAILABLE,
    );
  }
}

// --- Key lifecycle ---

function generateSigningKeyId() {
  return `${SIGNING_KEY_ID_PREFIX}${crypto.randomBytes(8).toString("hex")}`;
}

function publicInfoFromRow(row) {
  if (!row) return null;
  return {
    signingKeyId: row.signing_key_id,
    publicKeyPem: row.public_key_pem,
  };
}

async function selectActiveKeyRow(db) {
  const result = await db.query(
    `SELECT id, signing_key_id, public_key_pem, private_key_encrypted,
            encryption_version, status
       FROM certops_signing_keys
      WHERE status = 'active'
      LIMIT 1`,
  );
  return result.rows[0] || null;
}

/**
 * Public metadata of the active signing key, or null when none exists.
 * Never generates a key and never touches the env encryption key.
 */
async function getActiveSigningKeyPublicInfo(options = {}) {
  const db = options.client || pool;
  return publicInfoFromRow(await selectActiveKeyRow(db));
}

/**
 * Returns the single active signing key, generating one if none exists.
 * Key generation requires the env encryption key (fail-closed). The
 * unique-partial-index race (23505) is handled by re-selecting the winner.
 * Returns { signingKeyId, publicKeyPem } only; never the private key.
 */
async function ensureActiveSigningKey(options = {}) {
  const db = options.client || pool;

  const existing = await selectActiveKeyRow(db);
  if (existing) return publicInfoFromRow(existing);

  // Fail closed BEFORE generating key material (throws when the env key is
  // unset or malformed).
  getEncryptionKey();

  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey
    .export({ type: "spki", format: "pem" })
    .toString();
  const privateKeyPem = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  const signingKeyId = generateSigningKeyId();
  const privateKeyEncrypted = encryptPrivateKeyPem(privateKeyPem);

  try {
    const inserted = await db.query(
      `INSERT INTO certops_signing_keys (
         signing_key_id, public_key_pem, private_key_encrypted,
         encryption_version, status
       )
       VALUES ($1, $2, $3, $4, 'active')
       RETURNING id, signing_key_id, public_key_pem`,
      [signingKeyId, publicKeyPem, privateKeyEncrypted, ENCRYPTION_VERSION],
    );
    return publicInfoFromRow(inserted.rows[0]);
  } catch (error) {
    if (error?.code === "23505") {
      // Lost the single-active race: another writer inserted first.
      const winner = await selectActiveKeyRow(db);
      if (winner) return publicInfoFromRow(winner);
    }
    throw error;
  }
}

async function getActiveKeyWithPrivate(db) {
  const row = await selectActiveKeyRow(db);
  if (!row) {
    throw serviceError(
      "No active CertOps signing key is available",
      CERTOPS_SIGNING_KEY_UNAVAILABLE,
    );
  }
  const privateKeyPem = decryptPrivateKeyPem(
    row.private_key_encrypted,
    row.encryption_version,
  );
  return {
    signingKeyId: row.signing_key_id,
    privateKeyObject: crypto.createPrivateKey(privateKeyPem),
  };
}

// --- Dispatch signing ---

function generateNonce() {
  return crypto.randomBytes(NONCE_RANDOM_BYTES).toString("base64url");
}

/**
 * Signs a job for dispatch and records the issued nonce in the server-side
 * replay ledger (certops_consumed_nonces, consumed_at stays NULL until the
 * result is ingested).
 *
 * Wire shape (what the agent's verifyJobSignature expects): the caller's
 * job payload fields (jobId, workspaceId, certificateId, action, target,
 * keyMode, requestedAt, ... per job-payload.schema.json) PLUS the signed
 * dispatch envelope added here: nonce, issuedAt, expiresAt, signingKeyId,
 * and the top-level signature (base64 Ed25519 over the canonical JSON of
 * everything except the signature itself).
 *
 * @param {object} params
 * @param {object} [params.client]
 * @param {object} params.job base job payload (plain object, no signature)
 * @param {string|null} [params.agentId] certops_agents uuid or null
 * @param {string} params.workspaceId
 * @param {number} [params.nonceTtlSeconds]
 * @returns {Promise<object>} the signed job ready for the claim `jobs` array
 */
async function signJobForDispatch(options = {}) {
  const db = options.client || pool;
  const {
    job,
    agentId = null,
    workspaceId,
    nonceTtlSeconds = DEFAULT_NONCE_TTL_SECONDS,
  } = options;

  if (
    job === null ||
    typeof job !== "object" ||
    Array.isArray(job) ||
    typeof job.jobId !== "string" ||
    job.jobId.length === 0
  ) {
    throw serviceError(
      "signJobForDispatch requires a plain job object with a jobId",
      CERTOPS_SIGNING_PAYLOAD_INVALID,
    );
  }
  if (typeof workspaceId !== "string" || workspaceId.length === 0) {
    throw serviceError(
      "signJobForDispatch requires a workspaceId",
      CERTOPS_SIGNING_PAYLOAD_INVALID,
    );
  }
  if (!Number.isFinite(nonceTtlSeconds) || nonceTtlSeconds <= 0) {
    throw serviceError(
      "signJobForDispatch nonceTtlSeconds must be a positive number",
      CERTOPS_SIGNING_PAYLOAD_INVALID,
    );
  }

  // Fail closed on the env key before touching the DB row.
  const { signingKeyId, privateKeyObject } = await getActiveKeyWithPrivate(db);

  const nowMs = Date.now();
  const nonce = generateNonce();
  const issuedAt = new Date(nowMs).toISOString();
  const expiresAt = new Date(nowMs + nonceTtlSeconds * 1000).toISOString();

  const signedJob = {
    ...job,
    nonce,
    issuedAt,
    expiresAt,
    signingKeyId,
  };
  delete signedJob.signature;

  // Identical canonical form to the agent verifier (shared module). Throws
  // CERTOPS_SIGNING_PAYLOAD_INVALID on unserializable payloads.
  let canonical;
  try {
    canonical = canonicalizeJobPayload(signedJob);
  } catch (error) {
    throw serviceError(
      `Job payload cannot be canonically serialized: ${error.message}`,
      CERTOPS_SIGNING_PAYLOAD_INVALID,
    );
  }

  signedJob.signature = crypto
    .sign(null, Buffer.from(canonical, "utf8"), privateKeyObject)
    .toString("base64");

  await db.query(
    `INSERT INTO certops_consumed_nonces (
       nonce, job_id, workspace_id, issued_to_agent_id, expires_at
     )
     VALUES ($1, $2, $3, $4, $5)`,
    [nonce, job.jobId, workspaceId, agentId, expiresAt],
  );

  return signedJob;
}

// --- Nonce consumption / sweeping ---

/**
 * Single-use consume of an issued nonce (called at result ingestion).
 * Returns { consumed: true } or { consumed: false, code } where code
 * distinguishes CERTOPS_NONCE_REPLAYED (already consumed) from
 * CERTOPS_NONCE_UNKNOWN_OR_EXPIRED (never issued, or past expires_at).
 */
async function consumeNonce(options = {}) {
  const db = options.client || pool;
  const { nonce, jobId } = options;
  if (typeof nonce !== "string" || !NONCE_PATTERN.test(nonce)) {
    return { consumed: false, code: CERTOPS_NONCE_UNKNOWN_OR_EXPIRED };
  }

  const updated = await db.query(
    `UPDATE certops_consumed_nonces
        SET consumed_at = NOW()
      WHERE nonce = $1
        AND job_id = $2
        AND consumed_at IS NULL
        AND expires_at > NOW()
      RETURNING nonce`,
    [nonce, jobId],
  );
  if (updated.rows[0]) return { consumed: true };

  // Distinguish replay from unknown/expired with an existence check.
  const existing = await db.query(
    `SELECT consumed_at
       FROM certops_consumed_nonces
      WHERE nonce = $1
        AND job_id = $2
      LIMIT 1`,
    [nonce, jobId],
  );
  const row = existing.rows[0];
  if (row && row.consumed_at !== null && row.consumed_at !== undefined) {
    return { consumed: false, code: CERTOPS_NONCE_REPLAYED };
  }
  return { consumed: false, code: CERTOPS_NONCE_UNKNOWN_OR_EXPIRED };
}

/**
 * Deletes nonce rows whose expires_at is more than the grace window in the
 * past (consumed or not), bounded per call. Returns the deleted count.
 * Called by the worker sweep loop (separate task).
 */
async function sweepExpiredNonces(options = {}) {
  const db = options.client || pool;
  const batchSize = Number.isInteger(options.batchSize)
    ? Math.max(1, options.batchSize)
    : 1000;

  const result = await db.query(
    `DELETE FROM certops_consumed_nonces
      WHERE (nonce, job_id) IN (
        SELECT nonce, job_id
          FROM certops_consumed_nonces
         WHERE expires_at < NOW() - INTERVAL '${SWEEP_GRACE_SECONDS} seconds'
         LIMIT $1
      )`,
    [batchSize],
  );
  return result.rowCount || 0;
}

module.exports = {
  CERTOPS_SIGNING_ENCRYPTION_KEY_MISSING,
  CERTOPS_SIGNING_KEY_UNAVAILABLE,
  CERTOPS_SIGNING_PAYLOAD_INVALID,
  CERTOPS_NONCE_REPLAYED,
  CERTOPS_NONCE_UNKNOWN_OR_EXPIRED,
  DEFAULT_NONCE_TTL_SECONDS,
  ensureActiveSigningKey,
  getActiveSigningKeyPublicInfo,
  signJobForDispatch,
  consumeNonce,
  sweepExpiredNonces,
  _test: {
    ENV_KEY_NAME,
    ENCRYPTION_VERSION,
    NONCE_PATTERN,
    SIGNING_KEY_ID_PREFIX,
    SIGNING_KEY_ID_PATTERN,
    SWEEP_GRACE_SECONDS,
    canonicalizeJobPayload,
    encryptPrivateKeyPem,
    decryptPrivateKeyPem,
    generateNonce,
    generateSigningKeyId,
    getEncryptionKey,
  },
};
