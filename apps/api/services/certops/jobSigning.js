"use strict";

/**
 * Control-plane Ed25519 job-signing service (ADR-0003).
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
// can still distinguish "replayed" from "never issued". Kept aligned with
// the lease hard-grace window (leaseTiming.DEFAULT_LEASE_HARD_GRACE_SECONDS).
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
 * single-active race is resolved with INSERT ... ON CONFLICT DO NOTHING:
 * no error is raised inside the caller's transaction (a caught 23505 would
 * abort it), and the loser re-selects the winner's row.
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

  const inserted = await db.query(
    `INSERT INTO certops_signing_keys (
       signing_key_id, public_key_pem, private_key_encrypted,
       encryption_version, status
     )
     VALUES ($1, $2, $3, $4, 'active')
     ON CONFLICT DO NOTHING
     RETURNING id, signing_key_id, public_key_pem`,
    [signingKeyId, publicKeyPem, privateKeyEncrypted, ENCRYPTION_VERSION],
  );
  if (inserted.rows[0]) return publicInfoFromRow(inserted.rows[0]);

  // Lost the single-active race: another writer inserted first. The
  // transaction is still healthy (no constraint error was raised), so the
  // winner's row is visible to a plain re-select.
  const winner = await selectActiveKeyRow(db);
  if (winner) return publicInfoFromRow(winner);
  throw serviceError(
    "Active signing key could not be created or found",
    CERTOPS_SIGNING_KEY_UNAVAILABLE,
  );
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

async function selectRetiringKeyRow(db) {
  const result = await db.query(
    `SELECT id, signing_key_id, public_key_pem, status, supersedes_signing_key_id,
            rotation_started_at, rotation_forced_at, rotation_force_reason
       FROM certops_signing_keys
      WHERE status = 'retiring'
      ORDER BY rotation_started_at DESC NULLS LAST, created_at DESC
      LIMIT 1`,
  );
  return result.rows[0] || null;
}

/**
 * Begin overlapping signing-key rotation: create a new active key and move the
 * previous active key to retiring so existing agents can still verify while
 * they acknowledge the replacement via heartbeat.
 */
async function beginSigningKeyRotation(options = {}) {
  const db = options.client || pool;
  getEncryptionKey();

  const current = await selectActiveKeyRow(db);
  if (!current) {
    return ensureActiveSigningKey({ client: db });
  }

  const retiring = await selectRetiringKeyRow(db);
  if (retiring) {
    throw serviceError(
      "A signing-key rotation is already in progress",
      CERTOPS_SIGNING_KEY_UNAVAILABLE,
    );
  }

  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey
    .export({ type: "spki", format: "pem" })
    .toString();
  const privateKeyPem = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  const signingKeyId = generateSigningKeyId();
  const privateKeyEncrypted = encryptPrivateKeyPem(privateKeyPem);

  await db.query(
    `UPDATE certops_signing_keys
        SET status = 'retiring',
            rotation_started_at = COALESCE(rotation_started_at, NOW()),
            updated_at = NOW()
      WHERE id = $1
        AND status = 'active'`,
    [current.id],
  );

  const inserted = await db.query(
    `INSERT INTO certops_signing_keys (
       signing_key_id, public_key_pem, private_key_encrypted,
       encryption_version, status, supersedes_signing_key_id, rotation_started_at
     )
     VALUES ($1, $2, $3, $4, 'active', $5, NOW())
     RETURNING id, signing_key_id, public_key_pem`,
    [
      signingKeyId,
      publicKeyPem,
      privateKeyEncrypted,
      ENCRYPTION_VERSION,
      current.signing_key_id,
    ],
  );

  return {
    signingKeyId: inserted.rows[0].signing_key_id,
    publicKeyPem: inserted.rows[0].public_key_pem,
    supersedesSigningKeyId: current.signing_key_id,
    status: "active",
  };
}

/**
 * Heartbeat rotation notice for agents that have not yet pinned the new key.
 * Field shape is documented in COORDINATION-H3.md.
 */
async function getSigningKeyRotationNotice(options = {}) {
  const db = options.client || pool;
  const active = await selectActiveKeyRow(db);
  if (!active) return null;

  const pinnedSigningKeyId =
    typeof options.pinnedSigningKeyId === "string"
      ? options.pinnedSigningKeyId
      : null;
  if (pinnedSigningKeyId && pinnedSigningKeyId === active.signing_key_id) {
    return null;
  }

  const retiring = await selectRetiringKeyRow(db);
  if (!retiring && !active.supersedes_signing_key_id) {
    return null;
  }

  return {
    pendingSigningKeyId: active.signing_key_id,
    pendingPublicKeyPem: active.public_key_pem,
    supersedesSigningKeyId:
      active.supersedes_signing_key_id || retiring?.signing_key_id || null,
    status: "pending_ack",
  };
}

async function acknowledgeSigningKey(options = {}) {
  const db = options.client || pool;
  const signingKeyId =
    typeof options.signingKeyId === "string" ? options.signingKeyId.trim() : "";
  if (!signingKeyId || !SIGNING_KEY_ID_PATTERN.test(signingKeyId)) {
    return { acknowledged: false };
  }
  if (!options.agentRowId || !options.workspaceId) {
    return { acknowledged: false };
  }

  await db.query(
    `INSERT INTO certops_signing_key_acks (
       workspace_id, agent_id, signing_key_id
     ) VALUES ($1, $2, $3)
     ON CONFLICT (agent_id, signing_key_id) DO UPDATE
       SET acknowledged_at = NOW()`,
    [options.workspaceId, options.agentRowId, signingKeyId],
  );
  return { acknowledged: true, signingKeyId };
}

/**
 * Retire the previous (retiring) signing key once the active fleet has
 * acknowledged the replacement, or when an operator forces incomplete
 * rotation after a grace period.
 */
async function completeSigningKeyRotation(options = {}) {
  const db = options.client || pool;
  const force = options.force === true;
  const retiring = await selectRetiringKeyRow(db);
  if (!retiring) {
    return { completed: false, reason: "no_retiring_key" };
  }

  const active = await selectActiveKeyRow(db);
  if (!active) {
    throw serviceError(
      "No active CertOps signing key is available",
      CERTOPS_SIGNING_KEY_UNAVAILABLE,
    );
  }

  const fleet = await db.query(
    `SELECT COUNT(*)::int AS active_agents
       FROM certops_agents
      WHERE status = 'active'`,
  );
  const acks = await db.query(
    `SELECT COUNT(DISTINCT agent_id)::int AS ack_count
       FROM certops_signing_key_acks
      WHERE signing_key_id = $1`,
    [active.signing_key_id],
  );
  const activeAgents = Number(fleet.rows[0]?.active_agents || 0);
  const ackCount = Number(acks.rows[0]?.ack_count || 0);
  const fullyAcked = activeAgents === 0 || ackCount >= activeAgents;

  if (!fullyAcked && !force) {
    return {
      completed: false,
      reason: "fleet_incomplete",
      activeAgents,
      ackCount,
    };
  }

  await db.query(
    `UPDATE certops_signing_keys
        SET status = 'retired',
            retired_at = NOW(),
            rotation_forced_at = CASE WHEN $2 THEN NOW() ELSE rotation_forced_at END,
            rotation_force_reason = CASE
              WHEN $2 THEN $3
              ELSE rotation_force_reason
            END,
            updated_at = NOW()
      WHERE id = $1
        AND status = 'retiring'`,
    [
      retiring.id,
      force,
      force
        ? options.reason ||
          "Forced incomplete rotation: retiring key stopped before full fleet acknowledgement"
        : null,
    ],
  );

  return {
    completed: true,
    forced: force && !fullyAcked,
    retiredSigningKeyId: retiring.signing_key_id,
    activeSigningKeyId: active.signing_key_id,
    activeAgents,
    ackCount,
  };
}

/**
 * Read-only rotation state for operators: which key is active, which is
 * retiring, and how much of the active fleet has acknowledged the active key.
 * Never requires the env encryption key and never returns private material,
 * so it is safe to call before deciding to start or complete a rotation.
 */
async function getSigningKeyRotationStatus(options = {}) {
  const db = options.client || pool;
  const active = await selectActiveKeyRow(db);
  const retiring = await selectRetiringKeyRow(db);

  let activeAgents = 0;
  let ackCount = 0;
  if (active) {
    const fleet = await db.query(
      `SELECT COUNT(*)::int AS active_agents
         FROM certops_agents
        WHERE status = 'active'`,
    );
    const acks = await db.query(
      `SELECT COUNT(DISTINCT agent_id)::int AS ack_count
         FROM certops_signing_key_acks
        WHERE signing_key_id = $1`,
      [active.signing_key_id],
    );
    activeAgents = Number(fleet.rows[0]?.active_agents || 0);
    ackCount = Number(acks.rows[0]?.ack_count || 0);
  }

  return {
    active: publicInfoFromRow(active),
    retiring: retiring
      ? {
          signingKeyId: retiring.signing_key_id,
          status: retiring.status,
          rotationStartedAt: retiring.rotation_started_at || null,
        }
      : null,
    rotationInProgress: Boolean(retiring),
    activeAgents,
    ackCount,
    // Mirrors the completeSigningKeyRotation gate so a caller can tell
    // whether completing now would need --force.
    fullyAcked: activeAgents === 0 || ackCount >= activeAgents,
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
 * Binding: the nonce row must match the job AND, when the caller provides
 * them, the workspace and the agent the nonce was issued to. A nonce
 * dispensed to one agent can never be consumed by another, and a nonce from
 * one workspace can never satisfy a result in a different one.
 * Returns { consumed: true } or { consumed: false, code } where code
 * distinguishes CERTOPS_NONCE_REPLAYED (already consumed) from
 * CERTOPS_NONCE_UNKNOWN_OR_EXPIRED (never issued, issued to a different
 * agent/workspace, or past expires_at).
 */
async function consumeNonce(options = {}) {
  const db = options.client || pool;
  const { nonce, jobId, workspaceId = null, agentRowId = null } = options;
  if (typeof nonce !== "string" || !NONCE_PATTERN.test(nonce)) {
    return { consumed: false, code: CERTOPS_NONCE_UNKNOWN_OR_EXPIRED };
  }

  const updated = await db.query(
    `UPDATE certops_consumed_nonces
        SET consumed_at = NOW()
      WHERE nonce = $1
        AND job_id = $2
        AND ($3::uuid IS NULL OR workspace_id = $3::uuid)
        AND ($4::uuid IS NULL OR issued_to_agent_id IS NULL
             OR issued_to_agent_id = $4::uuid)
        AND consumed_at IS NULL
        AND expires_at > NOW()
      RETURNING nonce`,
    [nonce, jobId, workspaceId, agentRowId],
  );
  if (updated.rows[0]) return { consumed: true };

  // Distinguish replay from unknown/expired/foreign with an existence check
  // under the same binding.
  const existing = await db.query(
    `SELECT consumed_at
       FROM certops_consumed_nonces
      WHERE nonce = $1
        AND job_id = $2
        AND ($3::uuid IS NULL OR workspace_id = $3::uuid)
        AND ($4::uuid IS NULL OR issued_to_agent_id IS NULL
             OR issued_to_agent_id = $4::uuid)
      LIMIT 1`,
    [nonce, jobId, workspaceId, agentRowId],
  );
  const row = existing.rows[0];
  if (row && row.consumed_at !== null && row.consumed_at !== undefined) {
    return { consumed: false, code: CERTOPS_NONCE_REPLAYED };
  }
  return { consumed: false, code: CERTOPS_NONCE_UNKNOWN_OR_EXPIRED };
}

/**
 * Extends the still-open dispatch nonce for a job so it stays consumable
 * for as long as the renewable lease is alive (B6/B7). Only rows that are
 * unconsumed and currently bound to the claiming agent are touched.
 *
 * @returns {Promise<{ extended: boolean, expiresAt: string|null }>}
 */
async function extendJobNonceExpiry(options = {}) {
  const db = options.client || pool;
  const {
    jobId,
    workspaceId,
    agentRowId = null,
    nonceTtlSeconds = DEFAULT_NONCE_TTL_SECONDS,
  } = options;

  if (typeof jobId !== "string" || jobId.length === 0) {
    return { extended: false, expiresAt: null };
  }
  if (!Number.isFinite(nonceTtlSeconds) || nonceTtlSeconds <= 0) {
    return { extended: false, expiresAt: null };
  }

  const result = await db.query(
    `UPDATE certops_consumed_nonces
        SET expires_at = NOW() + make_interval(secs => $4)
      WHERE job_id = $1
        AND workspace_id = $2
        AND consumed_at IS NULL
        AND ($3::uuid IS NULL OR issued_to_agent_id IS NULL
             OR issued_to_agent_id = $3::uuid)
      RETURNING expires_at`,
    [jobId, workspaceId, agentRowId, nonceTtlSeconds],
  );
  const row = result.rows[0];
  if (!row) return { extended: false, expiresAt: null };
  const expiresAt =
    row.expires_at instanceof Date
      ? row.expires_at.toISOString()
      : row.expires_at
        ? new Date(row.expires_at).toISOString()
        : null;
  return { extended: true, expiresAt };
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
  acknowledgeSigningKey,
  beginSigningKeyRotation,
  completeSigningKeyRotation,
  ensureActiveSigningKey,
  getActiveSigningKeyPublicInfo,
  getSigningKeyRotationNotice,
  getSigningKeyRotationStatus,
  signJobForDispatch,
  consumeNonce,
  extendJobNonceExpiry,
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
