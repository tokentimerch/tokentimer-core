"use strict";

/**
 * At-rest encryption for CertOps agent registration-replay credentials (H1).
 *
 * The short-lived certops_agent_registration_replays row must store the
 * reusable ttagent_... credential so a lost register response can be
 * replayed. That value must NEVER sit in Postgres as plaintext.
 *
 * Pattern mirrors jobSigning.js (AES-256-GCM, ivHex:tagHex:cipherHex) with a
 * dedicated wrap key CERTOPS_REGISTRATION_ENCRYPTION_KEY so registration
 * credential encryption can rotate independently of job-signing key custody.
 * FAIL-CLOSED: encrypt/decrypt throw when the env key is unset or malformed.
 *
 * No function in this module ever logs plaintext credentials or envelopes.
 */

const crypto = require("node:crypto");

const CERTOPS_REGISTRATION_ENCRYPTION_KEY_MISSING =
  "CERTOPS_REGISTRATION_ENCRYPTION_KEY_MISSING";
const CERTOPS_REGISTRATION_CREDENTIAL_UNAVAILABLE =
  "CERTOPS_REGISTRATION_CREDENTIAL_UNAVAILABLE";

const ENV_KEY_NAME = "CERTOPS_REGISTRATION_ENCRYPTION_KEY";
const ENV_KEY_PATTERN = /^[a-fA-F0-9]{64}$/;
const ENCRYPTION_VERSION = 1;

function serviceError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function getEncryptionKey() {
  const raw = process.env[ENV_KEY_NAME];
  if (typeof raw !== "string" || !ENV_KEY_PATTERN.test(raw.trim())) {
    throw serviceError(
      `${ENV_KEY_NAME} is not set or malformed (expected 64 hex chars = ` +
        "32 bytes); refusing to handle registration replay credentials",
      CERTOPS_REGISTRATION_ENCRYPTION_KEY_MISSING,
    );
  }
  return Buffer.from(raw.trim(), "hex");
}

function encryptRegistrationCredential(plaintext) {
  if (typeof plaintext !== "string" || plaintext.length === 0) {
    throw serviceError(
      "Registration credential plaintext is required for encryption",
      CERTOPS_REGISTRATION_CREDENTIAL_UNAVAILABLE,
    );
  }
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  let encrypted = cipher.update(plaintext, "utf8", "hex");
  encrypted += cipher.final("hex");
  const tag = cipher.getAuthTag().toString("hex");
  return `${iv.toString("hex")}:${tag}:${encrypted}`;
}

function decryptRegistrationCredential(ciphertext, encryptionVersion) {
  if (Number(encryptionVersion) !== ENCRYPTION_VERSION) {
    throw serviceError(
      `Unsupported registration-credential encryption version ${encryptionVersion}`,
      CERTOPS_REGISTRATION_CREDENTIAL_UNAVAILABLE,
    );
  }
  const key = getEncryptionKey();
  const parts = String(ciphertext || "").split(":");
  if (parts.length !== 3) {
    throw serviceError(
      "Stored registration credential envelope is malformed",
      CERTOPS_REGISTRATION_CREDENTIAL_UNAVAILABLE,
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
      "Failed to unwrap the registration replay credential (wrong " +
        `${ENV_KEY_NAME} or corrupted envelope)`,
      CERTOPS_REGISTRATION_CREDENTIAL_UNAVAILABLE,
    );
  }
}

/**
 * Deletes expired registration-replay rows, bounded per call.
 * Called by the CertOps maintenance worker.
 */
async function sweepExpiredRegistrationReplays(options = {}) {
  const db = options.client;
  if (!db || typeof db.query !== "function") {
    throw serviceError(
      "sweepExpiredRegistrationReplays requires a database client",
      CERTOPS_REGISTRATION_CREDENTIAL_UNAVAILABLE,
    );
  }
  const batchSize = Number.isInteger(options.batchSize)
    ? Math.max(1, options.batchSize)
    : 1000;

  const result = await db.query(
    `DELETE FROM certops_agent_registration_replays
      WHERE id IN (
        SELECT id
          FROM certops_agent_registration_replays
         WHERE expires_at < NOW()
         LIMIT $1
      )`,
    [batchSize],
  );
  return result.rowCount || 0;
}

module.exports = {
  CERTOPS_REGISTRATION_ENCRYPTION_KEY_MISSING,
  CERTOPS_REGISTRATION_CREDENTIAL_UNAVAILABLE,
  ENCRYPTION_VERSION,
  encryptRegistrationCredential,
  decryptRegistrationCredential,
  sweepExpiredRegistrationReplays,
  _test: {
    ENV_KEY_NAME,
    ENCRYPTION_VERSION,
    ENV_KEY_PATTERN,
    getEncryptionKey,
  },
};
