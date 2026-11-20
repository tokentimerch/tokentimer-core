"use strict";

const crypto = require("crypto");
const fs = require("fs");

const ALG = "aes-256-gcm";
const ENVELOPE_VERSION = 1;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;

/** @type {{ primary: string, keys: Record<string, Buffer> } | null} */
let cachedKeyring = null;

function keyringError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

/**
 * @param {string} providerId UUID
 * @param {string} secretName
 * @returns {string}
 */
function buildSecretAad(providerId, secretName) {
  return `tokentimer:sso_provider_secret:v1:${providerId}:${secretName}`;
}

function decodeKeyMaterial(b64, kid) {
  if (typeof b64 !== "string" || !b64.trim()) {
    throw keyringError("secret_keyring_invalid", `Key "${kid}" must be a base64 string`);
  }
  const buf = Buffer.from(b64.trim(), "base64");
  if (buf.length !== KEY_BYTES) {
    throw keyringError(
      "secret_keyring_invalid",
      `Key "${kid}" must decode to exactly ${KEY_BYTES} bytes (use openssl rand -base64 32 per key; do not base64-encode twice)`,
    );
  }
  return buf;
}

/**
 * @param {unknown} raw
 * @returns {{ primary: string, keys: Record<string, Buffer> }}
 */
function parseKeyringConfig(raw) {
  if (!raw || typeof raw !== "object") {
    throw keyringError("secret_keyring_invalid", "Keyring must be a JSON object");
  }
  const primary = String(raw.primary || "").trim();
  if (!primary) {
    throw keyringError("secret_keyring_invalid", "Keyring primary kid is required");
  }
  const keysRaw = raw.keys;
  if (!keysRaw || typeof keysRaw !== "object" || Array.isArray(keysRaw)) {
    throw keyringError("secret_keyring_invalid", "Keyring keys map is required");
  }
  const keys = Object.create(null);
  for (const [kid, b64] of Object.entries(keysRaw)) {
    keys[kid] = decodeKeyMaterial(b64, kid);
  }
  if (!keys[primary]) {
    throw keyringError(
      "secret_keyring_invalid",
      `Primary kid "${primary}" is not present in keys map`,
    );
  }
  return { primary, keys };
}

function parseKeyringJson(text) {
  let config;
  try {
    config = JSON.parse(text);
  } catch {
    throw keyringError("secret_keyring_invalid", "The SSO keyring must contain valid JSON");
  }
  return parseKeyringConfig(config);
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {{ primary: string, keys: Record<string, Buffer> } | null}
 */
function loadKeyring(env = process.env) {
  const inline = String(env.SSO_SECRETS_KEYRING || "").trim();
  const filePath = String(env.SSO_SECRETS_KEYRING_FILE || "").trim();
  if (inline && filePath) {
    throw keyringError(
      "secret_keyring_ambiguous",
      "Set either SSO_SECRETS_KEYRING or SSO_SECRETS_KEYRING_FILE, not both",
    );
  }
  if (filePath) {
    if (!fs.existsSync(filePath)) {
      throw keyringError(
        "secret_keyring_missing",
        `SSO_SECRETS_KEYRING_FILE not found: ${filePath}`,
      );
    }
    return parseKeyringJson(fs.readFileSync(filePath, "utf8"));
  }
  if (inline) {
    return parseKeyringJson(inline);
  }
  return null;
}

function requireKeyring(env = process.env) {
  if (cachedKeyring && env === process.env) return cachedKeyring;
  const keyring = loadKeyring(env);
  if (!keyring) {
    throw keyringError(
      "secret_keyring_missing",
      "SSO_SECRETS_KEYRING or SSO_SECRETS_KEYRING_FILE is required for secret operations",
    );
  }
  if (env === process.env) cachedKeyring = keyring;
  return keyring;
}

function getKeyring() {
  return requireKeyring();
}

function _resetKeyringForTests(keyring) {
  cachedKeyring = keyring;
}

/**
 * @param {string} plaintext
 * @param {string} aad
 * @param {{ primary: string, keys: Record<string, Buffer> }} [keyring]
 */
function encryptSecret(plaintext, aad, keyring = requireKeyring()) {
  if (plaintext == null) {
    throw new Error("encryptSecret: plaintext is required");
  }
  if (!aad) throw new Error("encryptSecret: aad is required");
  const kid = keyring.primary;
  const key = keyring.keys[kid];
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALG, key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const ct = Buffer.concat([
    cipher.update(String(plaintext), "utf8"),
    cipher.final(),
  ]);
  return {
    v: ENVELOPE_VERSION,
    alg: "AES-256-GCM",
    kid,
    iv: iv.toString("base64"),
    ct: ct.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
  };
}

/**
 * @param {object} envelope
 * @param {string} aad
 * @param {{ primary: string, keys: Record<string, Buffer> }} [keyring]
 */
function decryptSecret(envelope, aad, keyring = requireKeyring()) {
  const kid = String(envelope?.kid || "").trim();
  const key = keyring.keys[kid];
  if (!key) {
    throw keyringError("secret_keyring_missing", `No keyring entry for kid "${kid}"`);
  }
  const iv = Buffer.from(String(envelope.iv || ""), "base64");
  const ct = Buffer.from(String(envelope.ct || ""), "base64");
  const tag = Buffer.from(String(envelope.tag || ""), "base64");
  const decipher = crypto.createDecipheriv(ALG, key, iv, { authTagLength: TAG_BYTES });
  decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
  } catch (_) {
    throw keyringError(
      "secret_decrypt_failed",
      "GCM authentication failed (wrong key, AAD, or corrupted ciphertext)",
    );
  }
}

function reencryptSecret(envelope, aad, plaintext, keyring = requireKeyring()) {
  const fromKid = String(envelope?.kid || keyring.primary);
  const toKid = keyring.primary;
  if (fromKid === toKid) {
    return { envelope, fromKid, toKid, reencrypted: false };
  }
  return {
    envelope: encryptSecret(plaintext, aad, keyring),
    fromKid,
    toKid,
    reencrypted: true,
  };
}

module.exports = {
  ALG,
  ENVELOPE_VERSION,
  KEY_BYTES,
  buildSecretAad,
  secretAad: buildSecretAad,
  parseKeyringConfig,
  loadKeyring,
  requireKeyring,
  getKeyring,
  _resetKeyringForTests,
  encryptSecret,
  decryptSecret,
  reencryptSecret,
};
