"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert");
const crypto = require("crypto");

const { rotateProviderSecrets } = require("../../apps/api/scripts/rotate-sso-secrets.js");
const {
  buildSecretAad,
  encryptSecret,
  parseKeyringConfig,
  loadKeyring,
  _resetKeyringForTests,
  KEY_BYTES,
} = require("../../apps/api/sso/secrets-keyring");

describe("rotate-sso-secrets", () => {
  const envBackup = { ...process.env };

  beforeEach(() => {
    const k0 = crypto.randomBytes(KEY_BYTES).toString("base64");
    const k1 = crypto.randomBytes(KEY_BYTES).toString("base64");
    process.env.SSO_SECRETS_KEYRING = JSON.stringify({
      primary: "k1",
      keys: { k0, k1 },
    });
    _resetKeyringForTests(parseKeyringConfig(JSON.parse(process.env.SSO_SECRETS_KEYRING)));
  });

  afterEach(() => {
    process.env = { ...envBackup };
    _resetKeyringForTests(null);
  });

  it("reports a constant error for invalid keyring JSON", () => {
    assert.throws(() => loadKeyring({ SSO_SECRETS_KEYRING: "invalid-json-fixture" }), {
      code: "secret_keyring_invalid", message: "The SSO keyring must contain valid JSON",
    });
  });

  it("re-encrypts secrets encrypted under a retired primary kid", async () => {
    const providerId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const keyringConfig = JSON.parse(process.env.SSO_SECRETS_KEYRING);
    const oldRing = parseKeyringConfig({
      primary: "k0",
      keys: { k0: keyringConfig.keys.k0 },
    });
    const aad = buildSecretAad(providerId, "client_secret");
    const envelope = encryptSecret("rotate-me", aad, oldRing);

    let updatedEnvelope = null;
    const pool = {
      connect: async () => ({
        query: async (sql, params) => {
          const s = String(sql);
          if (s.trim() === "BEGIN" || s.trim() === "COMMIT" || s.trim() === "ROLLBACK") {
            return { rows: [] };
          }
          if (s.includes("FROM sso_provider_secrets") && s.includes("FOR UPDATE")) {
            return {
              rows: [{ secret_name: "client_secret", encrypted_value: envelope }],
            };
          }
          if (s.includes("UPDATE sso_provider_secrets")) {
            updatedEnvelope = JSON.parse(params[2]);
            return { rowCount: 1, rows: [] };
          }
          return { rows: [] };
        },
        release: () => {},
      }),
      query: async () => ({ rows: [] }),
    };

    const rotated = await rotateProviderSecrets(pool, providerId, "azure-ad");
    assert.strictEqual(rotated, 1);
    assert.ok(updatedEnvelope);
    assert.strictEqual(updatedEnvelope.kid, "k1");
  });

  it("skips rows already encrypted with the current primary kid", async () => {
    const providerId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    const keyring = parseKeyringConfig(JSON.parse(process.env.SSO_SECRETS_KEYRING));
    const aad = buildSecretAad(providerId, "client_secret");
    const envelope = encryptSecret("already-primary", aad, keyring);

    let updates = 0;
    const pool = {
      connect: async () => ({
        query: async (sql) => {
          const s = String(sql);
          if (s.trim() === "BEGIN" || s.trim() === "COMMIT" || s.trim() === "ROLLBACK") {
            return { rows: [] };
          }
          if (s.includes("FROM sso_provider_secrets")) {
            return {
              rows: [{ secret_name: "client_secret", encrypted_value: envelope }],
            };
          }
          if (s.includes("UPDATE sso_provider_secrets")) {
            updates += 1;
            return { rowCount: 1, rows: [] };
          }
          return { rows: [] };
        },
        release: () => {},
      }),
      query: async () => ({ rows: [] }),
    };

    const rotated = await rotateProviderSecrets(pool, providerId, "azure-ad");
    assert.strictEqual(rotated, 0);
    assert.strictEqual(updates, 0);
  });
});
