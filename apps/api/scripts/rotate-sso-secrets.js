#!/usr/bin/env node
"use strict";

/**
 * Re-encrypt every row in sso_provider_secrets under the keyring's current primary kid.
 * Idempotent: rows already encrypted with the primary kid are skipped.
 *
 * Usage: node apps/api/scripts/rotate-sso-secrets.js (inside the API container)
 */

const { pool } = require("../db/database");
const { writeAudit } = require("../services/audit");
const {
  buildSecretAad,
  decryptSecret,
  reencryptSecret,
  requireKeyring,
} = require("../sso/secrets-keyring");

async function rotateProviderSecrets(database, providerId, slug) {
  const keyring = requireKeyring();
  const client = await database.connect();
  try {
    await client.query("BEGIN");
    const secrets = await client.query(
      `SELECT secret_name, encrypted_value
         FROM sso_provider_secrets
        WHERE provider_id = $1
        FOR UPDATE`,
      [providerId],
    );

    let rotated = 0;
    for (const row of secrets.rows) {
      const aad = buildSecretAad(providerId, row.secret_name);
      const plaintext = decryptSecret(row.encrypted_value, aad, keyring);
      const { envelope, fromKid, toKid, reencrypted } = reencryptSecret(
        row.encrypted_value,
        aad,
        plaintext,
        keyring,
      );
      if (!reencrypted) continue;
      await client.query(
        `UPDATE sso_provider_secrets
            SET encrypted_value = $3::jsonb, updated_at = NOW()
          WHERE provider_id = $1 AND secret_name = $2`,
        [providerId, row.secret_name, JSON.stringify(envelope)],
      );
      await writeAudit({
        client,
        actorUserId: null,
        action: "SSO_PROVIDER_SECRET_REENCRYPTED",
        targetType: "sso_provider",
        targetId: slug,
        metadata: {
          provider_slug: slug,
          secret_name: row.secret_name,
          from_kid: fromKid,
          to_kid: toKid,
        },
      });
      rotated += 1;
    }
    await client.query("COMMIT");
    return rotated;
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch (_) {}
    throw err;
  } finally {
    client.release();
  }
}

async function main() {
  requireKeyring();
  try {
    const providers = await pool.query(
      "SELECT id, slug FROM sso_providers ORDER BY slug",
    );
    let total = 0;
    for (const row of providers.rows) {
      const n = await rotateProviderSecrets(pool, row.id, row.slug);
      total += n;
      if (n > 0) {
        console.log(`Re-encrypted ${n} secret(s) for provider ${row.slug}`);
      }
    }
    console.log(`Done. Re-encrypted ${total} secret row(s) across ${providers.rowCount} provider(s).`);
  } finally {
    await pool.end();
  }
}

if (require.main === module) {
  main().catch(() => {
    console.error("SSO secret rotation failed. Check database access and that the keyring contains every stored key ID.");
    process.exit(1);
  });
}

module.exports = {
  rotateProviderSecrets,
  main,
};
