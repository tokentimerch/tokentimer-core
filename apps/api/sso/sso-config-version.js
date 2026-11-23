"use strict";

/**
 * Monotonic SSO config version on system_settings. Bumped when sso_providers
 * or secrets change so every API replica can reload passport strategies.
 */

/**
 * @param {import('pg').Pool} pool
 * @returns {Promise<number>}
 */
async function getSsoConfigVersion(pool) {
  const res = await pool.query(
    "SELECT COALESCE(sso_config_version, 1)::bigint AS v FROM system_settings WHERE id = 1",
  );
  const v = res.rows[0]?.v;
  return Number(v) > 0 ? Number(v) : 1;
}

/**
 * @param {import('pg').Pool} pool
 * @returns {Promise<number>}
 */
async function bumpSsoConfigVersion(pool) {
  const res = await pool.query(
    `UPDATE system_settings
        SET sso_config_version = COALESCE(sso_config_version, 1) + 1,
            updated_at = NOW()
      WHERE id = 1
      RETURNING sso_config_version::bigint AS v`,
  );
  const v = res.rows[0]?.v;
  return Number(v) > 0 ? Number(v) : 1;
}

// Serialize policy edits against the persisted snapshot and publish their version atomically.
async function saveVersionedSsoSettings(saveJsonColumn, pool, column, payload, userId, options) {
  const client = await pool.connect();
  let discard = false;
  try {
    await client.query("BEGIN");
    const { rows } = await client.query("SELECT * FROM system_settings WHERE id = 1 FOR UPDATE");
    if (!rows.length) throw new Error("System settings row is missing");
    const result = await saveJsonColumn(client, column, payload, userId, { ...options, rowSnapshot: rows[0] });
    await bumpSsoConfigVersion(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch (_) {
      discard = true;
    }
    throw err;
  } finally {
    client.release(discard);
  }
}

module.exports = {
  getSsoConfigVersion,
  bumpSsoConfigVersion,
  saveVersionedSsoSettings,
};
