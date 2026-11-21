"use strict";

/**
 * Lockout-prevention guard for SSO provider disable/delete/secret-clear.
 * Mirrors production SQL in tests/unit/login-reachability.test.js.
 */

const SSO_NO_PASSWORD = "SSO_NO_PASSWORD";

/** Verbatim production query for a usable local admin account. */
const USABLE_LOCAL_ADMIN_SQL = `
  SELECT 1
  FROM users
  WHERE is_admin = TRUE
    AND (auth_method <> 'local' OR email_verified = TRUE)
    AND password_hash <> $1
    AND password_hash ~ '^[$]2[aby][$][0-9]{2}[$][./A-Za-z0-9]{53}$'
    AND lower(email) NOT LIKE '%@example.invalid'
    AND display_name IS DISTINCT FROM 'Deleted Account'
  LIMIT 1`;

const ENABLED_OTHER_PROVIDERS_SQL = `
  SELECT slug, type
  FROM sso_providers
  WHERE enabled = TRUE
    AND slug <> $1
    AND NOT EXISTS (
      SELECT 1 FROM sso_providers peer
      WHERE peer.type = sso_providers.type AND peer.enabled AND peer.slug <> sso_providers.slug
    )
    AND EXISTS (
      SELECT 1 FROM external_identities ei
      JOIN users u ON u.id = ei.user_id
      WHERE ei.provider_slug = sso_providers.slug AND u.is_admin
        AND lower(u.email) NOT LIKE '%@example.invalid'
        AND u.display_name IS DISTINCT FROM 'Deleted Account'
    )
  ORDER BY sort_order, display_name`;

/**
 * @param {import('pg').Pool} pool
 * @returns {Promise<boolean>}
 */
async function hasUsableLocalAdmin(pool, { lock = false, retiringSlug } = {}) {
  const params = [SSO_NO_PASSWORD];
  let sql = USABLE_LOCAL_ADMIN_SQL;
  if (retiringSlug) {
    params.push(retiringSlug);
    sql = sql.replace("  LIMIT 1", `    AND (
      is_admin_manual
      OR NOT EXISTS (SELECT 1 FROM sso_system_admin_grants g WHERE g.user_id = users.id AND g.provider_slug = $2)
      OR EXISTS (SELECT 1 FROM sso_system_admin_grants g WHERE g.user_id = users.id AND g.provider_slug <> $2)
    )
  LIMIT 1`);
  }
  const res = await pool.query(sql + (lock ? " FOR SHARE" : ""), params);
  return res.rows.length > 0;
}

/**
 * @param {import('pg').Pool} pool
 * @param {string} excludingSlug
 * @param {(slug: string) => { signInReady?: boolean }} getRuntimeStatus
 * @returns {Promise<string[]>}
 */
async function getSignInReadyProviderSlugs(pool, excludingSlug, getRuntimeStatus) {
  const res = await pool.query(ENABLED_OTHER_PROVIDERS_SQL, [excludingSlug]);
  const ready = [];
  for (const row of res.rows) {
    const runtime = getRuntimeStatus(row.slug);
    if (runtime?.signInReady === true) {
      ready.push(row.slug);
    }
  }
  return ready;
}

/**
 * @param {import('pg').Pool} pool
 * @param {object} opts
 * @param {string} opts.changingSlug
 * @param {(slug: string) => { signInReady?: boolean }} opts.getRuntimeStatus
 * @returns {Promise<{
 *   localAuthEnabled: boolean,
 *   hasUsableLocalAdmin: boolean,
 *   otherSignInReadySlugs: string[],
 *   wouldLockOut: boolean,
 * }>}
 */
async function evaluateLoginReachability(pool, { changingSlug, getRuntimeStatus, localAuthEnabled = true, lockLocalAdmin = false }) {
  const usableLocalAdmin = localAuthEnabled
    ? await hasUsableLocalAdmin(pool, { lock: lockLocalAdmin })
    : false;
  const otherSignInReadySlugs = await getSignInReadyProviderSlugs(
    pool,
    changingSlug,
    getRuntimeStatus,
  );
  const hasLocalEscape = localAuthEnabled && usableLocalAdmin;
  const wouldLockOut =
    !hasLocalEscape && otherSignInReadySlugs.length === 0;

  return {
    localAuthEnabled,
    hasUsableLocalAdmin: usableLocalAdmin,
    otherSignInReadySlugs,
    wouldLockOut,
  };
}

/**
 * @param {import('pg').Pool} pool
 * @param {object} opts
 * @param {string} opts.changingSlug
 * @param {(slug: string) => { signInReady?: boolean }} opts.getRuntimeStatus
 * @returns {Promise<{ allowed: boolean, code?: string, reachability: object }>}
 */
async function assertNotLastLoginMethod(pool, opts) {
  const reachability = await evaluateLoginReachability(pool, opts);
  if (reachability.wouldLockOut) {
    return {
      allowed: false,
      code: "last_login_method",
      reachability,
    };
  }
  return { allowed: true, reachability };
}

module.exports = {
  SSO_NO_PASSWORD,
  USABLE_LOCAL_ADMIN_SQL,
  ENABLED_OTHER_PROVIDERS_SQL,
  hasUsableLocalAdmin,
  getSignInReadyProviderSlugs,
  evaluateLoginReachability,
  assertNotLastLoginMethod,
};
