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
  LIMIT 1`;

const ENABLED_OTHER_PROVIDERS_SQL = `
  SELECT slug, type
  FROM sso_providers
  WHERE enabled = TRUE
    AND slug <> $1
  ORDER BY sort_order, display_name`;

/**
 * @param {import('pg').Pool} pool
 * @returns {Promise<boolean>}
 */
async function hasUsableLocalAdmin(pool) {
  const res = await pool.query(USABLE_LOCAL_ADMIN_SQL, [SSO_NO_PASSWORD]);
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
async function evaluateLoginReachability(pool, { changingSlug, getRuntimeStatus, localAuthEnabled = true }) {
  const usableLocalAdmin = localAuthEnabled
    ? await hasUsableLocalAdmin(pool)
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
