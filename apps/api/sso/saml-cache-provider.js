"use strict";

/**
 * Postgres-backed node-saml cacheProvider scoped by provider_slug (InResponseTo).
 * Requires table `saml_request_cache (provider_slug, cache_key)`.
 */

/** Default 1h — accommodates slow IdP MFA; override with SAML_CACHE_TTL_SEC. */
const DEFAULT_TTL_SEC = 3600;
const { createHash } = require("node:crypto");

const CLEANUP_LOCK_KEY = 867530901;

/** @type {ReturnType<typeof setInterval>|null} */
let cleanupTimer = null;

/**
 * @param {import('pg').Pool} pool
 * @param {{ providerSlug: string, ttlSec?: number, logger?: object }} opts
 */
function createPostgresSamlCacheProvider(pool, opts = {}) {
  if (!pool) {
    throw new Error("createPostgresSamlCacheProvider: pool is required");
  }
  const providerSlug = String(opts.providerSlug || "").trim();
  if (!providerSlug) {
    throw new Error("createPostgresSamlCacheProvider: providerSlug is required");
  }
  const envTtl = Number(process.env.SAML_CACHE_TTL_SEC);
  const ttlSec =
    Number(opts.ttlSec) > 0
      ? Number(opts.ttlSec)
      : Number.isFinite(envTtl) && envTtl > 0
        ? Math.trunc(envTtl)
        : DEFAULT_TTL_SEC;
  const logger = opts.logger || null;

  async function pruneExpired() {
    try {
      await pool.query(
        `DELETE FROM saml_request_cache
          WHERE provider_slug = $1
            AND created_at < NOW() - ($2::text || ' seconds')::interval`,
        [providerSlug, String(ttlSec)],
      );
    } catch (err) {
      logger?.warn?.("SAML cache prune failed", {
        providerSlug,
        error: err?.message,
      });
    }
  }

  return {
    providerSlug,
    ttlMs: ttlSec * 1000,
    saveAsync: async (key, value) => {
      await pruneExpired();
      await pool.query(
        `INSERT INTO saml_request_cache (provider_slug, cache_key, cache_value, created_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (provider_slug, cache_key)
         DO UPDATE SET cache_value = EXCLUDED.cache_value, created_at = NOW()`,
        [providerSlug, key, value],
      );
      return { value, createdAt: Date.now() };
    },
    getAsync: async (key) => {
      const res = await pool.query(
        `SELECT cache_value FROM saml_request_cache
          WHERE provider_slug = $1
            AND cache_key = $2
            AND created_at >= NOW() - ($3::text || ' seconds')::interval`,
        [providerSlug, key, String(ttlSec)],
      );
      return res.rows[0]?.cache_value ?? null;
    },
    consumeAsync: async (key) => {
      if (key == null) return null;
      const res = await pool.query(
        `DELETE FROM saml_request_cache
          WHERE provider_slug = $1 AND cache_key = $2
            AND created_at >= NOW() - ($3::text || ' seconds')::interval
          RETURNING cache_value`,
        [providerSlug, key, String(ttlSec)],
      );
      return res.rows[0]?.cache_value ?? null;
    },
    removeAsync: async (key) => {
      if (key == null) return null;
      const res = await pool.query(
        `DELETE FROM saml_request_cache
          WHERE provider_slug = $1 AND cache_key = $2
          RETURNING cache_value`,
        [providerSlug, key],
      );
      return res.rows[0]?.cache_value ?? null;
    },
  };
}

// Keep request IDs private to the initiating browser across replicas. Store only the digest
// of its cookie, so database rows cannot be used as browser credentials.
function bindSamlCacheToBrowser(cache, browserId) {
  const prefix = createHash("sha256").update(browserId).digest("hex");
  const scoped = (key) => `${prefix}:${key}`;
  return {
    saveAsync: (key, value) => cache.saveAsync(scoped(key), value),
    getAsync: (key) => cache.getAsync(scoped(key)),
    consumeAsync: (key) => cache.consumeAsync(scoped(key)),
    removeAsync: (key) => key == null ? Promise.resolve(null) : cache.removeAsync(scoped(key)),
  };
}

/**
 * Opportunistic global sweep; only one pod holds the advisory lock at a time.
 * @param {import('pg').Pool} pool
 * @param {{ intervalMs?: number, logger?: object }} [opts]
 */
function startSamlCacheCleanupTimer(pool, opts = {}) {
  if (cleanupTimer || !pool) return cleanupTimer;
  const intervalMs =
    Number(process.env.SAML_CACHE_CLEANUP_INTERVAL_MS) > 0
      ? Number(process.env.SAML_CACHE_CLEANUP_INTERVAL_MS)
      : Number(opts.intervalMs) > 0
        ? Number(opts.intervalMs)
        : 10 * 60 * 1000;
  const logger = opts.logger || null;
  const envTtl = Number(process.env.SAML_CACHE_TTL_SEC);
  const ttlSec =
    Number.isFinite(envTtl) && envTtl > 0 ? Math.trunc(envTtl) : DEFAULT_TTL_SEC;

  cleanupTimer = setInterval(async () => {
    try {
      // Keep the lock and delete in the same implicit transaction on one pooled connection.
      await pool.query(
        `WITH cleanup_lock AS MATERIALIZED (
           SELECT pg_try_advisory_xact_lock($1) AS acquired
         )
         DELETE FROM saml_request_cache
          WHERE (SELECT acquired FROM cleanup_lock)
            AND created_at < NOW() - ($2::text || ' seconds')::interval`,
        [CLEANUP_LOCK_KEY, String(ttlSec)],
      );
    } catch (err) {
      logger?.warn?.("SAML cache cleanup sweep failed", { error: err?.message });
    }
  }, intervalMs);
  if (typeof cleanupTimer.unref === "function") {
    cleanupTimer.unref();
  }
  return cleanupTimer;
}

function _stopSamlCacheCleanupTimerForTests() {
  if (cleanupTimer) {
    clearInterval(cleanupTimer);
    cleanupTimer = null;
  }
}

module.exports = {
  createPostgresSamlCacheProvider,
  bindSamlCacheToBrowser,
  startSamlCacheCleanupTimer,
  DEFAULT_TTL_SEC,
  _stopSamlCacheCleanupTimerForTests,
};
