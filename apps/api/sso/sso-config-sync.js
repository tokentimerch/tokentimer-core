"use strict";

const { getSsoConfigVersion } = require("./sso-config-version.js");
const { listProviderRows } = require("./provider-reload.js");
const {
  getAllProviderRuntimeStatuses,
  getProviderRuntimeStatus,
  setProviderRuntimeStatus,
  providerRuntimeStatuses,
} = require("./sso-runtime-status.js");

/** @type {number|null} */
let observedSsoConfigVersion = null;

/** @type {number|null} */
let localSsoConfigVersion = null;

/** @type {{version: number, promise: Promise<void>}|null} */
let reloadInFlight = null;

function getObservedSsoConfigVersion() {
  return observedSsoConfigVersion;
}

function markLocalSsoConfigVersion(version) {
  localSsoConfigVersion = Number(version) > 0 ? Number(version) : 1;
  observedSsoConfigVersion = localSsoConfigVersion;
}

function getLocalSsoConfigVersion() {
  return localSsoConfigVersion;
}

/**
 * @param {import('pg').Pool} pool
 * @returns {Promise<{
 *   allProvidersApplied: boolean,
 *   staleProviders: string[],
 *   failedProviders: string[],
 *   observedSsoConfigVersion: number|null,
 *   localSsoConfigVersion: number|null,
 * }>}
 */
async function getSsoSyncAggregateFlags(pool, remote = observedSsoConfigVersion) {
  const rows = await listProviderRows(pool);
  const enabledProviders = rows.filter((row) => row.enabled);

  const staleProviders = [];
  const failedProviders = [];

  for (const row of enabledProviders) {
    const st = getProviderRuntimeStatus(row.slug);
    const fullyApplied =
      st.registered === true &&
      st.signInReady === true &&
      (remote == null || st.appliedConfigVersion === remote);

    if (!fullyApplied) {
      staleProviders.push(row.slug);
    }

    if (
      st.registered === false &&
      st.reason &&
      st.reason !== "provider_disabled" &&
      st.reason !== "not_configured"
    ) {
      failedProviders.push(row.slug);
    }
  }

  const allProvidersApplied =
    enabledProviders.length === 0 ||
    enabledProviders.every((row) => {
      const st = getProviderRuntimeStatus(row.slug);
      return (
        st.registered === true &&
        st.signInReady === true &&
        (remote == null || st.appliedConfigVersion === remote)
      );
    });

  return {
    allProvidersApplied,
    staleProviders: [...new Set(staleProviders)],
    failedProviders: [...new Set(failedProviders)],
    observedSsoConfigVersion: remote,
    localSsoConfigVersion,
  };
}

/**
 * Stamp appliedConfigVersion from real runtime setup results (not schema probes).
 * @param {import('pg').Pool} pool
 * @param {number} observedVersion
 * @param {object} [runtimeResults]
 */
async function stampAppliedConfigVersionFromRuntimes(pool, observedVersion, runtimeResults) {
  const rows = await listProviderRows(pool);
  const seen = new Set(rows.map((r) => r.slug));

  for (const slug of [...providerRuntimeStatuses.keys()]) {
    if (!seen.has(slug)) {
      providerRuntimeStatuses.delete(slug);
    }
  }

  for (const [slug, st] of getAllProviderRuntimeStatuses()) {
    const applied =
      st.signInReady === true && st.registered === true && runtimeResults?.[st.type]?.registered !== false
        ? observedVersion
        : null;
    setProviderRuntimeStatus(slug, {
      ...st,
      appliedConfigVersion: applied,
    });
  }
}

async function applySsoConfigVersion(reloadCtx, remoteVersion) {
  const { reloadAllSsoProviders } = require("./reload-strategies.js");
  const runtimeResults = await reloadAllSsoProviders();

  await stampAppliedConfigVersionFromRuntimes(reloadCtx.pool, remoteVersion, runtimeResults);

  const flags = await getSsoSyncAggregateFlags(reloadCtx.pool, remoteVersion);
  const allApplied = flags.allProvidersApplied;
  const runtimeOk =
    (runtimeResults.oidc?.registered !== false ||
      runtimeResults.oidc?.reason === "not_configured") &&
    (runtimeResults.saml?.registered !== false ||
      runtimeResults.saml?.reason === "not_configured");

  if (allApplied && runtimeOk) {
    localSsoConfigVersion = remoteVersion;
    reloadCtx.logger?.info?.("SSO providers reloaded (sso_config_version sync)", {
      ssoConfigVersion: remoteVersion,
      slugs: [...getAllProviderRuntimeStatuses().keys()],
    });
  } else {
    reloadCtx.logger?.warn?.(
      "SSO config version not fully applied; per-provider retry will continue",
      {
        remoteVersion,
        localSsoConfigVersion,
        stale: flags.staleProviders,
        failed: flags.failedProviders,
      },
    );
  }
}

/**
 * @returns {Promise<boolean>}
 */
async function reloadAllSsoStrategiesIfStale() {
  const { __getReloadContextForSync } = require("./reload-strategies.js");
  const reloadCtx = __getReloadContextForSync?.();
  if (!reloadCtx?.pool) return false;

  const version = await getSsoConfigVersion(reloadCtx.pool);
  // Concurrent SELECTs can finish out of order. Never reload an older generation.
  observedSsoConfigVersion = Math.max(observedSsoConfigVersion ?? 0, version);
  if (!reloadInFlight && localSsoConfigVersion === observedSsoConfigVersion) {
    const flags = await getSsoSyncAggregateFlags(reloadCtx.pool);
    if (!reloadInFlight && flags.allProvidersApplied && localSsoConfigVersion === observedSsoConfigVersion) {
      return false;
    }
  }

  // Wait for an older reload once, then start or join the newest observed generation.
  if (reloadInFlight && reloadInFlight.version < observedSsoConfigVersion) {
    await reloadInFlight.promise;
  }
  if (!reloadInFlight) {
    const target = observedSsoConfigVersion;
    reloadInFlight = {
      version: target,
      promise: applySsoConfigVersion(reloadCtx, target).finally(() => { reloadInFlight = null; }),
    };
  }
  await reloadInFlight.promise;
  return true;
}

function assertSsoConfigCurrentForProvider(slug) {
  if (observedSsoConfigVersion == null) return;
  const status = getProviderRuntimeStatus(slug);
  const current = status.registered
    ? status.appliedConfigVersion === observedSsoConfigVersion
    : localSsoConfigVersion === observedSsoConfigVersion;
  if (reloadInFlight || !current) throw new Error("SSO configuration is not current");
}

function ssoConfigSyncMiddleware() {
  return async (req, res, next) => {
    try {
      await reloadAllSsoStrategiesIfStale();
      assertSsoConfigCurrentForProvider(req.params?.[0]?.toLowerCase());
    } catch (err) {
      const ctx = require("./reload-strategies.js").__getReloadContextForSync?.();
      ctx?.logger?.warn?.("SSO config sync before auth route failed", {
        error: err?.message,
      });
      return res.status(503).json({ error: "SSO is temporarily unavailable", code: "SSO_UNAVAILABLE" });
    }
    return next();
  };
}

function startSsoConfigVersionPoller(opts = {}) {
  const intervalMs = Number(opts.intervalMs) > 0 ? Number(opts.intervalMs) : 45_000;
  const timer = setInterval(() => {
    reloadAllSsoStrategiesIfStale().catch((err) => {
      const ctx = require("./reload-strategies.js").__getReloadContextForSync?.();
      ctx?.logger?.warn?.("SSO config version poll failed", {
        error: err?.message,
      });
    });
  }, intervalMs);
  if (typeof timer.unref === "function") {
    timer.unref();
  }
  return timer;
}

/**
 * Reload passport strategies on this pod after a provider registry mutation.
 * @param {import('pg').Pool} pool
 * @param {string} slug
 * @returns {Promise<Array<{ code: string, message: string }>>}
 */
async function reloadAndCollectProviderWarnings(pool, slug) {
  const { getProviderRuntimeStatus } = require("./sso-runtime-status.js");
  const warnings = [];
  try {
    await reloadAllSsoStrategiesIfStale();
  } catch (err) {
    warnings.push({
      code: "reload_failed",
      message: err?.message || "SSO strategy reload failed on this API pod",
    });
    return warnings;
  }

  let enabled = false;
  try {
    const res = await pool.query(
      "SELECT enabled FROM sso_providers WHERE slug = $1 LIMIT 1",
      [slug],
    );
    enabled = res.rows[0]?.enabled === true;
  } catch (err) {
    if (err.code !== "42P01") throw err;
  }

  if (!enabled) return warnings;

  const st = getProviderRuntimeStatus(slug);
  if (st.signInReady === true || st.registered === true) {
    return warnings;
  }

  warnings.push({
    code: st.reason || "not_registered",
    message: `Provider enabled but sign-in is not ready on this API pod (${st.reason || "not_registered"})`,
  });
  return warnings;
}

module.exports = {
  markLocalSsoConfigVersion,
  getLocalSsoConfigVersion,
  getObservedSsoConfigVersion,
  getSsoSyncAggregateFlags,
  stampAppliedConfigVersionFromRuntimes,
  reloadAllSsoStrategiesIfStale,
  reloadAndCollectProviderWarnings,
  assertSsoConfigCurrentForProvider,
  ssoConfigSyncMiddleware,
  startSsoConfigVersionPoller,
  getProviderRuntimeStatus,
};
