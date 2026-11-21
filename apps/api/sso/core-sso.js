"use strict";

const { setupOidcStrategy, oidcRoutes } = require("../auth/oidc.js");
const { setupSamlStrategy, samlRoutes } = require("../auth/saml.js");
const { canonicalizeEmail } = require("../db/models/User.js");
const systemSettings = require("../services/systemSettings.js");
const { ensureInitialWorkspaceForUser } = require("../services/workspace.js");
const { writeAudit } = require("../services/audit.js");
const { logger } = require("../utils/logger.js");
const { createSsoRateLimitMiddleware } = require("./sso-rate-limit.js");
const { configureSsoStrategyReload } = require("./reload-strategies.js");
const {
  getSsoSyncAggregateFlags,
  reloadAllSsoStrategiesIfStale,
  assertSsoConfigCurrentForProvider,
  startSsoConfigVersionPoller,
} = require("./sso-config-sync.js");
const { saveVersionedSsoSettings } = require("./sso-config-version.js");
const { resolveConfigSyncIntervalMs } = require("./sso-global-settings.js");
const { verifySsoHaSchema, warnIfEnvOnlySsoConfigured } = require("./sso-ha-preflight.js");
const { getProviderRuntimeStatus } = require("./sso-runtime-status.js");
const { absoluteAuthRouteUrl } = require("./login-redirect.js");
const {
  SSO_GLOBAL_ENV_MAP,
  SSO_GLOBAL_SETTINGS_COLUMN,
  SSO_GLOBAL_SETTINGS_RESPONSE_KEY,
} = require("./sso-global-settings-schema.js");

const providerRoute = /^\/auth\/(oidc|saml)\/([a-z0-9][a-z0-9_-]{0,62})(?:\/(callback|metadata))?\/?$/i;
const startLimiter = createSsoRateLimitMiddleware({ phase: "start" });
const callbackLimiter = createSsoRateLimitMiddleware({ phase: "callback" });

async function loadProviders(db, options) {
  const { conflictingProviderTypes, listProviders } = require("./provider-registry.js");
  const providers = await listProviders(db, options);
  const conflicts = conflictingProviderTypes(providers);
  return providers.map((provider) => provider.enabled && conflicts.has(provider.type)
    ? { ...provider, enabled: false, disabledReason: "provider_selection_required" }
    : provider);
}

function registerSsoSystemSettings() {
  systemSettings.registerJsonColumn(SSO_GLOBAL_SETTINGS_COLUMN, {
    envMap: SSO_GLOBAL_ENV_MAP,
    responseKey: SSO_GLOBAL_SETTINGS_RESPONSE_KEY,
  });
  const saveJsonColumn = systemSettings.saveJsonColumn.bind(systemSettings);
  systemSettings.saveJsonColumn = async (...args) => {
    if (args[1] !== SSO_GLOBAL_SETTINGS_COLUMN) return saveJsonColumn(...args);
    const result = await saveVersionedSsoSettings(saveJsonColumn, ...args);
    await reloadAllSsoStrategiesIfStale();
    return result;
  };
}

async function startSso({ passport, pool }) {
  const { reconcileSsoProvidersFromEnv } = require("./bootstrap-from-env.js");
  const preflight = await verifySsoHaSchema(pool, logger);
  if (!preflight.ok) throw new Error("SSO database preflight failed");

  const boot = await reconcileSsoProvidersFromEnv(pool, { logger });
  if (boot?.ok) logger.info("SSO bootstrap reconciled providers", { count: boot.count });
  warnIfEnvOnlySsoConfigured(logger);

  registerSsoSystemSettings();
  configureSsoStrategyReload({
    passport,
    pool,
    systemSettings,
    SamlStrategy: require("@node-saml/passport-saml"),
    setupOidcStrategy,
    setupSamlStrategy,
    deps: { canonicalizeEmail, ensureInitialWorkspaceForUser, writeAudit, logger, loadProviders },
    logger,
  });
  await reloadAllSsoStrategiesIfStale();
  startSsoConfigVersionPoller({ intervalMs: resolveConfigSyncIntervalMs() });
}

function mountSsoRoutes(app, { passport, express, pool }) {
  function notFound(res) {
    return res.status(404).json({ error: "Endpoint not found", code: "NOT_FOUND" });
  }

  app.use((req, res, next) => {
    const match = providerRoute.exec(req.path);
    if (!match) {
      return /^\/auth\/(?:oidc|saml)(?:\/|$)/i.test(req.path) ? notFound(res) : next();
    }
    const [, protocol, slug, endpoint] = match.map((part) => part?.toLowerCase());

    const limiter = endpoint === "callback" ? callbackLimiter : startLimiter;
    return limiter(req, res, async () => {
      try {
        await reloadAllSsoStrategiesIfStale();
        const { rows } = await pool.query(
          "SELECT slug FROM sso_providers WHERE enabled = TRUE AND type = $1 LIMIT 2",
          [protocol],
        );
        if (rows.length !== 1 || rows[0].slug !== slug) return notFound(res);
        assertSsoConfigCurrentForProvider(slug);
        return next();
      } catch (err) {
        logger.warn("SSO runtime configuration lookup failed", { error: err?.message });
        return res.status(503).json({ error: "SSO is temporarily unavailable", code: "SSO_UNAVAILABLE" });
      }
    });
  });
  app.use(oidcRoutes(passport, express));
  app.use(samlRoutes(passport, express));
}

async function getSsoAuthFeatures(pool) {
  const [rows, haFlags] = await Promise.all([
    loadProviders(pool, { includeStatuses: false }),
    getSsoSyncAggregateFlags(pool),
  ]);
  const providers = { oidc: [], saml: [] };
  for (const active of rows.filter((row) => row.enabled)) {
    const runtime = getProviderRuntimeStatus(active.slug);
    providers[active.type].push({
      slug: active.slug,
      type: active.type,
      displayName: active.displayName,
      sortOrder: active.sortOrder ?? 100,
      signInReady: runtime.signInReady === true,
      lastReason: runtime.reason || null,
      computed: active.computed,
      loginUrl: absoluteAuthRouteUrl(`/auth/${active.type}/${encodeURIComponent(active.slug)}`),
    });
  }
  return { providers, sso: { ssoConfigVersion: haFlags } };
}

module.exports = { getSsoAuthFeatures, mountSsoRoutes, startSso };
