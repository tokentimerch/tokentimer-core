"use strict";

const router = require("express").Router();
const { pool } = require("../db/database");
const { logger } = require("../utils/logger");
const { writeAudit } = require("../services/audit");
const { requireAuth } = require("../middleware/auth");
const { getApiLimiter } = require("../middleware/rateLimit");
const {
  listProviders,
  getProvider,
  createProvider,
  updateProvider,
  deleteProvider,
} = require("../sso/provider-registry.js");
const { previewProviderChangeImpact } = require("../sso/change-impact.js");
const { runOidcDiagnostics } = require("../sso/oidc-diagnostics.js");
const { runProviderTest } = require("../sso/provider-test.js");
const { fetchIdpMetadataXml, formatFetchReason } = require("../sso/fetch-idp-metadata.js");
const { validateOutboundUrl } = require("../sso/safe-fetch.js");
const { buildSsoDiagnosticBundle } = require("../sso/diagnostic-bundle.js");
const {
  reloadAndCollectProviderWarnings,
} = require("../sso/sso-config-sync.js");

async function withProviderTransaction(operation) {
  const client = await pool.connect();
  let discard = false;
  try {
    await client.query("BEGIN");
    const result = await operation(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {
      discard = true;
    }
    throw err;
  } finally {
    client.release(discard);
  }
}

function auditProvider(client, actorUserId, slug, action, metadata = {}) {
  return writeAudit({
    client, actorUserId, subjectUserId: null, action,
    targetType: "sso_provider", metadata: { slug, ...metadata },
  });
}

async function auditSecretChanges(client, userId, slug, { set, cleared }) {
  for (const name of set) {
    await auditProvider(client, userId, slug, "SSO_PROVIDER_SECRET_SET", { secret_name: name, provider_slug: slug });
  }
  for (const name of cleared) {
    await auditProvider(client, userId, slug, "SSO_PROVIDER_SECRET_CLEARED", { secret_name: name, provider_slug: slug });
  }
}

async function providerChangeResponse(slug, provider) {
  const result = provider || { ok: true };
  try {
    const warnings = await reloadAndCollectProviderWarnings(pool, slug);
    if (!warnings.some((warning) => warning.code === "reload_failed")) {
      const current = provider && await getProvider(pool, slug);
      if (!provider || current) {
        return {
          ...result,
          ...(current && { runtime: current.runtime }),
          ...(warnings.length ? { sso_reload_warnings: warnings } : {}),
        };
      }
    }
  } catch {
    // The change and its audit already committed. Runtime status can be retried.
  }
  return {
    ...result,
    ...(provider && {
      runtime: {
        signInReady: false, lastReason: "reload_failed", lastReloadAt: null, appliedConfigVersion: null,
      },
    }),
    sso_reload_warnings: [{
      code: "reload_failed",
      message: "The provider change was saved. Runtime status could not be confirmed on this API instance.",
    }],
  };
}

async function requireSsoAdmin(req, res, next) {
  if (!req.user?.id) {
    return res.status(401).json({ error: "Unauthorized", code: "UNAUTHORIZED" });
  }
  const { rows } = await pool.query(
    "SELECT is_admin FROM users WHERE id = $1 LIMIT 1",
    [req.user.id],
  );
  if (rows.length === 0 || rows[0].is_admin !== true) {
    return res.status(403).json({ error: "Admin only", code: "FORBIDDEN" });
  }
  return next();
}

function mapRegistryError(err, res) {
  const code = err.code || "internal_error";
  if (code === "not_found") return res.status(404).json({ error: err.message, code });
  if (["slug_immutable", "type_immutable", "invalid_retirement_policy"].includes(code)) {
    return res.status(400).json({ error: err.message, code });
  }
  if (code === "redundant_override" || code === "invalid_slug" || code === "invalid_type" || code === "invalid_config") {
    return res.status(400).json({ error: err.message, code });
  }
  if ((code === "23505" && err.table === "sso_providers") || ["active_provider_exists", "provider_selection_required"].includes(code)) {
    return res.status(409).json({ error: code === "23505" ? "A provider already uses this identifier." : err.message, code });
  }
  if (code === "issuer_has_linked_accounts") return res.status(409).json({ error: err.message, code });
  if (code === "field_locked") {
    return res.status(409).json({ error: err.message, code, field: err.field });
  }
  if (code === "provider_in_use" || code === "last_login_method") {
    return res.status(409).json({
      error:
        err.message,
      code,
      dependencies: err.dependencies,
      reachability: err.reachability,
    });
  }
  return null;
}

router.get(
  "/api/admin/sso/providers",
  requireAuth,
  requireSsoAdmin,
  getApiLimiter(),
  async (req, res) => {
    try {
      const providers = await listProviders(pool);
      res.json({ providers });
    } catch (err) {
      logger.error("GET /api/admin/sso/providers failed", { error: err.message });
      res.status(500).json({ error: "SSO request failed." });
    }
  },
);

router.post(
  "/api/admin/sso/providers",
  requireAuth,
  requireSsoAdmin,
  getApiLimiter(),
  async (req, res) => {
    try {
      const provider = await withProviderTransaction(async (client) => {
        const secretChanges = { set: [], cleared: [] };
        const created = await createProvider(pool, req.body || {}, { userId: req.user.id }, {
          dbClient: client, secretChanges,
        });
        await auditProvider(client, req.user.id, created.slug, "SSO_PROVIDER_CREATED", { type: created.type });
        await auditSecretChanges(client, req.user.id, created.slug, secretChanges);
        return created;
      });
      res.status(201).json(await providerChangeResponse(provider.slug, provider));
    } catch (err) {
      const mapped = mapRegistryError(err, res);
      if (mapped) return mapped;
      logger.error("Could not create SSO provider. Check storage, keyring and provider configuration.");
      res.status(500).json({ error: "SSO request failed." });
    }
  },
);

router.get(
  "/api/admin/sso/providers/:slug",
  requireAuth,
  requireSsoAdmin,
  getApiLimiter(),
  async (req, res) => {
    try {
      const provider = await getProvider(pool, req.params.slug);
      if (!provider) return res.status(404).json({ error: "Not found", code: "not_found" });
      res.json(provider);
    } catch (err) {
      logger.error("GET /api/admin/sso/providers/:slug failed", { error: err.message });
      res.status(500).json({ error: "SSO request failed." });
    }
  },
);

router.put(
  "/api/admin/sso/providers/:slug",
  requireAuth,
  requireSsoAdmin,
  getApiLimiter(),
  async (req, res) => {
    const slug = req.params.slug;
    try {
      req.body ||= {};
      if (req.body.slug && req.body.slug !== slug) {
        return res.status(400).json({ error: "slug_immutable", code: "slug_immutable" });
      }
      const provider = await withProviderTransaction(async (client) => {
        const secretChanges = { set: [], cleared: [] };
        const updated = await updateProvider(pool, slug, req.body, { userId: req.user.id }, {
          dbClient: client, secretChanges,
        });
        const action = req.body.enabled === false ? "SSO_PROVIDER_DISABLED" : "SSO_PROVIDER_UPDATED";
        await auditProvider(client, req.user.id, slug, action, {
          clearSecrets: secretChanges.cleared,
          ...(req.body.selectForProtocol === true && { selected_for_protocol: updated.type }),
        });
        await auditSecretChanges(client, req.user.id, slug, secretChanges);
        return updated;
      });
      res.json(await providerChangeResponse(slug, provider));
    } catch (err) {
      const mapped = mapRegistryError(err, res);
      if (mapped) return mapped;
      logger.error("Could not update SSO provider. Check storage, keyring and provider configuration.");
      res.status(500).json({ error: "SSO request failed." });
    }
  },
);

router.delete(
  "/api/admin/sso/providers/:slug",
  requireAuth,
  requireSsoAdmin,
  getApiLimiter(),
  async (req, res) => {
    const slug = req.params.slug;
    try {
      await withProviderTransaction(async (client) => {
        const { membershipPolicy, identityPolicy, confirmRetirement } = req.query;
        const result = await deleteProvider(pool, slug, {
          dbClient: client, userId: req.user.id, membershipPolicy, identityPolicy,
          confirmRetirement: confirmRetirement === "true",
        });
        await auditProvider(client, req.user.id, slug, "SSO_PROVIDER_DELETED", {
          dependency_counts: result.dependencies,
          membershipPolicy: membershipPolicy ?? null,
          identityPolicy: identityPolicy ?? null,
        });
      });
      res.json(await providerChangeResponse(slug));
    } catch (err) {
      const mapped = mapRegistryError(err, res);
      if (mapped) return mapped;
      logger.error("Could not delete SSO provider. Check storage and audit configuration.");
      res.status(500).json({ error: "SSO request failed." });
    }
  },
);

router.post(
  "/api/admin/sso/providers/:slug/test",
  requireAuth,
  requireSsoAdmin,
  getApiLimiter(),
  async (req, res) => {
    try {
      const provider = await getProvider(pool, req.params.slug);
      if (!provider) return res.status(404).json({ error: "Not found", code: "not_found" });
      const result = await runProviderTest(pool, provider);
      await auditProvider(null, req.user.id, provider.slug, "SSO_PROVIDER_TESTED", {
        ok: result.ok,
        checks_summary: result.checks.map((c) => `${c.name}:${c.ok}`).join(","),
      });
      res.json(result);
    } catch (err) {
      logger.error("POST /api/admin/sso/providers/:slug/test failed", {
        error: err.message,
      });
      res.status(500).json({ error: "SSO request failed." });
    }
  },
);

router.post(
  "/api/admin/sso/providers/:slug/impact",
  requireAuth,
  requireSsoAdmin,
  getApiLimiter(),
  async (req, res) => {
    try {
      const impact = await previewProviderChangeImpact(
        pool,
        req.params.slug,
        req.body || {},
      );
      res.json(impact);
    } catch (err) {
      if (err.code === "not_found") {
        return res.status(404).json({ error: err.message, code: err.code });
      }
      logger.error("POST /api/admin/sso/providers/:slug/impact failed", {
        error: err.message,
      });
      res.status(500).json({ error: "SSO request failed." });
    }
  },
);

router.post(
  "/api/admin/sso/fetch-idp-metadata",
  requireAuth,
  requireSsoAdmin,
  getApiLimiter(),
  async (req, res) => {
    try {
      const url = String(req.body?.url || "").trim();
      if (!url) {
        return res.status(400).json({ error: "Metadata URL is required", code: "invalid_url" });
      }
      const outbound = await validateOutboundUrl(url);
      if (!outbound.ok) {
        return res.status(400).json({
          error: formatFetchReason(outbound.reason || "invalid_url"),
          code: "invalid_url",
        });
      }
      const xml = await fetchIdpMetadataXml(url);
      await writeAudit({
        actorUserId: req.user.id,
        subjectUserId: null,
        action: "SSO_IDP_METADATA_FETCHED",
        targetType: "sso",
        targetId: null,
        channel: null,
        workspaceId: null,
        metadata: { url_host: outbound.parsed?.hostname || null },
      });
      res.json({ xml });
    } catch (err) {
      logger.error("POST /api/admin/sso/fetch-idp-metadata failed", { error: err.message });
      res.status(502).json({ error: err.message || "Fetch failed", code: "fetch_failed" });
    }
  },
);

router.get(
  "/api/admin/sso/diagnostic-bundle",
  requireAuth,
  requireSsoAdmin,
  getApiLimiter(),
  async (req, res) => {
    try {
      const bundle = await buildSsoDiagnosticBundle(pool);
      await writeAudit({
        actorUserId: req.user.id,
        subjectUserId: null,
        action: "SSO_DIAGNOSTIC_BUNDLE_EXPORTED",
        targetType: "sso",
        targetId: null,
        channel: null,
        workspaceId: null,
        metadata: { providers_count: bundle.providers.length },
      });
      res.json(bundle);
    } catch (err) {
      logger.error("GET /api/admin/sso/diagnostic-bundle failed", {
        error: err.message,
      });
      res.status(500).json({ error: "SSO request failed." });
    }
  },
);

router.get(
  "/api/admin/sso/oidc/diagnostics",
  requireAuth,
  requireSsoAdmin,
  getApiLimiter(),
  async (req, res) => {
    try {
      res.json(await runOidcDiagnostics(pool, { slug: req.query.slug }, { logger }));
    } catch (err) {
      logger.warn("OIDC diagnostics failed", { error: err.message });
      res.status(500).json({ error: "OIDC diagnostics failed." });
    }
  },
);

module.exports = router;
