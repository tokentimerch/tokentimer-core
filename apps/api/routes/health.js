const client = require("prom-client");
const { csrfRejections } = require("../utils/metrics");
const { logger } = require("../utils/logger");
const { pool } = require("../db/database");
const {
  isContactGroupPluralWritesEnabled,
} = require("../src/shared/contactGroupPluralWrites");

const router = require("express").Router();

router.get("/", (req, res) => res.send("API running"));

router.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      status: "healthy",
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV,
    });
  } catch (err) {
    logger.error("Health check failed", { error: err.message });
    res.status(503).json({
      status: "unhealthy",
      timestamp: new Date().toISOString(),
      error: err.message,
    });
  }
});

const { getSsoAuthFeatures } = require("../sso/core-sso.js");

router.get("/api/auth/features", async (_req, res) => {
  let ssoFeatures = { providers: { oidc: [], saml: [] }, sso: { ssoConfigVersion: null } };
  try {
    ssoFeatures = await getSsoAuthFeatures(pool);
  } catch (err) {
    logger.warn("Auth features: SSO config read failed", { error: err.message });
  }
  res.set("Cache-Control", "no-store");
  res.json({
    ...ssoFeatures,
    oidc: ssoFeatures.providers.oidc.some((provider) => provider.signInReady),
    saml: ssoFeatures.providers.saml.some((provider) => provider.signInReady),
    manualInvitesDisabled: process.env.DISABLE_MANUAL_INVITES === "true",
    contactGroupPluralWrites: isContactGroupPluralWritesEnabled(),
  });
});

// CSRF rejection counter
router.use((err, _req, _res, next) => {
  if (
    err &&
    (err.code === "EBADCSRFTOKEN" || err.message === "invalid csrf token")
  ) {
    try {
      csrfRejections.inc();
    } catch (_) {
      /* best-effort metrics only */
    }
  }
  next(err);
});
// Prometheus /metrics endpoint
router.get("/metrics", async (req, res) => {
  try {
    res.set("Content-Type", client.register.contentType);
    res.send(await client.register.metrics());
  } catch (_err) {
    logger.error("Metrics endpoint failed", { error: _err.message });
    res.status(500).send("metrics error");
  }
});

module.exports = router;
