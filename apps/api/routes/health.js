const client = require("prom-client");
const { csrfRejections } = require("../utils/metrics");
const { logger } = require("../utils/logger");
const { pool } = require("../db/database");

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

// Auth features availability endpoint (for frontend conditional UI)
// Core only supports local email/password
router.get("/api/auth/features", (req, res) => {
  res.json({ saml: false, oidc: false });
});

// CSRF rejection counter
router.use((err, _req, res, next) => {
  if (
    err &&
    (err.code === "EBADCSRFTOKEN" || err.message === "invalid csrf token")
  ) {
    try {
      csrfRejections.inc();
    } catch (_) {
      /* eslint-disable-line no-empty */
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
