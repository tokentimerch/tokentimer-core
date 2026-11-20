const express = require("express");
const { logger } = require("../utils/logger");
const { getApiLimiter } = require("../middleware/rateLimit");

const router = express.Router();

const ERROR_KINDS = new Set(["render", "chunk-load"]);
const AREAS = new Set([
  "account", "authentication", "certops", "dashboard", "onboarding",
  "other", "settings", "workspaces",
]);

router.post("/api/diagnostics/dashboard", getApiLimiter(), (req, res) => {
  if (!req.isAuthenticated?.()) return res.sendStatus(401);

  const report = req.body;
  if (!req.is("application/json") || !report || Array.isArray(report) ||
      Object.keys(report).length !== 2 ||
      !Object.hasOwn(report, "kind") || !Object.hasOwn(report, "area") ||
      !ERROR_KINDS.has(report.kind) || !AREAS.has(report.area)) {
    return res.sendStatus(400);
  }

  // The correlation middleware provides the ID. The browser sends only
  // categories. Exception text, URLs and stacks may contain credentials.
  logger.warn("Dashboard error boundary reported", {
    kind: report.kind,
    area: report.area,
  });
  return res.sendStatus(204);
});

module.exports = router;
