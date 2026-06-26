"use strict";

const {
  CERTOPS_DISABLED,
  isCertOpsEnabled,
} = require("../services/certops/settings");
const { logger } = require("../utils/logger");

const NOT_FOUND_RESPONSE = Object.freeze({
  error: "Endpoint not found",
  code: "NOT_FOUND",
});

function createRequireCertOpsEnabled({ flagResolver = isCertOpsEnabled } = {}) {
  return async function requireCertOpsEnabled(req, res, next) {
    try {
      if (await flagResolver()) return next();
      return res.status(404).json(NOT_FOUND_RESPONSE);
    } catch (err) {
      logger.error("CertOps rollout flag check failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        path: req.route?.path || req.path,
      });
      return res.status(500).json({
        error: "Failed to check CertOps availability",
        code: CERTOPS_DISABLED,
      });
    }
  };
}

const requireCertOpsEnabled = createRequireCertOpsEnabled();

module.exports = {
  CERTOPS_DISABLED,
  NOT_FOUND_RESPONSE,
  createRequireCertOpsEnabled,
  requireCertOpsEnabled,
};
