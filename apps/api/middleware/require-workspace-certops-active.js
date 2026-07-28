"use strict";

const {
  CERTOPS_WORKSPACE_PAUSED,
  getWorkspaceCertOpsPauseState,
} = require("../services/certops/workspaceKillSwitch");
const { logger } = require("../utils/logger");

const PAUSED_RESPONSE = Object.freeze({
  error: "CertOps is paused for this workspace",
  code: CERTOPS_WORKSPACE_PAUSED,
});

function createRequireWorkspaceCertOpsActive({
  pauseStateResolver = getWorkspaceCertOpsPauseState,
} = {}) {
  return async function requireWorkspaceCertOpsActive(req, res, next) {
    const workspaceId = req.workspace?.id;
    if (!workspaceId) {
      return res.status(503).json({
        error: "CertOps workspace state is unavailable",
        code: "CERTOPS_WORKSPACE_STATE_UNAVAILABLE",
      });
    }

    try {
      const state = await pauseStateResolver({ workspaceId });
      req.certOpsWorkspaceState = state;
      if (state.certOpsPaused) {
        return res.status(409).json(PAUSED_RESPONSE);
      }
      return next();
    } catch (err) {
      logger.error("CertOps workspace pause check failed", {
        error: err.message,
        code: err.code || null,
        workspaceId,
        path: req.route?.path || req.path,
      });
      return res.status(503).json({
        error: "CertOps workspace state is unavailable",
        code: "CERTOPS_WORKSPACE_STATE_UNAVAILABLE",
      });
    }
  };
}

const requireWorkspaceCertOpsActive = createRequireWorkspaceCertOpsActive();

module.exports = {
  CERTOPS_WORKSPACE_PAUSED,
  PAUSED_RESPONSE,
  createRequireWorkspaceCertOpsActive,
  requireWorkspaceCertOpsActive,
};
