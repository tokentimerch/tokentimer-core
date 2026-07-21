const { logger } = require("../utils/logger");
const { requireAuth } = require("../middleware/auth");
const { getApiLimiter } = require("../middleware/rateLimit");
const {
  loadWorkspace,
  requireWorkspaceMembership,
} = require("../services/rbac");
const {
  fetchControlCenterStats,
  fetchNeverExpiresPage,
  fetchPrivilegeHighlightsPage,
} = require("../services/controlCenterStats");

const router = require("express").Router();

function requireWorkspaceManagerRole(req, res, next) {
  const role = req.authz?.workspaceRole;
  if (!role || !["admin", "workspace_manager"].includes(role)) {
    return res.status(403).json({ error: "Forbidden" });
  }
  next();
}

function parsePageParams(req) {
  return {
    limit: parseInt(req.query.limit, 10),
    offset: parseInt(req.query.offset, 10),
  };
}

router.get(
  "/api/v1/workspaces/:id/control-center/stats",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  requireWorkspaceManagerRole,
  async (req, res) => {
    try {
      const stats = await fetchControlCenterStats(req.workspace.id);
      return res.json(stats);
    } catch (err) {
      logger.error("Control center stats error", {
        error: err.message,
        workspaceId: req.params?.id,
        userId: req.user?.id,
      });
      return res
        .status(500)
        .json({ error: "Failed to fetch control center stats" });
    }
  },
);

router.get(
  "/api/v1/workspaces/:id/control-center/never-expires",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  requireWorkspaceManagerRole,
  async (req, res) => {
    try {
      const page = await fetchNeverExpiresPage(
        req.workspace.id,
        parsePageParams(req),
      );
      return res.json(page);
    } catch (err) {
      logger.error("Control center never-expires page error", {
        error: err.message,
        workspaceId: req.params?.id,
        userId: req.user?.id,
      });
      return res
        .status(500)
        .json({ error: "Failed to fetch perpetual assets" });
    }
  },
);

router.get(
  "/api/v1/workspaces/:id/control-center/privilege-highlights",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  requireWorkspaceManagerRole,
  async (req, res) => {
    try {
      const page = await fetchPrivilegeHighlightsPage(
        req.workspace.id,
        parsePageParams(req),
      );
      return res.json(page);
    } catch (err) {
      logger.error("Control center privilege-highlights page error", {
        error: err.message,
        workspaceId: req.params?.id,
        userId: req.user?.id,
      });
      return res
        .status(500)
        .json({ error: "Failed to fetch scopes and privileges" });
    }
  },
);

module.exports = router;
