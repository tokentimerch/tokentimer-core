const { logger } = require("../utils/logger");
const { requireAuth } = require("../middleware/auth");
const { getApiLimiter } = require("../middleware/rateLimit");
const {
  loadWorkspace,
  requireWorkspaceMembership,
} = require("../services/rbac");
const { fetchControlCenterStats } = require("../services/controlCenterStats");

const router = require("express").Router();

router.get(
  "/api/v1/workspaces/:id/control-center/stats",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  async (req, res) => {
    try {
      const role = req.authz?.workspaceRole;
      if (!role || !["admin", "workspace_manager"].includes(role)) {
        return res.status(403).json({ error: "Forbidden" });
      }

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

module.exports = router;
