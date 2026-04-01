/**
 * tokentimer-core: No paid plans. Access is role-based only
 * (viewer / workspace_manager / admin). plan_context is set for API compatibility
 * but is not used for gating.
 */
const { pool } = require("../db/database");
const { logger } = require("../utils/logger");

// Role hierarchy helper
const roleRank = {
  admin: 3,
  workspace_manager: 2,
  viewer: 1,
};

/**
 * Check if a user role meets or exceeds a minimum required role
 * @param {string} userRole - The user's role
 * @param {string} minimumRole - The minimum required role
 * @returns {boolean} True if userRole meets or exceeds minimumRole
 */
function hasAtLeastRole(userRole, minimumRole) {
  if (!userRole || !minimumRole) return false;
  return (roleRank[userRole] || 0) >= (roleRank[minimumRole] || 0);
}

// Action -> minimum role mapping
const actionPolicy = {
  "workspace.view": "viewer",
  "workspace.create": "viewer",
  "workspace.update": "admin",
  "workspace.delete": "admin",
  "membership.invite": "workspace_manager",
  "membership.change_role": "workspace_manager",
  "membership.remove": "workspace_manager",
  "section.create": "workspace_manager",
  "section.update": "workspace_manager",
  "section.delete": "workspace_manager",
  "audit.list": "viewer",
  "auto_sync.manage": "workspace_manager",
  "domain.manage": "workspace_manager",
};

/**
 * Get the role of a user in a workspace
 * @param {number|string} userId - The user ID
 * @param {number|string} workspaceId - The workspace ID
 * @returns {Promise<string|null>} The user's role in the workspace, or null if not a member
 */
async function getUserWorkspaceRole(userId, workspaceId) {
  const { rows } = await pool.query(
    "SELECT role FROM workspace_memberships WHERE user_id = $1 AND workspace_id = $2",
    [userId, workspaceId],
  );
  return rows[0]?.role || null;
}

/**
 * Check if a user role has permission to perform an action
 * @param {string} userRole - The user's role (admin, workspace_manager, viewer)
 * @param {string} action - The action to check (e.g., "workspace.view", "membership.invite")
 * @returns {boolean} True if the role has permission, false otherwise
 */
function can(userRole, action) {
  const minRole = actionPolicy[action];
  if (!minRole) return false; // deny by default
  return hasAtLeastRole(userRole, minRole);
}

/**
 * Express middleware to load workspace and set authorization context
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @returns {Promise<void>}
 */
async function loadWorkspace(req, res, next) {
  try {
    const workspaceId =
      req.params.id || req.params.workspaceId || req.query.workspace_id;
    if (!workspaceId)
      return res
        .status(400)
        .json({ error: "workspace_id required", code: "WORKSPACE_REQUIRED" });
    const workspaceIdString = String(workspaceId).trim();
    const uuidRegex =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(workspaceIdString))
      return res.status(400).json({
        error: "workspace_id must be a valid UUID",
        code: "INVALID_WORKSPACE_ID",
      });
    const wsRes = await pool.query(
      `SELECT w.id,
              w.name,
              w.plan,
              w.created_by,
              COALESCE(w.is_personal_default, FALSE) AS is_personal_default
       FROM workspaces w
       WHERE w.id = $1`,
      [workspaceIdString],
    );
    if (wsRes.rowCount === 0)
      return res.status(404).json({ error: "Workspace not found" });
    req.workspace = wsRes.rows[0];
    if (req.user && req.user.id) {
      let role = await getUserWorkspaceRole(req.user.id, workspaceIdString);
      // Treat workspace owner as implicit admin even if no membership row exists
      if (
        !role &&
        String(req.workspace.created_by || "") === String(req.user.id)
      ) {
        role = "admin";
      }
      req.authz = { ...(req.authz || {}), workspaceRole: role };
    }
    // Core: no paid plans; always "oss" for rate limiters and compatibility
    req.plan_context = {
      userPlan: "oss",
      workspacePlan: req.workspace?.plan || "oss",
    };
    return next();
  } catch (e) {
    logger.error("loadWorkspace middleware failed", {
      error: e.message,
      workspaceId:
        req.params?.id || req.params?.workspaceId || req.query?.workspace_id,
      userId: req.user?.id,
    });
    return next(e);
  }
}

/**
 * Express middleware that loads a section and its parent workspace,
 * attaches both to `req.section` / `req.workspace`, and resolves the
 * user's workspace role.
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @returns {Promise<void>}
 */
async function loadSection(req, res, next) {
  try {
    const sectionId = req.params.sectionId || req.params.id;
    if (!sectionId)
      return res.status(400).json({ error: "sectionId required" });
    const parsedSectionId = parseInt(String(sectionId), 10);
    if (
      !Number.isFinite(parsedSectionId) ||
      parsedSectionId <= 0 ||
      String(parsedSectionId) !== String(sectionId).trim()
    )
      return res
        .status(400)
        .json({ error: "sectionId must be a valid positive integer" });
    const secRes = await pool.query(
      `SELECT s.id, s.name, s.workspace_id, w.plan, w.created_by
       FROM sections s
       JOIN workspaces w ON w.id = s.workspace_id
       WHERE s.id = $1`,
      [sectionId],
    );
    if (secRes.rowCount === 0)
      return res.status(404).json({ error: "Section not found" });
    const row = secRes.rows[0];
    req.section = {
      id: row.id,
      name: row.name,
      workspace_id: row.workspace_id,
    };
    req.workspace = {
      id: row.workspace_id,
      plan: row.plan,
      created_by: row.created_by,
    };
    if (req.user && req.user.id) {
      const role = await getUserWorkspaceRole(req.user.id, row.workspace_id);
      req.authz = { ...(req.authz || {}), workspaceRole: role };
    }
    return next();
  } catch (e) {
    logger.error("loadSection middleware failed", {
      error: e.message,
      sectionId: req.params?.sectionId || req.params?.id,
      userId: req.user?.id,
    });
    return next(e);
  }
}

/**
 * Express middleware to require user is a workspace member
 * @param {Object} req - Express request object (must have req.authz.workspaceRole or req.workspace.created_by)
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @returns {void}
 */
function requireWorkspaceMembership(req, res, next) {
  let role = req.authz?.workspaceRole;
  // Fallback: treat workspace owner as implicit admin even without a membership row
  if (
    !role &&
    req.workspace &&
    req.user &&
    String(req.workspace.created_by || "") === String(req.user.id || "")
  ) {
    role = "admin";
    req.authz = { ...(req.authz || {}), workspaceRole: role };
  }
  if (!role)
    return res.status(403).json({ error: "Forbidden: not a workspace member" });
  return next();
}

/**
 * Create Express middleware to authorize an action based on user role
 * @param {string} action - The action to authorize (e.g., "workspace.update", "membership.invite")
 * @returns {Function} Express middleware function
 */
function authorize(action) {
  return (req, res, next) => {
    const role = req.authz?.workspaceRole;
    if (!role || !can(role, action)) {
      return res.status(403).json({ error: "Forbidden: insufficient role" });
    }
    // Note: tokentimer-core does not enforce plan restrictions
    // Plan gating is handled by variant overlays
    return next();
  };
}

/**
 * Express middleware to require paid plan (no-op in core, all features available)
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @returns {void}
 */
function requirePaidPlan(req, res, next) {
  return next();
}

/**
 * Middleware to check and enforce integration scan quota per workspace.
 * Note: tokentimer-core does not enforce integration quotas
 * Integration endpoints return stubs - quota enforcement is handled by variant overlays
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @returns {void}
 */
function requireIntegrationQuota(req, res, next) {
  // Pass through - integrations are stubbed out in core
  return next();
}

/**
 * Middleware to get integration quota info without incrementing.
 * Note: tokentimer-core does not track integration quotas
 * Returns empty quota - no limits in core
 * @param {Object} req - Express request object (sets req.integrationQuota)
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @returns {void}
 */
function getIntegrationQuotaInfo(req, res, next) {
  req.integrationQuota = { used: 0, limit: null, remaining: null };
  return next();
}

/**
 * Middleware to require user is not a viewer (for integration endpoints)
 * Checks workspace role if workspace_id is provided, otherwise checks if user has admin/manager role in any workspace
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @returns {Promise<void>}
 */
async function requireNotViewer(req, res, next) {
  try {
    // Get workspace_id from query if present (for integration endpoints)
    const workspaceId = req.query?.workspace_id || req.body?.workspace_id;

    // If workspace specified, check role in that workspace
    if (workspaceId) {
      let role = await getUserWorkspaceRole(req.user.id, workspaceId);

      // If no role found, check if user is workspace owner (implicit admin)
      if (!role) {
        const { rows } = await pool.query(
          "SELECT created_by FROM workspaces WHERE id = $1",
          [workspaceId],
        );

        if (rows.length === 0) {
          return res.status(404).json({
            error: "Workspace not found",
            code: "WORKSPACE_NOT_FOUND",
          });
        }

        // If user is the workspace owner, treat as implicit admin
        if (String(rows[0].created_by) === String(req.user.id)) {
          role = "admin";
        } else {
          // User has no role in this workspace and is not the owner
          return res.status(403).json({
            error: "You do not have access to this workspace",
            code: "NO_WORKSPACE_ACCESS",
          });
        }
      }

      // Now check if the role is viewer
      if (String(role).toLowerCase() === "viewer") {
        return res.status(403).json({
          error: "Viewers cannot use integrations",
          code: "VIEWER_NOT_ALLOWED",
        });
      }

      return next();
    }

    // If no workspace specified, check if user is ONLY a viewer across all workspaces
    // Users who are admin/manager in at least one workspace can use integrations
    const { rows } = await pool.query(
      `SELECT role FROM workspace_memberships 
       WHERE user_id = $1 AND role IN ('admin', 'workspace_manager')
       LIMIT 1`,
      [req.user.id],
    );

    // If user has admin or workspace_manager role in at least one workspace, allow
    if (rows.length > 0) {
      return next();
    }

    // Check if user owns any workspace (implicit admin)
    const { rows: ownedWorkspaces } = await pool.query(
      `SELECT id FROM workspaces WHERE created_by = $1 LIMIT 1`,
      [req.user.id],
    );

    if (ownedWorkspaces.length > 0) {
      return next();
    }

    // User is only a viewer (or not a member of any workspace) - deny access
    return res.status(403).json({
      error:
        "Viewers cannot use integrations. You need admin or manager access in at least one workspace.",
      code: "VIEWER_NOT_ALLOWED",
    });
  } catch (e) {
    logger.error("requireNotViewer middleware failed", {
      error: e.message,
      userId: req.user?.id,
      workspaceId: req.query?.workspace_id || req.body?.workspace_id,
    });
    return next(e);
  }
}

module.exports = {
  can,
  loadWorkspace,
  loadSection,
  requireWorkspaceMembership,
  authorize,
  getUserWorkspaceRole,
  hasAtLeastRole,
  requirePaidPlan,
  requireIntegrationQuota,
  getIntegrationQuotaInfo,
  requireNotViewer,
};
