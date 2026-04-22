const { pool } = require("../db/database");
const { logger } = require("../utils/logger");
const { writeAudit } = require("../services/audit");
const { requireAuth } = require("../middleware/auth");
const { getApiLimiter } = require("../middleware/rateLimit");
const {
  loadWorkspace,
  requireWorkspaceMembership,
  authorize,
  getUserWorkspaceRole,
} = require("../services/rbac");
const { MEMBER_LIMITS } = require("../services/planLimits");
const {
  sendEmail,
  generateEmailTemplate,
} = require("../services/emailService");
const { sanitizeForLogging } = require("../utils/sanitize");
const {
  workspacesCreatedTotal,
  inviteSentTotal,
  inviteCancelledTotal,
} = require("../utils/metrics");

const router = require("express").Router();

// --- WORKSPACES & SECTIONS API ---
// All routes require authentication
router.post(
  "/api/v1/workspaces",
  getApiLimiter(),
  requireAuth,
  async (req, res) => {
    try {
      const userId = req.user.id;
      const name = String(req.body?.name || "").trim();
      if (!name)
        return res
          .status(400)
          .json({ error: "Name is required", code: "VALIDATION_ERROR" });

      // Core: no plan limits; new workspaces use plan "oss"
      const plan = "oss";
      const id = require("crypto").randomUUID();
      await pool.query(
        "INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1,$2,$3,$4)",
        [id, name, plan, userId],
      );
      // Best-effort: explicitly set non-personal flag if column exists
      try {
        await pool.query(
          "UPDATE workspaces SET is_personal_default = FALSE WHERE id = $1",
          [id],
        );
      } catch (_err) {
        logger.warn("DB operation failed", { error: _err.message });
      }
      // Creator becomes admin member
      await pool.query(
        "INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by) VALUES ($1,$2,'admin',$1) ON CONFLICT DO NOTHING",
        [userId, id],
      );
      // Seed workspace_settings with default email = creator's email and enable email alerts
      try {
        await pool.query(
          `INSERT INTO workspace_settings (workspace_id, email_alerts_enabled)
           VALUES ($1, TRUE)
           ON CONFLICT (workspace_id) DO UPDATE
           SET email_alerts_enabled = TRUE`,
          [id],
        );
      } catch (_err) {
        logger.warn("DB operation failed", { error: _err.message });
      }
      // Seed creator's contact in this workspace if not already present (email-only)
      try {
        const emailLower = String(req.user?.email || "")
          .trim()
          .toLowerCase();
        const displayName = String(req.user?.display_name || "").trim();
        if (emailLower) {
          const exists = await pool.query(
            `SELECT id FROM workspace_contacts WHERE workspace_id = $1 AND LOWER(details->>'email') = $2 LIMIT 1`,
            [id, emailLower],
          );
          let contactId = exists.rows?.[0]?.id || null;
          if (!contactId) {
            const parts = displayName.split(/\s+/).filter(Boolean);
            const firstName = parts[0] || "Owner";
            const lastName = parts.slice(1).join(" ");
            const ins = await pool.query(
              `INSERT INTO workspace_contacts (workspace_id, first_name, last_name, phone_e164, details, created_by)
               VALUES ($1,$2,$3,NULL,$4,$5) RETURNING id`,
              [
                id,
                String(firstName).trim(),
                String(lastName || "").trim(),
                JSON.stringify({ email: emailLower }),
                userId,
              ],
            );
            contactId = ins.rows?.[0]?.id || null;
          }
          // If workspace has no groups yet, add a default group and enable email by default
          try {
            if (contactId) {
              const groupId = "default_admin";
              const group = [
                {
                  id: groupId,
                  name: "Default admin email",
                  email_contact_ids: [String(contactId)],
                },
              ];
              await pool.query(
                `UPDATE workspace_settings
                   SET contact_groups = $2::jsonb, default_contact_group_id = $3
                 WHERE workspace_id = $1 AND (contact_groups IS NULL OR jsonb_array_length(contact_groups) = 0)`,
                [id, JSON.stringify(group), groupId],
              );
            }
          } catch (_err) {
            logger.warn("DB operation failed", { error: _err.message });
          }
        }
      } catch (_err) {
        logger.warn("DB operation failed", { error: _err.message });
      }

      await writeAudit({
        actorUserId: userId,
        subjectUserId: userId,
        action: "WORKSPACE_CREATED",
        targetType: "workspace",
        targetId: null,
        workspaceId: id,
        metadata: { name },
      });
      workspacesCreatedTotal.inc();
      return res.status(201).json({ id, name, plan, role: "admin" });
    } catch (e) {
      logger.error("Create workspace failed", { error: e.message });
      return res
        .status(500)
        .json({ error: "Failed to create workspace", code: "INTERNAL_ERROR" });
    }
  },
);
router.get(
  "/api/v1/workspaces",
  getApiLimiter(),
  requireAuth,
  async (req, res) => {
    try {
      const userId = req.user.id;
      const limit = Math.max(
        1,
        Math.min(100, parseInt(req.query.limit || "50", 10)),
      );
      const offset = Math.max(0, parseInt(req.query.offset || "0", 10));
      const { rows } = await pool.query(
        `SELECT w.id,
                w.name,
                w.plan,
                wm.role,
                w.created_by,
                COALESCE(w.is_personal_default, FALSE) AS is_personal
         FROM workspace_memberships wm
         JOIN workspaces w ON w.id = wm.workspace_id
         WHERE wm.user_id = $1
         ORDER BY w.created_at DESC
         LIMIT $2 OFFSET $3`,
        [userId, limit, offset],
      );
      return res.json({ items: rows, pagination: { limit, offset } });
    } catch (err) {
      logger.error("Failed to list workspaces", { error: err.message });
      return res
        .status(500)
        .json({ error: "Failed to list workspaces", code: "INTERNAL_ERROR" });
    }
  },
);

router.get(
  "/api/v1/workspaces/:id",
  getApiLimiter(),
  requireAuth,
  async (req, res, next) => {
    try {
      const workspaceId = req.params.id;
      const wsRes = await pool.query(
        `SELECT id, name, plan, created_by,
                COALESCE(is_personal_default, FALSE) AS is_personal_default
         FROM workspaces WHERE id = $1`,
        [workspaceId],
      );
      if (wsRes.rowCount === 0)
        return res
          .status(404)
          .json({ error: "Workspace not found", code: "WORKSPACE_NOT_FOUND" });
      req.workspace = wsRes.rows[0];
      return next();
    } catch (e) {
      logger.error("Workspace detail load failed", {
        error: e.message,
        workspaceId: req.params?.id,
        userId: req.user?.id,
      });
      return next(e);
    }
  },
  loadWorkspace,
  requireWorkspaceMembership,
  (req, res) => {
    const role = req.authz?.workspaceRole || "viewer";
    return res.json({ ...req.workspace, role });
  },
);

router.patch(
  "/api/v1/workspaces/:id",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  authorize("workspace.update"),
  async (req, res) => {
    try {
      const userId = req.user.id;
      const before = req.workspace;
      const name = String(req.body?.name || "").trim();
      if (!name)
        return res
          .status(400)
          .json({ error: "Name is required", code: "VALIDATION_ERROR" });
      await pool.query(
        "UPDATE workspaces SET name=$1, updated_at=NOW() WHERE id=$2",
        [name, before.id],
      );
      await writeAudit({
        actorUserId: userId,
        subjectUserId: userId,
        action: "WORKSPACE_RENAMED",
        targetType: "workspace",
        workspaceId: before.id,
        metadata: { before: { name: before.name }, after: { name } },
      });
      return res.json({ ...before, name });
    } catch (err) {
      logger.error("Failed to update workspace", { error: err.message });
      return res
        .status(500)
        .json({ error: "Failed to update workspace", code: "INTERNAL_ERROR" });
    }
  },
);

// Transfer selected tokens between workspaces
router.post(
  "/api/v1/workspaces/:id/transfer-tokens",
  getApiLimiter(),
  requireAuth,
  async (req, res) => {
    const client = await pool.connect();
    try {
      const targetId = String(req.params.id);
      const fromWorkspaceId = String(req.body?.from_workspace_id || "");
      const tokenIds = Array.isArray(req.body?.token_ids)
        ? req.body.token_ids
            .map((v) => parseInt(v, 10))
            .filter((n) => Number.isInteger(n))
        : [];

      if (!fromWorkspaceId) {
        return res.status(400).json({
          error: "from_workspace_id is required",
          code: "VALIDATION_ERROR",
        });
      }
      if (tokenIds.length === 0) {
        return res.status(400).json({
          error: "token_ids must be a non-empty array",
          code: "VALIDATION_ERROR",
        });
      }
      if (tokenIds.length > 1000) {
        return res.status(400).json({
          error: "Too many tokens selected (max 1000 per request)",
          code: "VALIDATION_ERROR",
        });
      }
      if (targetId === fromWorkspaceId) {
        return res.status(400).json({
          error: "Target and source workspace must be different",
          code: "VALIDATION_ERROR",
        });
      }

      // Validate target workspace exists
      const tRes = await client.query(
        "SELECT id, created_by FROM workspaces WHERE id = $1",
        [targetId],
      );
      if (tRes.rowCount === 0) {
        return res.status(404).json({
          error: "Target workspace not found",
          code: "WORKSPACE_NOT_FOUND",
        });
      }
      const targetOwnerId = tRes.rows[0].created_by;

      // Validate source workspace exists
      const sRes = await client.query(
        "SELECT id FROM workspaces WHERE id = $1",
        [fromWorkspaceId],
      );
      if (sRes.rowCount === 0) {
        return res.status(404).json({
          error: "Source workspace not found",
          code: "WORKSPACE_NOT_FOUND",
        });
      }

      // Role checks: admin OR (workspace_manager with >= 2 workspaces attributed)
      const getRole = async (workspaceId) => {
        const r = await client.query(
          "SELECT role FROM workspace_memberships WHERE user_id = $1 AND workspace_id = $2",
          [req.user.id, workspaceId],
        );
        return String(r.rows?.[0]?.role || "").toLowerCase();
      };
      const roleSource = await getRole(fromWorkspaceId);
      const roleTarget = await getRole(targetId);
      const isAdminSource = roleSource === "admin";
      const isAdminTarget = roleTarget === "admin";
      const isManagerSource = roleSource === "workspace_manager";
      const isManagerTarget = roleTarget === "workspace_manager";

      // Count attributed workspaces for the user (where they are member)
      let attributedCount = 0;
      if (isManagerSource || isManagerTarget) {
        const cnt = await client.query(
          "SELECT COUNT(*)::int AS c FROM workspace_memberships WHERE user_id = $1",
          [req.user.id],
        );
        attributedCount = cnt.rows?.[0]?.c || 0;
      }

      // Allow if admin in both OR manager in both with >=2 attributed OR mixed (admin in one, manager in the other with >=2)
      const managerOk =
        isManagerSource || isManagerTarget ? attributedCount >= 2 : true;
      const allowed =
        (isAdminSource || isManagerSource) &&
        (isAdminTarget || isManagerTarget) &&
        managerOk;
      if (!allowed) {
        return res.status(403).json({
          error:
            "Forbidden: admin or qualified manager role required in both workspaces",
          code: "FORBIDDEN",
        });
      }

      await client.query("BEGIN");
      const updateRes = await client.query(
        `UPDATE tokens
         SET workspace_id = $1, updated_at = NOW()
         WHERE id = ANY($2::int[]) AND workspace_id = $3
         RETURNING id`,
        [targetId, tokenIds, fromWorkspaceId],
      );
      const movedIds = (updateRes.rows || []).map((r) => r.id);
      if (movedIds.length > 0 && targetOwnerId) {
        await client.query(
          `UPDATE alert_delivery_log
             SET user_id = $1, workspace_id = $2
           WHERE token_id = ANY($3::int[])
             AND date_trunc('month', (sent_at AT TIME ZONE 'UTC')) = date_trunc('month', (NOW() AT TIME ZONE 'UTC'))`,
          [targetOwnerId, targetId, movedIds],
        );
      }
      await client.query("COMMIT");

      const moved = updateRes.rowCount || 0;

      try {
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "TOKENS_TRANSFERRED_BETWEEN_WORKSPACES",
          targetType: "workspace",
          targetId: null,
          channel: null,
          workspaceId: targetId,
          metadata: {
            from_workspace_id: fromWorkspaceId,
            to_workspace_id: targetId,
            moved,
          },
        });
      } catch (_err) {
        logger.warn("Audit write failed", { error: _err.message });
      }

      return res.json({ moved, targetWorkspaceId: targetId, fromWorkspaceId });
    } catch (e) {
      try {
        await client.query("ROLLBACK");
      } catch (_err) {
        logger.warn("DB operation failed", { error: _err.message });
      }
      logger.error("Transfer tokens between workspaces failed", {
        error: e.message,
        userId: req.user?.id,
      });
      return res
        .status(500)
        .json({ error: "Failed to transfer tokens", code: "INTERNAL_ERROR" });
    } finally {
      client.release();
    }
  },
);

router.delete(
  "/api/v1/workspaces/:id",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  authorize("workspace.delete"),
  async (req, res) => {
    try {
      const userId = req.user.id;
      const ws = req.workspace;
      // Guard: prevent deleting a workspace if user is not admin
      const roleRes = await pool.query(
        "SELECT role FROM workspace_memberships WHERE user_id=$1 AND workspace_id=$2",
        [userId, ws.id],
      );
      const role = roleRes.rows?.[0]?.role || null;
      if (role !== "admin") {
        return res.status(403).json({
          error: "Forbidden: only admins can delete a workspace",
          code: "FORBIDDEN",
        });
      }
      // Record audit without a hard FK to avoid race/FK issues. Persist workspaceId in metadata.
      try {
        await writeAudit({
          actorUserId: userId,
          subjectUserId: userId,
          action: "WORKSPACE_DELETED",
          targetType: "workspace",
          workspaceId: null,
          metadata: { name: ws.name, workspaceId: ws.id },
        });
      } catch (_err) {
        logger.warn("Audit write failed (WORKSPACE_DELETED)", {
          error: _err.message,
        });
      }
      await pool.query("DELETE FROM workspaces WHERE id=$1", [ws.id]);
      return res.status(204).send();
    } catch (e) {
      logger.error("Delete workspace failed", {
        error: e.message,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res
        .status(500)
        .json({ error: "Failed to delete workspace", code: "INTERNAL_ERROR" });
    }
  },
);
// Memberships
router.post(
  "/api/v1/workspaces/:id/members",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  authorize("membership.invite"),
  async (req, res) => {
    try {
      const userId = req.user.id;
      const ws = req.workspace;
      const { email, role } = req.body || {};
      if (!email || !role)
        return res
          .status(400)
          .json({ error: "email and role required", code: "VALIDATION_ERROR" });
      // Disallow inviting yourself to your own workspace
      const normalizedEmail = String(email || "")
        .trim()
        .toLowerCase();
      const selfEmail = String(req.user?.email || "")
        .trim()
        .toLowerCase();
      if (normalizedEmail === selfEmail) {
        return res
          .status(403)
          .json({ error: "Cannot invite yourself", code: "FORBIDDEN" });
      }
      // Admin role cannot be granted via invite
      if (role === "admin") {
        return res.status(403).json({
          error: "Forbidden: admin role cannot be granted",
          code: "FORBIDDEN",
        });
      }
      // Already normalized above
      // Basic email format validation to avoid downstream errors
      if (!/.+@.+\..+/.test(normalizedEmail)) {
        return res
          .status(400)
          .json({ error: "Invalid email format", code: "VALIDATION_ERROR" });
      }
      // Enforce organization member cap based on plan
      try {
        let orgPlan = "oss";
        try {
          orgPlan = String(ws.plan || "oss").toLowerCase();
        } catch (_err) {
          logger.debug("Non-critical operation failed", {
            error: _err.message,
          });
        }
        let memberLimit = MEMBER_LIMITS[orgPlan];
        if (typeof memberLimit === "undefined") {
          logger.warn("Unknown plan in MEMBER_LIMITS lookup", {
            plan: orgPlan,
            workspaceId: ws.id,
          });
          memberLimit = MEMBER_LIMITS.oss ?? Infinity;
        }
        if (Number.isFinite(memberLimit)) {
          const memberCountRes = await pool.query(
            `SELECT COUNT(DISTINCT wm.user_id)::int AS c
               FROM workspaces w
               JOIN workspace_memberships wm ON wm.workspace_id = w.id
              WHERE w.created_by = $1`,
            [ws.created_by],
          );
          const activeMemberCount = memberCountRes.rows?.[0]?.c || 0;
          const pendingInvitesRes = await pool.query(
            `SELECT COUNT(DISTINCT LOWER(wi.email))::int AS c
               FROM workspaces w
               JOIN workspace_invitations wi ON wi.workspace_id = w.id
              WHERE w.created_by = $1 AND wi.accepted_at IS NULL`,
            [ws.created_by],
          );
          const pendingInviteCount = pendingInvitesRes.rows?.[0]?.c || 0;
          let alreadyMemberInOrg = false;
          try {
            const existsRes = await pool.query(
              `SELECT 1
                 FROM workspaces w
                 JOIN workspace_memberships wm ON wm.workspace_id = w.id
                 JOIN users u ON u.id = wm.user_id
                WHERE w.created_by = $1 AND LOWER(u.email) = $2
                LIMIT 1`,
              [ws.created_by, normalizedEmail],
            );
            alreadyMemberInOrg = existsRes.rowCount > 0;
          } catch (_err) {
            logger.warn("DB operation failed", { error: _err.message });
          }
          let alreadyPending = false;
          try {
            const pend = await pool.query(
              `SELECT 1
                 FROM workspaces w
                 JOIN workspace_invitations wi ON wi.workspace_id = w.id
                WHERE w.created_by = $1 AND LOWER(wi.email) = $2 AND wi.accepted_at IS NULL
                LIMIT 1`,
              [ws.created_by, normalizedEmail],
            );
            alreadyPending = pend.rowCount > 0;
          } catch (_err) {
            logger.warn("DB operation failed", { error: _err.message });
          }
          const additional = alreadyMemberInOrg || alreadyPending ? 0 : 1;
          const prospectiveTotal =
            activeMemberCount + pendingInviteCount + additional;
          if (prospectiveTotal > memberLimit) {
            return res.status(409).json({
              error: "Plan limit reached",
              code: "PLAN_LIMIT",
              limit: memberLimit,
            });
          }
        }
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }
      const userRes = await pool.query(
        "SELECT id, display_name FROM users WHERE email = $1",
        [normalizedEmail],
      );
      let targetUserId = null;
      let inviteToken = null;
      if (userRes.rowCount > 0) {
        // Existing user: create membership directly
        targetUserId = userRes.rows[0].id;
        await pool.query(
          `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by) VALUES ($1,$2,$3,$4)
         ON CONFLICT (user_id, workspace_id) DO UPDATE SET role = EXCLUDED.role`,
          [targetUserId, ws.id, role, userId],
        );
        // Clear any residual invitation row for this email so it does not count
        // against plan caps and does not leak through the pending list.
        try {
          await pool.query(
            `DELETE FROM workspace_invitations WHERE workspace_id = $1 AND LOWER(email) = $2`,
            [ws.id, normalizedEmail],
          );
        } catch (_err) {
          logger.warn("Residual invitation cleanup failed", {
            error: _err.message,
            workspaceId: ws.id,
          });
        }
      } else {
        // Not registered: create invitation token record
        const inviteId = require("crypto").randomUUID();
        inviteToken = require("crypto").randomBytes(32).toString("hex");
        await pool.query(
          `INSERT INTO workspace_invitations (id, workspace_id, email, role, invited_by, token)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (workspace_id, email) DO UPDATE SET role=EXCLUDED.role, invited_by=EXCLUDED.invited_by, token=EXCLUDED.token, accepted_at=NULL`,
          [inviteId, ws.id, normalizedEmail, role, userId, inviteToken],
        );
      }
      await writeAudit({
        actorUserId: userId,
        subjectUserId: targetUserId || userId,
        action: "MEMBER_INVITED_OR_UPDATED",
        targetType: "workspace",
        workspaceId: ws.id,
        metadata: {
          role,
          email: normalizedEmail,
          workspace_name: ws.name,
          recipient_type: userRes.rowCount > 0 ? "existing_user" : "new_user",
        },
      });
      // Send invitation/notification email (best-effort)
      try {
        const subject =
          userRes.rowCount > 0
            ? `You were added to "${ws.name}" on TokenTimer`
            : `You're invited to join "${ws.name}" on TokenTimer`;
        const appUrl = process.env.APP_URL || "http://localhost:5173";
        const actionUrl =
          userRes.rowCount > 0
            ? `${appUrl}/dashboard`
            : `${appUrl}/register?token=${encodeURIComponent(inviteToken || "")}&email=${encodeURIComponent(normalizedEmail)}`;
        const ctaText =
          userRes.rowCount > 0 ? "Open TokenTimer" : "Create your account";
        const hint =
          userRes.rowCount > 0
            ? ""
            : '<p style="margin-top: 20px;">Please register using this email to get started. After registration, you will automatically have access to this workspace.</p>';
        const { html, text, useEmbeddedLogo } = await generateEmailTemplate({
          title: `Workspace ${userRes.rowCount > 0 ? "Access" : "Invitation"}`,
          greeting: `Hi ${userRes.rows[0]?.display_name || "there"},`,
          content: `
            <p>You have been ${role ? `granted <strong>${role}</strong> access` : "added"} to the workspace <strong>${ws.name}</strong>.</p>
            ${hint}
            <p style="margin-top: 20px; color: #718096; font-size: 14px;">If you did not expect this invitation, please contact your workspace administrator.</p>
          `,
          buttonText: ctaText,
          buttonUrl: actionUrl,
          plainTextContent: `
Hi ${userRes.rows[0]?.display_name || "there"},

You have been ${role ? `granted ${role} access` : "added"} to the workspace ${ws.name}.

${userRes.rowCount > 0 ? "" : "Please register using this email to get started. After registration, you will automatically have access to this workspace.\n\n"}

${actionUrl}

If you did not expect this invitation, please contact your workspace administrator.
          `,
        });
        const emailResult = await sendEmail({
          to: normalizedEmail,
          subject,
          html,
          text,
          useEmbeddedLogo,
        });
        if (emailResult?.success) {
          await writeAudit({
            actorUserId: userId,
            subjectUserId: targetUserId || userId,
            action: "INVITE_EMAIL_SENT",
            targetType: "workspace",
            workspaceId: ws.id,
            metadata: {
              role,
              email: normalizedEmail,
              workspace_name: ws.name,
            },
          });
        } else {
          logger.warn("Invite email send failed", {
            error:
              emailResult?.providerError ||
              emailResult?.error ||
              "SMTP send returned unsuccessful result",
            workspaceId: ws.id,
            to: normalizedEmail,
          });
        }
      } catch (e) {
        logger.warn("Invite email send failed", {
          error: e.message,
          workspaceId: ws.id,
          to: normalizedEmail,
        });
      }
      inviteSentTotal.inc();
      return res.status(201).json({ user_id: targetUserId, role });
    } catch (e) {
      logger.error("Add member failed", {
        error: e.message,
        workspaceId: req.workspace?.id,
        body: sanitizeForLogging(req.body),
      });
      return res
        .status(500)
        .json({ error: "Failed to add member", code: "INTERNAL_ERROR" });
    }
  },
);
router.patch(
  "/api/v1/workspaces/:id/members/:userId",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  authorize("membership.change_role"),
  async (req, res) => {
    try {
      const userId = req.user.id;
      const ws = req.workspace;
      const targetUserId = String(req.params.userId || "").trim();
      if (!targetUserId) {
        return res
          .status(400)
          .json({ error: "Invalid target user", code: "VALIDATION_ERROR" });
      }
      const { role } = req.body || {};
      if (String(targetUserId) === String(userId)) {
        return res.status(403).json({
          error: "You cannot change your own role",
          code: "FORBIDDEN",
        });
      }
      // Disallow changing an admin role.
      const currentRoleRes = await pool.query(
        "SELECT role FROM workspace_memberships WHERE user_id=$1 AND workspace_id=$2",
        [targetUserId, ws.id],
      );
      const currentRole = String(
        currentRoleRes.rows?.[0]?.role || "",
      ).toLowerCase();
      if (currentRole === "admin") {
        return res
          .status(403)
          .json({ error: "Cannot change role of admin", code: "FORBIDDEN" });
      }
      if (!["workspace_manager", "viewer"].includes(role))
        return res
          .status(400)
          .json({ error: "Invalid role", code: "VALIDATION_ERROR" });
      // Prevent changing any role to admin via API
      await pool.query(
        "UPDATE workspace_memberships SET role=$1 WHERE user_id=$2 AND workspace_id=$3",
        [role, targetUserId, ws.id],
      );
      await writeAudit({
        actorUserId: userId,
        subjectUserId: targetUserId,
        action: "MEMBER_ROLE_CHANGED",
        targetType: "workspace",
        workspaceId: ws.id,
        metadata: { role },
      });
      return res.json({ user_id: targetUserId, role });
    } catch (err) {
      logger.error("Failed to change role", { error: err.message });
      return res
        .status(500)
        .json({ error: "Failed to change role", code: "INTERNAL_ERROR" });
    }
  },
);

router.delete(
  "/api/v1/workspaces/:id/members/:userId",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  authorize("membership.remove"),
  async (req, res) => {
    try {
      const userId = req.user.id;
      const ws = req.workspace;
      const targetUserId = String(req.params.userId || "").trim();
      if (!targetUserId) {
        return res
          .status(400)
          .json({ error: "Invalid target user", code: "VALIDATION_ERROR" });
      }
      // Prevent non-admin users from removing their own membership (avoid lockout/confusion)
      if (String(targetUserId) === String(userId)) {
        const myRole = req.authz?.workspaceRole;
        if (myRole !== "admin") {
          return res.status(403).json({
            error: "You cannot remove your own membership",
            code: "FORBIDDEN",
          });
        }
      }
      // Managers cannot remove admins
      const { rows } = await pool.query(
        "SELECT role FROM workspace_memberships WHERE user_id=$1 AND workspace_id=$2",
        [targetUserId, ws.id],
      );
      const targetRole = rows[0]?.role;
      // Admin cannot be removed via API (protect one-admin rule)
      if (targetRole === "admin") {
        return res
          .status(403)
          .json({ error: "Forbidden: cannot remove admin", code: "FORBIDDEN" });
      }
      await pool.query(
        "DELETE FROM workspace_memberships WHERE user_id=$1 AND workspace_id=$2",
        [targetUserId, ws.id],
      );
      await writeAudit({
        actorUserId: userId,
        subjectUserId: targetUserId,
        action: "MEMBER_REMOVED",
        targetType: "workspace",
        workspaceId: ws.id,
        metadata: {},
      });
      return res.status(204).send();
    } catch (err) {
      logger.error("Failed to remove member", { error: err.message });
      return res
        .status(500)
        .json({ error: "Failed to remove member", code: "INTERNAL_ERROR" });
    }
  },
);

// List workspace members
router.get(
  "/api/v1/workspaces/:id/members",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  async (req, res) => {
    try {
      const limit = Math.max(
        1,
        Math.min(200, parseInt(req.query.limit || "100", 10)),
      );
      const offset = Math.max(0, parseInt(req.query.offset || "0", 10));
      const { rows } = await pool.query(
        `SELECT wm.user_id, wm.role, u.display_name, u.email
       FROM workspace_memberships wm
       JOIN users u ON u.id = wm.user_id
       WHERE wm.workspace_id = $1
       ORDER BY wm.created_at ASC
       LIMIT $2 OFFSET $3`,
        [req.workspace.id, limit, offset],
      );
      return res.json({ items: rows, pagination: { limit, offset } });
    } catch (err) {
      logger.error("Failed to list members", { error: err.message });
      return res
        .status(500)
        .json({ error: "Failed to list members", code: "INTERNAL_ERROR" });
    }
  },
);

// List pending (unaccepted) invitations for a workspace.
// Never returns the `token` column (treated as a bearer secret).
router.get(
  "/api/v1/workspaces/:id/invitations",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  async (req, res) => {
    try {
      const limit = Math.max(
        1,
        Math.min(200, parseInt(req.query.limit || "100", 10)),
      );
      const offset = Math.max(0, parseInt(req.query.offset || "0", 10));
      const { rows } = await pool.query(
        `SELECT wi.id,
                wi.email,
                wi.role,
                wi.created_at,
                wi.accepted_at,
                wi.invited_by,
                u.display_name AS invited_by_name
           FROM workspace_invitations wi
           LEFT JOIN users u ON u.id = wi.invited_by
          WHERE wi.workspace_id = $1
            AND wi.accepted_at IS NULL
          ORDER BY wi.created_at DESC
          LIMIT $2 OFFSET $3`,
        [req.workspace.id, limit, offset],
      );
      return res.json({ items: rows, pagination: { limit, offset } });
    } catch (err) {
      logger.error("Failed to list workspace invitations", {
        error: err.message,
        workspaceId: req.workspace?.id,
      });
      return res.status(500).json({
        error: "Failed to list invitations",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

// Cancel a pending invitation. Only removes rows where accepted_at IS NULL so
// that accepted invitations (historical records) are never disturbed.
router.delete(
  "/api/v1/workspaces/:id/invitations/:invitationId",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  authorize("membership.cancel_invite"),
  async (req, res) => {
    try {
      const invitationId = String(req.params.invitationId || "").trim();
      if (!invitationId) {
        return res.status(400).json({
          error: "invitationId required",
          code: "VALIDATION_ERROR",
        });
      }
      const { rows } = await pool.query(
        `DELETE FROM workspace_invitations
          WHERE id = $1 AND workspace_id = $2 AND accepted_at IS NULL
          RETURNING email, role`,
        [invitationId, req.workspace.id],
      );
      if (rows.length === 0) {
        return res
          .status(404)
          .json({ error: "Invitation not found", code: "NOT_FOUND" });
      }
      const { email, role } = rows[0];
      try {
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "INVITATION_CANCELLED",
          targetType: "workspace_invitation",
          targetId: invitationId,
          workspaceId: req.workspace.id,
          metadata: {
            email,
            role,
            workspace_name: req.workspace.name,
            invitation_id: invitationId,
          },
        });
      } catch (auditErr) {
        logger.warn("Failed to write INVITATION_CANCELLED audit event", {
          error: auditErr.message,
          workspaceId: req.workspace.id,
          invitationId,
        });
      }
      try {
        inviteCancelledTotal.inc();
      } catch (metricErr) {
        logger.warn("Failed to increment inviteCancelledTotal metric", {
          error: metricErr.message,
        });
      }
      return res.status(204).send();
    } catch (err) {
      logger.error("Failed to cancel workspace invitation", {
        error: err.message,
        workspaceId: req.workspace?.id,
        invitationId: req.params?.invitationId,
      });
      return res.status(500).json({
        error: "Failed to cancel invitation",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

// Section endpoints removed: sections have been simplified to a free-text token field.

// Audit feed (workspace-scoped)
router.get("/api/v1/audit", getApiLimiter(), requireAuth, async (req, res) => {
  try {
    const workspaceId = req.query.workspace_id;
    if (!workspaceId)
      return res
        .status(400)
        .json({ error: "workspace_id required", code: "VALIDATION_ERROR" });
    // membership check
    const role = await getUserWorkspaceRole(req.user.id, workspaceId);
    if (!role)
      return res.status(403).json({ error: "Forbidden", code: "FORBIDDEN" });
    const eventType = req.query.event_type
      ? String(req.query.event_type)
      : null;
    const limit = Math.max(
      1,
      Math.min(200, parseInt(req.query.limit || "100", 10)),
    );
    const offset = Math.max(0, parseInt(req.query.offset || "0", 10));
    const params = [workspaceId, limit, offset];
    let sql = `SELECT id, occurred_at, actor_user_id, subject_user_id, action, target_type, target_id, channel, metadata
               FROM audit_events
               WHERE workspace_id = $1`;
    if (eventType) {
      sql += " AND action = $4";
      params.push(eventType);
    }
    sql += " ORDER BY occurred_at DESC LIMIT $2 OFFSET $3";
    const { rows } = await pool.query(sql, params);
    return res.json({ items: rows, pagination: { limit, offset } });
  } catch (err) {
    logger.error("Failed to fetch audit events", { error: err.message });
    return res
      .status(500)
      .json({ error: "Failed to fetch audit events", code: "INTERNAL_ERROR" });
  }
});

module.exports = router;
