const { pool } = require("../db/database");
const { logger } = require("../utils/logger");
const { writeAudit } = require("./audit");

/**
 * Ensure a user has initial workspace context.
 * Accepts any pending invitations, then creates a default workspace if none exists.
 * Idempotent - safe to call on every login.
 *
 * @param {string} userId - The user's ID
 * @param {string} userEmail - The user's email address
 * @param {string} displayName - The user's display name
 */
async function ensureInitialWorkspaceForUser(userId, userEmail, displayName) {
  try {
    const emailLc = (userEmail || "").trim().toLowerCase();
    const localPart = emailLc.includes("@") ? emailLc.split("@")[0] : emailLc;
    const domainPart = emailLc.includes("@") ? emailLc.split("@")[1] : "";
    const localNoPlus = localPart.split("+")[0];
    const isGmailLike =
      domainPart === "gmail.com" || domainPart === "googlemail.com";
    const gmailCanonicalLocal = localNoPlus.replace(/\./g, "");

    const invites = await pool.query(
      `SELECT id, workspace_id, role
         FROM workspace_invitations
        WHERE LOWER(email) = $1
           OR (
                LOWER(SPLIT_PART(email,'@',2)) = $2
            AND regexp_replace(SPLIT_PART(LOWER(email),'@',1), '\\+.*', '') = $3
              )
           OR (
                $4::boolean = TRUE
            AND LOWER(SPLIT_PART(email,'@',2)) IN ('gmail.com','googlemail.com')
            AND regexp_replace(
                  regexp_replace(SPLIT_PART(LOWER(email),'@',1), '\\+.*', ''),
                  '\\.',
                  '',
                  'g'
                ) = $5
              )`,
      [emailLc, domainPart, localNoPlus, isGmailLike, gmailCanonicalLocal],
    );
    if (invites.rowCount > 0) {
      for (const row of invites.rows) {
        await pool.query(
          `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
           VALUES ($1,$2,$3,NULL)
           ON CONFLICT (user_id, workspace_id) DO UPDATE SET role = EXCLUDED.role`,
          [userId, row.workspace_id, row.role],
        );
        try {
          await pool.query(
            "UPDATE workspace_invitations SET accepted_at = NOW() WHERE id = $1",
            [row.id],
          );
        } catch (_err) {
          logger.warn("DB operation failed", { error: _err.message });
        }
        try {
          await writeAudit({
            actorUserId: userId,
            subjectUserId: userId,
            action: "WORKSPACE_MEMBERSHIP_ACCEPTED",
            targetType: "workspace",
            targetId: null,
            channel: null,
            workspaceId: row.workspace_id,
            metadata: { role: row.role },
          });
        } catch (_err) {
          logger.warn("Audit write failed (WORKSPACE_MEMBERSHIP_ACCEPTED)", {
            error: _err.message,
            stack: _err.stack,
          });
        }
      }
      try {
        await pool.query(
          "DELETE FROM workspace_invitations WHERE LOWER(email) = $1",
          [emailLc],
        );
      } catch (_err) {
        logger.warn("DB operation failed", { error: _err.message });
      }
    }

    // In core, only admins get a default workspace.
    // Non-admin users (managers, viewers) only belong to workspaces they were invited to.
    try {
      const rolesResult = await pool.query(
        `SELECT DISTINCT role FROM workspace_memberships WHERE user_id = $1`,
        [userId],
      );
      const roles = rolesResult.rows.map((r) => r.role);
      if (roles.length > 0 && !roles.includes("admin")) {
        logger.debug("Non-admin user; skipping personal default workspace", {
          userId,
        });
        return;
      }
    } catch (_err) {
      logger.warn("Role check failed, proceeding with workspace creation", {
        error: _err.message,
      });
    }

    // Idempotency: skip if user already owns a workspace
    let hasWorkspace = false;
    try {
      const chk = await pool.query(
        `SELECT 1 FROM workspaces WHERE created_by = $1 LIMIT 1`,
        [userId],
      );
      hasWorkspace = chk.rowCount > 0;
    } catch (_err) {
      logger.warn("DB operation failed", { error: _err.message });
    }
    if (hasWorkspace) return;

    const wsId = require("crypto").randomUUID();
    const first = (displayName || emailLc || "User").split(" ")[0];
    const wsName = `${first}'s workspace`;
    await pool.query(
      "INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1,$2,'oss',$3)",
      [wsId, wsName, userId],
    );
    await pool.query(
      `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by) VALUES ($1,$2,'admin',$1) ON CONFLICT DO NOTHING`,
      [userId, wsId],
    );
    try {
      await pool.query(
        `INSERT INTO workspace_settings (workspace_id, email_alerts_enabled) VALUES ($1, TRUE) ON CONFLICT (workspace_id) DO UPDATE SET email_alerts_enabled = TRUE`,
        [wsId],
      );
    } catch (_err) {
      logger.warn("DB operation failed", { error: _err.message });
    }
    try {
      const parts = String(displayName || "")
        .trim()
        .split(/\s+/)
        .filter(Boolean);
      const ownerFirst = parts[0] || "Owner";
      const ownerLast = parts.slice(1).join(" ");
      const emailLower = (userEmail || "").trim().toLowerCase();
      if (emailLower) {
        const existing = await pool.query(
          `SELECT id FROM workspace_contacts WHERE workspace_id = $1 AND LOWER(details->>'email') = $2 LIMIT 1`,
          [wsId, emailLower],
        );
        let contactId = existing.rows?.[0]?.id || null;
        if (!contactId) {
          const ins = await pool.query(
            `INSERT INTO workspace_contacts (workspace_id, first_name, last_name, phone_e164, details, created_by) VALUES ($1,$2,$3,NULL,$4,$5) RETURNING id`,
            [
              wsId,
              String(ownerFirst).trim(),
              String(ownerLast || "").trim(),
              JSON.stringify({ email: emailLower }),
              userId,
            ],
          );
          contactId = ins.rows?.[0]?.id || null;
        }
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
              `UPDATE workspace_settings SET contact_groups = $2::jsonb, default_contact_group_id = $3 WHERE workspace_id = $1 AND (contact_groups IS NULL OR jsonb_array_length(contact_groups) = 0)`,
              [wsId, JSON.stringify(group), groupId],
            );
          }
        } catch (_err) {
          logger.warn("DB operation failed", { error: _err.message });
        }
      }
    } catch (_err) {
      logger.warn("DB operation failed", { error: _err.message });
    }
    try {
      await writeAudit({
        actorUserId: userId,
        subjectUserId: userId,
        action: "WORKSPACE_CREATED",
        targetType: "workspace",
        targetId: null,
        channel: null,
        workspaceId: wsId,
        metadata: { name: wsName, kind: "personal_default" },
      });
    } catch (_err) {
      logger.warn("Audit write failed (WORKSPACE_CREATED)", {
        error: _err.message,
        stack: _err.stack,
      });
    }
  } catch (err) {
    logger.error("ensureInitialWorkspaceForUser failed", {
      userId,
      error: err.message,
      stack: err.stack,
    });
  }
}

module.exports = { ensureInitialWorkspaceForUser };
