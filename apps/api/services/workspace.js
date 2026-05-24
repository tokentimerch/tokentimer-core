const { pool } = require("../db/database");
const { logger } = require("../utils/logger");
const { writeAudit } = require("./audit");

const DEFAULT_WORKSPACE_NAME = "Default workspace";
const INSTALLATION_DEFAULT_LOCK_KEY = 0x5454_5744; // TTWD

/**
 * Ensure a user has initial workspace context.
 * Accepts pending invitations, then ensures membership on the installation default workspace.
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

    const membershipCheck = await pool.query(
      `SELECT 1 FROM workspace_memberships WHERE user_id = $1 LIMIT 1`,
      [userId],
    );
    if (membershipCheck.rowCount > 0) {
      return;
    }

    const client = await pool.connect();
    let workspaceId;
    let created = false;
    let joinRole = "admin";
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock($1)", [
        INSTALLATION_DEFAULT_LOCK_KEY,
      ]);

      const existing = await client.query(
        `SELECT id
           FROM workspaces
          WHERE LOWER(TRIM(name)) = LOWER($1)
          ORDER BY created_at ASC
          LIMIT 1
          FOR UPDATE`,
        [DEFAULT_WORKSPACE_NAME],
      );
      if (existing.rowCount > 0) {
        workspaceId = existing.rows[0].id;
      } else {
        const allWorkspaces = await client.query(
          `SELECT id FROM workspaces ORDER BY created_at ASC FOR UPDATE`,
        );
        if (allWorkspaces.rowCount === 1) {
          workspaceId = allWorkspaces.rows[0].id;
        }
      }

      if (!workspaceId) {
        workspaceId = require("crypto").randomUUID();
        await client.query(
          "INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1,$2,'oss',$3)",
          [workspaceId, DEFAULT_WORKSPACE_NAME, userId],
        );
        try {
          await client.query(
            "UPDATE workspaces SET is_personal_default = FALSE WHERE id = $1",
            [workspaceId],
          );
        } catch (_err) {
          logger.debug("is_personal_default column update skipped", {
            error: _err.message,
          });
        }
        created = true;
        joinRole = "admin";
      } else {
        joinRole = await resolveJoinRole(client, userId);
      }

      await client.query(
        `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
         VALUES ($1,$2,$3,$1)
         ON CONFLICT (user_id, workspace_id) DO NOTHING`,
        [userId, workspaceId, joinRole],
      );

      await client.query("COMMIT");
    } catch (err) {
      try {
        await client.query("ROLLBACK");
      } catch (_) {
        /* ignore */
      }
      throw err;
    } finally {
      client.release();
    }

    if (created) {
      try {
        await pool.query(
          `INSERT INTO workspace_settings (workspace_id, email_alerts_enabled)
           VALUES ($1, TRUE)
           ON CONFLICT (workspace_id) DO UPDATE SET email_alerts_enabled = TRUE`,
          [workspaceId],
        );
      } catch (_err) {
        logger.warn("DB operation failed", { error: _err.message });
      }
      try {
        await seedCreatorContact(workspaceId, userId, userEmail, displayName);
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
          workspaceId,
          metadata: {
            name: DEFAULT_WORKSPACE_NAME,
            kind: "installation_default",
          },
        });
      } catch (_err) {
        logger.warn("Audit write failed (WORKSPACE_CREATED)", {
          error: _err.message,
          stack: _err.stack,
        });
      }
    } else {
      try {
        await writeAudit({
          actorUserId: userId,
          subjectUserId: userId,
          action: "WORKSPACE_MEMBERSHIP_ACCEPTED",
          targetType: "workspace",
          targetId: null,
          channel: null,
          workspaceId,
          metadata: { role: joinRole, kind: "installation_default" },
        });
      } catch (_err) {
        logger.warn("Audit write failed (installation default join)", {
          error: _err.message,
        });
      }
    }
  } catch (err) {
    logger.error("ensureInitialWorkspaceForUser failed", {
      userId,
      error: err.message,
      stack: err.stack,
    });
  }
}

function resolveJoinRole(_db, _userId) {
  // Join role for the shared Default workspace when it already exists.
  // users.is_admin is installation-wide and does not grant workspace admin here.
  // The creator branch in ensureInitialWorkspaceForUser still assigns admin when
  // the Default workspace is first created; all later automatic joins are manager.
  return "workspace_manager";
}

async function seedCreatorContact(workspaceId, userId, userEmail, displayName) {
  const parts = String(displayName || "")
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  const ownerFirst = parts[0] || "Owner";
  const ownerLast = parts.slice(1).join(" ");
  const emailLower = (userEmail || "").trim().toLowerCase();
  if (!emailLower) return;

  const existing = await pool.query(
    `SELECT id FROM workspace_contacts WHERE workspace_id = $1 AND LOWER(details->>'email') = $2 LIMIT 1`,
    [workspaceId, emailLower],
  );
  let contactId = existing.rows?.[0]?.id || null;
  if (!contactId) {
    const ins = await pool.query(
      `INSERT INTO workspace_contacts (workspace_id, first_name, last_name, phone_e164, details, created_by)
       VALUES ($1,$2,$3,NULL,$4,$5) RETURNING id`,
      [
        workspaceId,
        String(ownerFirst).trim(),
        String(ownerLast || "").trim(),
        JSON.stringify({ email: emailLower }),
        userId,
      ],
    );
    contactId = ins.rows?.[0]?.id || null;
  }
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
        WHERE workspace_id = $1
          AND (contact_groups IS NULL OR jsonb_array_length(contact_groups) = 0)`,
      [workspaceId, JSON.stringify(group), groupId],
    );
  }
}

module.exports = { ensureInitialWorkspaceForUser, DEFAULT_WORKSPACE_NAME };
