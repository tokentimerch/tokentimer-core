const { pool } = require("../db/database");
const { logger } = require("../utils/logger");
const { requireAuth } = require("../middleware/auth");
const { getApiLimiter } = require("../middleware/rateLimit");
const bcrypt = require("bcryptjs");

const router = require("express").Router();

router.delete(
  "/api/account",
  getApiLimiter(),
  requireAuth,
  async (req, res) => {
    logger.info("Account deletion attempt", {
      authenticated: req.isAuthenticated(),
      userId: req.user?.id,
      ip: req.ip,
    });

    const userId = req.user.id;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      // Lock the user row for the duration of the transaction
      const _ures = await client.query(
        "SELECT email FROM users WHERE id = $1 FOR UPDATE",
        [userId],
      );

      // Remove sessions where passport.user equals this userId
      await client.query(
        "DELETE FROM session WHERE sess->'passport'->>'user' = $1",
        [userId.toString()],
      );

      // Determine if user requested forced deletion (with workspace wipe)
      const forceParam = String(req.query?.force || "").toLowerCase();
      const forceDeleteWorkspaces =
        forceParam === "1" || forceParam === "true" || forceParam === "yes";

      // Check for any workspaces where this user is the sole admin and there are other members
      const soleAdmin = await client.query(
        `SELECT w.id, w.name
         FROM workspaces w
         JOIN workspace_memberships wm
           ON wm.workspace_id = w.id
        WHERE wm.user_id = $1
          AND wm.role = 'admin'
          AND NOT (
            w.created_by = $1 AND (SELECT COUNT(*) FROM workspace_memberships x WHERE x.workspace_id = w.id) = 1
          )
          AND NOT EXISTS (
            SELECT 1 FROM workspace_memberships wm2
             WHERE wm2.workspace_id = w.id AND wm2.role = 'admin' AND wm2.user_id <> $1
          )`,
        [userId],
      );
      if (soleAdmin.rowCount > 0) {
        if (forceDeleteWorkspaces) {
          const ids = (soleAdmin.rows || []).map((r) => r.id).filter(Boolean);
          if (ids.length > 0) {
            await client.query(
              "DELETE FROM workspaces WHERE id = ANY($1::uuid[])",
              [ids],
            );
          }
        } else {
          await client.query("ROLLBACK");
          logger.warn(
            "Account deletion blocked: user is sole admin of workspaces",
            { userId, workspaces: soleAdmin.rows },
          );
          return res.status(409).json({
            error:
              "You are the only admin of one or more workspaces. Transfer admin or delete the workspace(s) first.",
            code: "ONLY_ADMIN",
            workspaces: soleAdmin.rows, // [{ id, name }]
          });
        }
      }

      // Delete any single-member workspaces that were created by this user
      await client.query(
        `DELETE FROM workspaces
       WHERE created_by = $1
         AND id IN (
           SELECT w.id
           FROM workspaces w
           WHERE w.created_by = $1
             AND (SELECT COUNT(*) FROM workspace_memberships m WHERE m.workspace_id = w.id) = 1
         )`,
        [userId],
      );

      // Transfer ownership of remaining workspaces created by this user to another admin (if present)
      await client.query(
        `UPDATE workspaces w
       SET created_by = sub.new_owner
       FROM (
         SELECT w.id AS workspace_id, MIN(wm2.user_id) AS new_owner
         FROM workspaces w
         JOIN workspace_memberships wm
           ON wm.workspace_id = w.id AND wm.user_id = $1 AND wm.role = 'admin'
         JOIN workspace_memberships wm2
           ON wm2.workspace_id = w.id AND wm2.user_id <> $1 AND wm2.role = 'admin'
         WHERE w.created_by = $1
         GROUP BY w.id
       ) AS sub
       WHERE w.id = sub.workspace_id`,
        [userId],
      );

      const anonEmail = `deleted+${userId}@example.invalid`;
      const dummyHash = await bcrypt.hash(
        `account-deleted-${userId}-${Date.now()}`,
        10,
      );
      await client.query(
        `UPDATE users SET 
           email = $1,
           email_original = NULL,
           display_name = $2,
           first_name = NULL,
           last_name = NULL,
           password_hash = $3,
           auth_method = 'local',
           photo = NULL,
           access_token = NULL,
           refresh_token = NULL,
           token_expiry = NULL,
           email_verified = FALSE,
           verification_token = NULL,
           verification_token_expires = NULL,
           reset_token = NULL,
           reset_token_expires = NULL,
           two_factor_enabled = FALSE,
           two_factor_secret = NULL,
           updated_at = NOW()
         WHERE id = $4`,
        [anonEmail, "Deleted Account", dummyHash, userId],
      );

      // Proactively remove memberships so the anonymized account no longer belongs to orgs
      await client.query(
        "DELETE FROM workspace_memberships WHERE user_id = $1",
        [userId],
      );
      // section_memberships legacy table removed Ã¢â‚¬â€œ no action needed

      // Delete alert artifacts owned by this user
      await client.query("DELETE FROM alert_delivery_log WHERE user_id = $1", [
        userId,
      ]);
      await client.query("DELETE FROM alert_queue WHERE user_id = $1", [
        userId,
      ]);

      // Anonymize audit trail references for this user (preserve workspace audit history)
      try {
        await client.query(
          "UPDATE audit_events SET subject_user_id = NULL WHERE subject_user_id = $1",
          [userId],
        );
      } catch (_err) {
        logger.warn("Audit write failed", { error: _err.message });
      }
      try {
        await client.query(
          "UPDATE audit_events SET actor_user_id = NULL WHERE actor_user_id = $1",
          [userId],
        );
      } catch (_err) {
        logger.warn("Audit write failed", { error: _err.message });
      }

      // Best-effort: null invited_by references
      try {
        await client.query(
          "UPDATE workspace_invitations SET invited_by = NULL WHERE invited_by = $1",
          [userId],
        );
      } catch (_err) {
        logger.warn("Audit write failed", { error: _err.message });
      }
      // End anonymization branch

      await client.query("COMMIT");

      // Clear the session cookie first
      res.clearCookie("sessionId");

      // Logout and destroy session properly through Passport.js
      req.logout((err) => {
        if (err) {
          logger.error("Logout error during account deletion:", {
            error: err.message,
            stack: err.stack,
          });
        }
      });

      res.json({ message: "Account deleted successfully" });
    } catch (error) {
      await client.query("ROLLBACK");
      logger.error("Error deleting user account:", {
        error: error.message,
        stack: error.stack,
      });
      res
        .status(500)
        .json({ error: "Failed to delete account", code: "INTERNAL_ERROR" });
    } finally {
      client.release();
    }
  },
);

module.exports = router;
