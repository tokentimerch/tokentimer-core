const express = require("express");
const { pool } = require("../db/database");
const { logger } = require("../utils/logger");
const { writeAudit } = require("../services/audit");
const { maskPhone, hashPhone } = require("../utils/sanitize");
const { getApiLimiter } = require("../middleware/rateLimit");
const { requireAuth } = require("../middleware/auth");
const {
  loadWorkspace,
  requireWorkspaceMembership,
} = require("../services/rbac");

const router = express.Router({ mergeParams: true });

// Workspace contacts CRUD
router.get(
  "/api/v1/workspaces/:id/contacts",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  async (req, res) => {
    try {
      const { rows } = await pool.query(
        `SELECT id, first_name, last_name, phone_e164, details, created_at, updated_at
           FROM workspace_contacts
          WHERE workspace_id = $1
          ORDER BY last_name, first_name`,
        [req.workspace.id],
      );
      res.json({ items: rows });
    } catch (e) {
      logger.error("Workspace contacts list error", { error: e.message });
      res
        .status(500)
        .json({ error: "Failed to list contacts", code: "INTERNAL_ERROR" });
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/contacts",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  async (req, res) => {
    // Allow admin and workspace_manager to create contacts
    const role = req.authz?.workspaceRole;
    if (!role || !["admin", "workspace_manager"].includes(role)) {
      return res
        .status(403)
        .json({ error: "Forbidden: insufficient role", code: "FORBIDDEN" });
    }
    try {
      const { first_name, last_name, phone_e164, details } = req.body || {};
      if (!first_name || !last_name) {
        return res.status(400).json({
          error: "first_name and last_name are required",
          code: "VALIDATION_ERROR",
        });
      }
      const detailsObj = details && typeof details === "object" ? details : {};
      const emailStr = String(detailsObj.email || "")
        .trim()
        .toLowerCase();
      let phoneE164 = null;
      const phoneNorm = String(phone_e164 || "").trim();
      if (phoneNorm) {
        if (!/^\+?[1-9]\d{6,14}$/.test(phoneNorm)) {
          return res.status(400).json({
            error: "Invalid phone format (E.164 expected)",
            code: "INVALID_PHONE_FORMAT",
          });
        }
        phoneE164 = phoneNorm.startsWith("+") ? phoneNorm : `+${phoneNorm}`;
      }
      // Require at least a valid email or a valid phone
      if (!phoneE164 && !/.+@.+\..+/.test(emailStr)) {
        return res.status(400).json({
          error: "Provide at least a valid email or phone number",
          code: "VALIDATION_ERROR",
        });
      }
      // Normalize email back into details
      if (emailStr) detailsObj.email = emailStr;
      const { rows } = await pool.query(
        `INSERT INTO workspace_contacts (workspace_id, first_name, last_name, phone_e164, details, created_by)
         VALUES ($1,$2,$3,$4,$5,$6)
         RETURNING id, first_name, last_name, phone_e164, details, created_at`,
        [
          req.workspace.id,
          String(first_name).trim(),
          String(last_name).trim(),
          phoneE164,
          JSON.stringify(detailsObj),
          req.user.id,
        ],
      );

      try {
        if (phoneE164) {
          const phoneHash = hashPhone(phoneE164);
          if (phoneHash) {
            const evidence = {
              method: "contact_created",
              ip: req.ip || null,
              user_agent: req.get("user-agent") || null,
              at: new Date().toISOString(),
              created_by: req.user.id,
            };
            await pool.query(
              `INSERT INTO contact_opt_ins (workspace_id, channel, phone_hash, evidence)
             VALUES ($1, 'whatsapp', $2, $3)
             ON CONFLICT (workspace_id, channel, phone_hash) DO NOTHING`,
              [req.workspace.id, phoneHash, JSON.stringify(evidence)],
            );
          }
        }
      } catch (optinErr) {
        logger.warn("Failed to record opt-in evidence", {
          error: optinErr.message,
        });
      }

      try {
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "WORKSPACE_CONTACT_CREATED",
          targetType: "workspace",
          targetId: null,
          workspaceId: req.workspace.id,
          metadata: {
            contact_id: rows[0].id,
            phone_masked: phoneE164 ? maskPhone(phoneE164) : null,
          },
        });
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }

      res.status(201).json(rows[0]);
    } catch (e) {
      if (e.code === "23505")
        return res.status(400).json({
          error: "Phone already exists in this workspace",
          code: "DUPLICATE_PHONE",
        });
      logger.error("Create contact error", { error: e.message });
      res
        .status(500)
        .json({ error: "Failed to create contact", code: "INTERNAL_ERROR" });
    }
  },
);
router.put(
  "/api/v1/workspaces/:id/contacts/:contactId",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  async (req, res) => {
    // Allow admin and workspace_manager to update contacts
    const role = req.authz?.workspaceRole;
    if (!role || !["admin", "workspace_manager"].includes(role)) {
      return res
        .status(403)
        .json({ error: "Forbidden: insufficient role", code: "FORBIDDEN" });
    }
    try {
      const { first_name, last_name, phone_e164, details } = req.body || {};
      // Validation: require at least one of valid email or valid phone; phone E.164 if provided; names if provided must be non-empty
      const detailsObj = details && typeof details === "object" ? details : {};
      const emailStr = String(detailsObj.email || "")
        .trim()
        .toLowerCase();
      const hasPhoneField = Object.prototype.hasOwnProperty.call(
        req.body || {},
        "phone_e164",
      );
      const phoneNorm = String(phone_e164 || "").trim();
      if (phoneNorm && !/^\+?[1-9]\d{6,14}$/.test(phoneNorm)) {
        return res.status(400).json({
          error: "Invalid phone format (E.164 expected)",
          code: "INVALID_PHONE_FORMAT",
        });
      }
      const phoneE164 = phoneNorm
        ? phoneNorm.startsWith("+")
          ? phoneNorm
          : `+${phoneNorm}`
        : null;
      if (!phoneE164 && emailStr && !/.+@.+\..+/.test(emailStr)) {
        return res
          .status(400)
          .json({ error: "Invalid email format", code: "VALIDATION_ERROR" });
      }
      if (!phoneE164 && (!emailStr || !/.+@.+\..+/.test(emailStr))) {
        return res.status(400).json({
          error: "Provide at least a valid email or phone number",
          code: "VALIDATION_ERROR",
        });
      }
      const fields = [];
      const params = [];
      let p = 1;

      if (first_name && String(first_name).trim()) {
        fields.push(`first_name = $${p++}`);
        params.push(String(first_name).trim());
      }
      if (last_name && String(last_name).trim()) {
        fields.push(`last_name = $${p++}`);
        params.push(String(last_name).trim());
      }
      if (hasPhoneField) {
        fields.push(`phone_e164 = $${p++}`);
        params.push(phoneE164);
      }
      if (details !== undefined) {
        fields.push(`details = $${p++}`);
        // Normalize email back into details
        if (emailStr) detailsObj.email = emailStr;
        params.push(JSON.stringify(detailsObj || {}));
      }

      if (fields.length === 0) {
        return res
          .status(400)
          .json({ error: "No fields to update", code: "VALIDATION_ERROR" });
      }

      fields.push(`updated_at = NOW()`);
      params.push(req.workspace.id, req.params.contactId);

      const { rows } = await pool.query(
        `UPDATE workspace_contacts SET ${fields.join(", ")} WHERE workspace_id = $${p} AND id = $${p + 1} RETURNING id, first_name, last_name, phone_e164, details, created_at, updated_at`,
        params,
      );

      if (rows.length === 0) {
        return res
          .status(404)
          .json({ error: "Contact not found", code: "CONTACT_NOT_FOUND" });
      }

      // Audit event for contact update
      try {
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "WORKSPACE_CONTACT_UPDATED",
          targetType: "workspace",
          targetId: null,
          workspaceId: req.workspace.id,
          metadata: {
            contact_id: rows[0].id,
            fields_updated: fields.slice(0, -1).map((f) => f.split(" ")[0]),
          },
        });
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }

      res.json(rows[0]);
    } catch (e) {
      if (e.code === "23505") {
        return res.status(400).json({
          error: "Phone already exists in this workspace",
          code: "DUPLICATE_PHONE",
        });
      }
      logger.error("Update contact error", { error: e.message });
      res
        .status(500)
        .json({ error: "Failed to update contact", code: "INTERNAL_ERROR" });
    }
  },
);

router.delete(
  "/api/v1/workspaces/:id/contacts/:contactId",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  async (req, res) => {
    // Allow admin and workspace_manager to delete contacts
    const role = req.authz?.workspaceRole;
    if (!role || !["admin", "workspace_manager"].includes(role)) {
      return res
        .status(403)
        .json({ error: "Forbidden: insufficient role", code: "FORBIDDEN" });
    }
    try {
      const { rows } = await pool.query(
        `DELETE FROM workspace_contacts WHERE workspace_id = $1 AND id = $2 RETURNING phone_e164`,
        [req.workspace.id, req.params.contactId],
      );

      // Audit event for contact deletion
      if (rows.length > 0) {
        try {
          await writeAudit({
            actorUserId: req.user.id,
            subjectUserId: req.user.id,
            action: "WORKSPACE_CONTACT_DELETED",
            targetType: "workspace",
            targetId: null,
            workspaceId: req.workspace.id,
            metadata: {
              contact_id: req.params.contactId,
              phone_masked: maskPhone(rows[0].phone_e164),
            },
          });
        } catch (_err) {
          logger.debug("Non-critical operation failed", {
            error: _err.message,
          });
        }

        // Clean up contact ID from all contact groups
        try {
          const deletedContactId = req.params.contactId;
          const settingsRes = await pool.query(
            `SELECT contact_groups FROM workspace_settings WHERE workspace_id = $1`,
            [req.workspace.id],
          );

          if (
            settingsRes.rows.length > 0 &&
            settingsRes.rows[0].contact_groups
          ) {
            const contactGroups = settingsRes.rows[0].contact_groups;
            let modified = false;

            const updatedGroups = contactGroups.map((group) => {
              const emailContactIds = Array.isArray(group.email_contact_ids)
                ? group.email_contact_ids.filter(
                    (id) => id !== deletedContactId,
                  )
                : [];
              const whatsappContactIds = Array.isArray(
                group.whatsapp_contact_ids,
              )
                ? group.whatsapp_contact_ids.filter(
                    (id) => id !== deletedContactId,
                  )
                : [];

              if (
                (Array.isArray(group.email_contact_ids) &&
                  group.email_contact_ids.includes(deletedContactId)) ||
                (Array.isArray(group.whatsapp_contact_ids) &&
                  group.whatsapp_contact_ids.includes(deletedContactId))
              ) {
                modified = true;
              }

              return {
                ...group,
                email_contact_ids: emailContactIds,
                whatsapp_contact_ids: whatsappContactIds,
              };
            });

            if (modified) {
              await pool.query(
                `UPDATE workspace_settings SET contact_groups = $1 WHERE workspace_id = $2`,
                [JSON.stringify(updatedGroups), req.workspace.id],
              );
              logger.info(
                `Removed contact ${deletedContactId} from contact groups in workspace ${req.workspace.id}`,
              );
            }
          }
        } catch (cleanupErr) {
          logger.error("Failed to clean up contact from groups", {
            error: cleanupErr.message,
            workspace_id: req.workspace.id,
            contact_id: req.params.contactId,
          });
          // Don't fail the delete if cleanup fails
        }
      }

      res.json({ success: true });
    } catch (e) {
      logger.error("Delete contact error", { error: e.message });
      res
        .status(500)
        .json({ error: "Failed to delete contact", code: "INTERNAL_ERROR" });
    }
  },
);

module.exports = router;
