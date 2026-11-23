"use strict";

const router = require("express").Router();
const { pool } = require("../db/database");
const { logger } = require("../utils/logger");
const { writeAudit } = require("../services/audit");
const { requireAuth } = require("../middleware/auth");
const { getApiLimiter } = require("../middleware/rateLimit");
const {
  validateMappingPayload,
  SSO_MAPPING_ROLES,
  UUID_RE,
} = require("../sso/mapping-validation");
const { listProviders } = require("../sso/provider-registry.js");
const { runMappingSimulation } = require("../sso/mapping-simulator.js");

async function requireAnyAdmin(req, res, next) {
  try {
    if (!req.user?.id) {
      return res
        .status(401)
        .json({ error: "Unauthorized", code: "UNAUTHORIZED" });
    }
    const { rows } = await pool.query(
      "SELECT is_admin FROM users WHERE id = $1 LIMIT 1",
      [req.user.id],
    );
    if (rows.length === 0 || rows[0].is_admin !== true) {
      return res
        .status(403)
        .json({ error: "Admin access required", code: "FORBIDDEN" });
    }
    return next();
  } catch (err) {
    logger.warn("SSO mappings authorization check failed", {
      error: err?.message,
      userId: req.user?.id,
    });
    return res
      .status(500)
      .json({ error: "Authorization check failed", code: "INTERNAL_ERROR" });
  }
}

function rowToMapping(row) {
  return {
    id: row.id,
    provider_slug: row.provider_slug,
    idp_group: row.idp_group,
    role: row.role,
    workspace_id: row.workspace_id,
    priority: row.priority,
    created_at: row.created_at ? row.created_at.toISOString() : null,
    created_by: row.created_by_email || null,
    updated_at: row.updated_at ? row.updated_at.toISOString() : null,
  };
}

const SSO_MAPPING_BASE_SELECT = `
  SELECT m.id, m.provider_slug, m.idp_group, m.role, m.workspace_id,
         m.priority, m.created_at, m.updated_at,
         u.email AS created_by_email
`;

async function mutateMapping(req, res, { action, statement, params, value, status = 200 }) {
  let client;
  let discard = false;
  try {
    client = await pool.connect();
    await client.query("BEGIN");
    const { rows } = await client.query(
      `WITH changed AS (${statement} RETURNING *)
       ${SSO_MAPPING_BASE_SELECT}
       FROM changed m LEFT JOIN users u ON u.id = m.created_by`,
      params,
    );
    if (!rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Mapping not found" });
    }
    const mapping = rowToMapping(rows[0]);
    await writeAudit({
      client,
      actorUserId: req.user.id,
      subjectUserId: null,
      action,
      targetType: "sso_group_mapping",
      channel: "api",
      workspaceId: mapping.workspace_id,
      metadata: {
        mapping_id: mapping.id,
        provider_slug: mapping.provider_slug,
        idp_group: mapping.idp_group,
        role: mapping.role,
        workspace_id: mapping.workspace_id,
        priority: mapping.priority,
      },
    });
    await client.query("COMMIT");
    const response = req.method === "DELETE" ? { ok: true, removed: mapping } : mapping;
    return res.status(status).json(response);
  } catch (err) {
    if (client) {
      try {
        await client.query("ROLLBACK");
      } catch {
        discard = true;
      }
    }
    if (err.code === "23505" && err.constraint === "uniq_sso_group_mapping") {
      return res.status(409).json({ error: "An equivalent mapping already exists" });
    }
    if (err.code === "23503" && err.constraint === "sso_group_role_mappings_workspace_id_fkey") {
      return res.status(400).json({ error: `unknown workspace_id: ${value.workspace_id}` });
    }
    if (err.code === "23503" && err.constraint === "sso_group_role_mappings_provider_slug_fkey") {
      return res.status(400).json({ error: `unknown provider_slug: ${value.provider_slug}` });
    }
    logger.error("SSO group mapping mutation failed", { error: err.message, action });
    return res.status(500).json({ error: "Failed to change SSO group mapping", code: "INTERNAL_ERROR" });
  } finally {
    client?.release(discard);
  }
}

router.get(
  "/api/admin/sso/group-mappings",
  getApiLimiter(),
  requireAuth,
  requireAnyAdmin,
  async (req, res) => {
    try {
      const mappingsResult = await pool.query(
        `${SSO_MAPPING_BASE_SELECT}
         FROM sso_group_role_mappings m LEFT JOIN users u ON u.id = m.created_by
         ORDER BY m.created_at ASC`,
      );
      const workspacesResult = await pool.query(
        "SELECT id, name FROM workspaces ORDER BY name ASC",
      );
      const registryProviders = await listProviders(pool, { includeStatuses: false });
      res.json({
        mappings: mappingsResult.rows.map(rowToMapping),
        workspaces: workspacesResult.rows.map((w) => ({
          id: w.id,
          name: w.name,
        })),
        roles: SSO_MAPPING_ROLES,
        providers: registryProviders.map((p) => ({
          slug: p.slug,
          displayName: p.displayName,
          type: p.type,
        })),
      });
    } catch (err) {
      logger.error("SSO mappings list failed", { error: err.message });
      res.status(500).json({
        error: "Failed to fetch SSO group mappings",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.post(
  "/api/admin/sso/group-mappings/simulate",
  getApiLimiter(),
  requireAuth,
  requireAnyAdmin,
  async (req, res) => {
    try {
      const result = await runMappingSimulation(pool, {
        providerSlug: req.body?.provider_slug,
        groups: req.body?.groups,
        strictSyncPreview: req.body?.strict_sync_preview === true,
      });
      if (result.error) {
        return res.status(400).json({ error: result.error });
      }
      return res.json(result);
    } catch (err) {
      logger.error("SSO mapping simulate failed", { error: err.message });
      return res.status(500).json({
        error: "Failed to simulate SSO group mappings",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.post(
  "/api/admin/sso/group-mappings",
  getApiLimiter(),
  requireAuth,
  requireAnyAdmin,
  (req, res) => {
    const { error, value } = validateMappingPayload(req.body);
    if (error) return res.status(400).json({ error });
    return mutateMapping(req, res, {
      action: "SSO_GROUP_MAPPING_CREATED",
      status: 201,
      statement: `INSERT INTO sso_group_role_mappings
                    (provider_slug, idp_group, role, workspace_id, priority, created_by)
                  VALUES ($1, $2, $3, $4, $5, $6)`,
      params: [value.provider_slug, value.idp_group, value.role, value.workspace_id, value.priority, req.user.id],
      value,
    });
  },
);

router.put(
  "/api/admin/sso/group-mappings/:id",
  getApiLimiter(),
  requireAuth,
  requireAnyAdmin,
  (req, res) => {
    const { id } = req.params;
    if (!UUID_RE.test(id)) return res.status(400).json({ error: "Invalid mapping ID" });
    const { error, value } = validateMappingPayload(req.body);
    if (error) return res.status(400).json({ error });
    return mutateMapping(req, res, {
      action: "SSO_GROUP_MAPPING_UPDATED",
      statement: `UPDATE sso_group_role_mappings
                     SET provider_slug = $1, idp_group = $2, role = $3,
                         workspace_id = $4, priority = $5, updated_at = NOW()
                   WHERE id = $6`,
      params: [value.provider_slug, value.idp_group, value.role, value.workspace_id, value.priority, id],
      value,
    });
  },
);

router.delete(
  "/api/admin/sso/group-mappings/:id",
  getApiLimiter(),
  requireAuth,
  requireAnyAdmin,
  (req, res) => {
    const { id } = req.params;
    if (!UUID_RE.test(id)) return res.status(400).json({ error: "Invalid mapping ID" });
    return mutateMapping(req, res, {
      action: "SSO_GROUP_MAPPING_DELETED",
      statement: "DELETE FROM sso_group_role_mappings WHERE id = $1",
      params: [id],
    });
  },
);

module.exports = router;
