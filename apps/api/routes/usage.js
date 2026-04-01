const { pool } = require("../db/database");
const { logger } = require("../utils/logger");
const { writeAudit } = require("../services/audit");
const { requireAuth } = require("../middleware/auth");
const { getApiLimiter } = require("../middleware/rateLimit");
const {
  loadWorkspace,
  requireWorkspaceMembership,
} = require("../services/rbac");
const { TOKEN_LIMITS, ALERT_LIMITS } = require("../config/constants");
const {
  getWorkspaceIntegrationQuota,
  MEMBER_LIMITS,
  WORKSPACE_LIMITS,
} = require("../services/planLimits");
const { requeueAlertsCore } = require("../services/alertQueue");
const User = require("../db/models/User");
const Token = require("../db/models/Token");

const router = require("express").Router();

// --- ACCOUNT MANAGEMENT ROUTES ---

// Export user data (GDPR compliance)
router.get(
  "/api/account/export",
  getApiLimiter(),
  requireAuth,
  async (req, res) => {
    try {
      const scope = String(req.query.scope || "user").toLowerCase();
      const workspaceIdParam = req.query.workspace_id
        ? String(req.query.workspace_id)
        : null;

      // 1) Base: user profile and user-level settings always included
      const user = await User.findById(req.user.id);

      const userSettings = {
        plan: user.plan || "oss",
        alert_thresholds: user.alert_thresholds,
        email_alerts_enabled: user.email_alerts_enabled,
        webhooks_alerts_enabled: user.webhooks_alerts_enabled,
        whatsapp_alerts_enabled: user.whatsapp_alerts_enabled || false,
        phone_e164: user.phone_e164 || null,
        // Note: export webhook_urls with urlHash only and no raw URL for privacy
        webhook_urls: Array.isArray(user.webhook_urls)
          ? user.webhook_urls.map((w) => ({
              name: w.name || null,
              kind: w.kind || "generic",
              urlHash: w.url
                ? require("crypto")
                    .createHash("sha256")
                    .update(String(w.url))
                    .digest("hex")
                : null,
            }))
          : [],
        two_factor_enabled: user.two_factor_enabled,
        last_limit_reminder: user.last_limit_reminder,
      };

      const formatWorkspaceSettings = (row) => {
        if (!row) return null;
        const hashedWebhooks = Array.isArray(row.webhook_urls)
          ? row.webhook_urls.map((w) => ({
              name: w.name || null,
              kind: w.kind || "generic",
              urlHash: w.url
                ? require("crypto")
                    .createHash("sha256")
                    .update(String(w.url))
                    .digest("hex")
                : null,
              verified: w.verified === true,
            }))
          : [];
        return {
          alert_thresholds: row.alert_thresholds || null,
          email_alerts_enabled: row.email_alerts_enabled !== false,
          webhooks_alerts_enabled: row.webhooks_alerts_enabled === true,
          webhook_urls: hashedWebhooks,
          whatsapp_alerts_enabled: row.whatsapp_alerts_enabled === true,
          delivery_window_start: row.delivery_window_start || null,
          delivery_window_end: row.delivery_window_end || null,
          delivery_window_tz: row.delivery_window_tz || null,
          contact_groups: Array.isArray(row.contact_groups)
            ? row.contact_groups.map((g) => {
                if (Array.isArray(g.webhook_names)) return g;
                if (g.webhook_name)
                  return {
                    ...g,
                    webhook_names: [g.webhook_name],
                    webhook_name: undefined,
                  };
                return { ...g, webhook_names: [] };
              })
            : [],
          default_contact_group_id: row.default_contact_group_id || null,
        };
      };

      const formatTokenForExport = (t) => ({
        id: t.id,
        name: t.name,
        type: t.type,
        category: t.category,
        expiration: t.expiration,
        expiresAt: t.expiration,
        section: t.section,
        domains: t.domains,
        location: t.location,
        used_by: t.used_by,
        issuer: t.issuer,
        serial_number: t.serial_number,
        subject: t.subject,
        key_size: t.key_size,
        algorithm: t.algorithm,
        license_type: t.license_type,
        vendor: t.vendor,
        cost: t.cost,
        renewal_url: t.renewal_url,
        renewal_date: t.renewal_date,
        contacts: t.contacts,
        description: t.description,
        notes: t.notes,
        contact_group_id: t.contact_group_id || null,
        privileges: t.privileges,
        lastUsed: t.last_used,
        importedAt: t.imported_at,
        createdAt: t.created_at,
        updatedAt: t.updated_at,
      });

      // 2) Scope handling
      let exportWorkspaces = [];
      let scopeDescription = "";
      if (scope === "organization") {
        // Admins/Managers: export all workspaces where role is admin or manager
        const ws = await pool.query(
          `SELECT wm.workspace_id, w.name, wm.role
           FROM workspace_memberships wm
           JOIN workspaces w ON w.id = wm.workspace_id
           WHERE wm.user_id = $1 AND wm.role IN ('admin','workspace_manager')
           ORDER BY w.created_at ASC`,
          [req.user.id],
        );
        exportWorkspaces = ws.rows;
        scopeDescription = "Organization export for admin/manager workspaces";
      } else if (scope === "workspace" && workspaceIdParam) {
        // Validate membership and role
        const m = await pool.query(
          "SELECT wm.role, w.created_by FROM workspace_memberships wm JOIN workspaces w ON w.id = wm.workspace_id WHERE wm.workspace_id=$1 AND wm.user_id=$2",
          [workspaceIdParam, req.user.id],
        );
        if (m.rowCount === 0)
          return res
            .status(403)
            .json({ error: "Forbidden: not a member of requested workspace" });
        const role = String(m.rows[0].role || "").toLowerCase();
        const isPersonal =
          String(m.rows[0].created_by || "") === String(req.user.id);
        if (role === "viewer" && !isPersonal) {
          return res.status(403).json({
            error:
              "Forbidden: viewers can only export their personal workspace",
          });
        }
        exportWorkspaces = [
          { workspace_id: workspaceIdParam, name: null, role },
        ];
        scopeDescription = "Single workspace export";
      } else {
        // Default: include user's memberships, but for viewers only include personal workspace
        const ws = await pool.query(
          `SELECT wm.workspace_id, wm.role, w.name, w.created_by, COALESCE(w.is_personal_default, FALSE) AS is_personal_default
             FROM workspace_memberships wm
             JOIN workspaces w ON w.id = wm.workspace_id
            WHERE wm.user_id = $1
            ORDER BY w.created_at ASC`,
          [req.user.id],
        );
        exportWorkspaces = ws.rows.filter((w) => {
          const role = String(w.role || "").toLowerCase();
          const isOwner = String(w.created_by || "") === String(req.user.id);
          const isPersonal = isOwner || w.is_personal_default === true;
          if (role === "viewer" && !isPersonal) return false;
          return true;
        });
        scopeDescription =
          "User export: profile, user settings, and workspaces you belong to (viewers: personal workspace only)";
      }

      // 3) Build export payload
      // User-owned tokens (legacy/personal only, exclude workspace-scoped to avoid duplication)
      const userOwnedTokens = await Token.findByUserId(req.user.id);
      const userTokensExport = userOwnedTokens
        .filter((token) => !token.workspace_id)
        .map((token) => ({
          id: token.id,
          name: token.name,
          type: token.type,
          category: token.category,
          expiration: token.expiration,
          expiresAt: token.expiresAt || token.expiration,
          section: token.section,
          domains: token.domains,
          location: token.location,
          used_by: token.used_by,
          issuer: token.issuer,
          serial_number: token.serial_number,
          subject: token.subject,
          key_size: token.key_size,
          algorithm: token.algorithm,
          license_type: token.license_type,
          vendor: token.vendor,
          cost: token.cost,
          renewal_url: token.renewal_url,
          renewal_date: token.renewal_date,
          contacts: token.contacts,
          description: token.description,
          notes: token.notes,
          contact_group_id: token.contact_group_id || null,
          privileges: token.privileges,
          lastUsed: token.last_used,
          importedAt: token.imported_at,
          createdAt: token.created_at,
          updatedAt: token.updated_at,
        }));

      const workspaces = [];
      if (exportWorkspaces.length > 0) {
        const wsIds = exportWorkspaces.map((w) => w.workspace_id || w.id || w);

        const [
          allSettingsRes,
          allContactsRes,
          allMembershipsRes,
          allTokensRes,
          allWorkspacesRes,
        ] = await Promise.all([
          pool.query(
            "SELECT * FROM workspace_settings WHERE workspace_id = ANY($1::uuid[])",
            [wsIds],
          ),
          pool.query(
            "SELECT id, first_name, last_name, phone_e164, details, created_at, workspace_id FROM workspace_contacts WHERE workspace_id = ANY($1::uuid[]) ORDER BY last_name, first_name",
            [wsIds],
          ),
          pool.query(
            "SELECT workspace_id, role FROM workspace_memberships WHERE user_id = $1 AND workspace_id = ANY($2::uuid[])",
            [req.user.id, wsIds],
          ),
          pool.query(
            "SELECT * FROM tokens WHERE workspace_id = ANY($1::uuid[])",
            [wsIds],
          ),
          pool.query(
            "SELECT id, created_by, COALESCE(is_personal_default, FALSE) AS is_personal_default FROM workspaces WHERE id = ANY($1::uuid[])",
            [wsIds],
          ),
        ]);

        const settingsMap = new Map();
        for (const row of allSettingsRes.rows) {
          settingsMap.set(String(row.workspace_id), row);
        }

        const contactsMap = new Map();
        for (const row of allContactsRes.rows) {
          const key = String(row.workspace_id);
          if (!contactsMap.has(key)) contactsMap.set(key, []);
          contactsMap.get(key).push({
            id: row.id,
            first_name: row.first_name,
            last_name: row.last_name,
            phone_e164: row.phone_e164,
            details: row.details,
            created_at: row.created_at,
          });
        }

        const membershipMap = new Map();
        for (const row of allMembershipsRes.rows) {
          membershipMap.set(String(row.workspace_id), row.role);
        }

        const tokensMap = new Map();
        for (const row of allTokensRes.rows) {
          const key = String(row.workspace_id);
          if (!tokensMap.has(key)) tokensMap.set(key, []);
          tokensMap.get(key).push(row);
        }

        const workspaceInfoMap = new Map();
        for (const row of allWorkspacesRes.rows) {
          workspaceInfoMap.set(String(row.id), row);
        }

        for (const w of exportWorkspaces) {
          const wsId = String(w.workspace_id || w.id || w);
          const settings = formatWorkspaceSettings(
            settingsMap.get(wsId) || null,
          );
          const workspaceContacts = contactsMap.get(wsId) || [];

          const role = w.role || membershipMap.get(wsId) || null;

          let tokens = [];
          const isOwner = w.created_by
            ? String(w.created_by) === String(req.user.id)
            : false;
          const includeAll =
            role === "admin" || role === "workspace_manager" || isOwner;
          if (includeAll) {
            tokens = (tokensMap.get(wsId) || []).map(formatTokenForExport);
          } else if (role === "viewer") {
            const wsInfo = workspaceInfoMap.get(wsId) || {};
            const isPersonal =
              String(wsInfo.created_by || "") === String(req.user.id) ||
              wsInfo.is_personal_default === true;
            tokens = isPersonal
              ? (tokensMap.get(wsId) || []).map(formatTokenForExport)
              : [];
          }
          workspaces.push({
            id: wsId,
            name: w.name || null,
            role: role || null,
            settings,
            contacts: workspaceContacts,
            tokens,
          });
        }
      }

      const exportData = {
        exportInfo: {
          scope,
          scopeDescription,
          generatedAt: new Date().toISOString(),
          note: "This export includes your personal profile and settings. When using organization/workspace scope, it also includes workspace settings (with webhook URLs hashed), contact groups, and all tokens within allowed workspaces. For activity history, use the separate audit export feature.",
        },
        user: {
          id: user.id,
          displayName: user.display_name,
          email: user.email,
          email_original: user.email_original,
          auth_method: user.auth_method,
          email_verified: user.email_verified,
          createdAt: user.created_at,
          updatedAt: user.updated_at,
        },
        account_settings: userSettings,
        user_tokens: userTokensExport,
        workspaces,
      };

      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="tokentimer-data-${new Date().toISOString().split("T")[0]}.json"`,
      );
      res.send(JSON.stringify(exportData, null, 2));
    } catch (error) {
      logger.error("Error exporting user data:", {
        error: error.message,
        stack: error.stack,
      });
      res.status(500).json({ error: "Failed to export data" });
    }
  },
);

// Export audit events (pretty-printed JSON)
router.get(
  "/api/account/export-audit",
  getApiLimiter(),
  requireAuth,
  async (req, res) => {
    try {
      const scope = String(req.query.scope || "").toLowerCase();
      const workspaceIdParam = req.query.workspace_id
        ? String(req.query.workspace_id)
        : null;
      const limit = Math.max(
        1,
        Math.min(100000, parseInt(req.query.limit || "10000", 10)),
      );
      const sinceRaw = req.query.since ? String(req.query.since) : null;
      let since = null;
      if (sinceRaw) {
        const d = new Date(sinceRaw);
        if (!Number.isNaN(d.getTime())) since = d.toISOString();
      }
      const actionFilter = req.query.action
        ? String(req.query.action).trim()
        : null;
      const searchQuery = req.query.query
        ? String(req.query.query).trim()
        : null;

      // Core: organization scope is available to all users (no plan gating)

      let items = [];
      if (scope === "organization") {
        // Admins can export organization-wide audit (across their admin workspaces)
        const ws = await pool.query(
          "SELECT workspace_id FROM workspace_memberships WHERE user_id=$1 AND role='admin'",
          [req.user.id],
        );
        const wsIds = ws.rows.map((r) => r.workspace_id);
        if (wsIds.length === 0) {
          items = [];
        } else {
          const params = [wsIds, limit];
          const whereClauses = [];
          let paramIndex = 3;

          if (since) {
            whereClauses.push(`ae.occurred_at >= $${paramIndex}`);
            params.push(since);
            paramIndex++;
          }
          if (actionFilter) {
            whereClauses.push(`ae.action = $${paramIndex}`);
            params.push(actionFilter);
            paramIndex++;
          }
          if (searchQuery) {
            whereClauses.push(
              `(ae.action ILIKE $${paramIndex} OR ae.metadata::text ILIKE $${paramIndex})`,
            );
            const escapedSearch = searchQuery.replace(/[%_\\]/g, "\\$&");
            params.push(`%${escapedSearch}%`);
            paramIndex++;
          }

          const whereClause =
            whereClauses.length > 0 ? ` AND ${whereClauses.join(" AND ")}` : "";

          const { rows } = await pool.query(
            `SELECT ae.id,
                    ae.occurred_at AS occurred_at,
                    ae.actor_user_id,
                    u.display_name AS actor_display_name,
                    ae.subject_user_id,
                    ae.action,
                    ae.target_type,
                    ae.target_id,
                    ae.channel,
                    ae.metadata,
                    COALESCE(ae.workspace_id, (ae.metadata->>'workspaceId')::uuid) AS workspace_id,
                    w.name AS workspace_name
               FROM audit_events ae
               LEFT JOIN users u ON u.id = ae.actor_user_id
               LEFT JOIN workspaces w ON w.id = COALESCE(ae.workspace_id, (ae.metadata->>'workspaceId')::uuid)
              WHERE (ae.workspace_id = ANY($1) OR (ae.metadata->>'workspaceId')::uuid = ANY($1))${whereClause}
              ORDER BY ae.occurred_at DESC
              LIMIT $2`,
            params,
          );
          items = rows;
        }
      } else if (scope === "workspace" && workspaceIdParam) {
        // Check membership and role
        const m = await pool.query(
          "SELECT wm.role, w.created_by FROM workspace_memberships wm JOIN workspaces w ON w.id = wm.workspace_id WHERE wm.workspace_id=$1 AND wm.user_id=$2",
          [workspaceIdParam, req.user.id],
        );
        if (m.rowCount === 0)
          return res
            .status(403)
            .json({ error: "Forbidden: not a member of requested workspace" });
        const role = String(m.rows[0].role || "").toLowerCase();
        const isOwner =
          String(m.rows[0].created_by || "") === String(req.user.id);
        const canExport =
          role === "admin" || role === "workspace_manager" || isOwner;
        if (!canExport)
          return res.status(403).json({
            error: "Forbidden: insufficient role to export workspace audit",
          });

        const params = [workspaceIdParam, limit];
        const whereClauses = [];
        let paramIndex = 3;

        if (since) {
          whereClauses.push(`ae.occurred_at >= $${paramIndex}`);
          params.push(since);
          paramIndex++;
        }
        if (actionFilter) {
          whereClauses.push(`ae.action = $${paramIndex}`);
          params.push(actionFilter);
          paramIndex++;
        }
        if (searchQuery) {
          whereClauses.push(
            `(ae.action ILIKE $${paramIndex} OR ae.metadata::text ILIKE $${paramIndex})`,
          );
          const escapedSearch = searchQuery.replace(/[%_\\]/g, "\\$&");
          params.push(`%${escapedSearch}%`);
          paramIndex++;
        }

        const whereClause =
          whereClauses.length > 0 ? ` AND ${whereClauses.join(" AND ")}` : "";

        const { rows } = await pool.query(
          `SELECT ae.id,
                  ae.occurred_at AS occurred_at,
                  ae.actor_user_id,
                  u.display_name AS actor_display_name,
                  ae.subject_user_id,
                  ae.action,
                  ae.target_type,
                  ae.target_id,
                  ae.channel,
                  ae.metadata,
                  COALESCE(ae.workspace_id, (ae.metadata->>'workspaceId')::uuid) AS workspace_id,
                  w.name AS workspace_name
             FROM audit_events ae
             LEFT JOIN users u ON u.id = ae.actor_user_id
             LEFT JOIN workspaces w ON w.id = COALESCE(ae.workspace_id, (ae.metadata->>'workspaceId')::uuid)
            WHERE (ae.workspace_id = $1 OR (ae.metadata->>'workspaceId')::uuid = $1)${whereClause}
            ORDER BY ae.occurred_at DESC
            LIMIT $2`,
          params,
        );
        items = rows;
      } else {
        // Default: user-only export (their subject events)
        const params = [req.user.id, limit];
        const whereClauses = [];
        let paramIndex = 3;

        if (since) {
          whereClauses.push(`ae.occurred_at >= $${paramIndex}`);
          params.push(since);
          paramIndex++;
        }
        if (actionFilter) {
          whereClauses.push(`ae.action = $${paramIndex}`);
          params.push(actionFilter);
          paramIndex++;
        }
        if (searchQuery) {
          whereClauses.push(
            `(ae.action ILIKE $${paramIndex} OR ae.metadata::text ILIKE $${paramIndex})`,
          );
          const escapedSearch = searchQuery.replace(/[%_\\]/g, "\\$&");
          params.push(`%${escapedSearch}%`);
          paramIndex++;
        }

        const whereClause =
          whereClauses.length > 0 ? ` AND ${whereClauses.join(" AND ")}` : "";

        const { rows } = await pool.query(
          `SELECT ae.id,
                  ae.occurred_at AS occurred_at,
                  ae.actor_user_id,
                  u.display_name AS actor_display_name,
                  ae.subject_user_id,
                  ae.action,
                  ae.target_type,
                  ae.target_id,
                  ae.channel,
                  ae.metadata,
                  COALESCE(ae.workspace_id, (ae.metadata->>'workspaceId')::uuid) AS workspace_id,
                  w.name AS workspace_name
             FROM audit_events ae
             LEFT JOIN users u ON u.id = ae.actor_user_id
             LEFT JOIN workspaces w ON w.id = COALESCE(ae.workspace_id, (ae.metadata->>'workspaceId')::uuid)
            WHERE ae.subject_user_id = $1${whereClause}
            ORDER BY ae.occurred_at DESC
            LIMIT $2`,
          params,
        );
        items = rows;
      }

      const exportData = {
        exportInfo: {
          scope: scope || "user",
          generatedAt: new Date().toISOString(),
          count: items.length,
          note: "Audit events export for the selected scope. Fields: occurredAt, actor_user_id, subject_user_id, action, target_type, target_id, channel, metadata, workspace_id.",
        },
        events: items,
      };

      const fmt = String(req.query.format || "").toLowerCase();
      const wantsCsv =
        fmt === "csv" || (req.headers["accept"] || "").includes("text/csv");
      if (wantsCsv) {
        const headers = [
          "id",
          "occurred_at",
          "actor_display_name",
          "action",
          "target_type",
          "target_id",
          "channel",
          "workspace_id",
          "workspace_name",
          "metadata",
        ];
        const escape = (val) => {
          const s = val == null ? "" : String(val);
          return `"${s.replace(/"/g, '""').replace(/\n/g, " ")}"`;
        };
        const rows = items.map((ev) => [
          ev.id,
          ev.occurred_at,
          ev.actor_display_name || "",
          ev.action,
          ev.target_type || "",
          ev.target_id != null ? ev.target_id : "",
          ev.channel || "",
          ev.workspace_id || "",
          ev.workspace_name || "",
          ev.metadata ? JSON.stringify(ev.metadata) : "",
        ]);
        const csv = [
          headers.join(","),
          ...rows.map((r) => r.map(escape).join(",")),
        ].join("\n");
        res.setHeader("Content-Type", "text/csv; charset=utf-8");
        res.setHeader(
          "Content-Disposition",
          `attachment; filename="tokentimer-audit-${new Date().toISOString().split("T")[0]}.csv"`,
        );
        return res.send(csv);
      }

      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="tokentimer-audit-${new Date().toISOString().split("T")[0]}.json"`,
      );
      return res.send(JSON.stringify(exportData, null, 2));
    } catch (err) {
      logger.error("Audit export error", {
        error: err?.message,
        userId: req.user.id,
      });
      res.status(500).json({ error: "Failed to export audit events" });
    }
  },
);

router.get(
  "/api/account/plan",
  getApiLimiter(),
  requireAuth,
  async (req, res) => {
    try {
      const userId = req.user.id;
      const workspaceId = req.query?.workspace_id;
      const plan = "oss";
      let tokenCount = 0;

      if (workspaceId) {
        const tokenCountRes = await pool.query(
          "SELECT COUNT(*)::int AS c FROM tokens WHERE workspace_id = $1",
          [workspaceId],
        );
        tokenCount = tokenCountRes.rows?.[0]?.c || 0;
      } else {
        const tokenCountRes = await pool.query(
          `SELECT COUNT(*)::int AS c FROM tokens t
         JOIN workspace_memberships wm ON wm.workspace_id = t.workspace_id
         WHERE wm.user_id = $1`,
          [userId],
        );
        tokenCount = tokenCountRes.rows?.[0]?.c || 0;
      }

      // Count monthly deliveries aggregated at organization level using delivery_log.user_id (resilient to token deletions)
      const monthUsageRes = await pool.query(
        `SELECT COUNT(*)::int AS c
         FROM alert_delivery_log d
        WHERE d.user_id = $1
          AND d.status = 'success'
          AND d.channel <> 'whatsapp'
          AND date_trunc('month', (d.sent_at AT TIME ZONE 'UTC')) = date_trunc('month', (NOW() AT TIME ZONE 'UTC'))`,
        [userId],
      );
      const alertUsageMonth = monthUsageRes.rows?.[0]?.c || 0;

      // Count distinct members across all workspaces owned by this admin
      const membersRes = await pool.query(
        `SELECT COUNT(DISTINCT wm.user_id)::int AS c
         FROM workspaces w
         JOIN workspace_memberships wm ON wm.workspace_id = w.id
        WHERE w.created_by = $1`,
        [userId],
      );
      const memberCount = membersRes.rows?.[0]?.c || 0;

      // Count workspaces owned by this admin
      const wsCountRes = await pool.query(
        "SELECT COUNT(*)::int AS c FROM workspaces WHERE created_by = $1",
        [userId],
      );
      const workspaceCount = wsCountRes.rows?.[0]?.c || 0;

      // Get integration scan quota for specific workspace if provided
      // Integration quota is tracked per workspace, not per user
      let integrationScansUsed = null;
      let integrationScansLimit = null;
      let integrationScansRemaining = null;

      if (workspaceId) {
        // Get integration quota for the workspace (we already have the plan)
        const quota = await getWorkspaceIntegrationQuota(workspaceId, plan);
        integrationScansUsed = quota.used;
        integrationScansLimit = quota.limit;
        integrationScansRemaining = quota.remaining;
      }

      res.json({
        plan,
        tokenCount,
        tokenLimit: TOKEN_LIMITS[plan] ?? TOKEN_LIMITS.oss ?? Infinity,
        alertUsageMonth,
        alertLimitMonth: ALERT_LIMITS[plan] ?? ALERT_LIMITS.oss ?? Infinity,
        memberCount,
        memberLimit: MEMBER_LIMITS[plan] ?? MEMBER_LIMITS.oss ?? Infinity,
        workspaceCount,
        workspaceLimit:
          WORKSPACE_LIMITS[plan] ?? WORKSPACE_LIMITS.oss ?? Infinity,
        // Integration quota is per-workspace; null if no workspace specified
        integrationScansUsed,
        integrationScansLimit,
        integrationScansRemaining,
      });
    } catch (err) {
      logger.error("Plan endpoint error", {
        error: err.message,
        userId: req.user.id,
      });
      res.status(500).json({ error: "Failed to fetch plan info" });
    }
  },
);

// Organization-level usage (admin only)
router.get(
  "/api/organization/usage",
  getApiLimiter(),
  requireAuth,
  async (req, res) => {
    try {
      // Verify the user is an admin of at least one workspace they own
      const adminAny = await pool.query(
        `SELECT 1 FROM workspaces w
        JOIN workspace_memberships wm ON wm.workspace_id = w.id
       WHERE w.created_by = $1 AND wm.user_id = $1 AND wm.role = 'admin'
       LIMIT 1`,
        [req.user.id],
      );
      if (adminAny.rowCount === 0)
        return res.status(403).json({ error: "Forbidden" });

      const monthUsageRes = await pool.query(
        `SELECT COUNT(*)::int AS c
         FROM alert_delivery_log d
        WHERE d.user_id = $1
          AND d.status = 'success'
          AND d.channel <> 'whatsapp'
          AND date_trunc('month', (d.sent_at AT TIME ZONE 'UTC')) = date_trunc('month', (NOW() AT TIME ZONE 'UTC'))`,
        [req.user.id],
      );
      res.json({ monthUsage: monthUsageRes.rows?.[0]?.c || 0 });
    } catch (err) {
      logger.error("Organization usage fetch error", {
        error: err.message,
        userId: req.user.id,
      });
      res.status(500).json({ error: "Failed to fetch organization usage" });
    }
  },
);

// POST /api/alert-queue/requeue { workspace_id?: string }
router.post(
  "/api/alert-queue/requeue",
  getApiLimiter(),
  requireAuth,
  async (req, res) => {
    try {
      const workspaceId = req.body?.workspace_id || null;
      // If workspace specified, ensure caller is admin or manager
      if (workspaceId) {
        const roleRes = await pool.query(
          "SELECT role FROM workspace_memberships WHERE workspace_id = $1 AND user_id = $2",
          [workspaceId, req.user.id],
        );
        const role = roleRes.rows?.[0]?.role || null;
        if (!role || !["admin", "workspace_manager"].includes(String(role))) {
          return res.status(403).json({ error: "Forbidden" });
        }
      }

      try {
        const plan = "oss";
        const monthUsageRes = await pool.query(
          `SELECT COUNT(*)::int AS c
           FROM alert_delivery_log d
          WHERE d.user_id = $1
            AND d.status = 'success'
            AND d.channel <> 'whatsapp'
            AND date_trunc('month', (d.sent_at AT TIME ZONE 'UTC')) = date_trunc('month', (NOW() AT TIME ZONE 'UTC'))`,
          [req.user.id],
        );
        const monthUsage = monthUsageRes.rows?.[0]?.c || 0;
        const limit = ALERT_LIMITS[plan] ?? ALERT_LIMITS.oss ?? Infinity;
        if (monthUsage >= limit) {
          const now = new Date();
          const reset = new Date(now.getFullYear(), now.getMonth() + 1, 1);
          return res.status(400).json({
            error: `Maximum monthly usage reached, please wait until ${reset
              .toISOString()
              .slice(0, 10)} to process or consider upgrading to higher plan`,
            code: "PLAN_ALERT_LIMIT",
            resetDate: reset.toISOString().slice(0, 10),
          });
        }
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }

      // Build scope: either all alerts for user, or those tied to given workspace
      const updated = await requeueAlertsCore({
        userId: req.user.id,
        workspaceId,
      });
      try {
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "ALERTS_BULK_REQUEUED",
          targetType: workspaceId ? "workspace" : "user",
          targetId: workspaceId || req.user.id,
          channel: null,
          workspaceId: workspaceId || null,
          metadata: { updated, scope: workspaceId ? "workspace" : "user" },
        });
      } catch (_err) {
        logger.warn("Audit write failed (ALERTS_BULK_REQUEUED)", {
          error: _err.message,
        });
      }
      return res.json({ updated });
    } catch (e) {
      logger.warn("Bulk requeue error", {
        error: e?.message,
        userId: req.user?.id,
      });
      return res.status(500).json({ error: "Failed to requeue alerts" });
    }
  },
);

// Audit events endpoint (latest events for current user)
// Audit events endpoint
router.get(
  "/api/audit-events",
  getApiLimiter(),
  requireAuth,
  async (req, res) => {
    try {
      const limit = Math.max(
        1,
        Math.min(100000, parseInt(req.query.limit || "100", 10)),
      );
      const offset = Math.max(
        0,
        Math.min(100000, parseInt(req.query.offset || "0", 10)),
      );
      const scope = String(req.query.scope || "").toLowerCase();
      const actionFilter = req.query.action
        ? String(req.query.action).trim()
        : null;
      const searchQuery = req.query.query
        ? String(req.query.query).trim()
        : null;

      // Core: no paid plan gating; access is role-based.
      // Audit access requires manager or admin role in at least one workspace.
      try {
        const roleCheck = await pool.query(
          `SELECT 1 FROM workspace_memberships
         WHERE user_id = $1
         AND role IN ('admin', 'workspace_manager')
         LIMIT 1`,
          [req.user.id],
        );
        if (roleCheck.rowCount === 0) {
          return res
            .status(403)
            .json({ error: "Forbidden: audit requires manager or admin role" });
        }
      } catch (_err) {
        logger.warn("Audit write failed", { error: _err.message });
      }

      if (scope === "organization") {
        // Admins can view organization-wide audit (across their admin workspaces)
        const ws = await pool.query(
          "SELECT workspace_id FROM workspace_memberships WHERE user_id=$1 AND role='admin'",
          [req.user.id],
        );
        const wsIds = ws.rows.map((r) => r.workspace_id);
        if (wsIds.length === 0) return res.json([]);

        let query = `SELECT ae.id, ae.occurred_at, ae.actor_user_id, ae.subject_user_id, ae.action,
                ae.target_type, ae.target_id, ae.channel, ae.metadata,
                u.display_name AS actor_display_name,
                COALESCE(ae.workspace_id, (ae.metadata->>'workspaceId')::uuid) AS workspace_id,
                w.name AS workspace_name
         FROM audit_events ae
         LEFT JOIN users u ON u.id = ae.actor_user_id
         LEFT JOIN workspaces w ON w.id = COALESCE(ae.workspace_id, (ae.metadata->>'workspaceId')::uuid)
         WHERE (ae.workspace_id = ANY($1) OR (ae.metadata->>'workspaceId')::uuid = ANY($1))`;

        const params = [wsIds, limit, offset];
        let paramIndex = 4;

        if (actionFilter) {
          query += ` AND ae.action = $${paramIndex}`;
          params.push(actionFilter);
          paramIndex++;
        }

        if (searchQuery) {
          query += ` AND (ae.action ILIKE $${paramIndex} OR ae.metadata::text ILIKE $${paramIndex})`;
          const escapedSearch = searchQuery.replace(/[%_\\]/g, "\\$&");
          params.push(`%${escapedSearch}%`);
          paramIndex++;
        }

        query += ` ORDER BY ae.occurred_at DESC LIMIT $2 OFFSET $3`;

        const rows = await pool.query(query, params);
        return res.json(rows.rows);
      }

      // Default: user-only view (backwards-compatible)
      let query = `SELECT ae.id, ae.occurred_at, ae.actor_user_id, ae.subject_user_id, ae.action,
              ae.target_type, ae.target_id, ae.channel, ae.metadata,
              u.display_name AS actor_display_name,
              COALESCE(ae.workspace_id, (ae.metadata->>'workspaceId')::uuid) AS workspace_id,
              w.name AS workspace_name
       FROM audit_events ae
       LEFT JOIN users u ON u.id = ae.actor_user_id
       LEFT JOIN workspaces w ON w.id = COALESCE(ae.workspace_id, (ae.metadata->>'workspaceId')::uuid)
       WHERE ae.subject_user_id = $1`;

      const params = [req.user.id, limit, offset];
      let paramIndex = 4;

      if (actionFilter) {
        query += ` AND ae.action = $${paramIndex}`;
        params.push(actionFilter);
        paramIndex++;
      }

      if (searchQuery) {
        query += ` AND (ae.action ILIKE $${paramIndex} OR ae.metadata::text ILIKE $${paramIndex})`;
        const escapedSearch = searchQuery.replace(/[%_\\]/g, "\\$&");
        params.push(`%${escapedSearch}%`);
        paramIndex++;
      }

      query += ` ORDER BY ae.occurred_at DESC LIMIT $2 OFFSET $3`;

      const rows = await pool.query(query, params);
      res.json(rows.rows);
    } catch (err) {
      logger.error("Audit events endpoint error", {
        error: err.message,
        userId: req.user.id,
      });
      res.status(500).json({ error: "Failed to fetch audit events" });
    }
  },
);

// Workspace-scoped audit for managers/admins
router.get(
  "/api/v1/workspaces/:id/audit-events",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  async (req, res) => {
    try {
      const role = req.authz?.workspaceRole;
      if (!role || !["admin", "workspace_manager"].includes(role))
        return res.status(403).json({ error: "Forbidden" });
      const { id } = req.workspace;
      const limit = Math.max(
        1,
        Math.min(500, parseInt(req.query.limit || "100", 10)),
      );
      const offset = Math.max(
        0,
        Math.min(100000, parseInt(req.query.offset || "0", 10)),
      );
      const actionFilter = req.query.action
        ? String(req.query.action).trim()
        : null;
      const searchQuery = req.query.query
        ? String(req.query.query).trim()
        : null;

      let query = `SELECT ae.id, ae.occurred_at, ae.actor_user_id, ae.subject_user_id, ae.action,
              ae.target_type, ae.target_id, ae.channel, ae.metadata,
              u.display_name AS actor_display_name,
              COALESCE(ae.workspace_id, (ae.metadata->>'workspaceId')::uuid) AS workspace_id,
              w.name AS workspace_name
       FROM audit_events ae
       LEFT JOIN users u ON u.id = ae.actor_user_id
       LEFT JOIN workspaces w ON w.id = COALESCE(ae.workspace_id, (ae.metadata->>'workspaceId')::uuid)
       WHERE (ae.workspace_id = $1 OR (ae.metadata->>'workspaceId')::uuid = $1)`;

      const params = [id, limit, offset];
      let paramIndex = 4;

      if (actionFilter) {
        query += ` AND ae.action = $${paramIndex}`;
        params.push(actionFilter);
        paramIndex++;
      }

      if (searchQuery) {
        query += ` AND (ae.action ILIKE $${paramIndex} OR ae.metadata::text ILIKE $${paramIndex})`;
        const escapedSearch = searchQuery.replace(/[%_\\]/g, "\\$&");
        params.push(`%${escapedSearch}%`);
        paramIndex++;
      }

      query += ` ORDER BY ae.occurred_at DESC LIMIT $2 OFFSET $3`;

      const rows = await pool.query(query, params);
      res.json(rows.rows);
    } catch (err) {
      logger.error("Workspace audit events error", {
        error: err.message,
        workspaceId: req.params.id,
      });
      res.status(500).json({ error: "Failed to fetch workspace audit events" });
    }
  },
);

// Legacy user-level alert settings removed; use /api/workspaces/:id/alert-settings instead

module.exports = router;
