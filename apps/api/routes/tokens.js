const { pool } = require("../db/database");
const { logger } = require("../utils/logger");
const { writeAudit } = require("../services/audit");
const { requireAuth } = require("../middleware/auth");
const { getTestApiLimiter } = require("../middleware/rateLimit");
const {
  validateToken,
  handleValidationErrors,
} = require("../middleware/validation");
const Token = require("../db/models/Token");
const { requireNotViewer } = require("../services/rbac");
const { sanitizeForLogging } = require("../utils/sanitize");

const router = require("express").Router();

// --- TOKEN MANAGEMENT ROUTES ---

// Get tokens (scoped by workspace membership). Optional ?workspace_id=...
router.get(
  "/api/tokens",
  getTestApiLimiter(),
  requireAuth,
  async (req, res) => {
    try {
      const userId = req.user.id;
      const workspaceId = req.query.workspace_id
        ? String(req.query.workspace_id)
        : null;
      const limit = Math.max(
        1,
        Math.min(2000, parseInt(req.query.limit || "500", 10)),
      );
      const offset = Math.max(0, parseInt(req.query.offset || "0", 10));
      const sort = String(req.query.sort || "created_desc").toLowerCase();
      const q = String(req.query.q || "").trim();
      let sectionFilters = [];
      if (req.query.section !== undefined) {
        const s = String(req.query.section).trim();
        if (s === "__none__") {
          sectionFilters = ["__NONE_NULL__"];
        } else if (s.length > 0) {
          sectionFilters = s
            .split(",")
            .map((part) => part.trim())
            .filter(Boolean);
        }
      }
      // Normalize category filters: support category, category[], and comma-separated strings
      const rawCategory =
        req.query.category !== undefined
          ? req.query.category
          : req.query["category[]"] !== undefined
            ? req.query["category[]"]
            : undefined;
      let categories = [];
      if (Array.isArray(rawCategory)) {
        categories = rawCategory.map((c) => String(c).toLowerCase());
      } else if (typeof rawCategory === "string" && rawCategory.length > 0) {
        categories = rawCategory
          .split(",")
          .map((c) => c.trim().toLowerCase())
          .filter(Boolean);
      }

      // Prefix with "tokens." to avoid ambiguity when LEFT JOINing domain_monitors
      const sortSql =
        sort === "expiration_asc"
          ? "tokens.expiration ASC NULLS LAST"
          : sort === "expiration_desc"
            ? "tokens.expiration DESC NULLS LAST"
            : sort === "name_asc"
              ? "LOWER(tokens.name) ASC"
              : sort === "last_used_desc"
                ? "tokens.last_used DESC NULLS LAST"
                : sort === "last_used_asc"
                  ? "tokens.last_used ASC NULLS LAST"
                  : sort === "imported_desc"
                    ? "tokens.imported_at DESC NULLS LAST"
                    : sort === "imported_asc"
                      ? "tokens.imported_at ASC NULLS LAST"
                      : "tokens.created_at DESC NULLS LAST"; // created_desc default

      // Build filters: either legacy user-owned or any workspace where user is member
      // Performance optimization: Pre-fetch workspace IDs to avoid subquery in main token filter
      const membershipRes = await pool.query(
        "SELECT workspace_id FROM workspace_memberships WHERE user_id = $1",
        [userId],
      );
      const userWorkspaceIds = membershipRes.rows.map((r) => r.workspace_id);

      let p = 2;
      // Prefix columns with "tokens." to avoid ambiguity when LEFT JOINing domain_monitors
      const whereParts = [
        userWorkspaceIds.length > 0
          ? `(tokens.user_id = $1 OR tokens.workspace_id = ANY($2::uuid[]))`
          : "tokens.user_id = $1",
      ];
      const params = [userId];
      if (userWorkspaceIds.length > 0) {
        params.push(userWorkspaceIds);
        p++;
      }
      if (workspaceId) {
        whereParts.push(`tokens.workspace_id = $${p}`);
        params.push(workspaceId);
        p++;
      }
      if (categories.length > 0) {
        whereParts.push(`LOWER(tokens.category) = ANY($${p}::text[])`);
        params.push(categories);
        p++;
      }
      if (sectionFilters.length > 0) {
        if (sectionFilters.includes("__NONE_NULL__")) {
          whereParts.push(
            "(tokens.section IS NULL OR cardinality(tokens.section) = 0)",
          );
        } else {
          // Use contains operator (@>) to match all of the selected sections
          whereParts.push(`tokens.section @> $${p}::text[]`);
          params.push(sectionFilters);
          p++;
        }
      }
      if (q.length > 0) {
        whereParts.push(
          `(
          LOWER(tokens.name) LIKE LOWER($${p}) OR
          LOWER(tokens.subject) LIKE LOWER($${p}) OR
          LOWER(tokens.issuer) LIKE LOWER($${p}) OR
          LOWER(tokens.used_by) LIKE LOWER($${p}) OR
          LOWER(tokens.location) LIKE LOWER($${p})
        )`,
        );
        params.push(`%${q}%`);
        p++;
      }
      const whereSql = whereParts.join(" AND ");

      // 1. Fetch items page (with endpoint monitor health data)
      const itemsSql = `
      SELECT tokens.*, dm.last_health_status AS monitor_health_status,
             dm.last_health_response_ms AS monitor_response_ms, dm.url AS monitor_url
      FROM tokens
      LEFT JOIN domain_monitors dm ON dm.token_id = tokens.id
      WHERE ${whereSql}
      ORDER BY ${sortSql}
      LIMIT $${p} OFFSET $${p + 1}
    `;
      const itemsRes = await pool.query(itemsSql, [...params, limit, offset]);
      const items = itemsRes.rows.map((t) => Token.convertNumericFields(t));

      // 2. Fetch total count and facets in a single optimized query using CTEs
      const statsSql = `
      WITH filtered_tokens AS (
        SELECT category, section FROM tokens WHERE ${whereSql}
      ),
      total_count AS (
        SELECT COUNT(*)::int AS c FROM filtered_tokens
      ),
      category_facets AS (
        SELECT LOWER(category) AS category, COUNT(*)::int AS c
        FROM filtered_tokens
        GROUP BY LOWER(category)
      ),
      section_labels AS (
        -- Optimized single-pass unnest for all matching tokens
        SELECT unnest(CASE 
          WHEN section IS NULL OR cardinality(section) = 0 THEN ARRAY[NULL] 
          ELSE section 
        END) AS label
        FROM filtered_tokens
      ),
      section_facets AS (
        SELECT COALESCE(trim(label), '') AS section, COUNT(*)::int AS c
        FROM section_labels
        GROUP BY section
      )
      SELECT 
        (SELECT c FROM total_count) as total,
        (SELECT json_agg(cf) FROM (SELECT category, c FROM category_facets ORDER BY category ASC) cf) as category_facets,
        (SELECT json_agg(sf) FROM (SELECT section, c FROM section_facets WHERE c > 0 ORDER BY section ASC) sf) as section_facets
    `;

      const statsRes = await pool.query(statsSql, params);
      const stats = statsRes.rows[0] || {};

      const total = stats.total || 0;
      const facets = {
        category: stats.category_facets || [],
        section: stats.section_facets || [],
      };

      res.json({ items, total, facets });
    } catch (error) {
      logger.error("Error fetching tokens:", {
        error: error.message,
        stack: error.stack,
      });
      res
        .status(500)
        .json({ error: "Failed to fetch tokens", code: "INTERNAL_ERROR" });
    }
  },
);

// Get specific token by ID
router.get(
  "/api/tokens/:id",
  getTestApiLimiter(),
  requireAuth,
  async (req, res) => {
    try {
      const tokenId = parseInt(req.params.id);
      const token = await Token.findById(tokenId);

      if (!token) {
        return res
          .status(404)
          .json({ error: "Token not found", code: "TOKEN_NOT_FOUND" });
      }

      // Ensure user can only access tokens in their workspaces (or legacy own)
      if (token.workspace_id) {
        const m = await pool.query(
          "SELECT 1 FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2",
          [token.workspace_id, req.user.id],
        );
        if (m.rowCount === 0)
          return res
            .status(404)
            .json({ error: "Token not found", code: "TOKEN_NOT_FOUND" });
      } else if (token.user_id !== req.user.id) {
        return res
          .status(404)
          .json({ error: "Token not found", code: "TOKEN_NOT_FOUND" });
      }

      res.json(token);
    } catch (error) {
      logger.error("Error fetching token:", {
        error: error.message,
        stack: error.stack,
      });
      res
        .status(500)
        .json({ error: "Failed to fetch token", code: "INTERNAL_ERROR" });
    }
  },
);

// Create new token
router.post(
  "/api/tokens",
  getTestApiLimiter(),
  requireAuth,
  validateToken,
  handleValidationErrors,
  async (req, res) => {
    try {
      const {
        name,
        type,
        expiresAt,
        category,
        section,
        domains,
        location,
        used_by,
        issuer,
        serial_number,
        subject,
        key_size,
        algorithm,
        license_type,
        vendor,
        cost,
        renewal_url,
        renewal_date,
        contacts,
        description,
        notes,
        contact_group_id,
        privileges,
        last_used,
        imported_at,
        created_at,
      } = req.body;

      // Log the request for debugging
      logger.info("Token creation request", {
        userId: req.user?.id,
        type,
        category,
        expiresAt,
        cost,
        ip: req.ip,
      });

      // Note: Validation is now handled by express-validator middleware

      // Date handling - if expiration is not provided, default to "never expires" (2099-12-31)
      const NEVER_EXPIRES_DATE = "2099-12-31";
      let expiration;
      if (
        !expiresAt ||
        expiresAt === "" ||
        expiresAt === null ||
        expiresAt === undefined
      ) {
        expiration = NEVER_EXPIRES_DATE;
      } else {
        const expDate = new Date(expiresAt);

        // Check for very far future dates (warn but allow)
        const maxDate = new Date();
        maxDate.setFullYear(maxDate.getFullYear() + 100); // 100 years from now
        if (expDate > maxDate) {
          logger.warn("Token created with far future expiration", {
            userId: req.user.id,
            expirationDate: expDate.toISOString(),
            tokenType: type,
          });
        }

        // Format date as YYYY-MM-DD for PostgreSQL DATE type
        expiration = expDate.toISOString().split("T")[0];
      }
      const workspaceId = req.body?.workspace_id
        ? String(req.body.workspace_id)
        : null;
      if (!workspaceId) {
        return res.status(400).json({
          error: "workspace_id is required",
          code: "VALIDATION_ERROR",
        });
      }
      // Membership enforcement: creator must belong to the workspace and not be a viewer
      const mres = await pool.query(
        "SELECT role FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2",
        [workspaceId, req.user.id],
      );
      const creatorRole = mres.rows?.[0]?.role || null;
      if (!creatorRole)
        return res.status(403).json({ error: "Forbidden", code: "FORBIDDEN" });
      if (!["admin", "workspace_manager"].includes(String(creatorRole))) {
        return res
          .status(403)
          .json({ error: "Forbidden: insufficient role", code: "FORBIDDEN" });
      }

      // Validate domains array if provided
      let domainsArray = null;
      if (domains) {
        if (Array.isArray(domains)) {
          domainsArray = domains.filter((domain) => domain && domain.trim());
        } else if (typeof domains === "string") {
          domainsArray = domains
            .split(",")
            .map((d) => d.trim())
            .filter((d) => d);
        }
        // Convert empty arrays to null for consistency
        if (domainsArray && domainsArray.length === 0) {
          domainsArray = null;
        }
      }

      // Process cost with validation
      let costValue = null;
      if (cost !== undefined && cost !== null && cost !== "") {
        costValue = parseFloat(cost);
        if (isNaN(costValue) || costValue < 0 || costValue > 999999999999.99) {
          return res.status(400).json({
            error: "Validation failed",
            code: "VALIDATION_ERROR",
            details: ["Cost must be a positive number less than 1 trillion"],
          });
        }
      }

      // Process key_size with validation
      let keySizeValue = null;
      if (key_size !== undefined && key_size !== null && key_size !== "") {
        keySizeValue = parseInt(key_size);
        if (isNaN(keySizeValue) || keySizeValue <= 0) {
          return res.status(400).json({
            error: "Validation failed",
            code: "VALIDATION_ERROR",
            details: ["Key size must be a positive integer"],
          });
        }
      }

      // Validate conditional fields based on type
      if (
        algorithm &&
        ![
          "encryption_key",
          "ssh_key",
          "ssl_cert",
          "tls_cert",
          "code_signing",
          "client_cert",
          "secret",
        ].includes(type)
      ) {
        return res.status(400).json({
          error:
            "Algorithm is only valid for encryption keys, SSH keys, secrets, and certificates",
          code: "VALIDATION_ERROR",
        });
      }
      if (
        keySizeValue &&
        ![
          "encryption_key",
          "ssh_key",
          "ssl_cert",
          "tls_cert",
          "code_signing",
          "client_cert",
          "secret",
        ].includes(type)
      ) {
        return res.status(400).json({
          error:
            "Key size is only valid for encryption keys, SSH keys, secrets, and certificates",
          code: "VALIDATION_ERROR",
        });
      }

      // Category-specific validation - Only validate what's actually required
      // Domains are optional for certificates, so no validation needed

      // All fields except name, category, type, and expiration are optional
      // No additional validation needed for specific categories

      // Normalize section to array format (split any combined strings within arrays)
      const normalizeSectionArray = (input) => {
        if (!input) return null;
        const parts = Array.isArray(input) ? input : String(input).split(",");
        const flat = parts
          .flatMap((p) => (typeof p === "string" ? p.split(",") : [p]))
          .map((s) => (typeof s === "string" ? s.trim() : s))
          .filter(Boolean);
        return flat.length > 0 ? [...new Set(flat)] : null;
      };

      const tokenData = {
        userId: req.user.id,
        name: name.trim(),
        type,
        expiration,
        category,
        section: normalizeSectionArray(section),
        domains: domainsArray,
        location: location?.trim() || null,
        used_by: used_by?.trim() || null,
        issuer: issuer?.trim() || null,
        serial_number: serial_number?.trim() || null,
        subject: subject?.trim() || null,
        key_size: keySizeValue,
        algorithm: algorithm?.trim() || null,
        license_type: license_type?.trim() || null,
        vendor: vendor?.trim() || null,
        cost: costValue,
        renewal_url: renewal_url?.trim() || null,
        renewal_date: renewal_date?.trim() || null,
        contacts: contacts?.trim() || null,
        description: description?.trim() || null,
        notes: notes?.trim() || null,
      };

      // Check for duplicate token (same name + location in same workspace)
      const existingToken = await Token.findByNameLocationAndWorkspace(
        tokenData.name,
        tokenData.location,
        workspaceId,
      );

      if (existingToken) {
        // If duplicate exists and client didn't explicitly confirm, return warning
        if (!req.body.confirm_duplicate) {
          return res.status(409).json({
            error: "Token with same name and location already exists",
            code: "DUPLICATE_TOKEN",
            existing_token: {
              id: existingToken.id,
              name: existingToken.name,
              location: existingToken.location,
              expiration: existingToken.expiration,
            },
            message: `A token named "${tokenData.name}"${tokenData.location ? ` at location "${tokenData.location}"` : ""} already exists in this workspace. Creating this token will update the existing one.`,
          });
        }
        // If confirmed, update the existing token instead
        const updatedToken = await Token.update(existingToken.id, {
          ...tokenData,
          expiration,
          created_at: tokenData.created_at, // Allow updating to null if not found in latest import
        });
        // Audit: token updated via creation endpoint
        try {
          await writeAudit({
            actorUserId: req.user.id,
            subjectUserId: req.user.id,
            action: "TOKEN_UPDATED",
            targetType: "token",
            targetId: updatedToken.id,
            channel: null,
            workspaceId,
            metadata: {
              name: updatedToken.name,
              type: updatedToken.type,
              category: updatedToken.category,
              reason: "duplicate_creation_confirmed",
            },
          });
        } catch (_err) {
          logger.warn("Audit write failed", { error: _err.message });
        }
        logger.info("Token updated via creation endpoint (duplicate)", {
          tokenId: updatedToken.id,
          userId: req.user.id,
        });
        return res.status(200).json(updatedToken);
      }

      logger.info("Creating token with data:", {
        userId: tokenData.userId,
        name: tokenData.name,
        type: tokenData.type,
        category: tokenData.category,
        expiration: tokenData.expiration,
      });

      // Validate contact_group_id belongs to workspace (if provided)
      let normalizedContactGroupId = null;
      if (
        contact_group_id !== undefined &&
        contact_group_id !== null &&
        String(contact_group_id).trim() !== ""
      ) {
        const cgId = String(contact_group_id).trim();
        try {
          const sql =
            "SELECT 1 FROM workspace_settings WHERE workspace_id = $1 AND EXISTS (SELECT 1 FROM jsonb_array_elements(contact_groups) AS g WHERE (g->>'id') = $2)";
          const cgRes = await pool.query(sql, [workspaceId, cgId]);
          if (cgRes.rowCount === 0) {
            return res.status(400).json({
              error: "Invalid contact_group_id for workspace",
              code: "VALIDATION_ERROR",
            });
          }
          normalizedContactGroupId = cgId;
        } catch (_err) {
          logger.warn("DB operation failed", { error: _err.message });
        }
      }

      const tokenDataWithGroup = {
        ...tokenData,
        contact_group_id: normalizedContactGroupId,
      };
      const token = await Token.create({
        ...tokenDataWithGroup,
        workspaceId,
        created_by: req.user.id,
        privileges,
        last_used,
        imported_at: imported_at || null,
        created_at: created_at || null,
      });
      // Audit: token created
      try {
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "TOKEN_CREATED",
          targetType: "token",
          targetId: token.id,
          channel: null,
          workspaceId,
          metadata: {
            name: token.name,
            type: token.type,
            category: token.category,
          },
        });
      } catch (_err) {
        logger.warn("Audit write failed", { error: _err.message });
      }
      logger.info("Token created successfully", {
        tokenId: token.id,
        userId: req.user.id,
        type: token.type,
        category: token.category,
      });
      res.status(201).json(token);
    } catch (error) {
      logger.error("Token creation error:", error.message);
      logger.error("Token creation error stack:", error.stack);
      logger.error("Request details:", {
        user: req.user?.id,
        body: sanitizeForLogging(req.body),
        path: req.path,
      });
      res
        .status(500)
        .json({ error: "Failed to create token", code: "INTERNAL_ERROR" });
    }
  },
);

// Update token
router.put(
  "/api/tokens/:id",
  getTestApiLimiter(),
  requireAuth,
  async (req, res) => {
    const { id } = req.params;
    const {
      name,
      expiresAt,
      expiration, // Also accept 'expiration' field for compatibility
      type,
      category,
      section,
      domains,
      location,
      used_by,
      contact_group_id,
      issuer,
      serial_number,
      subject,
      key_size,
      algorithm,
      license_type,
      vendor,
      cost,
      renewal_url,
      renewal_date,
      contacts,
      description,
      notes,
      privileges,
      last_used,
    } = req.body;

    try {
      // Authorization: allow owners OR workspace admins/managers for workspace-scoped tokens
      const existingToken = await Token.findById(id);
      if (!existingToken) {
        return res
          .status(404)
          .json({ error: "Token not found", code: "TOKEN_NOT_FOUND" });
      }
      if (existingToken.workspace_id) {
        const canUpdate =
          (
            await pool.query(
              "SELECT 1 FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2 AND role IN ('admin','workspace_manager')",
              [existingToken.workspace_id, req.user.id],
            )
          ).rowCount > 0;
        if (!canUpdate) {
          return res
            .status(403)
            .json({ error: "Forbidden", code: "FORBIDDEN" });
        }
      } else if (existingToken.user_id !== req.user.id) {
        return res
          .status(404)
          .json({ error: "Token not found", code: "TOKEN_NOT_FOUND" });
      }

      // Validate name length if provided
      if (name !== undefined && name !== null) {
        const trimmedName = name.trim();
        if (trimmedName.length < 3) {
          return res.status(400).json({
            error: "Validation failed",
            code: "VALIDATION_ERROR",
            details: ["Token name must be between 3 and 100 characters"],
          });
        }
        if (trimmedName.length > 100) {
          return res.status(400).json({
            error: "Validation failed",
            code: "VALIDATION_ERROR",
            details: ["Token name must be between 3 and 100 characters"],
          });
        }
      }

      // Validate category if provided
      if (
        category &&
        !["cert", "key_secret", "license", "general"].includes(category)
      ) {
        return res.status(400).json({
          error: "Validation failed",
          code: "VALIDATION_ERROR",
          details: ["Invalid category"],
        });
      }

      // Validate type and category compatibility if both are provided
      if (type && category) {
        const certTypes = [
          "ssl_cert",
          "tls_cert",
          "code_signing",
          "client_cert",
        ];
        const keySecretTypes = [
          "api_key",
          "secret",
          "password",
          "encryption_key",
          "ssh_key",
        ];
        const licenseTypes = ["software_license", "service_subscription"];

        if (category === "cert" && !certTypes.includes(type)) {
          return res.status(400).json({
            error: "Validation failed",
            code: "VALIDATION_ERROR",
            details: ["Invalid token type for selected category"],
          });
        }
        if (category === "key_secret" && !keySecretTypes.includes(type)) {
          return res.status(400).json({
            error: "Validation failed",
            code: "VALIDATION_ERROR",
            details: ["Invalid token type for selected category"],
          });
        }
        if (category === "license" && !licenseTypes.includes(type)) {
          return res.status(400).json({
            error: "Validation failed",
            code: "VALIDATION_ERROR",
            details: ["Invalid token type for selected category"],
          });
        }
      }

      // Validate domains array if provided
      let domainsArray = undefined; // Use undefined to indicate not provided
      if (domains !== undefined) {
        if (domains === null || domains === "") {
          domainsArray = null;
        } else if (Array.isArray(domains)) {
          domainsArray = domains.filter((domain) => domain && domain.trim());
        } else if (typeof domains === "string") {
          domainsArray = domains
            .split(",")
            .map((d) => d.trim())
            .filter((d) => d);
        }
        // Convert empty arrays to null for consistency
        if (domainsArray && domainsArray.length === 0) {
          domainsArray = null;
        }
      }

      // All fields except name, category, type, and expiration are optional
      // No additional validation needed for specific categories during updates

      // Validate cost if provided
      let costValue = null;
      if (cost !== undefined && cost !== null && cost !== "") {
        const costNum = parseFloat(cost);
        if (isNaN(costNum) || costNum < 0) {
          return res.status(400).json({
            error: "Cost must be a valid positive number",
            code: "VALIDATION_ERROR",
          });
        }
        if (costNum > 999999999999.99) {
          return res.status(400).json({
            error: "Cost must be less than 1 trillion (1,000,000,000,000)",
            code: "VALIDATION_ERROR",
          });
        }
        costValue = costNum;
      }

      // Validate key_size if provided
      let keySizeValue = null;
      if (key_size !== undefined && key_size !== null && key_size !== "") {
        const keySizeNum = parseInt(key_size);
        if (isNaN(keySizeNum) || keySizeNum <= 0) {
          return res.status(400).json({
            error: "Key size must be a valid positive integer",
            code: "VALIDATION_ERROR",
          });
        }
        keySizeValue = keySizeNum;
      }

      // Validate and convert expiresAt/expiration if provided
      const NEVER_EXPIRES_DATE = "2099-12-31";
      let expirationDate = null;
      const dateToValidate = expiresAt || expiration; // Accept either field name
      if (
        dateToValidate !== undefined &&
        dateToValidate !== null &&
        dateToValidate !== ""
      ) {
        const expDate = new Date(dateToValidate);
        if (isNaN(expDate.getTime())) {
          return res.status(400).json({
            error: "Validation failed",
            code: "VALIDATION_ERROR",
            details: ["Invalid expiration date format"],
          });
        }
        if (expDate <= new Date()) {
          return res.status(400).json({
            error: "Validation failed",
            code: "VALIDATION_ERROR",
            details: ["Expiration date must be in the future"],
          });
        }
        expirationDate = expDate.toISOString().split("T")[0];
      } else {
        // If expiration is not provided in update, keep existing expiration
        // (don't change it to "never expires" unless explicitly set)
        expirationDate = existingToken.expiration || NEVER_EXPIRES_DATE;
      }

      // Validate conditional fields based on existing or new type
      const tokenType = type || existingToken.type;
      if (
        algorithm &&
        ![
          "encryption_key",
          "ssh_key",
          "ssl_cert",
          "tls_cert",
          "code_signing",
          "client_cert",
          "secret",
        ].includes(tokenType)
      ) {
        return res.status(400).json({
          error:
            "Algorithm is only valid for encryption keys, SSH keys, secrets, and certificates",
          code: "VALIDATION_ERROR",
        });
      }
      if (
        keySizeValue &&
        ![
          "encryption_key",
          "ssh_key",
          "ssl_cert",
          "tls_cert",
          "code_signing",
          "client_cert",
          "secret",
        ].includes(tokenType)
      ) {
        return res.status(400).json({
          error:
            "Key size is only valid for encryption keys, SSH keys, secrets, and certificates",
          code: "VALIDATION_ERROR",
        });
      }

      // Process string fields to convert empty strings to null (consistent with creation logic)
      const processStringField = (value, limit = null, fieldName = "") => {
        if (value === undefined) return undefined;
        if (value === null) return null;
        // Ensure value is a string before calling trim()
        const strValue = typeof value !== "string" ? String(value) : value;
        const trimmed = strValue.trim();

        if (limit && trimmed.length > limit) {
          throw new Error(`${fieldName} must be less than ${limit} characters`);
        }

        // Prevent HTML tags
        if (/[<>]/.test(trimmed)) {
          throw new Error(`${fieldName} cannot contain HTML tags`);
        }

        return trimmed === "" ? null : trimmed;
      };

      // Normalize section to array format for updates
      const processSectionField = (value) => {
        if (value === undefined) return undefined;
        if (value === null) return null;
        const parts = Array.isArray(value) ? value : String(value).split(",");

        if (Array.isArray(value) && value.length > 50) {
          throw new Error("Too many labels (max 50)");
        }
        if (typeof value === "string" && value.length > 255) {
          throw new Error("Section text must be less than 255 characters");
        }

        const flat = parts
          .flatMap((p) => (typeof p === "string" ? p.split(",") : [p]))
          .map((s) => (typeof s === "string" ? s.trim() : s))
          .filter(Boolean);

        for (const s of flat) {
          if (s.length > 120) {
            throw new Error("Each label must be less than 120 characters");
          }
          if (/[<>]/.test(s)) {
            throw new Error("Labels cannot contain HTML tags");
          }
        }

        return flat.length > 0 ? [...new Set(flat)] : null;
      };

      const updateData = {
        ...(name !== undefined && {
          name: processStringField(name, 100, "Name"),
        }),
        ...(expirationDate !== null &&
          expirationDate !== undefined && { expiration: expirationDate }),
        ...(type !== undefined && { type }),
        ...(category !== undefined && { category }),
        ...(section !== undefined && { section: processSectionField(section) }),
        ...(domainsArray !== undefined && { domains: domainsArray }),
        ...(location !== undefined && {
          location: processStringField(location, 500, "Location"),
        }),
        ...(used_by !== undefined && {
          used_by: processStringField(used_by, 500, "Used by"),
        }),
        ...(issuer !== undefined && {
          issuer: processStringField(issuer, 255, "Issuer"),
        }),
        ...(serial_number !== undefined && {
          serial_number: processStringField(
            serial_number,
            255,
            "Serial number",
          ),
        }),
        ...(subject !== undefined && {
          subject: processStringField(subject, 1000, "Subject"),
        }),
        ...(keySizeValue !== undefined && { key_size: keySizeValue }),
        ...(algorithm !== undefined && {
          algorithm: processStringField(algorithm, 100, "Algorithm"),
        }),
        ...(license_type !== undefined && {
          license_type: processStringField(license_type, 100, "License type"),
        }),
        ...(vendor !== undefined && {
          vendor: processStringField(vendor, 255, "Vendor"),
        }),
        ...(costValue !== undefined && { cost: costValue }),
        ...(renewal_url !== undefined && {
          renewal_url: processStringField(renewal_url, 500, "Renewal URL"),
        }),
        ...(renewal_date !== undefined && {
          renewal_date: processStringField(renewal_date),
        }),
        ...(contacts !== undefined && {
          contacts: processStringField(contacts, 500, "Contacts"),
        }),
        ...(description !== undefined && {
          description: processStringField(description, 10000, "Description"),
        }),
        ...(notes !== undefined && {
          notes: processStringField(notes, 10000, "Notes"),
        }),
        ...(privileges !== undefined && {
          privileges: processStringField(privileges, 5000, "Privileges"),
        }),
        ...(last_used !== undefined && {
          last_used: last_used ? new Date(last_used) : null,
        }),
      };

      // Validate contact_group_id ownership
      if (contact_group_id !== undefined && contact_group_id !== null) {
        const cgId = String(contact_group_id || "").trim();
        if (cgId.length > 0) {
          const sql =
            "SELECT 1 FROM workspace_settings WHERE workspace_id = $1 AND EXISTS (SELECT 1 FROM jsonb_array_elements(contact_groups) AS g WHERE (g->>'id') = $2)";
          const cgRes = await pool.query(sql, [
            existingToken.workspace_id,
            cgId,
          ]);
          if (cgRes.rowCount === 0) {
            return res.status(400).json({
              error: "Invalid contact_group_id for workspace",
              code: "VALIDATION_ERROR",
            });
          }
          updateData.contact_group_id = cgId;
        } else {
          updateData.contact_group_id = null;
        }
      }

      const updatedToken = await Token.update(id, updateData);
      // Audit: token updated (include before/after for key date fields)
      try {
        const changedFields = Object.keys(updateData);
        const changes = {};
        if (Object.prototype.hasOwnProperty.call(updateData, "expiration")) {
          changes.expiresAt = {
            from: existingToken.expiresAt || null,
            to: updatedToken.expiresAt || null,
          };
        }
        if (Object.prototype.hasOwnProperty.call(updateData, "renewal_date")) {
          changes.renewal_date = {
            from: existingToken.renewal_date || null,
            to: updatedToken.renewal_date || null,
          };
        }
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "TOKEN_UPDATED",
          targetType: "token",
          targetId: parseInt(id),
          channel: null,
          workspaceId: existingToken.workspace_id || null,
          metadata: { fields: changedFields, changes },
        });
      } catch (_err) {
        logger.warn("Audit write failed (TOKEN_UPDATED)", {
          error: _err.message,
        });
      }
      res.json(updatedToken);
    } catch (error) {
      logger.error("Error updating token:", {
        error: error.message,
        stack: error.stack,
        tokenId: id,
        userId: req.user?.id,
      });
      res
        .status(500)
        .json({ error: "Failed to update token", code: "INTERNAL_ERROR" });
    }
  },
);

// Delete tokens in bulk
router.delete(
  "/api/tokens/bulk",
  getTestApiLimiter(),
  requireAuth,
  requireNotViewer,
  async (req, res) => {
    const { ids } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
      return res
        .status(400)
        .json({ error: "No token IDs provided", code: "VALIDATION_ERROR" });
    }

    if (ids.length > 500) {
      return res.status(400).json({
        error: "Cannot delete more than 500 tokens at once",
        code: "VALIDATION_ERROR",
      });
    }

    try {
      const userId = req.user.id;

      // 1. Fetch all requested tokens to check ownership/workspace permissions in one go
      const tokensRes = await pool.query(
        "SELECT id, name, workspace_id, user_id FROM tokens WHERE id = ANY($1::int[])",
        [ids],
      );
      const existingTokens = tokensRes.rows;
      const existingIds = existingTokens.map((t) => t.id);

      const results = {
        success: [],
        failed: [],
      };

      // Identify missing tokens
      for (const id of ids) {
        if (!existingIds.includes(parseInt(id))) {
          results.failed.push({ id, reason: "Not found" });
        }
      }

      // 2. Filter tokens by permission
      const authorizedTokens = [];
      const workspaceIds = [
        ...new Set(
          existingTokens
            .filter((t) => t.workspace_id)
            .map((t) => t.workspace_id),
        ),
      ];

      // Load user roles for all relevant workspaces in one query
      const rolesMap = new Map();
      if (workspaceIds.length > 0) {
        const rolesRes = await pool.query(
          "SELECT workspace_id, role FROM workspace_memberships WHERE user_id = $1 AND workspace_id = ANY($2::uuid[])",
          [userId, workspaceIds],
        );
        rolesRes.rows.forEach((r) => rolesMap.set(r.workspace_id, r.role));
      }

      for (const token of existingTokens) {
        let canDelete = false;
        if (token.workspace_id) {
          const role = rolesMap.get(token.workspace_id);
          canDelete = role === "admin" || role === "workspace_manager";
        } else {
          canDelete = token.user_id === userId;
        }

        if (canDelete) {
          authorizedTokens.push(token);
        } else {
          results.failed.push({ id: token.id, reason: "Forbidden" });
        }
      }

      const authorizedIds = authorizedTokens.map((t) => t.id);

      if (authorizedIds.length > 0) {
        // 3. Bulk delete authorized tokens
        // Delete queue entries first (foreign key constraints)
        await pool.query(
          "DELETE FROM alert_queue WHERE token_id = ANY($1::int[])",
          [authorizedIds],
        );

        // Delete linked endpoint monitors so they don't become orphaned
        await pool.query(
          "DELETE FROM domain_monitors WHERE token_id = ANY($1::int[])",
          [authorizedIds],
        );

        // Delete the tokens
        await pool.query("DELETE FROM tokens WHERE id = ANY($1::int[])", [
          authorizedIds,
        ]);

        // 4. Audit deletion (async/background if possible, but here we'll do it sequentially for simplicity but in one batch soon)
        for (const token of authorizedTokens) {
          results.success.push(token.id);
          try {
            await writeAudit({
              actorUserId: userId,
              subjectUserId: userId,
              action: "TOKEN_DELETED",
              targetType: "token",
              targetId: token.id,
              channel: null,
              workspaceId: token.workspace_id || null,
              metadata: { name: token.name, bulk: true },
            });
          } catch (_err) {
            logger.warn("Audit write failed", { error: _err.message });
          }
        }
      }

      res.json({
        message: `Processed ${ids.length} tokens`,
        successCount: results.success.length,
        failedCount: results.failed.length,
        results,
      });
    } catch (error) {
      logger.error("Error in bulk delete", {
        error: error.message,
        stack: error.stack,
      });
      res.status(500).json({
        error: "Failed to process bulk deletion",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

// Delete token
router.delete(
  "/api/tokens/:id",
  getTestApiLimiter(),
  requireAuth,
  async (req, res) => {
    const { id } = req.params;

    try {
      // Delete any queue entries for this token (pending/failed/blocked)
      const existing = await Token.findById(id);
      if (!existing)
        return res
          .status(404)
          .json({ error: "Token not found", code: "TOKEN_NOT_FOUND" });
      const canDelete = existing.workspace_id
        ? (
            await pool.query(
              "SELECT 1 FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2 AND role IN ('admin','workspace_manager')",
              [existing.workspace_id, req.user.id],
            )
          ).rowCount > 0
        : existing.user_id === req.user.id;
      if (!canDelete)
        return res.status(403).json({ error: "Forbidden", code: "FORBIDDEN" });
      await pool.query("DELETE FROM alert_queue WHERE token_id = $1", [
        parseInt(id, 10),
      ]);
      // Delete linked endpoint monitors so they don't become orphaned
      await pool.query("DELETE FROM domain_monitors WHERE token_id = $1", [
        parseInt(id, 10),
      ]);
      const deletedToken = await Token.delete(id);
      try {
        // Ensure delivery log rows remain associated with the original workspace for stats
        if (deletedToken?.workspace_id) {
          await pool.query(
            "UPDATE alert_delivery_log SET workspace_id = $1 WHERE token_id = $2 AND workspace_id IS NULL",
            [deletedToken.workspace_id, parseInt(id, 10)],
          );
        }
      } catch (_err) {
        logger.warn("DB operation failed", { error: _err.message });
      }
      // Audit: token deleted
      try {
        const reason =
          (req.body && req.body.reason) || req.query?.reason || null;
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "TOKEN_DELETED",
          targetType: "token",
          targetId: parseInt(id),
          channel: null,
          workspaceId: existing.workspace_id || null,
          metadata: {
            name: deletedToken?.name || null,
            reason: reason || null,
          },
        });
      } catch (_err) {
        logger.debug("Parse failed", { error: _err.message });
      }
      res.json({ message: "Token deleted successfully" });
    } catch (error) {
      logger.error("Error deleting token:", {
        error: error.message,
        stack: error.stack,
      });
      res
        .status(500)
        .json({ error: "Failed to delete token", code: "INTERNAL_ERROR" });
    }
  },
);

// Health/test endpoint

module.exports = router;
