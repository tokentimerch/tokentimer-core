const { logger } = require("../utils/logger");
const { writeAudit } = require("../services/audit");
const { requireAuth } = require("../middleware/auth");
const { getApiLimiter } = require("../middleware/rateLimit");
const {
  generateErrorReference,
  formatIntegrationError,
} = require("../utils/errorReference");
const {
  loadWorkspace,
  requireWorkspaceMembership,
  requireIntegrationQuota,
  requireNotViewer,
} = require("../services/rbac");
const Token = require("../db/models/Token");

const { scanVault } = require("../services/vaultIntegration");
const { scanGitLab } = require("../services/gitlabIntegration");
const { scanGitHub } = require("../services/githubIntegration");
const { scanAWS, detectAWSRegions } = require("../services/awsIntegration");
const { scanAzure } = require("../services/azureIntegration");
const { scanAzureAD } = require("../services/azureADIntegration");
const { scanGCP } = require("../services/gcpIntegration");
const { formatDateYmd } = require("../services/integrationUtils");

const router = require("express").Router();

// --- Vault integration: scan mounts for inventory/expirations ---
// Note: requireIntegrationQuota handles workspace validation, role check, and quota enforcement
router.post(
  "/api/v1/integrations/vault/scan",
  getApiLimiter(),
  requireAuth,
  requireIntegrationQuota,
  async (req, res) => {
    // Helper to include quota in any response
    const withQuota = (obj) => ({
      ...obj,
      quota: {
        used: req.integrationQuota?.used || 0,
        limit: req.integrationQuota?.limit || null,
        remaining:
          req.integrationQuota?.remaining !== undefined
            ? req.integrationQuota.remaining
            : null,
      },
    });

    try {
      const { address, token, include, mounts, maxItemsPerMount, pathPrefix } =
        req.body || {};
      // Prevent caching of sensitive responses
      res.set("Cache-Control", "no-store");
      res.set("Pragma", "no-cache");
      if (!address || !token)
        return res
          .status(400)
          .json(withQuota({ error: "address and token are required" }));
      // Basic allowlist for schemes
      try {
        const u = new URL(address);
        if (!/^https?:$/.test(u.protocol))
          return res
            .status(400)
            .json(withQuota({ error: "address must be http(s)" }));
        // Optional SSRF allowlist via env: comma-separated hostnames
        const allow = String(process.env.VAULT_ADDRESS_ALLOWLIST || "").trim();
        if (allow.length > 0) {
          const allowedHosts = allow
            .split(",")
            .map((s) => s.trim().toLowerCase())
            .filter(Boolean);
          const hostLc = String(u.hostname || "").toLowerCase();
          if (!allowedHosts.includes(hostLc)) {
            return res
              .status(400)
              .json(withQuota({ error: "Vault address not allowed" }));
          }
        }
      } catch (e) {
        logger.warn("Vault scan: invalid address URL", { error: e.message });
        return res
          .status(400)
          .json(withQuota({ error: "invalid address URL" }));
      }
      const result = await scanVault({
        address,
        token,
        include: {
          kv: include && typeof include.kv === "boolean" ? include.kv : true,
          pki: include && typeof include.pki === "boolean" ? include.pki : true,
        },
        mounts: Array.isArray(mounts) ? mounts : null,
        maxItemsPerMount:
          Number.isFinite(maxItemsPerMount) && maxItemsPerMount > 0
            ? Math.min(2000, maxItemsPerMount)
            : 250,
        pathPrefix:
          typeof pathPrefix === "string"
            ? pathPrefix.trim().replace(/^\/+|\/+$/g, "")
            : "",
      });

      res.json(withQuota(result));
      try {
        if (req && req.user) {
          await writeAudit({
            actorUserId: req.user.id,
            subjectUserId: req.user.id,
            action: "INTEGRATION_SCAN",
            targetType: "integration",
            targetId: null,
            channel: null,
            workspaceId: req.integrationQuota?.workspaceId || null,
            metadata: {
              provider: "vault",
              itemsFound: result.items?.length || 0,
            },
          });
        }
      } catch (_err) {
        logger.warn("Audit write failed (INTEGRATION_SCAN)", {
          error: _err.message,
          stack: _err.stack,
        });
      }
      try {
        if (req && req.body) delete req.body.token;
      } catch (_) {
        logger.debug("Request body cleanup failed", { error: _?.message });
      }
    } catch (e) {
      const errorRef = generateErrorReference();
      logger.error("Vault scan failed", {
        errorReference: errorRef,
        error: e?.message,
        errorCode: e?.code,
        errorType: e?.name,
        status: e?.status,
        userId: req?.user?.id,
        address: req.body?.address
          ? req.body.address.substring(0, 100)
          : "unknown",
        cause: e?.cause?.message,
        stack: e?.stack?.split("\n")[0], // First line of stack trace
      });

      // Provide more helpful error message to user
      let userMessage = "Vault scan failed";
      const status =
        e?.status ||
        (e?.message?.match(/\s(\d{3})$/)?.[1]
          ? parseInt(e.message.match(/\s(\d{3})$/)[1])
          : null);

      if (e?.code === "ETIMEDOUT" || e?.name === "AbortError") {
        userMessage =
          "Vault connection timeout. Vault server is not responding - check if it is accessible from the server and verify firewall rules allow connections.";
      } else if (e?.code === "ENOTFOUND" || e?.code === "ECONNREFUSED") {
        userMessage =
          "Cannot connect to Vault. Check address and network connectivity. Verify firewall rules allow access to Vault.";
      } else if (
        e?.code === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
        e?.code === "SELF_SIGNED_CERT_IN_CHAIN" ||
        e?.code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" ||
        e?.code === "CERT_HAS_EXPIRED" ||
        e?.message?.includes("certificate") ||
        e?.message?.includes("SSL")
      ) {
        userMessage = `SSL certificate verification failed: ${e?.message || e?.code}. If using self-signed certificates, you may need to configure the server to trust your CA. Reference: ${errorRef}`;
      } else if (e?.status === 400 || e?.message?.includes(" 400")) {
        userMessage = `Invalid request: ${e?.message || "Bad Request"}. Check your Vault address format.`;
      } else if (status === 403 || e?.message?.includes(" 403")) {
        // 403 could be auth OR network/firewall (some proxies return 403 for blocked connections)
        userMessage =
          "Vault returned 403 Forbidden. This could be: (1) Token lacks permissions to access KV/PKI mounts, or (2) Firewall/proxy blocking the connection. Verify Vault is accessible and token has proper permissions.";
      } else if (status === 404 || e?.message?.includes(" 404")) {
        userMessage =
          "Vault endpoint not found. Check address and path. Ensure Vault API is accessible at the provided URL.";
      } else if (status === 429 || e?.message?.includes(" 429")) {
        userMessage =
          "Vault rate limit exceeded. Wait a moment and try again with fewer items or slower requests.";
      } else if (
        status === 503 ||
        e?.message?.includes("sealed") ||
        e?.message?.includes(" 503")
      ) {
        userMessage =
          "Vault is sealed or unavailable. Unseal Vault or wait for it to become available.";
      } else if (e?.message?.includes("Invalid Vault address")) {
        userMessage = e.message;
      } else {
        // Unexpected error - provide reference code
        userMessage = formatIntegrationError("Vault", e, errorRef);
      }

      res.status(e?.status || 502).json(withQuota({ error: userMessage }));
    }
  },
);

// --- Vault integration: list mounts (KV/PKI) for pre-filtering ---
// Note: This is a lightweight utility endpoint, not counted against scan quota
router.post(
  "/api/v1/integrations/vault/mounts",
  getApiLimiter(),
  requireAuth,
  requireNotViewer,
  async (req, res) => {
    try {
      const { address, token } = req.body || {};
      res.set("Cache-Control", "no-store");
      res.set("Pragma", "no-cache");
      if (!address || !token)
        return res
          .status(400)
          .json({ error: "address and token are required" });
      try {
        const u = new URL(address);
        if (!/^https?:$/.test(u.protocol))
          return res.status(400).json({ error: "address must be http(s)" });
        const allow = String(process.env.VAULT_ADDRESS_ALLOWLIST || "").trim();
        if (allow.length > 0) {
          const allowedHosts = allow
            .split(",")
            .map((s) => s.trim().toLowerCase())
            .filter(Boolean);
          const hostLc = String(u.hostname || "").toLowerCase();
          if (!allowedHosts.includes(hostLc)) {
            return res.status(400).json({ error: "Vault address not allowed" });
          }
        }
      } catch (e) {
        logger.warn("Vault mounts: invalid address URL", { error: e.message });
        return res.status(400).json({ error: "invalid address URL" });
      }
      const { listMounts } = require("../services/vaultIntegration");
      const mounts = await listMounts({ address, token });
      res.json({ mounts });
      try {
        if (req && req.body) delete req.body.token;
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }
    } catch (e) {
      const errorRef = generateErrorReference();
      logger.error("Vault mounts failed", {
        errorReference: errorRef,
        error: e?.message,
        errorCode: e?.code,
        errorType: e?.name,
        status: e?.status,
        userId: req?.user?.id,
        address: req.body?.address
          ? req.body.address.substring(0, 100)
          : "unknown",
        cause: e?.cause?.message,
      });

      // Provide more helpful error message to user
      let userMessage = "Vault mounts failed";
      const status =
        e?.status ||
        (e?.message?.match(/\s(\d{3})$/)?.[1]
          ? parseInt(e.message.match(/\s(\d{3})$/)[1])
          : null);

      if (e?.code === "ETIMEDOUT" || e?.name === "AbortError") {
        userMessage =
          "Vault connection timeout. Vault server is not responding - check if it is accessible from the server and verify firewall rules allow connections.";
      } else if (e?.code === "ENOTFOUND" || e?.code === "ECONNREFUSED") {
        userMessage =
          "Cannot connect to Vault. Check address and network connectivity. Verify firewall rules allow access to Vault.";
      } else if (
        e?.code === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
        e?.code === "SELF_SIGNED_CERT_IN_CHAIN" ||
        e?.code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" ||
        e?.code === "CERT_HAS_EXPIRED" ||
        e?.message?.includes("certificate") ||
        e?.message?.includes("SSL")
      ) {
        userMessage = `SSL certificate verification failed: ${e?.message || e?.code}. If using self-signed certificates, you may need to configure the server to trust your CA. Reference: ${errorRef}`;
      } else if (status === 403 || e?.message?.includes(" 403")) {
        // 403 could be auth OR network/firewall (some proxies return 403 for blocked connections)
        userMessage =
          "Vault returned 403 Forbidden. This could be: (1) Token lacks permissions to list mounts, or (2) Firewall/proxy blocking the connection. Verify Vault is accessible and token has proper permissions.";
      } else if (status === 404 || e?.message?.includes(" 404")) {
        userMessage =
          "Vault endpoint not found. Check address and ensure /v1/sys/mounts is accessible.";
      } else {
        userMessage = formatIntegrationError("Vault mounts", e, errorRef);
      }

      res.status(e?.status || 502).json({ error: userMessage });
    }
  },
);

// --- Vault integration: import selected discoveries as tokens ---
// Note: Import is allowed for free users who have performed scans; token limits still apply
router.post(
  "/api/v1/integrations/vault/import",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  async (req, res) => {
    try {
      res.set("Cache-Control", "no-store");
      res.set("Pragma", "no-cache");
      const role = req.authz?.workspaceRole;
      if (!role || !["admin", "workspace_manager"].includes(role)) {
        return res.status(403).json({ error: "Forbidden" });
      }
      const workspaceId = req.workspace.id;
      const { items, default_category, default_type, contact_group_id } =
        req.body || {};
      if (!Array.isArray(items) || items.length === 0) {
        return res.status(400).json({ error: "items array required" });
      }
      // Reuse core validation constraints for type/category; allow past expiration for imports
      const ALLOWED_TYPES = [
        "ssl_cert",
        "tls_cert",
        "code_signing",
        "client_cert",
        "api_key",
        "secret",
        "password",
        "encryption_key",
        "ssh_key",
        "software_license",
        "service_subscription",
        "domain_registration",
        "other",
        "document",
        "membership",
      ];
      const ALLOWED_CATEGORIES = ["cert", "key_secret", "license", "general"];

      // Enforce per-plan token limits before importing
      // Free: per-workspace limit

      const created = [];
      const updated = [];
      const errors = [];
      const NEVER_EXPIRES_DATE = "2099-12-31"; // Default for tokens without expiration
      for (const it of items) {
        try {
          const name = String(it?.name || "").trim();
          let expiration = it?.expiration || it?.expiresAt || null;
          let hasNoExpiration = false;
          if (expiration) {
            const d = new Date(expiration);
            if (isNaN(d.getTime())) expiration = null;
            else expiration = formatDateYmd(d);
          }
          // If no expiration date, use far-future default (e.g., GitHub SSH keys don't have expiration)
          if (!expiration) {
            expiration = NEVER_EXPIRES_DATE;
            hasNoExpiration = true;
          }
          const category = (
            it?.category ||
            default_category ||
            "general"
          ).toLowerCase();
          const type = (it?.type || default_type || "other").toLowerCase();
          if (!name) throw new Error("missing name");
          if (!ALLOWED_CATEGORIES.includes(category))
            throw new Error("invalid category");
          if (!ALLOWED_TYPES.includes(type)) throw new Error("invalid type");

          // Build notes with source info and expiration warning if needed
          let notes =
            it?.notes ||
            `Imported from ${it?.source || "vault"}:${it?.mount || ""}${it?.path || ""}`;
          if (hasNoExpiration) {
            const sourceInfo = it?.source ? ` (${it.source})` : "";
            notes = `Ã¢Å¡Â Ã¯Â¸Â This ${type} does not have an expiration date${sourceInfo}. Set to "Never expires" by default.\n${notes}`;
          }

          // Build section value (robust split and flatten)
          const normalizeSectionArray = (input, source) => {
            const parts = Array.isArray(input)
              ? input
              : String(input || "").split(",");
            const flat = parts
              .flatMap((p) => (typeof p === "string" ? p.split(",") : [p]))
              .map((s) => (typeof s === "string" ? s.trim() : s))
              .filter(Boolean);

            // Add default sections based on source if not already present
            if (source) {
              if (source.startsWith("gitlab") && !flat.includes("gitlab")) {
                flat.unshift("gitlab");
              } else if (
                source.startsWith("github") &&
                !flat.includes("github")
              ) {
                flat.unshift("github");
              } else if (source.startsWith("aws") && !flat.includes("aws")) {
                flat.unshift("aws");
              } else if (
                source.startsWith("azure") &&
                !flat.includes("azure")
              ) {
                flat.unshift("azure");
              } else if (source.startsWith("gcp") && !flat.includes("gcp")) {
                flat.unshift("gcp");
              } else if (source === "vault" && !flat.includes("vault")) {
                flat.unshift("vault");
              }
            }

            return flat.length > 0 ? [...new Set(flat)] : null;
          };

          const sectionValue = normalizeSectionArray(
            it?.section || (it?.source ? it.source : null),
            it?.source,
          );

          // Build privileges from scopes if available
          const privileges = Array.isArray(it?.scopes)
            ? it.scopes.join(", ").substring(0, 5000)
            : it?.privileges
              ? String(it.privileges).substring(0, 5000)
              : null;

          const tokenPayload = {
            name,
            category,
            type,
            expiration: expiration,
            section: sectionValue,
            domains: Array.isArray(it?.domains) ? it.domains : null,
            location: it?.location || null,
            used_by: it?.used_by || null,
            issuer: it?.issuer || null,
            serial_number: it?.serial_number || null,
            subject: it?.subject || null,
            key_size: it?.key_size || null,
            algorithm: it?.algorithm || null,
            license_type: it?.license_type || null,
            vendor: it?.vendor || null,
            cost: it?.cost || null,
            renewal_url: it?.renewal_url || null,
            renewal_date: it?.renewal_date || null,
            contacts: it?.contacts || null,
            description: it?.description || null,
            notes,
            contact_group_id: contact_group_id || null,
            privileges,
            last_used: it?.last_used_at || it?.last_used || null,
            created_at: it?.created_at || null,
            imported_at: new Date(),
          };

          // Check if token with same name and location already exists in this workspace
          let tok;
          const existingToken = await Token.findByNameLocationAndWorkspace(
            tokenPayload.name,
            tokenPayload.location,
            workspaceId,
          );

          if (existingToken) {
            // Update existing token with new characteristics
            tok = await Token.update(existingToken.id, tokenPayload);
            updated.push(tok);
            // Audit per-token update (best-effort)
            try {
              await writeAudit({
                actorUserId: req.user.id,
                subjectUserId: req.user.id,
                action: "TOKEN_UPDATED",
                targetType: "token",
                targetId: tok.id,
                channel: null,
                workspaceId,
                metadata: {
                  name: tok.name,
                  type: tok.type,
                  category: tok.category,
                  source: it?.source || "vault",
                  mount: it?.mount || null,
                  path: it?.path || null,
                  reason: "import_deduplication",
                },
              });
            } catch (_err) {
              logger.warn("Audit write failed", { error: _err.message });
            }
          } else {
            // Create new token
            tok = await Token.create({
              ...tokenPayload,
              userId: req.user.id,
              workspaceId,
              created_by: req.user.id,
              imported_at: new Date(),
            });
            created.push(tok);
            // Audit per-token import (best-effort)
            try {
              await writeAudit({
                actorUserId: req.user.id,
                subjectUserId: req.user.id,
                action: "TOKEN_IMPORTED",
                targetType: "token",
                targetId: tok.id,
                channel: null,
                workspaceId,
                metadata: {
                  name: tok.name,
                  type: tok.type,
                  category: tok.category,
                  source: it?.source || "vault",
                  mount: it?.mount || null,
                  path: it?.path || null,
                },
              });
            } catch (_err) {
              logger.warn("Audit write failed", { error: _err.message });
            }
          }
        } catch (e) {
          errors.push({
            item: it?.name || it?.path || "unknown",
            error: e?.message || String(e),
          });
        }
      }
      // Batch audit summary (best-effort)
      try {
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "TOKENS_IMPORTED",
          targetType: "workspace",
          targetId: null,
          channel: null,
          workspaceId,
          metadata: {
            created_count: created.length,
            updated_count: updated.length,
            error_count: errors.length,
            source: "vault",
          },
        });
      } catch (_err) {
        logger.warn("Audit write failed", { error: _err.message });
      }
      res.status(201).json({
        created_count: created.length,
        updated_count: updated.length,
        error_count: errors.length,
        created,
        updated,
        errors,
      });
      try {
        if (req && req.body) delete req.body.token;
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }
    } catch (e) {
      logger.error("Vault import failed", { error: e?.message });
      res.status(500).json({ error: "Vault import failed" });
    }
  },
);

// --- GitLab integration: scan for tokens/keys with expiration dates ---
router.post(
  "/api/v1/integrations/gitlab/scan",
  getApiLimiter(),
  requireAuth,
  requireIntegrationQuota,
  async (req, res) => {
    // Helper to include quota in any response
    const withQuota = (obj) => ({
      ...obj,
      quota: {
        used: req.integrationQuota?.used || 0,
        limit: req.integrationQuota?.limit || null,
        remaining:
          req.integrationQuota?.remaining !== undefined
            ? req.integrationQuota.remaining
            : null,
      },
    });

    try {
      const { baseUrl, token, include, maxItems, filters } = req.body || {};
      res.set("Cache-Control", "no-store");
      res.set("Pragma", "no-cache");
      if (!baseUrl || !token)
        return res
          .status(400)
          .json(withQuota({ error: "baseUrl and token are required" }));
      try {
        const u = new URL(baseUrl);
        if (!/^https?:$/.test(u.protocol))
          return res
            .status(400)
            .json(withQuota({ error: "baseUrl must be http(s)" }));
        // Optional SSRF allowlist via env: comma-separated hostnames
        const allow = String(process.env.GITLAB_ADDRESS_ALLOWLIST || "").trim();
        if (allow.length > 0) {
          const allowedHosts = allow
            .split(",")
            .map((s) => s.trim().toLowerCase())
            .filter(Boolean);
          const hostLc = String(u.hostname || "").toLowerCase();
          if (!allowedHosts.includes(hostLc)) {
            return res
              .status(400)
              .json(withQuota({ error: "GitLab address not allowed" }));
          }
        }
      } catch (_) {
        return res
          .status(400)
          .json(withQuota({ error: "invalid baseUrl URL" }));
      }
      if (
        maxItems !== undefined &&
        (!Number.isFinite(maxItems) || maxItems < 1 || maxItems > 2000)
      ) {
        return res
          .status(400)
          .json(withQuota({ error: "maxItems must be between 1 and 2000" }));
      }

      // Parse scan filters (defaults: all token types enabled, expired/revoked disabled)
      const scanFilters = {
        includePATs: filters?.includePATs !== false, // default true
        includeProjectTokens: filters?.includeProjectTokens !== false, // default true
        includeGroupTokens: filters?.includeGroupTokens !== false, // default true
        includeDeployTokens: filters?.includeDeployTokens !== false, // default true
        includeSSHKeys: filters?.includeSSHKeys !== false, // default true
        excludeUserPATs: filters?.excludeUserPATs === true, // default false
        includeExpired: filters?.includeExpired === true, // default false
        includeRevoked: filters?.includeRevoked === true, // default false
      };

      const result = await scanGitLab({
        baseUrl,
        token,
        include: {
          tokens:
            include && typeof include.tokens === "boolean"
              ? include.tokens
              : true,
          keys:
            include && typeof include.keys === "boolean" ? include.keys : true,
        },
        maxItems: maxItems || 500,
        filters: scanFilters,
      });

      res.json(withQuota(result));
      try {
        if (req && req.user) {
          await writeAudit({
            actorUserId: req.user.id,
            subjectUserId: req.user.id,
            action: "INTEGRATION_SCAN",
            targetType: "integration",
            targetId: null,
            channel: null,
            workspaceId: req.integrationQuota?.workspaceId || null,
            metadata: {
              provider: "gitlab",
              itemsFound: result.items?.length || 0,
            },
          });
        }
      } catch (_err) {
        logger.warn("Audit write failed", { error: _err.message });
      }
      try {
        if (req && req.body) delete req.body.token;
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }
    } catch (e) {
      const errorRef = generateErrorReference();
      logger.error("GitLab scan failed", {
        errorReference: errorRef,
        error: e?.message,
        status: e?.status,
        userId: req?.user?.id,
        baseUrl: req.body?.baseUrl,
      });

      let userMessage = "GitLab scan failed";
      if (e?.status === 400) {
        userMessage = `Invalid request: ${e?.message || "Bad Request"}. Check your GitLab URL format.`;
      } else if (e?.status === 401) {
        userMessage =
          e?.message ||
          'GitLab authentication failed. Token is invalid or expired. Generate a new Personal Access Token with "read_api" scope.';
      } else if (e?.status === 403) {
        userMessage =
          e?.message ||
          'GitLab permission denied. Ensure your token has "read_api" scope and you have access to the projects.';
      } else if (e?.status === 404) {
        userMessage =
          e?.message ||
          "Not a valid GitLab instance. Ensure the URL points to a GitLab server (e.g., https://gitlab.com or your self-hosted GitLab URL).";
      } else if (e?.status === 429) {
        userMessage =
          "GitLab rate limit exceeded. Wait a moment and try again.";
      } else if (
        e?.code === "ECONNABORTED" ||
        (e?.code === "ETIMEDOUT" && e?.message?.includes("timeout"))
      ) {
        // Connection timeout - likely firewall blocking or instance unreachable
        userMessage =
          "Connection timeout. The GitLab instance is not responding. This usually indicates:\n" +
          "Ã¢â‚¬Â¢ Firewall blocking the connection\n" +
          "Ã¢â‚¬Â¢ GitLab instance is unreachable or down\n" +
          "Ã¢â‚¬Â¢ Network routing issues\n" +
          "Please verify the URL, check firewall rules, and ensure the instance is accessible from this server.";
      } else if (
        e?.code === "ENOTFOUND" ||
        e?.code === "ECONNREFUSED" ||
        e?.code === "ETIMEDOUT" ||
        e?.code === "ECONNRESET" ||
        e?.code === "EPIPE"
      ) {
        // Use enhanced error message from gitlabRequest if available
        userMessage =
          e?.message ||
          "Cannot connect to GitLab instance. Verify the URL is correct, the instance is reachable, and check for any firewall rules that may be blocking the connection.";
      } else if (e?.message) {
        userMessage = e.message;
      } else {
        userMessage = formatIntegrationError("GitLab", e, errorRef);
      }

      res.status(e?.status || 502).json(withQuota({ error: userMessage }));
    }
  },
);

// --- GitHub integration: scan for tokens/keys with expiration dates ---
router.post(
  "/api/v1/integrations/github/scan",
  getApiLimiter(),
  requireAuth,
  requireIntegrationQuota,
  async (req, res) => {
    // Helper to include quota in any response
    const withQuota = (obj) => ({
      ...obj,
      quota: {
        used: req.integrationQuota?.used || 0,
        limit: req.integrationQuota?.limit || null,
        remaining:
          req.integrationQuota?.remaining !== undefined
            ? req.integrationQuota.remaining
            : null,
      },
    });

    try {
      const { baseUrl, token, include, maxItems } = req.body || {};
      res.set("Cache-Control", "no-store");
      res.set("Pragma", "no-cache");
      if (!baseUrl || !token)
        return res
          .status(400)
          .json(withQuota({ error: "baseUrl and token are required" }));
      try {
        const u = new URL(baseUrl);
        if (!/^https?:$/.test(u.protocol))
          return res
            .status(400)
            .json(withQuota({ error: "baseUrl must be http(s)" }));
        // Optional SSRF allowlist via env: comma-separated hostnames
        const allow = String(process.env.GITHUB_ADDRESS_ALLOWLIST || "").trim();
        if (allow.length > 0) {
          const allowedHosts = allow
            .split(",")
            .map((s) => s.trim().toLowerCase())
            .filter(Boolean);
          const hostLc = String(u.hostname || "").toLowerCase();
          if (!allowedHosts.includes(hostLc)) {
            return res
              .status(400)
              .json(withQuota({ error: "GitHub address not allowed" }));
          }
        }
      } catch (_) {
        return res
          .status(400)
          .json(withQuota({ error: "invalid baseUrl URL" }));
      }
      if (
        maxItems !== undefined &&
        (!Number.isFinite(maxItems) || maxItems < 1 || maxItems > 2000)
      ) {
        return res
          .status(400)
          .json(withQuota({ error: "maxItems must be between 1 and 2000" }));
      }
      // Backward compatibility: if old 'keys' param is used, apply to both sshKeys and deployKeys
      const useOldKeysParam = include && typeof include.keys === "boolean";
      const sshKeysValue =
        include && typeof include.sshKeys === "boolean"
          ? include.sshKeys
          : useOldKeysParam
            ? include.keys
            : true;
      const deployKeysValue =
        include && typeof include.deployKeys === "boolean"
          ? include.deployKeys
          : useOldKeysParam
            ? include.keys
            : true;

      const result = await scanGitHub({
        baseUrl,
        token,
        include: {
          tokens:
            include && typeof include.tokens === "boolean"
              ? include.tokens
              : true,
          sshKeys: sshKeysValue,
          deployKeys: deployKeysValue,
          secrets:
            include && typeof include.secrets === "boolean"
              ? include.secrets
              : true,
        },
        maxItems: maxItems || 500,
      });

      res.json(withQuota(result));
      try {
        if (req && req.user) {
          await writeAudit({
            actorUserId: req.user.id,
            subjectUserId: req.user.id,
            action: "INTEGRATION_SCAN",
            targetType: "integration",
            targetId: null,
            channel: null,
            workspaceId: req.integrationQuota?.workspaceId || null,
            metadata: {
              provider: "github",
              itemsFound: result.items?.length || 0,
            },
          });
        }
      } catch (_err) {
        logger.warn("Audit write failed", { error: _err.message });
      }
      try {
        if (req && req.body) delete req.body.token;
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }
    } catch (e) {
      const errorRef = generateErrorReference();
      logger.error("GitHub scan failed", {
        errorReference: errorRef,
        error: e?.message,
        status: e?.status,
        userId: req?.user?.id,
        baseUrl: req.body?.baseUrl,
      });

      let userMessage = "GitHub scan failed";
      if (e?.status === 400) {
        userMessage = `Invalid request: ${e?.message || "Bad Request"}. Check your GitHub URL format.`;
      } else if (e?.status === 401) {
        userMessage =
          e?.message ||
          "GitHub authentication failed. Token is invalid or expired. Generate a new Personal Access Token or Fine-grained token.";
      } else if (e?.status === 403) {
        userMessage =
          e?.message ||
          'GitHub permission denied. Token may lack required scopes. For classic tokens: "repo", "read:org", "read:user". For fine-grained: ensure repository access is granted.';
      } else if (e?.status === 404) {
        userMessage =
          e?.message ||
          "Not a valid GitHub instance. Ensure the URL points to GitHub.com or your GitHub Enterprise server (e.g., https://github.yourcompany.com/api/v3).";
      } else if (e?.status === 429) {
        userMessage =
          "GitHub rate limit exceeded. Wait for rate limit reset or use a token with higher limits.";
      } else if (
        e?.code === "ECONNABORTED" ||
        (e?.code === "ETIMEDOUT" && e?.message?.includes("timeout"))
      ) {
        // Connection timeout - likely firewall blocking or instance unreachable
        userMessage =
          "Connection timeout. The GitHub instance is not responding. This usually indicates:\n" +
          "Ã¢â‚¬Â¢ Firewall blocking the connection\n" +
          "Ã¢â‚¬Â¢ GitHub instance is unreachable or down\n" +
          "Ã¢â‚¬Â¢ Network routing issues\n" +
          "Please verify the URL, check firewall rules, and ensure the instance is accessible from this server.";
      } else if (
        e?.code === "ENOTFOUND" ||
        e?.code === "ECONNREFUSED" ||
        e?.code === "ETIMEDOUT" ||
        e?.code === "ECONNRESET" ||
        e?.code === "EPIPE"
      ) {
        // Use enhanced error message from githubRequest if available
        userMessage =
          e?.message ||
          "Cannot connect to GitHub instance. Verify the URL is correct, the instance is reachable, and check for any firewall rules that may be blocking the connection.";
      } else if (e?.message) {
        userMessage = e.message;
      } else {
        userMessage = formatIntegrationError("GitHub", e, errorRef);
      }

      res.status(e?.status || 502).json(withQuota({ error: userMessage }));
    }
  },
);

// --- AWS integration: detect regions with secrets ---
// Note: This is a lightweight utility endpoint, not counted against scan quota
router.post(
  "/api/v1/integrations/aws/detect-regions",
  getApiLimiter(),
  requireAuth,
  requireNotViewer,
  async (req, res) => {
    try {
      const { accessKeyId, secretAccessKey, sessionToken } = req.body || {};
      res.set("Cache-Control", "no-store");
      res.set("Pragma", "no-cache");
      if (!accessKeyId || !secretAccessKey)
        return res
          .status(400)
          .json({ error: "accessKeyId and secretAccessKey are required" });

      const result = await detectAWSRegions({
        accessKeyId,
        secretAccessKey,
        sessionToken: sessionToken || null,
      });

      logger.info("AWS region detection result", {
        regionsWithSecrets: result.regionsWithSecrets?.length || 0,
        regionsWithCertificates: result.regionsWithCertificates?.length || 0,
        iamUsers: result.iam?.usersCount || 0,
        iamKeys: result.iam?.keysCount || 0,
      });

      res.json(result);
      try {
        if (req && req.user) {
          await writeAudit({
            actorUserId: req.user.id,
            subjectUserId: req.user.id,
            action: "INTEGRATION_DETECT_REGIONS",
            targetType: "integration",
            targetId: null,
            channel: null,
            workspaceId: null,
            metadata: {
              provider: "aws",
              regionsFound: result.regionsWithSecrets?.length || 0,
            },
          });
        }
      } catch (_err) {
        logger.warn("Audit write failed", { error: _err.message });
      }
      try {
        if (req && req.body) {
          delete req.body.secretAccessKey;
          delete req.body.sessionToken;
        }
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }
    } catch (e) {
      const errorRef = generateErrorReference();
      logger.error("AWS region detection failed", {
        errorReference: errorRef,
        error: e?.message,
        status: e?.status,
        userId: req?.user?.id,
      });

      let userMessage = "AWS region detection failed";
      if (e?.status === 400) {
        userMessage = `Invalid AWS credentials: ${e?.message || "Bad Request"}. Verify your Access Key ID and Secret Access Key.`;
      } else if (
        e?.status === 401 ||
        e?.message?.includes("InvalidClientTokenId")
      ) {
        userMessage =
          "AWS authentication failed. Access key may be invalid or expired.";
      } else if (e?.status === 403 || e?.message?.includes("AccessDenied")) {
        userMessage =
          "AWS permission denied. IAM user/role needs at minimum: secretsmanager:ListSecrets, acm:ListCertificates, iam:ListUsers in multiple regions.";
      } else if (
        e?.status === 429 ||
        e?.message?.includes("ThrottlingException")
      ) {
        userMessage =
          "AWS rate limit exceeded during region detection. This scans multiple regions simultaneously - wait and try again.";
      } else if (e?.code === "ETIMEDOUT" || e?.name === "AbortError") {
        userMessage =
          "AWS region detection timeout. Scanning 27 regions takes time - this is normal, results are still being processed.";
      } else if (e?.message) {
        userMessage = e.message;
      } else {
        userMessage = formatIntegrationError(
          "AWS region detection",
          e,
          errorRef,
        );
      }

      res.status(e?.status || 502).json({ error: userMessage });
    }
  },
);

// --- AWS integration: scan for secrets/keys with expiration dates ---
router.post(
  "/api/v1/integrations/aws/scan",
  getApiLimiter(),
  requireAuth,
  requireIntegrationQuota,
  async (req, res) => {
    // Helper to include quota in any response
    const withQuota = (obj) => ({
      ...obj,
      quota: {
        used: req.integrationQuota?.used || 0,
        limit: req.integrationQuota?.limit || null,
        remaining:
          req.integrationQuota?.remaining !== undefined
            ? req.integrationQuota.remaining
            : null,
      },
    });

    try {
      const {
        accessKeyId,
        secretAccessKey,
        sessionToken,
        region,
        include,
        maxItems,
      } = req.body || {};
      res.set("Cache-Control", "no-store");
      res.set("Pragma", "no-cache");
      if (!accessKeyId || !secretAccessKey)
        return res.status(400).json(
          withQuota({
            error: "accessKeyId and secretAccessKey are required",
          }),
        );
      if (
        maxItems !== undefined &&
        (!Number.isFinite(maxItems) || maxItems < 1 || maxItems > 2000)
      ) {
        return res
          .status(400)
          .json(withQuota({ error: "maxItems must be between 1 and 2000" }));
      }
      const result = await scanAWS({
        accessKeyId,
        secretAccessKey,
        sessionToken: sessionToken || null,
        region: region || "us-east-1",
        include: {
          secrets:
            include && typeof include.secrets === "boolean"
              ? include.secrets
              : true,
          iam: include && typeof include.iam === "boolean" ? include.iam : true,
          certificates:
            include && typeof include.certificates === "boolean"
              ? include.certificates
              : true,
        },
        maxItems: maxItems || 500,
      });

      res.json(withQuota(result));
      try {
        if (req && req.user) {
          await writeAudit({
            actorUserId: req.user.id,
            subjectUserId: req.user.id,
            action: "INTEGRATION_SCAN",
            targetType: "integration",
            targetId: null,
            channel: null,
            workspaceId: req.integrationQuota?.workspaceId || null,
            metadata: {
              provider: "aws",
              itemsFound: result.items?.length || 0,
              region: region || "us-east-1",
            },
          });
        }
      } catch (_err) {
        logger.warn("Audit write failed", { error: _err.message });
      }
      try {
        if (req && req.body) {
          delete req.body.secretAccessKey;
          delete req.body.sessionToken;
        }
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }
    } catch (e) {
      const errorRef = generateErrorReference();
      logger.error("AWS scan failed", {
        errorReference: errorRef,
        error: e?.message,
        status: e?.status,
        userId: req?.user?.id,
        region: req.body?.region || "us-east-1",
      });

      let userMessage = "AWS scan failed";
      if (
        e?.status === 400 ||
        e?.message?.includes("Invalid accessKeyId") ||
        e?.message?.includes("Invalid secretAccessKey")
      ) {
        userMessage = `Invalid AWS credentials: ${e?.message || "Bad Request"}. Verify your Access Key ID and Secret Access Key.`;
      } else if (
        e?.status === 401 ||
        e?.message?.includes("InvalidClientTokenId") ||
        e?.message?.includes("SignatureDoesNotMatch")
      ) {
        userMessage =
          "AWS authentication failed. Access key may be invalid, expired, or credentials are incorrect.";
      } else if (e?.status === 403 || e?.message?.includes("AccessDenied")) {
        userMessage =
          "AWS permission denied. IAM user/role needs policies: secretsmanager:ListSecrets, secretsmanager:DescribeSecret, iam:ListUsers, iam:ListAccessKeys, acm:ListCertificates, acm:DescribeCertificate.";
      } else if (e?.message?.includes("InvalidParameterException")) {
        userMessage = `AWS invalid parameter: ${e?.message}. Check region format or other parameters.`;
      } else if (e?.message?.includes("ResourceNotFoundException")) {
        userMessage =
          "AWS resource not found. The specified resource (secret, certificate) may have been deleted.";
      } else if (
        e?.status === 429 ||
        e?.message?.includes("ThrottlingException")
      ) {
        userMessage =
          "AWS rate limit exceeded. Wait a moment and try again, or request a limit increase.";
      } else if (e?.message?.includes("ServiceUnavailableException")) {
        userMessage =
          "AWS service temporarily unavailable. Wait a moment and try again.";
      } else if (e?.code === "ENOTFOUND" || e?.code === "ECONNREFUSED") {
        userMessage = "Cannot connect to AWS. Check your network connectivity.";
      } else if (e?.message) {
        userMessage = e.message;
      } else {
        userMessage = formatIntegrationError("AWS", e, errorRef);
      }

      res.status(e?.status || 502).json(withQuota({ error: userMessage }));
    }
  },
);

// --- Azure integration: scan Key Vault for secrets/certificates/keys with expiration dates ---
router.post(
  "/api/v1/integrations/azure/scan",
  getApiLimiter(),
  requireAuth,
  requireIntegrationQuota,
  async (req, res) => {
    // Helper to include quota in any response
    const withQuota = (obj) => ({
      ...obj,
      quota: {
        used: req.integrationQuota?.used || 0,
        limit: req.integrationQuota?.limit || null,
        remaining:
          req.integrationQuota?.remaining !== undefined
            ? req.integrationQuota.remaining
            : null,
      },
    });

    try {
      const { vaultUrl, token, include, maxItems } = req.body || {};
      res.set("Cache-Control", "no-store");
      res.set("Pragma", "no-cache");
      if (!vaultUrl || !token)
        return res
          .status(400)
          .json(withQuota({ error: "vaultUrl and token are required" }));
      try {
        const u = new URL(vaultUrl);
        if (!/^https?:$/.test(u.protocol))
          return res
            .status(400)
            .json(withQuota({ error: "vaultUrl must be http(s)" }));
        // Optional SSRF allowlist via env: comma-separated hostnames
        const allow = String(
          process.env.AZURE_VAULT_ADDRESS_ALLOWLIST || "",
        ).trim();
        if (allow.length > 0) {
          const allowedHosts = allow
            .split(",")
            .map((s) => s.trim().toLowerCase())
            .filter(Boolean);
          const hostLc = String(u.hostname || "").toLowerCase();
          if (!allowedHosts.includes(hostLc)) {
            return res
              .status(400)
              .json(
                withQuota({ error: "Azure Key Vault address not allowed" }),
              );
          }
        }
      } catch (_) {
        return res
          .status(400)
          .json(withQuota({ error: "invalid vaultUrl URL" }));
      }
      if (
        maxItems !== undefined &&
        (!Number.isFinite(maxItems) || maxItems < 1 || maxItems > 2000)
      ) {
        return res
          .status(400)
          .json(withQuota({ error: "maxItems must be between 1 and 2000" }));
      }
      const result = await scanAzure({
        vaultUrl,
        token,
        include: {
          secrets:
            include && typeof include.secrets === "boolean"
              ? include.secrets
              : true,
          certificates:
            include && typeof include.certificates === "boolean"
              ? include.certificates
              : true,
          keys:
            include && typeof include.keys === "boolean" ? include.keys : true,
        },
        maxItems: maxItems || 500,
      });

      res.json(withQuota(result));
      try {
        if (req && req.user) {
          await writeAudit({
            actorUserId: req.user.id,
            subjectUserId: req.user.id,
            action: "INTEGRATION_SCAN",
            targetType: "integration",
            targetId: null,
            channel: null,
            workspaceId: req.integrationQuota?.workspaceId || null,
            metadata: {
              provider: "azure",
              itemsFound: result.items?.length || 0,
            },
          });
        }
      } catch (_err) {
        logger.warn("Audit write failed", { error: _err.message });
      }
      try {
        if (req && req.body) delete req.body.token;
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }
    } catch (e) {
      const errorRef = generateErrorReference();
      logger.error("Azure scan failed", {
        errorReference: errorRef,
        error: e?.message,
        status: e?.status,
        userId: req?.user?.id,
      });

      // Provide helpful error messages
      let userMessage = "Azure Key Vault scan failed";
      if (e?.status === 400) {
        userMessage = `Invalid request: ${e?.message || "Bad Request"}. Check your Key Vault URL format (should be https://[name].vault.azure.net).`;
      } else if (e?.status === 401) {
        userMessage =
          "Authentication failed. Token may be expired (Azure CLI tokens expire quickly) or invalid. Clear cache: az account clear && az login, then regenerate: az account get-access-token --resource https://vault.azure.net";
      } else if (e?.status === 403) {
        userMessage =
          'Permission denied. Ensure your account has "Key Vault Secrets User", "Key Vault Certificates User", and "Key Vault Crypto User" roles on the vault.';
      } else if (e?.status === 404) {
        userMessage =
          "Key Vault not found. Check the vault name and ensure it exists in your subscription.";
      } else if (e?.status === 429) {
        userMessage = "Azure rate limit exceeded. Wait a moment and try again.";
      } else if (
        e?.message?.includes("VaultNotFound") ||
        e?.message?.includes("ResourceNotFound")
      ) {
        userMessage =
          "Key Vault not found. Verify the vault URL and ensure you have access.";
      } else if (e?.code === "ENOTFOUND" || e?.code === "ECONNREFUSED") {
        userMessage =
          "Cannot connect to Azure. Check your vault URL and network connectivity.";
      } else if (e?.message) {
        userMessage = e.message;
      } else {
        // Unexpected error - provide reference code
        userMessage = formatIntegrationError("Azure Key Vault", e, errorRef);
      }

      res.status(e?.status || 502).json(withQuota({ error: userMessage }));
    }
  },
);

// --- GCP integration: scan Secret Manager for secrets with expiration dates ---
router.post(
  "/api/v1/integrations/gcp/scan",
  getApiLimiter(),
  requireAuth,
  requireIntegrationQuota,
  async (req, res) => {
    // Helper to include quota in any response
    const withQuota = (obj) => ({
      ...obj,
      quota: {
        used: req.integrationQuota?.used || 0,
        limit: req.integrationQuota?.limit || null,
        remaining:
          req.integrationQuota?.remaining !== undefined
            ? req.integrationQuota.remaining
            : null,
      },
    });

    try {
      const { projectId, accessToken, include, maxItems } = req.body || {};
      res.set("Cache-Control", "no-store");
      res.set("Pragma", "no-cache");
      if (!projectId || !accessToken)
        return res
          .status(400)
          .json(withQuota({ error: "projectId and accessToken are required" }));
      if (
        maxItems !== undefined &&
        (!Number.isFinite(maxItems) || maxItems < 1 || maxItems > 2000)
      ) {
        return res
          .status(400)
          .json(withQuota({ error: "maxItems must be between 1 and 2000" }));
      }
      const result = await scanGCP({
        projectId,
        accessToken,
        include: {
          secrets:
            include && typeof include.secrets === "boolean"
              ? include.secrets
              : true,
        },
        maxItems: maxItems || 500,
      });

      res.json(withQuota(result));
      try {
        if (req && req.user) {
          await writeAudit({
            actorUserId: req.user.id,
            subjectUserId: req.user.id,
            action: "INTEGRATION_SCAN",
            targetType: "integration",
            targetId: null,
            channel: null,
            workspaceId: req.integrationQuota?.workspaceId || null,
            metadata: {
              provider: "gcp",
              itemsFound: result.items?.length || 0,
              projectId,
            },
          });
        }
      } catch (_err) {
        logger.warn("Audit write failed", { error: _err.message });
      }
      try {
        if (req && req.body) delete req.body.accessToken;
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }
    } catch (e) {
      const errorRef = generateErrorReference();
      logger.error("GCP scan failed", {
        errorReference: errorRef,
        error: e?.message,
        status: e?.status,
        userId: req?.user?.id,
        projectId: req.body?.projectId,
      });

      let userMessage = "GCP scan failed";
      if (e?.status === 400) {
        userMessage = `Invalid request: ${e?.message || "Bad Request"}. Check your project ID format.`;
      } else if (e?.status === 401) {
        userMessage =
          "GCP authentication failed. Token may be expired or invalid. Generate fresh token: gcloud auth print-access-token";
      } else if (
        e?.status === 403 ||
        e?.message?.includes("PermissionDenied")
      ) {
        userMessage =
          'GCP permission denied. Ensure your account has "Secret Manager Secret Accessor" role (roles/secretmanager.secretAccessor) on the project.';
      } else if (e?.status === 404 || e?.message?.includes("NotFound")) {
        userMessage =
          "GCP project or resource not found. Verify your project ID is correct and you have access.";
      } else if (
        e?.status === 429 ||
        e?.message?.includes("ResourceExhausted") ||
        e?.message?.includes("RATE_LIMIT_EXCEEDED")
      ) {
        userMessage =
          "GCP rate limit or quota exceeded. Wait a moment and try again, or increase your quota.";
      } else if (
        e?.message?.includes("API has not been used") ||
        e?.message?.includes("API_NOT_ACTIVATED")
      ) {
        userMessage =
          'GCP Secret Manager API is not enabled. Enable it in Google Cloud Console: APIs & Services Ã¢â€ â€™ Enable "Secret Manager API".';
      } else if (e?.code === "ENOTFOUND" || e?.code === "ECONNREFUSED") {
        userMessage = "Cannot connect to GCP. Check your network connectivity.";
      } else if (e?.message) {
        userMessage = e.message;
      } else {
        // Unexpected error - provide reference code
        userMessage = formatIntegrationError("GCP", e, errorRef);
      }

      res.status(e?.status || 502).json(withQuota({ error: userMessage }));
    }
  },
);

// --- Azure AD integration: scan app registrations and service principals for expiring credentials ---
router.post(
  "/api/v1/integrations/azure-ad/scan",
  getApiLimiter(),
  requireAuth,
  requireIntegrationQuota,
  async (req, res) => {
    // Helper to include quota in any response
    const withQuota = (obj) => ({
      ...obj,
      quota: {
        used: req.integrationQuota?.used || 0,
        limit: req.integrationQuota?.limit || null,
        remaining:
          req.integrationQuota?.remaining !== undefined
            ? req.integrationQuota.remaining
            : null,
      },
    });

    try {
      const { token, include, maxItems } = req.body || {};
      res.set("Cache-Control", "no-store");
      res.set("Pragma", "no-cache");
      if (!token)
        return res.status(400).json(withQuota({ error: "token is required" }));
      if (typeof token === "string" && token.length > 5000) {
        return res
          .status(400)
          .json(
            withQuota({ error: "token is too long (max 5000 characters)" }),
          );
      }
      if (
        maxItems !== undefined &&
        (!Number.isFinite(maxItems) || maxItems < 1 || maxItems > 2000)
      ) {
        return res
          .status(400)
          .json(withQuota({ error: "maxItems must be between 1 and 2000" }));
      }
      const result = await scanAzureAD({
        token,
        include: {
          applications:
            include && typeof include.applications === "boolean"
              ? include.applications
              : true,
          servicePrincipals:
            include && typeof include.servicePrincipals === "boolean"
              ? include.servicePrincipals
              : true,
        },
        maxItems: maxItems || 500,
      });

      res.json(withQuota(result));
      try {
        if (req && req.user) {
          await writeAudit({
            actorUserId: req.user.id,
            subjectUserId: req.user.id,
            action: "INTEGRATION_SCAN",
            targetType: "integration",
            targetId: null,
            channel: null,
            workspaceId: req.integrationQuota?.workspaceId || null,
            metadata: {
              provider: "azure-ad",
              itemsFound: result.items?.length || 0,
            },
          });
        }
      } catch (_err) {
        logger.warn("Audit write failed", { error: _err.message });
      }
      try {
        if (req && req.body) delete req.body.token;
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }
    } catch (e) {
      const errorRef = generateErrorReference();
      logger.error("Azure AD scan failed", {
        errorReference: errorRef,
        error: e?.message,
        status: e?.status,
        graphError: e?.graphError,
        userId: req?.user?.id,
      });

      // Provide helpful error messages based on status code
      let userMessage = "Azure AD scan failed";
      if (e?.status === 400 || e?.graphError === "BadRequest") {
        if (e?.message?.includes("Invalid version")) {
          userMessage =
            "Microsoft Graph API version error. This should not happen - please report this. Reference: ${errorRef}";
        } else {
          userMessage = `Invalid request: ${e?.message || "Bad Request"}. Ensure token is for Microsoft Graph API (resource: https://graph.microsoft.com).`;
        }
      } else if (
        e?.status === 401 ||
        e?.graphError === "InvalidAuthenticationToken"
      ) {
        userMessage =
          "Authentication failed. Token may be expired (Azure CLI tokens expire quickly) or invalid. Clear cache: az account clear && az login, then regenerate.";
      } else if (e?.status === 403 || e?.graphError === "Forbidden") {
        userMessage =
          'Permission denied. Token needs "Application.Read.All" or "Directory.Read.All" permission with admin consent granted in Azure Portal.';
      } else if (e?.status === 404) {
        userMessage =
          "Microsoft Graph endpoint not found. Verify the token audience is correct.";
      } else if (e?.status === 429 || e?.graphError === "TooManyRequests") {
        userMessage =
          "Microsoft Graph rate limit exceeded. Wait a moment and try again.";
      } else if (
        e?.message?.includes("CompactToken") ||
        e?.message?.includes("audience")
      ) {
        userMessage = `Token audience mismatch: ${e?.message}. Token must be for https://graph.microsoft.com (not ARM or other resource).`;
      } else if (e?.code === "ENOTFOUND" || e?.code === "ECONNREFUSED") {
        userMessage =
          "Cannot connect to Microsoft Graph API. Check your network connectivity.";
      } else if (e?.message) {
        userMessage = e.message;
      } else {
        // Unexpected error - provide reference code
        userMessage = formatIntegrationError("Azure AD", e, errorRef);
      }

      res.status(e?.status || 502).json(withQuota({ error: userMessage }));
    }
  },
);

// --- Check for duplicate tokens before import ---
// Note: Utility endpoint for import, allowed for free users
router.post(
  "/api/v1/integrations/check-duplicates",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  async (req, res) => {
    try {
      res.set("Cache-Control", "no-store");
      res.set("Pragma", "no-cache");
      const role = req.authz?.workspaceRole;
      if (!role || !["admin", "workspace_manager"].includes(role)) {
        return res.status(403).json({ error: "Forbidden" });
      }
      const workspaceId = req.workspace.id;
      const { items } = req.body || {};
      if (!Array.isArray(items) || items.length === 0) {
        return res.status(400).json({ error: "items array required" });
      }

      const duplicates = [];
      for (const it of items) {
        const name = String(it?.name || "").trim();
        const location = it?.location ? String(it.location).trim() : null;

        if (name) {
          const existingToken = await Token.findByNameLocationAndWorkspace(
            name,
            location,
            workspaceId,
          );

          if (existingToken) {
            duplicates.push({
              name,
              location,
              existing_token: {
                id: existingToken.id,
                name: existingToken.name,
                location: existingToken.location,
                expiration: existingToken.expiration,
              },
            });
          }
        }
      }

      res.json({ duplicates, duplicate_count: duplicates.length });
    } catch (e) {
      logger.error("Check duplicates failed", { error: e?.message });
      res.status(500).json({ error: "Check duplicates failed" });
    }
  },
);

// --- Integration import endpoint (shared for all integrations) ---
// Note: Import is allowed for free users who have performed scans; token limits still apply
router.post(
  "/api/v1/integrations/import",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  async (req, res) => {
    try {
      res.set("Cache-Control", "no-store");
      res.set("Pragma", "no-cache");
      const role = req.authz?.workspaceRole;
      if (!role || !["admin", "workspace_manager"].includes(role)) {
        return res.status(403).json({ error: "Forbidden" });
      }
      const workspaceId = req.workspace.id;
      const { items, default_category, default_type, contact_group_id } =
        req.body || {};
      if (!Array.isArray(items) || items.length === 0) {
        return res.status(400).json({ error: "items array required" });
      }
      const ALLOWED_TYPES = [
        "ssl_cert",
        "tls_cert",
        "code_signing",
        "client_cert",
        "api_key",
        "secret",
        "password",
        "encryption_key",
        "ssh_key",
        "software_license",
        "service_subscription",
        "domain_registration",
        "other",
        "document",
        "membership",
      ];
      const ALLOWED_CATEGORIES = ["cert", "key_secret", "license", "general"];
      const created = [];
      const updated = [];
      const errors = [];
      const NEVER_EXPIRES_DATE = "2099-12-31"; // Default for tokens without expiration
      for (const it of items) {
        try {
          // Sanitize and validate name (HTML escape for XSS protection)
          let name = String(it?.name || "").trim();
          name = name
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#x27;");

          let expiration = it?.expiration || it?.expiresAt || null;
          let hasNoExpiration = false;
          if (expiration) {
            const d = new Date(expiration);
            if (isNaN(d.getTime())) expiration = null;
            else expiration = formatDateYmd(d);
          }
          // If no expiration date, use far-future default (e.g., GitHub SSH keys, AWS IAM access keys don't have expiration)
          if (!expiration) {
            expiration = NEVER_EXPIRES_DATE;
            hasNoExpiration = true;
          }
          const category = (
            it?.category ||
            default_category ||
            "general"
          ).toLowerCase();
          const type = (it?.type || default_type || "other").toLowerCase();

          // Validate required fields
          if (!name) throw new Error("missing name");
          if (name.length < 3 || name.length > 100)
            throw new Error("name must be between 3 and 100 characters");
          if (!ALLOWED_CATEGORIES.includes(category))
            throw new Error("invalid category");
          if (!ALLOWED_TYPES.includes(type)) throw new Error("invalid type");

          // Validate optional field lengths
          if (it?.location && String(it.location).length > 500)
            throw new Error("location must be less than 500 characters");
          if (it?.used_by && String(it.used_by).length > 500)
            throw new Error("used_by must be less than 500 characters");
          if (it?.issuer && String(it.issuer).length > 255)
            throw new Error("issuer must be less than 255 characters");
          if (it?.serial_number && String(it.serial_number).length > 255)
            throw new Error("serial_number must be less than 255 characters");
          if (it?.subject && String(it.subject).length > 1000)
            throw new Error("subject must be less than 1000 characters");
          if (it?.algorithm && String(it.algorithm).length > 100)
            throw new Error("algorithm must be less than 100 characters");
          if (it?.license_type && String(it.license_type).length > 100)
            throw new Error("license_type must be less than 100 characters");
          if (it?.vendor && String(it.vendor).length > 255)
            throw new Error("vendor must be less than 255 characters");
          if (it?.renewal_url && String(it.renewal_url).length > 500)
            throw new Error("renewal_url must be less than 500 characters");
          if (it?.contacts && String(it.contacts).length > 500)
            throw new Error("contacts must be less than 500 characters");
          if (it?.section) {
            if (Array.isArray(it.section)) {
              if (it.section.length > 50)
                throw new Error("Too many labels (max 50)");
              for (const s of it.section) {
                if (String(s).length > 120)
                  throw new Error(
                    "Each label must be less than 120 characters",
                  );
              }
            } else if (String(it.section).length > 255) {
              throw new Error("section must be less than 255 characters");
            }
          }
          if (it?.description && String(it.description).length > 10000)
            throw new Error("description must be less than 10000 characters");
          if (it?.notes && String(it.notes).length > 10000)
            throw new Error("notes must be less than 10000 characters");
          if (it?.privileges && String(it.privileges).length > 5000)
            throw new Error("privileges must be less than 5000 characters");

          // Validate numeric fields
          if (it?.key_size !== undefined && it?.key_size !== null) {
            const ks = Number(it.key_size);
            if (!Number.isInteger(ks) || ks < 128 || ks > 16384)
              throw new Error("key_size must be between 128 and 16384");
          }
          if (it?.cost !== undefined && it?.cost !== null) {
            const c = Number(it.cost);
            if (isNaN(c) || c < 0 || c >= 1000000000000)
              throw new Error("cost must be between 0 and 1 trillion");
          }

          // Validate domains format
          if (it?.domains) {
            const domainArray = Array.isArray(it.domains)
              ? it.domains
              : String(it.domains)
                  .split(",")
                  .map((d) => d.trim());
            for (const domain of domainArray) {
              if (domain && !/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
                throw new Error(`invalid domain format: ${domain}`);
              }
            }
          }

          // Validate renewal_date format if provided
          if (it?.renewal_date) {
            const renewalDate = String(it.renewal_date).trim();
            if (renewalDate && !/^\d{4}-\d{2}-\d{2}$/.test(renewalDate)) {
              throw new Error("renewal_date must be in YYYY-MM-DD format");
            }
            const rd = new Date(renewalDate);
            if (isNaN(rd.getTime())) {
              throw new Error("renewal_date is not a valid date");
            }
          }

          // Sanitize text fields (basic HTML escape for XSS protection)
          const sanitizeText = (text) => {
            if (!text) return text;
            return String(text).replace(/</g, "&lt;").replace(/>/g, "&gt;");
          };

          // Apply sanitization to user-editable text fields
          const sanitizedLocation = sanitizeText(it?.location);
          let sanitizedUsedBy = sanitizeText(it?.used_by);
          let sanitizedDescription = sanitizeText(it?.description);

          // Build owner/user information for "Used by" field
          // This field shows who owns/uses the token
          const usedByParts = [];
          if (sanitizedUsedBy) {
            usedByParts.push(sanitizedUsedBy); // Preserve any existing used_by value
          }

          // Add GitLab owner (actual owner from admin scan)
          if (it?.gitlab_owner) {
            const adminBadge = it?.gitlab_owner_is_admin ? " (Admin)" : "";
            usedByParts.push(`${it.gitlab_owner}${adminBadge}`);
          }

          // Add token username/owner (for service accounts like project access tokens)
          if (it?.token_username) {
            usedByParts.push(`${it.token_username} (Service Account)`);
          }

          // Add GitHub owner/org context (for repo-level resources)
          if (it?.github_owner) {
            usedByParts.push(it.github_owner);
          }

          // Build the final used_by field
          if (usedByParts.length > 0) {
            sanitizedUsedBy = usedByParts.join(", ");
          }

          // Build contextual description from integration metadata (technical details)
          // Enhancement: dedicated columns (scopes, source_context) could replace this JSON approach
          const contextParts = [];

          // Add project context (GitLab/GitHub project tokens)
          if (it?.project_name) {
            contextParts.push(`Project: ${it.project_name}`);
          }

          // Add group context (GitLab group tokens)
          if (it?.group_name) {
            contextParts.push(`Group: ${it.group_name}`);
          }

          // Add scopes if available (GitLab, GitHub, etc.)
          if (it?.scopes && Array.isArray(it.scopes) && it.scopes.length > 0) {
            contextParts.push(`Scopes: ${it.scopes.join(", ")}`);
          }

          // Add last used timestamp if available
          // Only show if there's actual usage data (omit if never used)
          if (it?.last_used_at) {
            try {
              const lastUsed = new Date(it.last_used_at);
              if (!isNaN(lastUsed.getTime())) {
                const now = new Date();
                const diffMs = now - lastUsed;
                const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

                // Format as readable relative time
                let timeAgo;
                if (diffDays === 0) {
                  timeAgo = "today";
                } else if (diffDays === 1) {
                  timeAgo = "yesterday";
                } else if (diffDays < 7) {
                  timeAgo = `${diffDays} days ago`;
                } else if (diffDays < 30) {
                  const weeks = Math.floor(diffDays / 7);
                  timeAgo = weeks === 1 ? "1 week ago" : `${weeks} weeks ago`;
                } else if (diffDays < 365) {
                  const months = Math.floor(diffDays / 30);
                  timeAgo =
                    months === 1 ? "1 month ago" : `${months} months ago`;
                } else {
                  const years = Math.floor(diffDays / 365);
                  timeAgo = years === 1 ? "1 year ago" : `${years} years ago`;
                }

                // Add exact date in parentheses
                const dateStr = lastUsed.toISOString().split("T")[0];
                contextParts.push(`Last used: ${timeAgo} (${dateStr})`);
              }
            } catch (_err) {
              logger.debug("Non-critical operation failed", {
                error: _err.message,
              });
            }
          }

          // Prepend context to description
          if (contextParts.length > 0) {
            const contextText = contextParts.join("\n");
            if (sanitizedDescription) {
              sanitizedDescription = `${contextText}\n\n${sanitizedDescription}`;
            } else {
              sanitizedDescription = contextText;
            }
          }

          // Build notes with source info and expiration warning if needed
          let notes =
            it?.notes || `Imported from ${it?.source || "integration"}`;
          if (hasNoExpiration) {
            const sourceInfo = it?.source ? ` (${it.source})` : "";
            notes = `Ã¢Å¡Â Ã¯Â¸Â This ${type} does not have an expiration date${sourceInfo}. Set to "Never expires" by default.\n${notes}`;
          }

          // privileges from scopes or other source-specific fields
          let privileges = null;
          if (it?.scopes && Array.isArray(it.scopes)) {
            privileges = it.scopes.join(", ");
          } else if (it?.privileges) {
            privileges = String(it.privileges);
          }
          privileges = sanitizeText(privileges);

          // Determine section from source field (robust split and flatten)
          const normalizeSectionArray = (input, source) => {
            const parts = Array.isArray(input)
              ? input
              : String(input || "").split(",");
            const flat = parts
              .flatMap((p) => (typeof p === "string" ? p.split(",") : [p]))
              .map((s) => (typeof s === "string" ? s.trim() : s))
              .filter(Boolean);

            // Add default sections based on source if not already present
            if (source) {
              if (source.startsWith("gitlab") && !flat.includes("gitlab")) {
                flat.unshift("gitlab");
              } else if (
                source.startsWith("github") &&
                !flat.includes("github")
              ) {
                flat.unshift("github");
              } else if (source.startsWith("aws") && !flat.includes("aws")) {
                flat.unshift("aws");
              } else if (
                source.startsWith("azure") &&
                !flat.includes("azure")
              ) {
                flat.unshift("azure");
              } else if (source.startsWith("gcp") && !flat.includes("gcp")) {
                flat.unshift("gcp");
              } else if (source === "vault" && !flat.includes("vault")) {
                flat.unshift("vault");
              }
            }

            return flat.length > 0 ? [...new Set(flat)] : null;
          };

          const sectionValue = normalizeSectionArray(
            it?.section || (it?.source ? it.source : null),
            it?.source,
          );

          // Robustly parse date fields from integration
          const parseIntegrationDate = (val) => {
            if (!val) return null;
            try {
              const d = new Date(val);
              return isNaN(d.getTime()) ? null : d;
            } catch (_) {
              return null;
            }
          };

          const tokenPayload = {
            name,
            category,
            type,
            expiration: expiration, // Database column is 'expiration', not 'expiresAt'
            section: sectionValue,
            domains: Array.isArray(it?.domains) ? it.domains : null,
            location: sanitizedLocation
              ? sanitizedLocation.substring(0, 500)
              : null,
            used_by: sanitizedUsedBy ? sanitizedUsedBy.substring(0, 500) : null,
            issuer: it?.issuer
              ? sanitizeText(String(it.issuer)).substring(0, 255)
              : null,
            serial_number: it?.serial_number
              ? sanitizeText(String(it.serial_number)).substring(0, 255)
              : null,
            subject: it?.subject
              ? sanitizeText(String(it.subject)).substring(0, 1000)
              : null,
            key_size: it?.key_size ? Number(it.key_size) : null,
            algorithm: it?.algorithm
              ? sanitizeText(String(it.algorithm)).substring(0, 100)
              : null,
            license_type: it?.license_type
              ? sanitizeText(String(it.license_type)).substring(0, 100)
              : null,
            vendor: it?.vendor
              ? sanitizeText(String(it.vendor)).substring(0, 255)
              : null,
            cost: it?.cost ? Number(it.cost) : null,
            renewal_url: it?.renewal_url
              ? String(it.renewal_url).trim().substring(0, 500)
              : null,
            renewal_date: it?.renewal_date
              ? String(it.renewal_date).trim()
              : null,
            contacts: it?.contacts
              ? sanitizeText(String(it.contacts)).substring(0, 500)
              : null,
            description: sanitizedDescription
              ? sanitizedDescription.substring(0, 10000)
              : null,
            notes: notes ? sanitizeText(notes).substring(0, 10000) : null,
            contact_group_id: contact_group_id || null,
            privileges,
            last_used: parseIntegrationDate(it?.last_used_at || it?.last_used),
            created_at: parseIntegrationDate(it?.created_at),
            imported_at: new Date(),
          };

          // Check if token with same name and location already exists in this workspace
          let tok;
          const existingToken = await Token.findByNameLocationAndWorkspace(
            tokenPayload.name,
            tokenPayload.location,
            workspaceId,
          );

          if (existingToken) {
            // Update existing token with new characteristics
            tok = await Token.update(existingToken.id, tokenPayload);
            updated.push(tok);
            try {
              await writeAudit({
                actorUserId: req.user.id,
                subjectUserId: req.user.id,
                action: "TOKEN_UPDATED",
                targetType: "token",
                targetId: tok.id,
                channel: null,
                workspaceId,
                metadata: {
                  name: tok.name,
                  type: tok.type,
                  category: tok.category,
                  source: it?.source || "integration",
                  reason: "import_deduplication",
                },
              });
            } catch (_err) {
              logger.warn("Audit write failed", { error: _err.message });
            }
          } else {
            // Create new token
            tok = await Token.create({
              ...tokenPayload,
              userId: req.user.id,
              workspaceId,
              created_by: req.user.id,
              imported_at: new Date(),
            });
            created.push(tok);
            try {
              await writeAudit({
                actorUserId: req.user.id,
                subjectUserId: req.user.id,
                action: "TOKEN_IMPORTED",
                targetType: "token",
                targetId: tok.id,
                channel: null,
                workspaceId,
                metadata: {
                  name: tok.name,
                  type: tok.type,
                  category: tok.category,
                  source: it?.source || "integration",
                },
              });
            } catch (_err) {
              logger.warn("Audit write failed", { error: _err.message });
            }
          }
        } catch (e) {
          const errorMsg = e?.message || String(e);
          logger.warn("Integration import item validation failed", {
            item: it?.name || it?.location || "unknown",
            error: errorMsg,
            source: it?.source,
          });
          errors.push({
            item: it?.name || it?.location || "unknown",
            error: errorMsg,
            field: errorMsg.includes("name")
              ? "name"
              : errorMsg.includes("location")
                ? "location"
                : null,
          });
        }
      }
      try {
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "TOKENS_IMPORTED",
          targetType: "workspace",
          targetId: null,
          channel: null,
          workspaceId,
          metadata: {
            created_count: created.length,
            updated_count: updated.length,
            error_count: errors.length,
            source: "integration",
          },
        });
      } catch (_err) {
        logger.warn("Audit write failed", { error: _err.message });
      }
      res.status(201).json({
        created_count: created.length,
        updated_count: updated.length,
        error_count: errors.length,
        created,
        updated,
        errors,
      });
    } catch (e) {
      logger.error("Integration import failed", { error: e?.message });
      res.status(500).json({ error: "Integration import failed" });
    }
  },
);

module.exports = router;
