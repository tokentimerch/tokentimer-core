const { pool } = require("../db/database");
const { logger } = require("../utils/logger");
const { writeAudit } = require("../services/audit");
const { requireAuth } = require("../middleware/auth");
const {
  getApiLimiter,
  getDomainCheckerLookupLimiter,
} = require("../middleware/rateLimit");
const systemSettings = require("../services/systemSettings");
const {
  loadWorkspace,
  requireWorkspaceMembership,
  authorize,
} = require("../services/rbac");
const { formatDateYmd } = require("../services/integrationUtils");
const {
  getDomainCheckerDiscoveryMaxResults,
  getDomainCheckerImportMaxCertificates,
} = require("../services/planLimits");
const {
  lookupDomain,
  normalizeHostname,
  normalizeRootDomain,
  isWithinRootDomain,
  fetchHostnameCertificate,
  liveCertificateImportSkipDetail,
} = require("../services/domainChecker");

const DNS_LIVE_CERT_SKIP_DETAILS = new Set([
  "live_certificate_dns_unresolved",
  "live_certificate_dns_temporary",
]);

const router = require("express").Router();

function publicToolErrors(toolErrors) {
  if (!Array.isArray(toolErrors) || toolErrors.length === 0) return undefined;
  return toolErrors.map((error) => ({
    tool: error.tool || "unknown",
    code: error.code || "DOMAIN_CHECKER_TOOL_ERROR",
    message: error.message || "Discovery tool failed",
  }));
}

function attachLongRunningDomainImportSocket(req, res) {
  try {
    res.setHeader("X-Accel-Buffering", "no");
  } catch (_) {}
  try {
    if (req.socket) {
      const ms = Number(process.env.DOMAIN_CHECKER_IMPORT_SOCKET_TIMEOUT_MS);
      if (Number.isFinite(ms) && ms > 0) req.socket.setTimeout(ms);
      else req.socket.setTimeout(0);
    }
  } catch (_) {}
}

function normalizeTokenSectionInput(value) {
  if (value === undefined || value === null || value === "") return null;
  const parts = Array.isArray(value) ? value : String(value).split(",");
  const flat = [];
  for (const p of parts) {
    if (p === undefined || p === null || p === "") continue;
    if (typeof p === "string") {
      for (const piece of p.split(",")) {
        const t = piece.trim();
        if (t) flat.push(t.slice(0, 200));
      }
    } else {
      const s = String(p).trim();
      if (s) flat.push(s.slice(0, 200));
    }
  }
  const uniq = [...new Set(flat)];
  return uniq.length ? uniq : null;
}

// ============================================================
// AUTO-SYNC CONFIGURATION ENDPOINTS
// ============================================================

const CORE_AUTO_SYNC_PROVIDERS = ["github", "gitlab"];

/**
 * Convert a local time (HH:MM) in a given IANA timezone to a UTC Date for
 * the given calendar date string (YYYY-MM-DD).
 */
function localTimeToUtcApi(dateStr, hours, minutes, tz) {
  const naive = new Date(
    `${dateStr}T${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:00Z`,
  );
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: tz,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).formatToParts(naive);
  const get = (type) => {
    const part = parts.find((x) => x.type === type);
    return part ? parseInt(part.value, 10) : 0;
  };
  const localInTz = new Date(
    Date.UTC(
      get("year"),
      get("month") - 1,
      get("day"),
      get("hour") === 24 ? 0 : get("hour"),
      get("minute"),
      get("second"),
    ),
  );
  const offsetMs = localInTz.getTime() - naive.getTime();
  return new Date(naive.getTime() - offsetMs);
}

function addMonthsClampedApi(date, months) {
  const result = new Date(date);
  const targetMonth = result.getMonth() + months;
  result.setMonth(targetMonth);
  if (result.getMonth() !== ((targetMonth % 12) + 12) % 12) {
    result.setDate(0);
  }
  return result;
}

/**
 * Compute the next sync timestamp respecting user-chosen schedule_time and timezone.
 * If "today at schedule_time" is still in the future, that is the first sync.
 * Otherwise, advance by frequency until we find a future time.
 */
function computeNextSyncAt(frequency, scheduleTime, scheduleTz) {
  const tz = scheduleTz || "UTC";
  const [rawH, rawM] = (scheduleTime || "09:00").split(":").map(Number);
  const h = Number.isFinite(rawH) ? rawH : 9;
  const m = Number.isFinite(rawM) ? rawM : 0;
  const nowUtc = new Date();

  const todayInTz = new Intl.DateTimeFormat("en-CA", {
    timeZone: tz,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(nowUtc);

  let candidate = localTimeToUtcApi(todayInTz, h, m, tz);

  function advance(d) {
    if (frequency === "monthly") return addMonthsClampedApi(d, 1);
    if (frequency === "weekly") return new Date(d.getTime() + 7 * 86400000);
    return new Date(d.getTime() + 86400000);
  }

  while (candidate <= nowUtc) {
    candidate = advance(candidate);
  }

  return candidate;
}

// List auto-sync configs for a workspace
router.get(
  "/api/v1/workspaces/:id/auto-sync",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT id, provider, scan_params, frequency, schedule_time, schedule_tz,
                enabled, last_sync_at, last_sync_status, last_sync_error,
                last_sync_items_count, next_sync_at, created_at, updated_at
         FROM auto_sync_configs WHERE workspace_id = $1 ORDER BY provider`,
        [req.workspace.id],
      );
      res.json({ items: result.rows });
    } catch (e) {
      logger.error("Auto-sync list error", { error: e.message });
      res.status(500).json({ error: "Failed to list auto-sync configs" });
    }
  },
);

// Create auto-sync config
router.post(
  "/api/v1/workspaces/:id/auto-sync",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  authorize("auto_sync.manage"),
  async (req, res) => {
    try {
      const {
        provider,
        credentials,
        scan_params,
        frequency,
        schedule_time,
        schedule_tz,
      } = req.body || {};
      if (!provider || !credentials) {
        return res
          .status(400)
          .json({ error: "provider and credentials are required" });
      }
      // Check provider is allowed
      const allowed = CORE_AUTO_SYNC_PROVIDERS;
      if (!allowed.includes(provider)) {
        return res.status(403).json({
          error: `Auto-sync for ${provider} is not available in this edition.`,
          code: "FEATURE_NOT_AVAILABLE",
        });
      }
      // Encrypt credentials
      const credJson =
        typeof credentials === "string"
          ? credentials
          : JSON.stringify(credentials);
      const encrypted = systemSettings.encrypt
        ? systemSettings.encrypt(credJson)
        : require("../services/systemSettings").encrypt(credJson);
      if (!encrypted) {
        return res.status(500).json({ error: "Failed to encrypt credentials" });
      }
      // Compute next_sync_at respecting user-chosen time and timezone
      const effFreq = frequency || "daily";
      const effTime = schedule_time || "09:00";
      const effTz = schedule_tz || "UTC";
      const nextSync = computeNextSyncAt(effFreq, effTime, effTz);

      const result = await pool.query(
        `INSERT INTO auto_sync_configs
          (workspace_id, provider, credentials_encrypted, scan_params, frequency, schedule_time, schedule_tz, next_sync_at, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING id, provider, scan_params, frequency, schedule_time, schedule_tz, enabled, next_sync_at, created_at`,
        [
          req.workspace.id,
          provider,
          encrypted,
          scan_params || {},
          effFreq,
          effTime,
          effTz,
          nextSync,
          req.user.id,
        ],
      );
      try {
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "AUTO_SYNC_CREATED",
          targetType: "auto_sync",
          targetId: null,
          channel: null,
          workspaceId: req.workspace.id,
          metadata: { provider },
        });
      } catch (_err) {
        logger.warn("Audit write failed (AUTO_SYNC_CREATED)", {
          error: _err.message,
        });
      }
      res.status(201).json(result.rows[0]);
    } catch (e) {
      if (e.code === "23505") {
        return res.status(409).json({
          error: "Auto-sync for this provider already exists in this workspace",
        });
      }
      logger.error("Auto-sync create error", { error: e.message });
      res.status(500).json({ error: "Failed to create auto-sync config" });
    }
  },
);

// Update auto-sync config
router.put(
  "/api/v1/workspaces/:id/auto-sync/:configId",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  authorize("auto_sync.manage"),
  async (req, res) => {
    try {
      const {
        credentials,
        scan_params,
        frequency,
        schedule_time,
        schedule_tz,
        enabled,
      } = req.body || {};
      const updates = [];
      const values = [];
      let idx = 1;

      if (credentials !== undefined) {
        const credJson =
          typeof credentials === "string"
            ? credentials
            : JSON.stringify(credentials);
        const encrypted = systemSettings.encrypt
          ? systemSettings.encrypt(credJson)
          : require("../services/systemSettings").encrypt(credJson);
        updates.push(`credentials_encrypted = $${idx++}`);
        values.push(encrypted);
      }
      if (scan_params !== undefined) {
        updates.push(`scan_params = $${idx++}`);
        values.push(scan_params);
      }
      if (frequency !== undefined) {
        updates.push(`frequency = $${idx++}`);
        values.push(frequency);
      }
      if (schedule_time !== undefined) {
        updates.push(`schedule_time = $${idx++}`);
        values.push(schedule_time);
      }
      if (schedule_tz !== undefined) {
        updates.push(`schedule_tz = $${idx++}`);
        values.push(schedule_tz);
      }
      if (enabled !== undefined) {
        updates.push(`enabled = $${idx++}`);
        values.push(enabled);
      }
      updates.push(`updated_at = NOW()`);

      if (updates.length <= 1) {
        return res.status(400).json({ error: "No fields to update" });
      }

      values.push(req.params.configId, req.workspace.id);
      const result = await pool.query(
        `UPDATE auto_sync_configs SET ${updates.join(", ")}
         WHERE id = $${idx++} AND workspace_id = $${idx}
         RETURNING id, provider, scan_params, frequency, schedule_time, schedule_tz, enabled, next_sync_at, updated_at`,
        values,
      );
      if (result.rows.length === 0) {
        return res.status(404).json({ error: "Auto-sync config not found" });
      }
      try {
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "AUTO_SYNC_UPDATED",
          targetType: "auto_sync_config",
          targetId: req.params.configId,
          channel: null,
          workspaceId: req.workspace.id,
          metadata: {
            provider: result.rows[0].provider,
            enabled: result.rows[0].enabled,
          },
        });
      } catch (_err) {
        logger.warn("Audit write failed (AUTO_SYNC_UPDATED)", {
          error: _err.message,
        });
      }
      res.json(result.rows[0]);
    } catch (e) {
      logger.error("Auto-sync update error", { error: e.message });
      res.status(500).json({ error: "Failed to update auto-sync config" });
    }
  },
);

// Delete auto-sync config
router.delete(
  "/api/v1/workspaces/:id/auto-sync/:configId",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  authorize("auto_sync.manage"),
  async (req, res) => {
    try {
      const result = await pool.query(
        "DELETE FROM auto_sync_configs WHERE id = $1 AND workspace_id = $2 RETURNING provider",
        [req.params.configId, req.workspace.id],
      );
      if (result.rows.length === 0) {
        return res.status(404).json({ error: "Auto-sync config not found" });
      }
      try {
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "AUTO_SYNC_DELETED",
          targetType: "auto_sync",
          targetId: null,
          channel: null,
          workspaceId: req.workspace.id,
          metadata: { provider: result.rows[0].provider },
        });
      } catch (_err) {
        logger.warn("Audit write failed (AUTO_SYNC_DELETED)", {
          error: _err.message,
        });
      }
      res.json({ success: true });
    } catch (e) {
      logger.error("Auto-sync delete error", { error: e.message });
      res.status(500).json({ error: "Failed to delete auto-sync config" });
    }
  },
);

// Trigger manual sync now
router.post(
  "/api/v1/workspaces/:id/auto-sync/:configId/run",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  authorize("auto_sync.manage"),
  async (req, res) => {
    try {
      // Mark next_sync_at as NOW so the worker picks it up immediately
      const result = await pool.query(
        `UPDATE auto_sync_configs SET next_sync_at = NOW(), updated_at = NOW()
         WHERE id = $1 AND workspace_id = $2 AND enabled = TRUE
         RETURNING id, provider, next_sync_at`,
        [req.params.configId, req.workspace.id],
      );
      if (result.rows.length === 0) {
        return res
          .status(404)
          .json({ error: "Auto-sync config not found or disabled" });
      }
      try {
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "AUTO_SYNC_TRIGGERED",
          targetType: "auto_sync_config",
          targetId: req.params.configId,
          channel: null,
          workspaceId: req.workspace.id,
          metadata: { provider: result.rows[0].provider },
        });
      } catch (_err) {
        logger.warn("Audit write failed (AUTO_SYNC_TRIGGERED)", {
          error: _err.message,
        });
      }
      res.json({
        success: true,
        message: "Sync queued",
        config: result.rows[0],
      });
    } catch (e) {
      logger.error("Auto-sync run error", { error: e.message });
      res.status(500).json({ error: "Failed to trigger sync" });
    }
  },
);

// ============================================================
// ENDPOINT (SSL) MONITORING ENDPOINTS
// ============================================================

// List endpoint monitors for a workspace
router.get(
  "/api/v1/workspaces/:id/domains",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT id, url, validated, validated_at,
                ssl_issuer, ssl_subject, ssl_valid_from, ssl_valid_to, ssl_serial, ssl_fingerprint,
                token_id, health_check_enabled,
                last_health_check_at, last_health_status, last_health_status_code,
                last_health_error, last_health_response_ms,
                check_interval, alert_after_failures, consecutive_failures,
                created_at, updated_at
         FROM domain_monitors WHERE workspace_id = $1 ORDER BY created_at DESC`,
        [req.workspace.id],
      );
      res.json({ items: result.rows });
    } catch (e) {
      logger.error("Endpoint monitors list error", { error: e.message });
      res.status(500).json({ error: "Failed to list endpoint monitors" });
    }
  },
);

// Discover hostnames for a root domain via passive open-source discovery tools.
router.post(
  "/api/v1/workspaces/:id/domain-checker/lookup",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  authorize("domain.manage"),
  getDomainCheckerLookupLimiter(),
  async (req, res) => {
    try {
      const domain = normalizeRootDomain(req.body?.domain);
      if (!domain) {
        return res.status(400).json({
          error: "A valid root domain is required",
          code: "INVALID_DOMAIN",
        });
      }

      logger.info("Domain checker lookup started", {
        domain,
        workspaceId: req.workspace.id,
        userId: req.user.id,
      });
      const subfinderAll = req.body && req.body.subfinder_all === true;
      const result = await lookupDomain(domain, {
        workspaceId: req.workspace.id,
        maxResults: getDomainCheckerDiscoveryMaxResults("oss"),
        subfinderAll,
      });
      logger.info("Domain checker lookup completed", {
        domain,
        workspaceId: req.workspace.id,
        userId: req.user.id,
        results: result.items.length,
        partial: Boolean(result.partial),
        toolsSucceeded: result.meta?.toolsSucceeded ?? null,
        toolsFailed: result.meta?.toolsFailed ?? null,
        truncated: Boolean(result.meta?.truncated),
        durationMs: result.meta?.durationMs ?? null,
        toolErrors: result.toolErrors || [],
      });

      try {
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "DOMAIN_CHECKER_LOOKUP",
          targetType: "domain_checker",
          targetId: null,
          channel: null,
          workspaceId: req.workspace.id,
          metadata: {
            domain,
            source: result.source,
            subfinder_all: subfinderAll,
            results: result.items.length,
            partial: Boolean(result.partial),
            tools_succeeded: result.meta?.toolsSucceeded ?? null,
            tools_failed: result.meta?.toolsFailed ?? null,
            truncated: Boolean(result.meta?.truncated),
          },
        });
      } catch (_err) {
        logger.warn("Audit write failed (DOMAIN_CHECKER_LOOKUP)", {
          error: _err.message,
        });
      }

      res.json({
        ...result,
        toolErrors: publicToolErrors(result.toolErrors),
      });
    } catch (e) {
      const code = e.code || "DOMAIN_CHECKER_LOOKUP_FAILED";
      const status = (() => {
        if (code === "INVALID_DOMAIN") return 400;
        if (code === "DOMAIN_CHECKER_TIMEOUT") return 504;
        if (code === "DOMAIN_CHECKER_BUSY") return 409;
        if (code === "DOMAIN_CHECKER_TOOL_MISSING") return 503;
        if (Number.isFinite(Number(e.status))) return Number(e.status);
        return 502;
      })();
      logger.warn("Domain checker lookup failed", {
        error: e.message,
        code,
        status,
        attempts: e.attempts || null,
        retryAfterSec: e.retryAfterSec || null,
        toolErrors: e.toolErrors || [],
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      if (e.retryAfterSec) {
        res.set("Retry-After", String(e.retryAfterSec));
      }
      const payload = {
        error:
          code === "DOMAIN_CHECKER_TIMEOUT"
            ? "Domain discovery timed out. Please try again later."
            : code === "DOMAIN_CHECKER_BUSY"
              ? "A domain discovery scan is already running for this workspace."
              : code === "DOMAIN_CHECKER_TOOL_MISSING"
                ? "Domain discovery tools are not available in this deployment."
                : "Failed to discover hostnames for this domain",
        code,
        toolErrors: publicToolErrors(e.toolErrors),
      };
      if (e.retryAfterSec) payload.retry_after_seconds = e.retryAfterSec;
      if (e.attempts) payload.attempts = e.attempts;
      res.status(status).json(payload);
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/domain-checker/import",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  authorize("domain.manage"),
  async (req, res) => {
    try {
      attachLongRunningDomainImportSocket(req, res);
      const domain = normalizeRootDomain(req.body?.domain);
      const certificates = Array.isArray(req.body?.certificates)
        ? req.body.certificates
        : [];
      const monitorOptions = req.body?.monitorOptions || {};
      const createMonitors = Boolean(monitorOptions.enabled);
      const monitorHealthCheckEnabled =
        monitorOptions.health_check_enabled === true;
      const monitorCheckInterval = [
        "1min",
        "5min",
        "30min",
        "hourly",
        "daily",
      ].includes(String(monitorOptions.check_interval || ""))
        ? String(monitorOptions.check_interval)
        : "hourly";
      const monitorAlertAfterFailures = Math.max(
        1,
        Math.min(
          10,
          Number.parseInt(
            String(monitorOptions.alert_after_failures ?? "2"),
            10,
          ) || 2,
        ),
      );

      if (!domain) {
        return res.status(400).json({
          error: "A valid root domain is required",
          code: "INVALID_DOMAIN",
        });
      }
      if (certificates.length === 0) {
        return res.status(400).json({
          error: "At least one certificate must be selected",
          code: "NO_CERTIFICATES_SELECTED",
        });
      }
      const importMax = getDomainCheckerImportMaxCertificates("oss");
      if (certificates.length > importMax) {
        return res.status(400).json({
          error: `A maximum of ${importMax} certificates can be imported at once`,
          code: "TOO_MANY_CERTIFICATES",
        });
      }

      const tokenOptions = req.body?.tokenOptions || {};
      const importSection = normalizeTokenSectionInput(tokenOptions.section);
      if (importSection && importSection.length > 50) {
        return res.status(400).json({
          error: "At most 50 section labels are allowed",
          code: "INVALID_SECTION",
        });
      }

      let defaultContactGroupId = null;
      try {
        const wsSettings = await pool.query(
          "SELECT default_contact_group_id FROM workspace_settings WHERE workspace_id = $1",
          [req.workspace.id],
        );
        if (wsSettings.rows[0]?.default_contact_group_id) {
          defaultContactGroupId = String(
            wsSettings.rows[0].default_contact_group_id,
          );
        }
      } catch (_err) {
        logger.warn("DB operation failed", { error: _err.message });
      }

      const imported = [];
      const skipped = [];
      let monitorsCreated = 0;
      let monitorsExisting = 0;
      let skippedDuplicate = 0;
      let skippedInvalid = 0;

      for (const certificate of certificates) {
        const rawDomains = Array.isArray(certificate.domains)
          ? certificate.domains
          : [certificate.name || certificate.commonName || domain];
        const certDomains = Array.from(
          new Set(
            rawDomains
              .map(normalizeHostname)
              .filter(
                (hostname) => hostname && isWithinRootDomain(hostname, domain),
              ),
          ),
        ).sort();

        let expiration = formatDateYmd(
          certificate.expiration ||
            certificate.validTo ||
            certificate.not_after,
        );
        let issuer = certificate.issuer || certificate.issuerName || null;
        let subject =
          certificate.subject || certificate.commonName || certDomains[0];
        let serialNumber =
          certificate.serialNumber || certificate.serial_number || null;
        let tlsFingerprint =
          certificate.fingerprint || certificate.ssl_fingerprint || null;

        let liveCertFetchErr = null;
        if (certDomains.length > 0 && !expiration) {
          try {
            const liveCert = await fetchHostnameCertificate(certDomains[0]);
            expiration = formatDateYmd(liveCert.validTo);
            issuer = issuer || liveCert.issuer;
            subject = subject || liveCert.subject || certDomains[0];
            serialNumber = serialNumber || liveCert.serialNumber;
            tlsFingerprint = tlsFingerprint || liveCert.fingerprint;
          } catch (tlsErr) {
            liveCertFetchErr = tlsErr;
            logger.warn(
              "Domain checker import live certificate lookup failed",
              {
                workspaceId: req.workspace.id,
                userId: req.user.id,
                domain,
                hostname: certDomains[0],
                error: tlsErr.message,
                code: tlsErr.code || null,
              },
            );
          }
        }

        if (certDomains.length === 0 || !expiration) {
          const invalidReason =
            certDomains.length === 0
              ? !expiration
                ? "no_matching_domains_and_missing_expiration"
                : "no_matching_domains"
              : liveCertificateImportSkipDetail(liveCertFetchErr);
          const skipEntry = {
            id: certificate.id || certificate.sourceCertId || null,
            reason: "invalid_certificate",
            detail: invalidReason,
            domains: certDomains,
            rawDomains: Array.isArray(rawDomains) ? rawDomains.slice(0, 5) : [],
            expiration: expiration || null,
          };
          skipped.push(skipEntry);
          skippedInvalid += 1;
          logger.warn("Domain checker import skipped certificate", {
            workspaceId: req.workspace.id,
            userId: req.user.id,
            domain,
            reason: skipEntry.reason,
            detail: skipEntry.detail,
            certificateId: skipEntry.id,
            rawDomains: skipEntry.rawDomains,
          });
          continue;
        }

        const sourceCertId =
          certificate.sourceCertId || certificate.min_cert_id || null;
        const sourceUrl = certificate.sourceUrl || null;
        const sources = Array.isArray(certificate.sources)
          ? certificate.sources.filter(Boolean)
          : [];
        const noteSource = sources.length
          ? `sources: ${sources.join(", ")}`
          : "sources: subfinder";

        let duplicate = null;
        if (sourceCertId) {
          const duplicateBySource = await pool.query(
            `SELECT id FROM tokens
             WHERE workspace_id = $1
               AND type = 'ssl_cert'
               AND notes ILIKE $2
             LIMIT 1`,
            [req.workspace.id, `%domain checker source id: ${sourceCertId}%`],
          );
          duplicate = duplicateBySource.rows[0] || null;
        }
        if (!duplicate) {
          const duplicateByShape = await pool.query(
            `SELECT id FROM tokens
             WHERE workspace_id = $1
               AND type = 'ssl_cert'
               AND expiration = $2
               AND COALESCE(issuer, '') = COALESCE($3, '')
               AND domains && $4::text[]
             LIMIT 1`,
            [req.workspace.id, expiration, issuer, certDomains],
          );
          duplicate = duplicateByShape.rows[0] || null;
        }

        if (duplicate) {
          const skipEntry = {
            id: certificate.id || sourceCertId || null,
            tokenId: duplicate.id,
            reason: "duplicate",
            detail: sourceCertId
              ? "existing_token_for_domain_checker_source_id"
              : "existing_token_for_expiration_issuer_and_domain",
            subject,
            domains: certDomains,
            expiration,
            issuer: issuer || null,
          };
          skipped.push(skipEntry);
          skippedDuplicate += 1;
          logger.warn("Domain checker import skipped certificate", {
            workspaceId: req.workspace.id,
            userId: req.user.id,
            domain,
            reason: skipEntry.reason,
            detail: skipEntry.detail,
            certificateId: skipEntry.id,
            existingTokenId: duplicate.id,
            subject,
            domains: certDomains,
            expiration,
          });
          continue;
        }

        const tokenResult = await pool.query(
          `INSERT INTO tokens
             (user_id, workspace_id, created_by, name, expiration, type, category,
              issuer, serial_number, subject, domains, location, notes, contact_group_id, imported_at, section)
           VALUES ($1, $2, $3, $4, $5, 'ssl_cert', 'cert',
                   $6, $7, $8, $9, $10, $11, $12, NOW(), $13::text[])
           RETURNING id, name, expiration`,
          [
            req.user.id,
            req.workspace.id,
            req.user.id,
            String(
              certificate.name || certificate.commonName || certDomains[0],
            ).slice(0, 100),
            expiration,
            issuer,
            serialNumber,
            subject,
            certDomains,
            sourceUrl,
            `Imported by domain checker (${noteSource}).${sourceCertId ? ` domain checker source id: ${sourceCertId}.` : ""} Fingerprint: ${tlsFingerprint || "unknown"}. Domains: ${certDomains.join(", ")}`,
            certificate.contact_group_id || defaultContactGroupId,
            importSection,
          ],
        );

        imported.push({
          certificateId: certificate.id || sourceCertId || null,
          tokenId: tokenResult.rows[0].id,
          name: tokenResult.rows[0].name,
          expiration: tokenResult.rows[0].expiration,
        });

        if (createMonitors) {
          for (const certDomain of certDomains) {
            const monitorUrl = `https://${certDomain}`;
            const existingMonitor = await pool.query(
              `SELECT id FROM domain_monitors
               WHERE workspace_id = $1 AND url = $2
               LIMIT 1`,
              [req.workspace.id, monitorUrl],
            );
            if (existingMonitor.rows[0]?.id) {
              monitorsExisting += 1;
              continue;
            }
            let monitorSslValidTo = null;
            try {
              if (expiration) {
                const expStr = String(expiration);
                const d = new Date(
                  expStr.includes("T") ? expStr : `${expStr}T12:00:00.000Z`,
                );
                if (Number.isFinite(d.getTime())) monitorSslValidTo = d;
              }
            } catch (_) {}
            const monitorValidated = Boolean(monitorSslValidTo);
            const monitorValidatedAt = monitorValidated ? new Date() : null;
            await pool.query(
              `INSERT INTO domain_monitors
                 (workspace_id, url, validated, validated_at,
                  ssl_issuer, ssl_subject, ssl_valid_from, ssl_valid_to, ssl_serial, ssl_fingerprint,
                  token_id, health_check_enabled, check_interval, alert_after_failures, created_by)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
              [
                req.workspace.id,
                monitorUrl,
                monitorValidated,
                monitorValidatedAt,
                issuer || null,
                subject || null,
                null,
                monitorSslValidTo,
                serialNumber || null,
                tlsFingerprint || null,
                tokenResult.rows[0].id,
                monitorHealthCheckEnabled,
                monitorCheckInterval,
                monitorAlertAfterFailures,
                req.user.id,
              ],
            );
            monitorsCreated += 1;
          }
        }
      }

      logger.info("Domain checker import completed", {
        workspaceId: req.workspace.id,
        userId: req.user.id,
        domain,
        submitted: certificates.length,
        imported: imported.length,
        skipped: skipped.length,
        skipped_duplicate: skippedDuplicate,
        skipped_invalid: skippedInvalid,
        monitors_created: monitorsCreated,
        monitors_existing: monitorsExisting,
        create_monitors: createMonitors,
      });

      try {
        const skippedUnreachable = skipped.filter(
          (s) =>
            s.reason === "invalid_certificate" &&
            DNS_LIVE_CERT_SKIP_DETAILS.has(s.detail),
        ).length;
        const skippedOtherInvalid = Math.max(
          0,
          skippedInvalid - skippedUnreachable,
        );
        const auditMetadata = {
          domain,
          source: "subfinder",
          submitted: certificates.length,
          imported: imported.length,
          skipped: skipped.length,
          skipped_duplicate: skippedDuplicate,
          skipped_invalid: skippedInvalid,
          skipped_unreachable: skippedUnreachable,
          skipped_other_invalid: skippedOtherInvalid,
          create_monitors: createMonitors,
          monitors_created: monitorsCreated,
          monitors_existing: monitorsExisting,
        };
        if (createMonitors) {
          auditMetadata.monitor_check_interval = monitorCheckInterval;
          auditMetadata.monitor_health_check_enabled =
            monitorHealthCheckEnabled;
          auditMetadata.monitor_alert_after_failures =
            monitorAlertAfterFailures;
          auditMetadata.monitor_contact_group_id =
            monitorOptions.contact_group_id || defaultContactGroupId || null;
        }
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "DOMAIN_CHECKER_IMPORT",
          targetType: "domain_checker",
          targetId: null,
          channel: null,
          workspaceId: req.workspace.id,
          metadata: auditMetadata,
        });
      } catch (_err) {
        logger.warn("Audit write failed (DOMAIN_CHECKER_IMPORT)", {
          error: _err.message,
        });
      }

      res.status(201).json({
        imported,
        skipped,
        skippedCounts: {
          duplicate: skippedDuplicate,
          invalid: skippedInvalid,
        },
        monitors: { created: monitorsCreated, existing: monitorsExisting },
      });
    } catch (e) {
      logger.error("Domain checker import failed", {
        error: e.message,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      res.status(500).json({
        error: "Failed to import domain certificates",
        code: "DOMAIN_CHECKER_IMPORT_FAILED",
      });
    }
  },
);

// Add endpoint monitor
router.post(
  "/api/v1/workspaces/:id/domains",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  authorize("domain.manage"),
  async (req, res) => {
    try {
      const {
        url,
        health_check_enabled,
        check_interval,
        alert_after_failures,
        contact_group_id,
        section: endpointSectionRaw,
      } = req.body || {};
      if (!url || typeof url !== "string") {
        return res.status(400).json({ error: "url is required" });
      }
      const endpointTokenSection =
        normalizeTokenSectionInput(endpointSectionRaw);
      if (endpointTokenSection && endpointTokenSection.length > 50) {
        return res.status(400).json({
          error: "At most 50 section labels are allowed",
          code: "INVALID_SECTION",
        });
      }
      // Basic URL validation
      let parsedUrl;
      try {
        parsedUrl = new URL(url.startsWith("http") ? url : `https://${url}`);
        if (!/^https?:$/.test(parsedUrl.protocol)) {
          return res.status(400).json({ error: "URL must use http or https" });
        }
      } catch (_) {
        return res.status(400).json({ error: "Invalid URL format" });
      }
      const normalizedUrl = parsedUrl.toString().replace(/\/+$/, "");

      // Try to fetch SSL cert immediately
      let sslData = {};
      try {
        const tls = require("tls");
        const { X509Certificate } = require("crypto");
        const hostname = parsedUrl.hostname;
        const port =
          parsedUrl.port || (parsedUrl.protocol === "https:" ? 443 : 80);

        if (parsedUrl.protocol === "https:") {
          const cert = await new Promise((resolve, reject) => {
            const socket = tls.connect(
              {
                host: hostname,
                port,
                servername: hostname,
                rejectUnauthorized: false,
                timeout: 10000,
              },
              () => {
                const peerCert = socket.getPeerCertificate(true);
                socket.destroy();
                resolve(peerCert);
              },
            );
            socket.on("error", reject);
            socket.on("timeout", () => {
              socket.destroy();
              reject(new Error("TLS timeout"));
            });
          });

          if (cert && cert.raw) {
            const x509 = new X509Certificate(cert.raw);
            sslData = {
              ssl_issuer: x509.issuer || cert.issuer?.O || null,
              ssl_subject: x509.subject || cert.subject?.CN || null,
              ssl_valid_from: cert.valid_from
                ? new Date(cert.valid_from)
                : null,
              ssl_valid_to: cert.valid_to ? new Date(cert.valid_to) : null,
              ssl_serial: x509.serialNumber || cert.serialNumber || null,
              ssl_fingerprint: cert.fingerprint256 || cert.fingerprint || null,
            };
          }
        }
      } catch (sslErr) {
        logger.warn("SSL cert fetch failed for endpoint", {
          url: normalizedUrl,
          error: sslErr.message,
        });
      }

      // Validate alert_after_failures (must be >= 1 if provided)
      const parsedAlertAfter =
        alert_after_failures != null
          ? Math.max(1, Math.round(Number(alert_after_failures) || 2))
          : 2;

      // Create endpoint monitor
      const result = await pool.query(
        `INSERT INTO domain_monitors
          (workspace_id, url, validated, validated_at, ssl_issuer, ssl_subject, ssl_valid_from, ssl_valid_to, ssl_serial, ssl_fingerprint,
           health_check_enabled, check_interval, alert_after_failures, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
         RETURNING *`,
        [
          req.workspace.id,
          normalizedUrl,
          !!sslData.ssl_valid_to,
          sslData.ssl_valid_to ? new Date() : null,
          sslData.ssl_issuer || null,
          sslData.ssl_subject || null,
          sslData.ssl_valid_from || null,
          sslData.ssl_valid_to || null,
          sslData.ssl_serial || null,
          sslData.ssl_fingerprint || null,
          health_check_enabled !== false,
          check_interval || "hourly",
          parsedAlertAfter,
          req.user.id,
        ],
      );

      const domainRow = result.rows[0];

      // Resolve contact_group_id: use provided value, or fall back to workspace default
      let resolvedContactGroupId = null;
      if (contact_group_id && String(contact_group_id).trim()) {
        resolvedContactGroupId = String(contact_group_id).trim();
      } else {
        try {
          const wsSettings = await pool.query(
            "SELECT default_contact_group_id FROM workspace_settings WHERE workspace_id = $1",
            [req.workspace.id],
          );
          if (wsSettings.rows[0]?.default_contact_group_id) {
            resolvedContactGroupId = String(
              wsSettings.rows[0].default_contact_group_id,
            );
          }
        } catch (_err) {
          logger.warn("DB operation failed", { error: _err.message });
        }
      }

      // Auto-create token for SSL cert if we got cert data
      if (sslData.ssl_valid_to) {
        try {
          const tokenResult = await pool.query(
            `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category, issuer, serial_number, subject, domains, location, notes, contact_group_id, section)
             VALUES ($1, $2, $3, $4, $5, 'ssl_cert', 'cert', $6, $7, $8, $9, $10, $11, $12, $13::text[])
             RETURNING id`,
            [
              req.user.id,
              req.workspace.id,
              req.user.id,
              parsedUrl.hostname,
              formatDateYmd(new Date(sslData.ssl_valid_to)),
              sslData.ssl_issuer,
              sslData.ssl_serial,
              sslData.ssl_subject,
              [parsedUrl.hostname],
              normalizedUrl,
              `Auto-created by endpoint monitor. Fingerprint: ${sslData.ssl_fingerprint || "unknown"}`,
              resolvedContactGroupId,
              endpointTokenSection,
            ],
          );
          // Link token to endpoint monitor
          await pool.query(
            "UPDATE domain_monitors SET token_id = $1 WHERE id = $2",
            [tokenResult.rows[0].id, domainRow.id],
          );
          domainRow.token_id = tokenResult.rows[0].id;
        } catch (tokenErr) {
          logger.warn("Failed to auto-create token for endpoint", {
            error: tokenErr.message,
          });
        }
      }

      try {
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "DOMAIN_MONITOR_CREATED",
          targetType: "domain_monitor",
          targetId: null,
          channel: null,
          workspaceId: req.workspace.id,
          metadata: {
            url: normalizedUrl,
            ssl_detected: !!sslData.ssl_valid_to,
          },
        });
      } catch (_err) {
        logger.warn("Audit write failed (DOMAIN_MONITOR_CREATED)", {
          error: _err.message,
        });
      }

      res.status(201).json(domainRow);
    } catch (e) {
      logger.error("Endpoint monitor create error", { error: e.message });
      res.status(500).json({ error: "Failed to create endpoint monitor" });
    }
  },
);

// Update endpoint monitor
router.put(
  "/api/v1/workspaces/:id/domains/:domainId",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  authorize("domain.manage"),
  async (req, res) => {
    try {
      const { health_check_enabled, check_interval } = req.body || {};
      const result = await pool.query(
        `UPDATE domain_monitors
         SET health_check_enabled = COALESCE($1, health_check_enabled),
             check_interval = COALESCE($2, check_interval),
             updated_at = NOW()
         WHERE id = $3 AND workspace_id = $4
         RETURNING *`,
        [
          health_check_enabled,
          check_interval,
          req.params.domainId,
          req.workspace.id,
        ],
      );
      if (result.rows.length === 0) {
        return res.status(404).json({ error: "Endpoint monitor not found" });
      }
      try {
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "DOMAIN_MONITOR_UPDATED",
          targetType: "domain_monitor",
          targetId: req.params.domainId,
          channel: null,
          workspaceId: req.workspace.id,
          metadata: { url: result.rows[0].url },
        });
      } catch (_err) {
        logger.warn("Audit write failed (DOMAIN_MONITOR_UPDATED)", {
          error: _err.message,
        });
      }
      res.json(result.rows[0]);
    } catch (e) {
      logger.error("Endpoint monitor update error", { error: e.message });
      res.status(500).json({ error: "Failed to update endpoint monitor" });
    }
  },
);

// Delete endpoint monitor
router.delete(
  "/api/v1/workspaces/:id/domains/:domainId",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  authorize("domain.manage"),
  async (req, res) => {
    try {
      const result = await pool.query(
        "DELETE FROM domain_monitors WHERE id = $1 AND workspace_id = $2 RETURNING url",
        [req.params.domainId, req.workspace.id],
      );
      if (result.rows.length === 0) {
        return res.status(404).json({ error: "Endpoint monitor not found" });
      }
      try {
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "DOMAIN_MONITOR_DELETED",
          targetType: "domain_monitor",
          targetId: null,
          channel: null,
          workspaceId: req.workspace.id,
          metadata: { url: result.rows[0].url },
        });
      } catch (_err) {
        logger.warn("Audit write failed (DOMAIN_MONITOR_DELETED)", {
          error: _err.message,
        });
      }
      res.json({ success: true });
    } catch (e) {
      logger.error("Endpoint monitor delete error", { error: e.message });
      res.status(500).json({ error: "Failed to delete endpoint monitor" });
    }
  },
);

// Manual health check for an endpoint
router.post(
  "/api/v1/workspaces/:id/domains/:domainId/check",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  authorize("domain.manage"),
  async (req, res) => {
    try {
      // Fetch the domain
      const domainResult = await pool.query(
        "SELECT * FROM domain_monitors WHERE id = $1 AND workspace_id = $2",
        [req.params.domainId, req.workspace.id],
      );
      if (domainResult.rows.length === 0) {
        return res.status(404).json({ error: "Endpoint monitor not found" });
      }
      const domain = domainResult.rows[0];

      // Perform health check
      const https = require("https");
      const http = require("http");
      const startTime = Date.now();
      let status = "healthy";
      let statusCode = null;
      let errorMsg = null;

      try {
        const parsedUrl = new URL(domain.url);
        const client = parsedUrl.protocol === "https:" ? https : http;
        const result = await new Promise((resolve, reject) => {
          const req = client.get(
            domain.url,
            { timeout: 15000, rejectUnauthorized: false },
            (response) => {
              resolve({ statusCode: response.statusCode });
            },
          );
          req.on("error", reject);
          req.on("timeout", () => {
            req.destroy();
            reject(new Error("Request timeout"));
          });
        });
        statusCode = result.statusCode;
        if (statusCode >= 400) {
          status = "unhealthy";
          errorMsg = `HTTP ${statusCode}`;
        }
      } catch (checkErr) {
        status = "error";
        errorMsg = checkErr.message;
      }

      const responseMs = Date.now() - startTime;

      // Update endpoint monitor
      await pool.query(
        `UPDATE domain_monitors
         SET last_health_check_at = NOW(), last_health_status = $1,
             last_health_status_code = $2, last_health_error = $3,
             last_health_response_ms = $4, updated_at = NOW()
         WHERE id = $5`,
        [status, statusCode, errorMsg, responseMs, domain.id],
      );

      try {
        await writeAudit({
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "DOMAIN_MONITOR_HEALTH_CHECK",
          targetType: "domain_monitor",
          targetId: domain.id,
          channel: null,
          workspaceId: req.workspace.id,
          metadata: { url: domain.url, status, statusCode, responseMs },
        });
      } catch (_err) {
        logger.warn("Audit write failed (DOMAIN_MONITOR_HEALTH_CHECK)", {
          error: _err.message,
        });
      }

      res.json({
        status,
        statusCode,
        error: errorMsg,
        responseMs,
        checkedAt: new Date().toISOString(),
      });
    } catch (e) {
      logger.error("Endpoint health check error", { error: e.message });
      res.status(500).json({ error: "Health check failed" });
    }
  },
);

// ============================================================
// END AUTO-SYNC & ENDPOINT MONITORING
// ============================================================

module.exports = router;
