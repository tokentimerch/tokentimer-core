/**
 * Auto-Sync Worker (Core)
 *
 * Processes scheduled integration scans from auto_sync_configs.
 * Picks up configs where next_sync_at <= NOW() and enabled = TRUE,
 * runs the corresponding scan, imports results, and updates status.
 *
 * Core edition supports github and gitlab only. Enterprise replaces this
 * file via src/worker/auto-sync-worker.js in tokentimer-enterprise.
 */

import { pool, withClient } from "./db.js";
import { isNodeEntrypoint } from "./is-node-entrypoint.js";
import { logger } from "./logger.js";
import {
  cAutoSync,
  cAutoSyncItems,
  gAutoSyncLastRun,
  pushMetrics,
} from "./metrics.js";
import crypto from "crypto";
import axios from "axios";
import { isAutoSyncProviderAllowed } from "./auto-sync-providers.js";
import {
  formatAutoSyncError,
  recordAutoSyncCompleted,
  recordAutoSyncFailure,
} from "./shared/autoSyncFailure.js";

// Encryption helpers — must mirror systemSettings.js exactly
const KDF_SALT = "tokentimer-settings-encryption";

// Derive the key once per process; scryptSync is intentionally expensive.
let _encryptionKey = null;
let _legacyEncryptionKey = null;

function getEncryptionKey() {
  if (!_encryptionKey) {
    const secret = process.env.SESSION_SECRET || "";
    _encryptionKey = crypto.scryptSync(secret, KDF_SALT, 32);
  }
  return _encryptionKey;
}

// Legacy key used before the scrypt KDF was introduced (pre-v0.1 values)
function getLegacyEncryptionKey() {
  if (!_legacyEncryptionKey) {
    const secret = process.env.SESSION_SECRET || "";
    _legacyEncryptionKey = crypto.createHash("sha256").update(secret).digest();
  }
  return _legacyEncryptionKey;
}

function decryptWithKey(ciphertext, key) {
  const parts = ciphertext.split(":");
  if (parts.length !== 3) return null;
  const iv = Buffer.from(parts[0], "hex");
  const tag = Buffer.from(parts[1], "hex");
  const encrypted = parts[2];
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

function decrypt(ciphertext) {
  if (!ciphertext) return null;
  try {
    return decryptWithKey(ciphertext, getEncryptionKey());
  } catch (_) {
    try {
      return decryptWithKey(ciphertext, getLegacyEncryptionKey());
    } catch (e) {
      logger.error("Failed to decrypt auto-sync credentials", {
        error: e.message,
      });
      return null;
    }
  }
}

/**
 * Convert a local time (HH:MM) in a given IANA timezone to a UTC Date for
 * the given calendar date string (YYYY-MM-DD).
 */
function localTimeToUtc(dateStr, hours, minutes, tz) {
  // Parse the date string as if it were UTC, then adjust for the timezone offset
  const naive = new Date(
    `${dateStr}T${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:00Z`,
  );
  // Determine what local time `naive` represents in `tz` so we can compute the offset
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
  // offset = localInTz - naive  (positive means tz is ahead of UTC)
  const offsetMs = localInTz.getTime() - naive.getTime();
  return new Date(naive.getTime() - offsetMs);
}

/**
 * Safely advance a date by N months without overflowing.
 * e.g. Jan 31 + 1 month = Feb 28 (or 29), not Mar 3.
 */
function addMonthsClamped(date, months) {
  const result = new Date(date);
  const targetMonth = result.getMonth() + months;
  result.setMonth(targetMonth);
  // If the day overflowed (e.g. 31 -> next month 3rd), clamp to last day
  if (result.getMonth() !== ((targetMonth % 12) + 12) % 12) {
    result.setDate(0); // sets to last day of previous month
  }
  return result;
}

/**
 * Compute the next sync time respecting user-chosen schedule_time and schedule_tz.
 *
 * 1. Figure out "today at HH:MM in the user's timezone" as a UTC timestamp.
 * 2. If that moment is still in the future, use it as the first sync.
 * 3. Otherwise, advance by one period and keep advancing until it is in the future.
 */
function computeNextSync(frequency, scheduleTime, scheduleTz) {
  const tz = scheduleTz || "UTC";
  const [rawH, rawM] = (scheduleTime || "09:00").split(":").map(Number);
  const h = Number.isFinite(rawH) ? rawH : 9;
  const m = Number.isFinite(rawM) ? rawM : 0;
  const nowUtc = new Date();

  // Get "today" in the user's timezone as YYYY-MM-DD
  const todayInTz = new Intl.DateTimeFormat("en-CA", {
    timeZone: tz,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(nowUtc);

  // Start with "today at the scheduled time" converted to UTC
  let candidate = localTimeToUtc(todayInTz, h, m, tz);

  // If that time has already passed, advance by one period
  function advance(d) {
    if (frequency === "monthly") return addMonthsClamped(d, 1);
    if (frequency === "weekly") return new Date(d.getTime() + 7 * 86400000);
    return new Date(d.getTime() + 86400000); // daily
  }

  // Keep advancing until the candidate is strictly in the future
  while (candidate <= nowUtc) {
    candidate = advance(candidate);
  }

  return candidate;
}

async function runAutoSync() {
  logger.info("Auto-sync worker started");

  await withClient(async (client) => {
    // Wrap the SELECT FOR UPDATE and the per-config status updates in an
    // explicit transaction so the row locks are held until each UPDATE commits.
    // Without BEGIN/COMMIT the lock is released immediately after SELECT in
    // autocommit mode, making SKIP LOCKED useless against concurrent workers.
    await client.query("BEGIN");

    // Pick up due configs with row-level locking
    const dueResult = await client.query(
      `SELECT * FROM auto_sync_configs
       WHERE enabled = TRUE AND next_sync_at <= NOW()
       ORDER BY next_sync_at ASC
       LIMIT 10
       FOR UPDATE SKIP LOCKED`,
    );

    if (dueResult.rows.length === 0) {
      await client.query("ROLLBACK");
      logger.info("No auto-sync configs due");
      return;
    }

    logger.info(`Processing ${dueResult.rows.length} auto-sync configs`);

    // Run all due configs concurrently. The HTTP calls (scan + import) are
    // independent of each other; only the final status UPDATE needs the
    // shared client, but since we serialise those writes and they are fast,
    // sharing the client is safe here.
    await Promise.allSettled(
      dueResult.rows.map(async (config) => {
        const {
          id,
          workspace_id,
          provider,
          credentials_encrypted,
          scan_params,
          frequency,
          schedule_time,
          schedule_tz,
          last_sync_status: previousStatus,
          created_by: createdBy,
        } = config;
        logger.info(`Syncing ${provider} for workspace ${workspace_id}`);

        // Guard against stale rows (e.g. restored from an enterprise backup).
        // Core rejects providers outside the github/gitlab allowlist without
        // calling the scan API.
        if (!isAutoSyncProviderAllowed(provider)) {
          const nextSync = computeNextSync(frequency, schedule_time, schedule_tz);
          const message = `Auto-sync for ${provider} is not available in this edition.`;
          await recordAutoSyncFailure(client, {
            configId: id,
            workspaceId: workspace_id,
            provider,
            createdBy,
            previousStatus,
            errorMessage: message,
            nextSync,
          });
          logger.warn(message, { workspace_id, provider });
          cAutoSync.inc({ provider, status: "failure" });
          gAutoSyncLastRun.set({ provider, status: "failure" }, Date.now() / 1000);
          return;
        }

        try {
          // Decrypt credentials
          const credJson = decrypt(credentials_encrypted);
          if (!credJson) {
            throw new Error("Failed to decrypt credentials");
          }
          const creds = JSON.parse(credJson);

          // Validate that required credential fields are present before hitting
          // the scan endpoint, so missing-field errors surface with clear context
          // rather than an opaque 400 from the downstream API.
          const REQUIRED_CRED_FIELDS = {
            github: ["token"],
            gitlab: ["token"],
          };
          const missing = (REQUIRED_CRED_FIELDS[provider] || []).filter(
            (f) => !creds[f],
          );
          if (missing.length > 0) {
            const detail = missing.map((f) =>
              f in creds ? `${f} (empty)` : `${f} (absent)`,
            );
            throw new Error(
              `Invalid credentials for ${provider}: ${detail.join(", ")}. ` +
                `Re-save the auto-sync config with valid credentials.`,
            );
          }

          // Call the API's scan endpoint via HTTP
          const apiUrl = process.env.API_URL || "http://api:4000";
          const workerKey =
            process.env.WORKER_API_KEY || process.env.SESSION_SECRET;
          const authHeaders = workerKey
            ? { Authorization: `Bearer ${workerKey}` }
            : {};
          let scanUrl;
          let scanBody;
          const filterRules = Array.isArray(scan_params?.filterRules)
            ? scan_params.filterRules
            : undefined;

          switch (provider) {
            case "github":
              scanUrl = `${apiUrl}/api/v1/integrations/github/scan?workspace_id=${workspace_id}`;
              scanBody = {
                baseUrl: creds.baseUrl || "https://api.github.com",
                token: creds.token,
                include: scan_params?.include || {
                  tokens: true,
                  sshKeys: true,
                  deployKeys: true,
                  secrets: true,
                },
                maxItems: scan_params?.maxItems || 500,
                filterRules,
              };
              break;
            case "gitlab":
              scanUrl = `${apiUrl}/api/v1/integrations/gitlab/scan?workspace_id=${workspace_id}`;
              scanBody = {
                baseUrl: creds.baseUrl || "https://gitlab.com",
                token: creds.token,
                include: scan_params?.include || { tokens: true, keys: true },
                maxItems: scan_params?.maxItems || 500,
                filters: scan_params?.filters || {},
                filterRules,
              };
              break;
            default:
              throw new Error(`Unknown provider: ${provider}`);
          }

          // 1. Scan: discover items from the provider
          const scanResponse = await axios.post(scanUrl, scanBody, {
            timeout: 120000,
            headers: authHeaders,
          });
          const scanResult = scanResponse.data;
          const itemsCount = scanResult?.items?.length || 0;

          // 2. Import: delegate to the existing import endpoint so deduplication,
          //    sanitization, type validation, and audit logging are identical to
          //    what a user gets when importing manually from the dashboard.
          let importedCount = 0;
          let importErrorCount = 0;
          let deletedCount = 0;
          if (itemsCount > 0) {
            const importUrl = `${apiUrl}/api/v1/integrations/import?workspace_id=${workspace_id}`;
            // Cleanup of obsolete tokens is only attempted when the scan
            // returned at least one item, so an empty/broken scan can never
            // mass-delete a workspace.
            let cleanup;
            if (scan_params?.cleanupObsolete === true) {
              const scannedSources = [];
              if (provider === "gitlab") {
                const f = scan_params?.filters || {};
                if (f.includePATs !== false) scannedSources.push("gitlab-pat");
                if (f.includeProjectTokens !== false)
                  scannedSources.push("gitlab-project-token");
                if (f.includeGroupTokens !== false)
                  scannedSources.push("gitlab-group-token");
                if (f.includeDeployTokens !== false)
                  scannedSources.push("gitlab-deploy-token");
                if (f.includeTriggerTokens === true)
                  scannedSources.push("gitlab-trigger-token");
                if (f.includeSSHKeys === true)
                  scannedSources.push("gitlab-ssh-key");
              } else if (provider === "github") {
                const inc = scan_params?.include || {
                  tokens: true,
                  sshKeys: true,
                  deployKeys: true,
                  secrets: true,
                };
                if (inc.sshKeys) scannedSources.push("github-ssh-key");
                if (inc.deployKeys) scannedSources.push("github-deploy-key");
                if (inc.secrets) scannedSources.push("github-secret");
              }
              if (scannedSources.length > 0) {
                cleanup = {
                  enabled: true,
                  provider,
                  scannedSources,
                  scannedLocations: (scanResult.items || [])
                    .map((it) => it.location)
                    .filter(Boolean),
                  reason: "auto_sync_cleanup",
                };
              }
            }
            const importResponse = await axios.post(
              importUrl,
              { items: scanResult.items, ...(cleanup ? { cleanup } : {}) },
              { timeout: 60000, headers: authHeaders },
            );
            const importResult = importResponse.data || {};
            importedCount =
              (importResult.created_count || 0) + (importResult.updated_count || 0);
            importErrorCount = importResult.error_count || 0;
            deletedCount = importResult.deleted_count || 0;
            if (deletedCount > 0) {
              logger.info(
                `Auto-sync cleanup removed ${deletedCount} obsolete token(s) for config ${config.id}`,
              );
            }
          }

          // A run only counts as a real success if items that were scanned
          // actually made it into the workspace. Otherwise surface a 'partial'
          // status so the discrepancy between "sync completed" and "no tokens
          // visible" is visible to the user instead of silently reporting success.
          const syncStatus =
            itemsCount > 0 && importedCount === 0
              ? "partial"
              : importErrorCount > 0
                ? "partial"
                : "success";
          const syncError =
            syncStatus === "partial"
              ? itemsCount > 0 && importedCount === 0
                ? `Scan found ${itemsCount} item(s) but none were imported (all failed validation or were rejected).`
                : `${importErrorCount} of ${itemsCount} scanned item(s) failed to import.`
              : null;

          // Update config: success/partial
          const nextSync = computeNextSync(frequency, schedule_time, schedule_tz);
          await client.query(
            `UPDATE auto_sync_configs
             SET last_sync_at = NOW(), last_sync_status = $1, last_sync_error = $2,
                 last_sync_items_count = $3, next_sync_at = $4, updated_at = NOW()
             WHERE id = $5`,
            [syncStatus, syncError, importedCount, nextSync, id],
          );

          // Scheduled runs must leave an audit trail like manual runs do
          // (AUTO_SYNC_TRIGGERED is only written by the API "run now" path).
          await recordAutoSyncCompleted(client, {
            configId: id,
            workspaceId: workspace_id,
            provider,
            createdBy,
            status: syncStatus,
            itemsScanned: itemsCount,
            itemsImported: importedCount,
            error: syncError,
          });

          cAutoSync.inc({ provider, status: syncStatus });
          cAutoSyncItems.inc({ provider }, importedCount);
          gAutoSyncLastRun.set({ provider, status: syncStatus }, Date.now() / 1000);
          logger.info(
            `Auto-sync ${provider} completed: ${importedCount}/${itemsCount} items imported (${syncStatus})`,
            { workspace_id },
          );
        } catch (syncErr) {
          logger.error(`Auto-sync ${provider} failed`, {
            workspace_id,
            error: syncErr?.message || String(syncErr),
            httpStatus: syncErr?.response?.status,
            httpBody: syncErr?.response?.data,
            stack: syncErr?.stack,
          });

          cAutoSync.inc({ provider, status: "failure" });
          gAutoSyncLastRun.set({ provider, status: "failure" }, Date.now() / 1000);
          const nextSync = computeNextSync(frequency, schedule_time, schedule_tz);
          await recordAutoSyncFailure(client, {
            configId: id,
            workspaceId: workspace_id,
            provider,
            createdBy,
            previousStatus,
            errorMessage: formatAutoSyncError(syncErr),
            httpStatus: syncErr?.response?.status || null,
            nextSync,
          });
        }
      }),
    );

    // Commit all status updates and release the FOR UPDATE locks atomically.
    await client.query("COMMIT");
  });

  logger.info("Auto-sync worker finished");
  await pushMetrics("auto-sync").catch((e) =>
    logger.warn("Failed to push metrics", { error: e.message }),
  );
}

// Entry point
if (isNodeEntrypoint(import.meta.url)) {
  void (async () => {
    try {
      await runAutoSync();
      await pool.end();
      process.exit(0);
    } catch (error) {
      logger.error("Auto-sync worker fatal error", {
        error: error.message,
        stack: error.stack,
      });
      try {
        await pool.end();
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }
      process.exit(1);
    }
  })();
}

export { runAutoSync };
