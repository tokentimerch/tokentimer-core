/**
 * Auto-Sync Worker
 *
 * Processes scheduled integration scans from auto_sync_configs.
 * Picks up configs where next_sync_at <= NOW() and enabled = TRUE,
 * runs the corresponding scan, imports results, and updates status.
 */

import { pool, withClient } from "./db.js";
import { logger } from "./logger.js";
import crypto from "crypto";
import axios from "axios";

// Encryption helpers (same as systemSettings.js)
function getEncryptionKey() {
  const secret = process.env.SESSION_SECRET || "";
  return crypto.createHash("sha256").update(secret).digest();
}

function decrypt(ciphertext) {
  if (!ciphertext) return null;
  try {
    const parts = ciphertext.split(":");
    if (parts.length !== 3) return null;
    const key = getEncryptionKey();
    const iv = Buffer.from(parts[0], "hex");
    const tag = Buffer.from(parts[1], "hex");
    const encrypted = parts[2];
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (e) {
    logger.error("Failed to decrypt auto-sync credentials", {
      error: e.message,
    });
    return null;
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
    // Pick up due configs with row-level locking
    const dueResult = await client.query(
      `SELECT * FROM auto_sync_configs
       WHERE enabled = TRUE AND next_sync_at <= NOW()
       ORDER BY next_sync_at ASC
       LIMIT 10
       FOR UPDATE SKIP LOCKED`,
    );

    if (dueResult.rows.length === 0) {
      logger.info("No auto-sync configs due");
      return;
    }

    logger.info(`Processing ${dueResult.rows.length} auto-sync configs`);

    for (const config of dueResult.rows) {
      const {
        id,
        workspace_id,
        provider,
        credentials_encrypted,
        scan_params,
        frequency,
        schedule_time,
        schedule_tz,
      } = config;
      logger.info(`Syncing ${provider} for workspace ${workspace_id}`);

      try {
        // Decrypt credentials
        const credJson = decrypt(credentials_encrypted);
        if (!credJson) {
          throw new Error("Failed to decrypt credentials");
        }
        const creds = JSON.parse(credJson);

        // Call the API's scan endpoint via HTTP
        const apiUrl = process.env.API_URL || "http://api:4000";
        const workerKey =
          process.env.WORKER_API_KEY || process.env.SESSION_SECRET;
        const authHeaders = workerKey
          ? { Authorization: `Bearer ${workerKey}` }
          : {};
        let scanUrl;
        let scanBody;

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
            };
            break;
          case "aws":
            scanUrl = `${apiUrl}/api/v1/integrations/aws/scan?workspace_id=${workspace_id}`;
            scanBody = {
              accessKeyId: creds.accessKeyId,
              secretAccessKey: creds.secretAccessKey,
              sessionToken: creds.sessionToken || null,
              region: creds.region || scan_params?.region || "us-east-1",
              include: scan_params?.include || {
                secrets: true,
                iam: true,
                certificates: true,
              },
              maxItems: scan_params?.maxItems || 500,
            };
            break;
          case "azure":
            scanUrl = `${apiUrl}/api/v1/integrations/azure/scan?workspace_id=${workspace_id}`;
            scanBody = {
              vaultUrl: creds.vaultUrl,
              token: creds.token,
              include: scan_params?.include || {
                secrets: true,
                certificates: true,
                keys: true,
              },
              maxItems: scan_params?.maxItems || 500,
            };
            break;
          case "azure-ad":
            scanUrl = `${apiUrl}/api/v1/integrations/azure-ad/scan?workspace_id=${workspace_id}`;
            scanBody = {
              token: creds.token,
              include: scan_params?.include || {
                applications: true,
                servicePrincipals: true,
              },
              maxItems: scan_params?.maxItems || 500,
            };
            break;
          case "gcp":
            scanUrl = `${apiUrl}/api/v1/integrations/gcp/scan?workspace_id=${workspace_id}`;
            scanBody = {
              projectId: creds.projectId,
              accessToken: creds.accessToken,
              include: scan_params?.include || { secrets: true },
              maxItems: scan_params?.maxItems || 500,
            };
            break;
          case "vault":
            scanUrl = `${apiUrl}/api/v1/integrations/vault/scan?workspace_id=${workspace_id}`;
            scanBody = {
              address: creds.address,
              token: creds.token,
              include: scan_params?.include || { kv: true, pki: true },
              maxItemsPerMount: scan_params?.maxItemsPerMount || 250,
              pathPrefix: scan_params?.pathPrefix || null,
            };
            break;
          default:
            throw new Error(`Unknown provider: ${provider}`);
        }

        // Call the scan API endpoint
        const scanResponse = await axios.post(scanUrl, scanBody, {
          timeout: 120000,
          headers: authHeaders,
        });
        const scanResult = scanResponse.data;

        const itemsCount = scanResult?.items?.length || 0;

        // Import results into workspace
        if (itemsCount > 0) {
          const NEVER_EXPIRES_DATE = "2099-12-31";
          for (const item of scanResult.items) {
            try {
              const name = String(item.name || "").trim();
              if (!name || name.length < 3) continue;
              let expiration = item.expiration || item.expiresAt || null;
              if (expiration) {
                const d = new Date(expiration);
                if (isNaN(d.getTime())) expiration = null;
                else expiration = d.toISOString().split("T")[0];
              }
              if (!expiration) expiration = NEVER_EXPIRES_DATE;

              const category = (item.category || "general").toLowerCase();
              const type = (item.type || "other").toLowerCase();
              const section = item.source ? [item.source] : null;

              // Upsert: update if exists, create if not
              await client.query(
                `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category, section, location, notes, imported_at)
                 VALUES (NULL, $1, NULL, $2, $3, $4, $5, $6, $7, $8, NOW())
                 ON CONFLICT ON CONSTRAINT tokens_pkey DO NOTHING`,
                [
                  workspace_id,
                  name.substring(0, 100),
                  expiration,
                  type,
                  category,
                  section,
                  item.location || null,
                  `Auto-synced from ${provider}`,
                ],
              );
            } catch (itemErr) {
              logger.warn("Auto-sync: failed to import item", {
                name: item.name,
                error: itemErr.message,
              });
            }
          }
        }

        // Update config: success
        const nextSync = computeNextSync(frequency, schedule_time, schedule_tz);
        await client.query(
          `UPDATE auto_sync_configs
           SET last_sync_at = NOW(), last_sync_status = 'success', last_sync_error = NULL,
               last_sync_items_count = $1, next_sync_at = $2, updated_at = NOW()
           WHERE id = $3`,
          [itemsCount, nextSync, id],
        );

        logger.info(`Auto-sync ${provider} completed: ${itemsCount} items`, {
          workspace_id,
        });
      } catch (syncErr) {
        logger.error(`Auto-sync ${provider} failed`, {
          workspace_id,
          error: syncErr.message,
        });

        // Update config: failed
        const nextSync = computeNextSync(frequency, schedule_time, schedule_tz);
        await client.query(
          `UPDATE auto_sync_configs
           SET last_sync_at = NOW(), last_sync_status = 'failed',
               last_sync_error = $1, next_sync_at = $2, updated_at = NOW()
           WHERE id = $3`,
          [String(syncErr.message).substring(0, 1000), nextSync, id],
        );
      }
    }
  });

  logger.info("Auto-sync worker finished");
}

// Entry point
if (import.meta.url === new URL(process.argv[1], "file://").href) {
  runAutoSync()
    .catch(async (e) => {
      logger.error("Auto-sync worker fatal error", {
        error: e.message,
        stack: e.stack,
      });
      await pool.end();
      process.exit(1);
    })
    .then(async () => {
      await pool.end();
      process.exit(0);
    });
}

export { runAutoSync };
