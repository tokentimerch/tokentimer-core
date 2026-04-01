/**
 * Endpoint (SSL) Check Worker
 *
 * Periodically checks endpoint monitors for:
 * 1. SSL certificate changes (updates linked token expiration)
 * 2. Health checks (HTTP status, response time)
 * 3. Queues alerts for unhealthy endpoints or expiring certs
 */

import { pool, withClient } from "./db.js";
import { logger } from "./logger.js";
import tls from "tls";
import https from "https";
import http from "http";
import { X509Certificate } from "crypto";
import {
  resolveContactGroup,
  hasEmailContacts,
  hasWhatsAppContacts,
  hasWebhookNames,
  getWebhookNames,
} from "./shared/contactGroups.js";

function formatDateYmd(date) {
  if (!date) return null;
  const d = new Date(date);
  if (isNaN(d.getTime())) return null;
  return d.toISOString().split("T")[0];
}

function fetchSSLCert(hostname, port = 443) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: 15000,
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
      reject(new Error("TLS connection timeout"));
    });
  });
}

function checkHealth(url) {
  const startTime = Date.now();
  const parsedUrl = new URL(url);
  const client = parsedUrl.protocol === "https:" ? https : http;

  return new Promise((resolve) => {
    const req = client.get(
      url,
      { timeout: 15000, rejectUnauthorized: false },
      (response) => {
        const responseMs = Date.now() - startTime;
        const statusCode = response.statusCode;
        // Consume response to free socket
        response.resume();
        resolve({
          status:
            statusCode >= 200 && statusCode < 400 ? "healthy" : "unhealthy",
          statusCode,
          error: statusCode >= 400 ? `HTTP ${statusCode}` : null,
          responseMs,
        });
      },
    );
    req.on("error", (err) => {
      resolve({
        status: "error",
        statusCode: null,
        error: err.message,
        responseMs: Date.now() - startTime,
      });
    });
    req.on("timeout", () => {
      req.destroy();
      resolve({
        status: "error",
        statusCode: null,
        error: "Request timeout",
        responseMs: Date.now() - startTime,
      });
    });
  });
}

/**
 * Queue an endpoint health alert into alert_queue for delivery.
 *
 * Full alert strategy (sequential):
 *
 *   1. The endpoint-check-worker detects STATE TRANSITIONS:
 *        healthy -> unhealthy/error   => queue a "down" alert
 *        unhealthy/error -> healthy   => queue a "recovered" alert (only if a "down" was sent)
 *        NULL -> anything             => no alert (first check, no baseline)
 *        same -> same                 => no alert (no transition)
 *
 *   2. Alert keys use NO date so there is exactly ONE row per endpoint per type:
 *        down:      endpoint_health:<id>:down
 *        recovered: endpoint_health:<id>:recovered
 *      This prevents duplicate alerts. A new "down" can only be queued after the
 *      previous "down" row is cleaned up (which happens on recovery).
 *
 *   3. The delivery worker gates "down" alerts on alert_after_failures:
 *      - If consecutive_failures < alert_after_failures, skip (defer to next run).
 *      - If consecutive_failures == 0 (endpoint recovered before threshold), discard.
 *      - Once consecutive_failures >= alert_after_failures, deliver the alert.
 *
 *   4. Recovery alerts are only queued if a "down" alert was previously SENT
 *      (status='sent' in alert_queue). If the "down" was never delivered (e.g. endpoint
 *      recovered before threshold), recovery is NOT sent because the user was never
 *      told it was down.
 *
 *   5. On recovery, the old "down" row is deleted so the next outage can queue fresh.
 */
async function queueEndpointAlert(
  client,
  domain,
  status,
  health,
  transitionType,
) {
  const { id, url, token_id, workspace_id } = domain;
  if (!token_id) {
    logger.warn(`Skipping endpoint alert for ${url}: no linked token`);
    return;
  }

  try {
    const parsedUrl = new URL(url);
    const hostname = parsedUrl.hostname;

    const downKey = `endpoint_health:${id}:down`;
    const recoveredKey = `endpoint_health:${id}:recovered`;
    const alertKey = transitionType === "down" ? downKey : recoveredKey;

    // --- Recovery: only notify if a "down" alert was actually delivered ---
    if (transitionType === "recovered") {
      const sentDown = await client.query(
        "SELECT id FROM alert_queue WHERE alert_key = $1 AND status = 'sent'",
        [downKey],
      );
      // Clean up the old "down" row regardless (so next outage can queue a new one)
      await client.query("DELETE FROM alert_queue WHERE alert_key = $1", [
        downKey,
      ]);

      if (sentDown.rows.length === 0) {
        // "down" was never delivered (recovered before threshold or still pending)
        // No point telling the user it recovered if they were never told it was down
        logger.info(
          `Skipping recovery alert for ${hostname}: down alert was never delivered`,
        );
        return;
      }
      // Also clean up any previous "recovered" row so we can insert a fresh one
      await client.query("DELETE FROM alert_queue WHERE alert_key = $1", [
        recoveredKey,
      ]);
    }

    // --- Down: check if one is already queued/pending ---
    if (transitionType === "down") {
      const existing = await client.query(
        "SELECT id FROM alert_queue WHERE alert_key = $1",
        [alertKey],
      );
      if (existing.rows.length > 0) return; // already queued
    }

    // Resolve workspace user (owner/admin) for the alert
    const userRes = await client.query(
      `SELECT wm.user_id FROM workspace_memberships wm
       WHERE wm.workspace_id = $1 AND wm.role = 'admin'
       LIMIT 1`,
      [workspace_id],
    );
    if (userRes.rows.length === 0) return;
    const userId = userRes.rows[0].user_id;

    // Resolve channels using the same contact-group eligibility rules as token alerts.
    const settingsRes = await client.query(
      "SELECT email_alerts_enabled, contact_groups, default_contact_group_id, webhook_urls FROM workspace_settings WHERE workspace_id = $1",
      [workspace_id],
    );
    const settings = settingsRes.rows[0] || {};
    let tokenContactGroupId = null;
    try {
      const tokenRes = await client.query(
        "SELECT contact_group_id FROM tokens WHERE id = $1 LIMIT 1",
        [token_id],
      );
      tokenContactGroupId = tokenRes.rows[0]?.contact_group_id || null;
    } catch (_tokenErr) {
      logger.debug("Failed to resolve token contact group", {
        tokenId: token_id,
        error: _tokenErr?.message,
      });
    }

    const resolvedGroup = resolveContactGroup({
      contactGroups: settings.contact_groups,
      contactGroupId: tokenContactGroupId,
      defaultContactGroupId: settings.default_contact_group_id,
    });

    const channels = [];
    if (settings.email_alerts_enabled !== false && hasEmailContacts(resolvedGroup)) {
      channels.push("email");
    }

    if (resolvedGroup && hasWebhookNames(resolvedGroup)) {
      const selectedWebhookNames = getWebhookNames(resolvedGroup);
      const workspaceWebhooks = Array.isArray(settings.webhook_urls)
        ? settings.webhook_urls
        : [];
      const matchingWebhookCount = workspaceWebhooks.filter((webhook) =>
        selectedWebhookNames.includes(String(webhook?.name || "").trim()),
      ).length;
      if (matchingWebhookCount > 0) {
        channels.push("webhooks");
      }
    }

    if (hasWhatsAppContacts(resolvedGroup)) {
      channels.push("whatsapp");
    }

    if (channels.length === 0) return;

    await client.query(
      `INSERT INTO alert_queue (user_id, token_id, alert_key, threshold_days, due_date, channels, status)
       VALUES ($1, $2, $3, $4, CURRENT_DATE, $5::jsonb, 'pending')`,
      [
        userId,
        token_id,
        alertKey,
        0, // threshold_days not applicable for health alerts, use 0
        JSON.stringify(channels),
      ],
    );

    logger.info(`Queued endpoint ${transitionType} alert for ${hostname}`, {
      alertKey,
      channels,
    });
  } catch (alertErr) {
    logger.error(`Failed to queue endpoint alert for ${url}`, {
      error: alertErr.message,
    });
  }
}

async function runEndpointChecks() {
  logger.info("Endpoint check worker started");

  await withClient(async (client) => {
    // Find endpoints due for check based on their configured interval
    const result = await client.query(
      `SELECT * FROM domain_monitors
       WHERE (
         (check_interval = '1min'   AND (last_health_check_at IS NULL OR last_health_check_at < NOW() - INTERVAL '1 minute'))
         OR
         (check_interval = '5min'   AND (last_health_check_at IS NULL OR last_health_check_at < NOW() - INTERVAL '5 minutes'))
         OR
         (check_interval = '30min'  AND (last_health_check_at IS NULL OR last_health_check_at < NOW() - INTERVAL '30 minutes'))
         OR
         (check_interval = 'hourly' AND (last_health_check_at IS NULL OR last_health_check_at < NOW() - INTERVAL '1 hour'))
         OR
         (check_interval = 'daily'  AND (last_health_check_at IS NULL OR last_health_check_at < NOW() - INTERVAL '24 hours'))
       )
       ORDER BY last_health_check_at ASC NULLS FIRST
       LIMIT 50
       FOR UPDATE SKIP LOCKED`,
    );

    if (result.rows.length === 0) {
      logger.info("No endpoint monitors due for check");
      return;
    }

    logger.info(`Checking ${result.rows.length} endpoints`);

    for (const domain of result.rows) {
      const {
        id,
        url,
        token_id,
        health_check_enabled,
        workspace_id,
        consecutive_failures,
      } = domain;
      logger.info(`Checking endpoint: ${url}`);

      try {
        const parsedUrl = new URL(url);

        // 1. SSL cert check (for HTTPS URLs)
        if (parsedUrl.protocol === "https:") {
          try {
            const port = parsedUrl.port || 443;
            const cert = await fetchSSLCert(parsedUrl.hostname, port);

            if (cert && cert.raw) {
              const x509 = new X509Certificate(cert.raw);
              const sslData = {
                ssl_issuer: x509.issuer || null,
                ssl_subject: x509.subject || null,
                ssl_valid_from: cert.valid_from
                  ? new Date(cert.valid_from)
                  : null,
                ssl_valid_to: cert.valid_to ? new Date(cert.valid_to) : null,
                ssl_serial: x509.serialNumber || null,
                ssl_fingerprint:
                  cert.fingerprint256 || cert.fingerprint || null,
              };

              // Update endpoint monitor with cert data
              await client.query(
                `UPDATE domain_monitors
                 SET ssl_issuer = $1, ssl_subject = $2, ssl_valid_from = $3,
                     ssl_valid_to = $4, ssl_serial = $5, ssl_fingerprint = $6,
                     validated = TRUE, validated_at = COALESCE(validated_at, NOW()),
                     updated_at = NOW()
                 WHERE id = $7`,
                [
                  sslData.ssl_issuer,
                  sslData.ssl_subject,
                  sslData.ssl_valid_from,
                  sslData.ssl_valid_to,
                  sslData.ssl_serial,
                  sslData.ssl_fingerprint,
                  id,
                ],
              );

              // Update linked token expiration if cert changed
              if (token_id && sslData.ssl_valid_to) {
                const newExpiry = formatDateYmd(sslData.ssl_valid_to);
                if (newExpiry) {
                  await client.query(
                    `UPDATE tokens SET expiration = $1, issuer = $2, serial_number = $3,
                            subject = $4, updated_at = NOW()
                     WHERE id = $5`,
                    [
                      newExpiry,
                      sslData.ssl_issuer,
                      sslData.ssl_serial,
                      sslData.ssl_subject,
                      token_id,
                    ],
                  );
                }
              }

              // Auto-create token if we got cert data but no token is linked yet
              if (!token_id && sslData.ssl_valid_to) {
                try {
                  // Resolve workspace default contact group for the new token
                  let defaultCgId = null;
                  try {
                    const cgRes = await client.query(
                      "SELECT default_contact_group_id FROM workspace_settings WHERE workspace_id = $1",
                      [workspace_id],
                    );
                    if (cgRes.rows[0]?.default_contact_group_id) {
                      defaultCgId = String(
                        cgRes.rows[0].default_contact_group_id,
                      );
                    }
                  } catch (_err) {
                    logger.warn("DB operation failed", { error: _err.message });
                  }

                  const tokenRes = await client.query(
                    `INSERT INTO tokens (workspace_id, name, expiration, type, category, issuer, serial_number, subject, domains, location, notes, contact_group_id)
                     VALUES ($1, $2, $3, 'ssl_cert', 'cert', $4, $5, $6, $7, $8, $9, $10)
                     RETURNING id`,
                    [
                      workspace_id,
                      parsedUrl.hostname.substring(0, 100),
                      formatDateYmd(sslData.ssl_valid_to),
                      sslData.ssl_issuer,
                      sslData.ssl_serial,
                      sslData.ssl_subject,
                      [parsedUrl.hostname],
                      url,
                      `Auto-created by endpoint monitor. Fingerprint: ${sslData.ssl_fingerprint || "unknown"}`,
                      defaultCgId,
                    ],
                  );
                  await client.query(
                    "UPDATE domain_monitors SET token_id = $1 WHERE id = $2",
                    [tokenRes.rows[0].id, id],
                  );
                } catch (tokenErr) {
                  logger.warn("Failed to auto-create token for endpoint", {
                    url,
                    error: tokenErr.message,
                  });
                }
              }
            }
          } catch (sslErr) {
            logger.warn(`SSL check failed for ${url}`, {
              error: sslErr.message,
            });
          }
        }

        // 2. Health check
        if (health_check_enabled) {
          const health = await checkHealth(url);
          const isHealthy = health.status === "healthy";
          const newFailures = isHealthy ? 0 : (consecutive_failures || 0) + 1;
          // last_health_status from the SELECT is the PREVIOUS check's result
          const prevStatus = domain.last_health_status;

          await client.query(
            `UPDATE domain_monitors
             SET last_health_check_at = NOW(), last_health_status = $1,
                 last_health_status_code = $2, last_health_error = $3,
                 last_health_response_ms = $4,
                 previous_health_status = last_health_status,
                 consecutive_failures = $5,
                 updated_at = NOW()
             WHERE id = $6`,
            [
              health.status,
              health.statusCode,
              health.error,
              health.responseMs,
              newFailures,
              id,
            ],
          );

          // --- Alert on STATE TRANSITION only ---
          // Queue alert immediately on transition. The delivery worker will
          // check alert_after_failures before actually sending the "down" alert.
          const transitionedDown =
            prevStatus && prevStatus === "healthy" && !isHealthy;
          const transitionedUp =
            prevStatus && prevStatus !== "healthy" && isHealthy;

          if (transitionedDown) {
            logger.warn(
              `Endpoint TRANSITION healthy -> ${health.status}: ${url}`,
              {
                statusCode: health.statusCode,
                error: health.error,
              },
            );
            await queueEndpointAlert(
              client,
              domain,
              health.status,
              health,
              "down",
            );
          } else if (transitionedUp) {
            logger.info(`Endpoint RECOVERED: ${url}`);
            await queueEndpointAlert(
              client,
              domain,
              "healthy",
              health,
              "recovered",
            );
          } else if (!isHealthy) {
            logger.debug(
              `Endpoint still unhealthy: ${url} (failure ${newFailures})`,
              {
                status: health.status,
                statusCode: health.statusCode,
              },
            );
          }
        }
      } catch (domainErr) {
        logger.error(`Endpoint check failed for ${url}`, {
          error: domainErr.message,
        });

        const newFailures = (domain.consecutive_failures || 0) + 1;
        const prevStatus = domain.last_health_status;

        await client.query(
          `UPDATE domain_monitors
           SET last_health_check_at = NOW(), last_health_status = 'error',
               last_health_error = $1,
               previous_health_status = last_health_status,
               consecutive_failures = $2,
               updated_at = NOW()
           WHERE id = $3`,
          [String(domainErr.message).substring(0, 500), newFailures, id],
        );

        // Queue alert on transition healthy -> error
        if (prevStatus && prevStatus === "healthy") {
          await queueEndpointAlert(
            client,
            domain,
            "error",
            { error: domainErr.message, responseMs: null, statusCode: null },
            "down",
          );
        }
      }
    }
  });

  logger.info("Endpoint check worker finished");
}

// Entry point
if (import.meta.url === new URL(process.argv[1], "file://").href) {
  runEndpointChecks()
    .catch(async (e) => {
      logger.error("Endpoint check worker fatal error", {
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

export { runEndpointChecks };
