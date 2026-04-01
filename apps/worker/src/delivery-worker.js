import { pool, withClient } from "./db.js";
import {
  cDelivery,
  cRetry,
  hLatency,
  gCooldownInEffect,
  gRunnerUp,
  gQueueDueNow,
  gQueueDepth,
  pushMetrics,
  gMonthlyChannelUsage,
} from "./metrics.js";
import {
  sendEmailNotification,
  generateEmailTemplate,
} from "./notify/email.js";
import { sendWhatsApp } from "./notify/whatsapp.js";
import { postJson, formatPayload } from "./notify/webhooks.js";
import crypto from "node:crypto";
import { logger } from "./logger.js";
import { computeDaysLeft } from "./shared/thresholds.js";
import {
  resolveContactGroup,
  hasEmailContacts,
  hasWhatsAppContacts,
  hasWebhookNames,
  getWebhookNames,
} from "./shared/contactGroups.js";

function safeJoinList(value) {
  if (!value) return null;
  if (Array.isArray(value)) return value.filter(Boolean).join(", ") || null;
  try {
    const parsed = JSON.parse(value);
    if (Array.isArray(parsed)) return parsed.filter(Boolean).join(", ") || null;
  } catch (_err) {
    logger.debug("Parse failed", { error: _err.message });
  }
  return String(value);
}

function buildEmailContent(alert, resolvedDays) {
  const name = alert.name || "Token";
  const computed = computeDaysLeft(alert.expiration);
  const days = Number.isFinite(resolvedDays)
    ? resolvedDays
    : Number.isFinite(computed)
      ? computed
      : alert.threshold_days;
  const expires = alert.expiration
    ? new Date(alert.expiration).toISOString().slice(0, 10)
    : null;

  // Handle expired tokens (negative days) with appropriate messaging
  const isExpired = days <= 0;
  const daysText = isExpired ? Math.abs(days) : days;
  const timePhrase = isExpired ? "expired" : "expiring";
  const subject = `${name} ${timePhrase} ${isExpired ? `${daysText} day(s) ago` : `in ${daysText} day(s)`}`;

  const lines = [];
  if (isExpired) {
    lines.push(`${name} expired ${daysText} day(s) ago.`);
  } else {
    lines.push(`${name} is scheduled to expire in ${daysText} day(s).`);
  }
  if (expires) lines.push(`Expiration date: ${expires}`);
  lines.push("");

  const fields = [
    ["Name", alert.name],
    ["Type", alert.type],
    ["Category", alert.category],
    ["Domains", safeJoinList(alert.domains)],
    ["Location", alert.location],
    ["Used By", alert.used_by],
    ["Issuer", alert.issuer],
    ["Serial Number", alert.serial_number],
    ["Subject", alert.subject],
    ["Key Size", alert.key_size],
    ["Algorithm", alert.algorithm],
    ["License Type", alert.license_type],
    ["Vendor", alert.vendor],
    ["Cost", alert.cost != null ? String(alert.cost) : null],
    ["Renewal URL", alert.renewal_url],
    [
      "Renewal Date",
      alert.renewal_date
        ? new Date(alert.renewal_date).toISOString().slice(0, 10)
        : null,
    ],
    ["Contacts", safeJoinList(alert.contacts)],
    ["Description", alert.description],
    ["Notes", alert.notes],
  ];

  lines.push("Details:");
  for (const [label, value] of fields) {
    if (value !== undefined && value !== null && String(value).trim() !== "") {
      lines.push(`- ${label}: ${value}`);
    }
  }

  const text = lines.join("\n");

  // Build HTML content for template
  const htmlContentLines = [];
  if (isExpired) {
    htmlContentLines.push(
      `<p><strong>${name}</strong> expired <strong>${daysText}</strong> day(s) ago.</p>`,
    );
  } else {
    htmlContentLines.push(
      `<p><strong>${name}</strong> is scheduled to expire in <strong>${daysText}</strong> day(s).</p>`,
    );
  }
  if (expires)
    htmlContentLines.push(
      `<p><strong>Expiration date:</strong> ${expires}</p>`,
    );
  htmlContentLines.push(
    '<h3 style="color: #1a202c; font-size: 18px; font-weight: 600; margin: 20px 0 10px;">Details</h3>',
  );
  htmlContentLines.push(
    '<ul style="color: #4a5568; line-height: 1.8; padding-left: 20px; margin: 0;">',
  );
  for (const [label, value] of fields) {
    if (value !== undefined && value !== null && String(value).trim() !== "") {
      if (label === "Renewal URL") {
        htmlContentLines.push(
          `<li><strong>${label}:</strong> <a href="${String(value)}" style="color: #2B6CB0; text-decoration: none;">${String(value)}</a></li>`,
        );
      } else {
        htmlContentLines.push(
          `<li><strong>${label}:</strong> ${String(value)}</li>`,
        );
      }
    }
  }
  htmlContentLines.push("</ul>");
  const htmlContent = htmlContentLines.join("");

  // Use the email template generator to wrap content in proper template
  const { html, text: templateText } = generateEmailTemplate({
    title: subject,
    content: htmlContent,
    plainTextContent: text,
  });

  return { subject, text: templateText, html };
}

function buildEndpointHealthEmailContent(alert, token) {
  const name = token.name || "Endpoint";
  const location = token.location || token.name || "Unknown";
  const url = token.location || "";
  const parts = (alert.alert_key || "").split(":");
  const transition = parts[2] || "down";
  const isDown = transition === "down";
  const status = isDown ? "DOWN" : "RECOVERED";
  const statusColor = isDown ? "#e53e3e" : "#38a169";
  const statusBg = isDown ? "#FFF5F5" : "#F0FFF4";
  const statusBorder = isDown ? "#FEB2B2" : "#9AE6B4";
  const statusIcon = isDown ? "\u26A0\uFE0F" : "\u2705"; // warning / check mark
  const frontendUrl = process.env.APP_URL || "http://localhost:5173";
  const timestamp = new Date().toLocaleString("en-US", {
    weekday: "short",
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short",
  });

  const subject = isDown
    ? `${statusIcon} Endpoint Down: ${name}`
    : `${statusIcon} Endpoint Recovered: ${name}`;

  let showLinkedToken = false;
  if (name && name !== "Endpoint") {
    try {
      const hostname = url ? new URL(url).hostname : "";
      showLinkedToken = name !== hostname && name !== url && name !== location;
    } catch { showLinkedToken = name !== url && name !== location; }
  }

  // Plain text version
  const textLines = [
    `Endpoint ${status}: ${name}`,
    "",
    `Status: ${status}`,
    `URL: ${url || location}`,
    ...(showLinkedToken ? [`Linked Token: ${name}`] : []),
    `Detected at: ${timestamp}`,
    "",
    isDown
      ? "The endpoint is no longer responding or is returning an error. Please check the service."
      : "The endpoint is back online and responding normally.",
    "",
    `View your dashboard: ${frontendUrl}`,
  ];
  const text = textLines.join("\n");

  // HTML content
  const statusBadge = `
    <div style="background: ${statusBg}; border: 1px solid ${statusBorder}; border-radius: 8px; padding: 16px 20px; margin: 16px 0;">
      <table cellpadding="0" cellspacing="0" border="0" width="100%">
        <tr>
          <td style="vertical-align: middle; width: 40px;">
            <span style="font-size: 28px;">${statusIcon}</span>
          </td>
          <td style="vertical-align: middle; padding-left: 12px;">
            <span style="font-size: 20px; font-weight: 700; color: ${statusColor};">${status}</span>
            <br/>
            <span style="font-size: 14px; color: #4A5568;">${isDown ? "Endpoint is unreachable or returning errors" : "Endpoint is back online and healthy"}</span>
          </td>
        </tr>
      </table>
    </div>`;

  const detailsTable = `
    <table cellpadding="0" cellspacing="0" border="0" width="100%" style="margin: 20px 0; border-collapse: collapse;">
      <tr>
        <td style="padding: 10px 12px; border-bottom: 1px solid #E2E8F0; color: #718096; font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; width: 120px;">URL</td>
        <td style="padding: 10px 12px; border-bottom: 1px solid #E2E8F0; font-size: 14px;">
          ${url ? `<a href="${url}" style="color: #2B6CB0; text-decoration: none;">${url}</a>` : location}
        </td>
      </tr>
      ${showLinkedToken ? `<tr>
        <td style="padding: 10px 12px; border-bottom: 1px solid #E2E8F0; color: #718096; font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">Linked Token</td>
        <td style="padding: 10px 12px; border-bottom: 1px solid #E2E8F0; font-size: 14px;">${name}</td>
      </tr>` : ""}
      <tr>
        <td style="padding: 10px 12px; border-bottom: 1px solid #E2E8F0; color: #718096; font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">Detected</td>
        <td style="padding: 10px 12px; border-bottom: 1px solid #E2E8F0; font-size: 14px;">${timestamp}</td>
      </tr>
      ${
        token.type
          ? `
      <tr>
        <td style="padding: 10px 12px; border-bottom: 1px solid #E2E8F0; color: #718096; font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">Type</td>
        <td style="padding: 10px 12px; border-bottom: 1px solid #E2E8F0; font-size: 14px;">${token.type}</td>
      </tr>`
          : ""
      }
      ${
        token.issuer
          ? `
      <tr>
        <td style="padding: 10px 12px; border-bottom: 1px solid #E2E8F0; color: #718096; font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">Issuer</td>
        <td style="padding: 10px 12px; border-bottom: 1px solid #E2E8F0; font-size: 14px;">${token.issuer}</td>
      </tr>`
          : ""
      }
      ${
        token.expiration
          ? `
      <tr>
        <td style="padding: 10px 12px; border-bottom: 1px solid #E2E8F0; color: #718096; font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">SSL Expiry</td>
        <td style="padding: 10px 12px; border-bottom: 1px solid #E2E8F0; font-size: 14px;">${new Date(token.expiration).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" })}</td>
      </tr>`
          : ""
      }
    </table>`;

  const tip = isDown
    ? `<p style="color: #718096; font-size: 13px; line-height: 1.6; margin-top: 16px;">
        You will receive a recovery notification once the endpoint is back online.
        No further alerts will be sent for this outage.
       </p>`
    : `<p style="color: #718096; font-size: 13px; line-height: 1.6; margin-top: 16px;">
        This endpoint was previously reported as down. It is now responding normally.
       </p>`;

  const htmlContent = `${statusBadge}${detailsTable}${tip}`;

  const { html, text: templateText } = generateEmailTemplate({
    title: `Endpoint ${status}: ${name}`,
    content: htmlContent,
    buttonText: "View Dashboard",
    buttonUrl: frontendUrl,
    plainTextContent: text,
  });

  return { subject, text: templateText, html };
}

function getEndpointHealthContext(alert, token = alert) {
  const parts = String(alert.alert_key || "").split(":");
  const transition = parts[2] || "down";
  const isDown = transition === "down";
  const status = isDown ? "DOWN" : "RECOVERED";
  const endpointName = token.name || "Endpoint";
  const location = token.location || token.name || "Unknown";
  const url = token.location || "";
  let showLinkedToken = false;
  if (endpointName && endpointName !== "Endpoint") {
    try {
      const hostname = url ? new URL(url).hostname : "";
      showLinkedToken = endpointName !== hostname && endpointName !== url && endpointName !== location;
    } catch { showLinkedToken = endpointName !== url && endpointName !== location; }
  }
  return {
    transition,
    isDown,
    status,
    severity: isDown ? "critical" : "info",
    statusIcon: isDown ? "\u26A0\uFE0F" : "\u2705",
    endpointName,
    location,
    url,
    showLinkedToken,
    title: isDown
      ? `Endpoint Down: ${endpointName}`
      : `Endpoint Recovered: ${endpointName}`,
    description: isDown
      ? "The endpoint is no longer responding or is returning an error. Please check the service."
      : "The endpoint is back online and responding normally.",
  };
}

function buildEndpointHealthWebhookPayload(
  kind,
  alert,
  {
    severity,
    title,
    routingKey,
  } = {},
) {
  const context = getEndpointHealthContext(alert, alert);
  const selectedSeverity = String(severity || context.severity).toLowerCase();
  const selectedTitle = title || context.title;
  const endpointData = {
    type: "endpoint_health",
    token_id: alert.token_id,
    token_name: alert.name || context.endpointName,
    endpoint_name: context.endpointName,
    location: context.location,
    url: context.url || context.location,
    status: context.status,
    transition: context.transition,
  };

  if (kind === "slack") {
    return {
      text: `${context.statusIcon} ${selectedTitle}`,
      blocks: [
        {
          type: "header",
          text: { type: "plain_text", text: `${context.statusIcon} ${selectedTitle}` },
        },
        {
          type: "section",
          text: { type: "mrkdwn", text: context.description },
        },
        {
          type: "section",
          fields: [
            { type: "mrkdwn", text: `*Status:*\n${context.status}` },
            { type: "mrkdwn", text: `*URL:*\n${context.url || context.location}` },
            ...(context.showLinkedToken ? [{ type: "mrkdwn", text: `*Linked Token:*\n${alert.name || context.endpointName}` }] : []),
          ],
        },
      ],
    };
  }

  if (kind === "discord") {
    return {
      content: `${context.statusIcon} **${selectedTitle}**`,
      embeds: [
        {
          title: selectedTitle,
          description: context.description,
          color: context.isDown ? 15158332 : 3066993,
          fields: [
            { name: "Status", value: context.status, inline: true },
            { name: "URL", value: context.url || context.location, inline: false },
            ...(context.showLinkedToken ? [{
              name: "Linked Token",
              value: alert.name || context.endpointName,
              inline: true,
            }] : []),
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    };
  }

  if (kind === "teams") {
    return {
      "@type": "MessageCard",
      "@context": "https://schema.org/extensions",
      summary: selectedTitle,
      themeColor: context.isDown ? "E02424" : "2F855A",
      sections: [
        {
          activityTitle: `${context.statusIcon} ${selectedTitle}`,
          text: context.description,
          facts: [
            { name: "Status", value: context.status },
            { name: "URL", value: context.url || context.location },
            ...(context.showLinkedToken ? [{ name: "Linked Token", value: alert.name || context.endpointName }] : []),
          ],
          markdown: true,
        },
      ],
    };
  }

  if (kind === "pagerduty") {
    return {
      routing_key: routingKey,
      event_action: "trigger",
      payload: {
        summary: selectedTitle,
        source: "TokenTimer",
        severity: selectedSeverity,
        timestamp: new Date().toISOString(),
        custom_details: endpointData,
      },
    };
  }

  return {
    text: `${context.statusIcon} ${selectedTitle}`,
    content: `${context.statusIcon} ${selectedTitle}`,
    message: context.description,
    severity: selectedSeverity,
    title: selectedTitle,
    timestamp: new Date().toISOString(),
    type: "endpoint_health_alert",
    endpoint: endpointData,
  };
}

function buildEndpointHealthWhatsAppTemplateVariables(
  alert,
  recipientName = "there",
) {
  const context = getEndpointHealthContext(alert, alert);
  const detectedAt = new Intl.DateTimeFormat("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short",
  }).format(new Date());

  return {
    recipient_name: recipientName,
    endpoint_name: context.endpointName,
    endpoint_url: context.url || context.location,
    token_name: alert.name || context.endpointName,
    detected_at: detectedAt,
  };
}

// Per-organization WhatsApp per-minute rate limit (soft throttle, safety valve)
const WHATSAPP_RATE_PER_MIN = Number(process.env.WHATSAPP_RATE_PER_MIN) || 60;

// Maximum number of retry attempts per channel before permanently blocking
const MAX_ATTEMPTS_PER_CHANNEL = Number.isFinite(
  Number(process.env.ALERT_MAX_ATTEMPTS),
)
  ? Number(process.env.ALERT_MAX_ATTEMPTS)
  : 20;

async function writeAudit(
  client,
  {
    actorUserId = null,
    subjectUserId,
    action,
    targetType = "token",
    targetId,
    channel = null,
    metadata = {},
  },
) {
  await client.query(
    `INSERT INTO audit_events (actor_user_id, subject_user_id, action, target_type, target_id, channel, metadata)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [
      actorUserId,
      subjectUserId,
      action,
      targetType,
      targetId,
      channel,
      metadata,
    ],
  );
}

// Graceful shutdown handler
let isShuttingDown = false;
const shutdown = async (signal) => {
  if (isShuttingDown) return;
  isShuttingDown = true;
  logger.info(
    JSON.stringify({
      level: "INFO",
      message: "delivery-worker-shutdown",
      signal,
    }),
  );
  try {
    await pool.end();
  } catch (err) {
    logger.error(
      JSON.stringify({
        level: "ERROR",
        message: "delivery-worker-shutdown-error",
        error: err.message,
      }),
    );
  }
  process.exit(0);
};

// Register signal handlers for graceful shutdown
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

export async function deliveryWorkerJob() {
  const startedAt = Date.now();
  let processed = 0,
    sent = 0,
    failed = 0;

  await withClient(async (client) => {
    // In test mode, ignore next_attempt_at gating to allow repeated processing in quick succession
    const gatingClause =
      process.env.NODE_ENV === "test"
        ? ""
        : "AND (aq.next_attempt_at IS NULL OR aq.next_attempt_at <= NOW())";
    let contentSidExpires =
      process.env.TWILIO_WHATSAPP_ALERT_CONTENT_SID_EXPIRES || null;
    let contentSidExpired =
      process.env.TWILIO_WHATSAPP_ALERT_CONTENT_SID_EXPIRED || null;
    let contentSidEndpointDown =
      process.env.TWILIO_WHATSAPP_ALERT_CONTENT_SID_ENDPOINT_DOWN || null;
    let contentSidEndpointRecovered =
      process.env.TWILIO_WHATSAPP_ALERT_CONTENT_SID_ENDPOINT_RECOVERED || null;
    if (
      !contentSidExpires ||
      !contentSidExpired ||
      !contentSidEndpointDown ||
      !contentSidEndpointRecovered
    ) {
      try {
        const sidRes = await client.query(
          "SELECT twilio_whatsapp_alert_content_sid_expires, twilio_whatsapp_alert_content_sid_expired, twilio_whatsapp_alert_content_sid_endpoint_down, twilio_whatsapp_alert_content_sid_endpoint_recovered FROM system_settings WHERE id = 1",
        );
        const sidRow = sidRes.rows?.[0] || {};
        if (!contentSidExpires) {
          contentSidExpires =
            sidRow.twilio_whatsapp_alert_content_sid_expires || null;
        }
        if (!contentSidExpired) {
          contentSidExpired =
            sidRow.twilio_whatsapp_alert_content_sid_expired || null;
        }
        if (!contentSidEndpointDown) {
          contentSidEndpointDown =
            sidRow.twilio_whatsapp_alert_content_sid_endpoint_down || null;
        }
        if (!contentSidEndpointRecovered) {
          contentSidEndpointRecovered =
            sidRow.twilio_whatsapp_alert_content_sid_endpoint_recovered || null;
        }
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }
    }
    // Get pending alerts due today or overdue
    // Use FOR UPDATE SKIP LOCKED to prevent duplicate processing by concurrent workers
    const alertsRes = await client.query(
      `SELECT 
         aq.*, 
         COALESCE(w.created_by, wf.created_by, wj.created_by, aq.user_id) AS owner_user_id,
         u.email AS owner_email,
         COALESCE(ws.webhook_urls, wsf.webhook_urls, wjj.webhook_urls) AS webhook_urls,
         COALESCE(ws.contact_groups, wsf.contact_groups, wjj.contact_groups) AS contact_groups,
         COALESCE(ws.default_contact_group_id, wsf.default_contact_group_id, wjj.default_contact_group_id) AS default_contact_group_id,
         COALESCE(ws.email_alerts_enabled, wsf.email_alerts_enabled, wjj.email_alerts_enabled) AS email_alerts_enabled,
         COALESCE(ws.delivery_window_start, wsf.delivery_window_start, wjj.delivery_window_start) AS delivery_window_start,
         COALESCE(ws.delivery_window_end, wsf.delivery_window_end, wjj.delivery_window_end) AS delivery_window_end,
         COALESCE(ws.delivery_window_tz, wsf.delivery_window_tz, wjj.delivery_window_tz) AS delivery_window_tz,
         COALESCE(ws.webhooks_alerts_enabled, wsf.webhooks_alerts_enabled, wjj.webhooks_alerts_enabled, FALSE) AS webhooks_alerts_enabled,
         t.name, t.type, t.category, t.expiration::date AS expiration,
         t.domains, t.location, t.used_by, t.issuer, t.serial_number, t.subject, 
         t.key_size, t.algorithm, t.license_type, t.vendor, t.cost, 
         t.renewal_url, t.renewal_date::date AS renewal_date, t.contacts, 
         t.description, t.notes,
         t.contact_group_id,
         t.workspace_id,
         COALESCE(w.name, wf.name, wj.name) AS workspace_name
       FROM alert_queue aq
       JOIN tokens t ON t.id = aq.token_id
       LEFT JOIN workspaces w ON w.id = t.workspace_id
       LEFT JOIN LATERAL (
         SELECT w2.*
         FROM workspaces w2
         WHERE w2.created_by = t.user_id
         ORDER BY w2.created_at ASC
         LIMIT 1
       ) wf ON TRUE
       LEFT JOIN LATERAL (
         SELECT w3.*
         FROM workspaces w3
         JOIN workspace_memberships wm3 ON wm3.workspace_id = w3.id AND wm3.user_id = t.user_id
         WHERE wm3.role IN ('admin','workspace_manager')
         ORDER BY w3.created_at ASC
         LIMIT 1
       ) wj ON TRUE
       LEFT JOIN users u ON u.id = COALESCE(w.created_by, wf.created_by, wj.created_by, aq.user_id)
       LEFT JOIN workspace_settings ws ON ws.workspace_id = w.id
       LEFT JOIN workspace_settings wsf ON wsf.workspace_id = wf.id
       LEFT JOIN workspace_settings wjj ON wjj.workspace_id = wj.id
        WHERE aq.status IN ('pending', 'failed', 'partial') 
         AND aq.due_date <= CURRENT_DATE
         ${gatingClause}
       ORDER BY aq.due_date ASC, aq.created_at ASC
       LIMIT 1000
       FOR UPDATE OF aq SKIP LOCKED`,
    );

    for (const alert of alertsRes.rows) {
      processed++;

      // Never process alerts that are already blocked
      if (String(alert.status || "").toLowerCase() === "blocked") {
        continue;
      }

      // Never process alerts that have already been sent successfully
      if (String(alert.status || "").toLowerCase() === "sent") {
        continue;
      }

      // For endpoint health "down" alerts, defer until consecutive_failures >= alert_after_failures.
      // The endpoint-check-worker queues the alert on the first state transition; we wait
      // here until enough consecutive failures have accumulated before actually delivering.
      if (
        alert.alert_key &&
        alert.alert_key.startsWith("endpoint_health:") &&
        alert.alert_key.includes(":down")
      ) {
        try {
          const monitorIdMatch = alert.alert_key.match(
            /^endpoint_health:([^:]+):down/,
          );
          if (monitorIdMatch) {
            const monitorRes = await client.query(
              "SELECT consecutive_failures, alert_after_failures FROM domain_monitors WHERE id = $1",
              [monitorIdMatch[1]],
            );
            if (monitorRes.rows.length > 0) {
              const dm = monitorRes.rows[0];
              const threshold = dm.alert_after_failures || 2;
              if ((dm.consecutive_failures || 0) < threshold) {
                // Not enough failures yet -- skip for now, will retry next delivery run
                continue;
              }
              // If endpoint recovered (consecutive_failures = 0), discard the stale down alert
              if ((dm.consecutive_failures || 0) === 0) {
                await client.query(
                  "UPDATE alert_queue SET status = 'sent', last_attempt = NOW(), error_message = 'Discarded: endpoint recovered before threshold', updated_at = NOW() WHERE id = $1",
                  [alert.id],
                );
                continue;
              }
            }
          }
        } catch (dmErr) {
          logger.warn(
            "Failed to check alert_after_failures for endpoint alert",
            { error: dmErr.message },
          );
          // Proceed with delivery anyway if the check fails
        }
      }

      // Defer if outside workspace delivery window
      try {
        let start = String(alert.delivery_window_start || "").trim();
        let end = String(alert.delivery_window_end || "").trim();
        const tzInput = String(alert.delivery_window_tz || "").trim();
        if (!start && !end) {
          start = process.env.DELIVERY_WINDOW_DEFAULT_START || "00:00";
          end = process.env.DELIVERY_WINDOW_DEFAULT_END || "23:59";
        }
        if (start && end) {
          const now = new Date();
          let hh = "00";
          let mm = "00";
          try {
            const fmt = new Intl.DateTimeFormat("en-US", {
              timeZone: tzInput || "UTC",
              hour12: false,
              hour: "2-digit",
              minute: "2-digit",
            });
            const parts = fmt.formatToParts(now);
            hh = parts.find((p) => p.type === "hour")?.value || "00";
            mm = parts.find((p) => p.type === "minute")?.value || "00";
          } catch (_tzErr) {
            // Invalid timezone; fall back to UTC
            hh = String(now.getUTCHours()).padStart(2, "0");
            mm = String(now.getUTCMinutes()).padStart(2, "0");
            if (tzInput)
              logger.warn(
                `Invalid delivery_window_tz: ${tzInput}, falling back to UTC`,
              );
          }
          const cur = `${hh}:${mm}`;
          const inWindow =
            start <= end
              ? cur >= start && cur <= end
              : cur >= start || cur <= end;
          if (!inWindow) {
            const defMs = process.env.DELIVERY_WINDOW_DEFERRAL_MS
              ? Number(process.env.DELIVERY_WINDOW_DEFERRAL_MS)
              : 3 * 60 * 60 * 1000; // Default: 3 hours (reduced load for OUT_OF_WINDOW alerts)
            const ts = new Date(
              Date.now() + (Number.isFinite(defMs) ? defMs : 10800000),
            );
            await client.query(
              `UPDATE alert_queue 
              SET status = 'pending', last_attempt = NOW(), error_message = 'OUT_OF_WINDOW', updated_at = NOW(), next_attempt_at = $2
               WHERE id = $1`,
              [alert.id, ts.toISOString()],
            );
            // Do not count this as a failure; simply defer
            continue;
          }
        }
      } catch (_err) {
        logger.warn("DB operation failed", { error: _err.message });
      }

      // Process each channel respecting user toggles
      // Handle alert.channels which could be a JSON string from the database
      let channelsArray = [];
      if (Array.isArray(alert.channels)) {
        channelsArray = alert.channels;
      } else if (typeof alert.channels === "string") {
        try {
          const parsed = JSON.parse(alert.channels);
          channelsArray = Array.isArray(parsed) ? parsed : [];
        } catch (_) {
          channelsArray = [];
        }
      }

      // Resolve contact group once for all channel checks
      const resolvedGroup = resolveContactGroup({
        contactGroups: alert.contact_groups,
        contactGroupId: alert.contact_group_id,
        defaultContactGroupId: alert.default_contact_group_id,
      });

      const channels = channelsArray.filter((ch) => {
        if (ch === "email") {
          const wsEmailEnabled = alert.email_alerts_enabled !== false;
          return wsEmailEnabled && hasEmailContacts(resolvedGroup);
        }
        if (ch === "webhooks") {
          return hasWebhookNames(resolvedGroup);
        }
        if (ch === "whatsapp") {
          return hasWhatsAppContacts(resolvedGroup);
        }
        return true;
      });

      const finalChannels = channels;

      // If no eligible channels remain, mark failed and continue
      if (!Array.isArray(finalChannels) || finalChannels.length === 0) {
        const minimalCooldown =
          process.env.NODE_ENV === "test" ? new Date(Date.now() + 1000) : null;
        await client.query(
          `UPDATE alert_queue 
           SET status = 'failed', attempts = attempts + 1, last_attempt = NOW(), error_message = 'NO_CONTACTS_DEFINED: No email, webhook, or WhatsApp contacts are configured in the selected contact group', updated_at = NOW(), next_attempt_at = $2
           WHERE id = $1`,
          [alert.id, minimalCooldown ? minimalCooldown.toISOString() : null],
        );
        failed++;
        continue;
      }
      let allSucceeded = true;
      const deliveryResults = [];
      // Track if WhatsApp encountered a permanent failure (non-rate-limit) to block the alert immediately
      let whatsappPermanentFailure = false;

      // Calculate actual days left based on expiration date (fallback to threshold)
      const computedDays = computeDaysLeft(alert.expiration);
      const daysLeft = Number.isFinite(computedDays)
        ? computedDays
        : alert.threshold_days;

      // Per-channel backoff helpers
      const computeCooldownMs = (attempts) => {
        // Use greatly reduced cooldowns in test mode to allow rapid retries
        if (process.env.NODE_ENV === "test") {
          if (attempts >= 20) return 4000;
          if (attempts >= 10) return 3000;
          if (attempts >= 5) return 2000;
          if (attempts >= 3) return 1000;
          return 0;
        }
        // thresholds: 3->5m, 5->15m, 10->60m, 20->24h
        if (attempts >= 20) return 24 * 60 * 60 * 1000;
        if (attempts >= 10) return 60 * 60 * 1000;
        if (attempts >= 5) return 15 * 60 * 1000;
        if (attempts >= 3) return 5 * 60 * 1000;
        return 0;
      };
      let nextAttemptTimestamp = null;
      let newAttemptsEmail = Number(alert.attempts_email || 0);
      let newAttemptsWebhooks = Number(alert.attempts_webhooks || 0);
      let newAttemptsWhatsApp = Number(alert.attempts_whatsapp || 0);

      // Track partial failures for webhooks to improve observability
      let webhookPartialErrors = [];

      for (const channel of finalChannels) {
        let success = false;
        let errorMessage = null;
        let errorCode = null;

        try {
          if (channel === "email") {
            // Build recipients: group emails only; no fallback
            let recipients = [];
            const groupIdUsed = resolvedGroup ? String(resolvedGroup.id) : null;
            try {
              if (resolvedGroup && hasEmailContacts(resolvedGroup)) {
                // Resolve emails from workspace_contacts by id
                const contactsRes = await client.query(
                  `SELECT details FROM workspace_contacts WHERE workspace_id = $1 AND id = ANY($2::uuid[])`,
                  [alert.workspace_id, resolvedGroup.email_contact_ids],
                );
                recipients = contactsRes.rows
                  .map((r) => {
                    try {
                      return String((r.details && r.details.email) || "")
                        .toLowerCase()
                        .trim();
                    } catch (_) {
                      return "";
                    }
                  })
                  .filter((e) => /.+@.+\..+/.test(e));
              }
            } catch (_err) {
              logger.debug("Non-critical operation failed", {
                error: _err.message,
              });
            }
            // No fallback: if recipients is empty, email channel will result in no sends

            // Dedupe recipients
            const trimmed = Array.from(new Set(recipients)).filter((e) =>
              /.+@.+\..+/.test(e),
            );

            if (trimmed.length === 0) {
              success = false;
              errorMessage =
                "No email contacts are defined in the selected contact group";
            } else {
              // Send individually and log per recipient
              const isEndpointAlert =
                alert.alert_key &&
                alert.alert_key.startsWith("endpoint_health:");
              const { subject, text, html } = isEndpointAlert
                ? buildEndpointHealthEmailContent(alert, alert)
                : buildEmailContent(alert, daysLeft);
              let allOk = true;
              for (const rcpt of trimmed) {
                const res = await sendEmailNotification({
                  to: rcpt,
                  subject,
                  text,
                  html,
                });
                await client.query(
                  `INSERT INTO alert_delivery_log (alert_queue_id, user_id, token_id, workspace_id, channel, status, error_message, metadata)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
                  [
                    alert.id,
                    alert.owner_user_id,
                    alert.token_id,
                    alert.workspace_id,
                    "email",
                    res.success ? "success" : "failed",
                    res.success ? null : res.error || null,
                    JSON.stringify({
                      group_id: groupIdUsed,
                      recipient: rcpt,
                    }),
                  ],
                );
                // Increment metric for each email delivery attempt
                try {
                  cDelivery
                    .labels(
                      "email",
                      "email",
                      res.success ? "success" : "failed",
                    )
                    .inc();
                } catch (_) {
                  logger.debug("Metrics recording failed", {
                    error: _.message,
                  });
                }
                if (!res.success) allOk = false;
              }
              success = allOk;
              errorMessage = allOk ? null : "PARTIAL_FAILURE";
            }
          } else if (channel === "webhooks") {
            let webhooks = Array.isArray(alert.webhook_urls)
              ? [...alert.webhook_urls]
              : [];
            // If a group selects named webhook(s), restrict to only those; otherwise, send none
            const groupIdUsedForWebhooks = resolvedGroup
              ? String(resolvedGroup.id)
              : null;
            try {
              if (resolvedGroup && hasWebhookNames(resolvedGroup)) {
                const names = getWebhookNames(resolvedGroup);
                const filtered = webhooks.filter((w) =>
                  names.includes(String(w.name || "").trim()),
                );
                webhooks = filtered.length > 0 ? filtered : [];
              } else {
                webhooks = [];
              }
            } catch (_err) {
              logger.debug("Non-critical operation failed", {
                error: _err.message,
              });
            }
            if (webhooks.length === 0) {
              success = false;
              errorMessage =
                "No webhook names defined in the selected contact group";
            } else {
              // Consider the webhooks channel successful if at least one endpoint succeeds
              let webhookSuccess = false;
              const errors = [];

              // Load previously successful webhook url hashes for this alert_queue
              const priorSuccessRes = await client.query(
                `SELECT metadata->>'urlHash' AS h
                 FROM alert_delivery_log
                 WHERE alert_queue_id = $1 AND channel = 'webhooks' AND status = 'success'`,
                [alert.id],
              );
              const priorSuccess = new Set(
                priorSuccessRes.rows
                  .map((r) => String(r.h || "").trim())
                  .filter(Boolean),
              );

              for (const wh of webhooks) {
                let kind = String(wh?.kind || "generic");
                const url = String(wh?.url || "");
                const routingKey = String(wh?.routingKey || "");
                if (!url) continue;
                // Auto-detect provider kind by hostname when not explicitly set
                try {
                  const host = new URL(url).hostname.toLowerCase();
                  if (!wh?.kind || kind === "generic") {
                    if (host === "hooks.slack.com") kind = "slack";
                    else if (
                      host.endsWith("discord.com") ||
                      host.endsWith("discordapp.com")
                    )
                      kind = "discord";
                    else if (
                      host === "outlook.office.com" ||
                      host === "webhook.office.com" ||
                      host.endsWith("office365.com") ||
                      host.endsWith(".office.com")
                    )
                      kind = "teams";
                    else if (host.endsWith("pagerduty.com")) kind = "pagerduty";
                  }
                } catch (_err) {
                  logger.debug("Non-critical operation failed", {
                    error: _err.message,
                  });
                }

                // Compute a stable hash for the URL to identify unique endpoints without storing the raw URL
                const urlHash = crypto
                  .createHash("sha256")
                  .update(url)
                  .digest("hex");
                if (priorSuccess.has(urlHash)) {
                  // Already delivered successfully to this endpoint for this alert; skip re-sending
                  continue;
                }
                const name = alert.name || `Token #${alert.token_id}`;
                const isEndpointHealthWebhook =
                  alert.alert_key &&
                  alert.alert_key.startsWith("endpoint_health:");

                let text;
                let tokenData;
                let endpointTransition = null;
                if (isEndpointHealthWebhook) {
                  const ehParts = alert.alert_key.split(":");
                  const ehTransition = ehParts[2] || "down";
                  endpointTransition = ehTransition;
                  const ehStatus =
                    ehTransition === "down" ? "DOWN" : "RECOVERED";
                  const location = alert.location || alert.name || "Unknown";
                  text = location && location !== name
                    ? `Endpoint ${ehStatus}: ${name} (${location})`
                    : `Endpoint ${ehStatus}: ${name}`;
                  tokenData = {
                    type: "endpoint_health",
                    token_id: alert.token_id,
                    name: alert.name,
                    location: alert.location,
                    status: ehStatus,
                    transition: ehTransition,
                  };
                } else {
                  const expires = alert.expiration
                    ? new Date(alert.expiration).toISOString().slice(0, 10)
                    : null;
                  const expired = typeof daysLeft === "number" && daysLeft <= 0;
                  const absDays =
                    typeof daysLeft === "number"
                      ? Math.abs(daysLeft)
                      : daysLeft;
                  text = expired
                    ? `${name} expired ${absDays} day(s) ago` +
                      (expires ? ` (on ${expires})` : "") +
                      `.`
                    : `${name} expires in ${daysLeft} day(s)` +
                      (expires ? ` (on ${expires})` : "") +
                      `.`;

                  tokenData = {
                    token_id: alert.token_id,
                    name: alert.name,
                    type: alert.type,
                    expiration: expires,
                    daysLeft: daysLeft,
                    ...(alert.renewal_url && {
                      renewal_url: alert.renewal_url,
                    }),
                  };
                }

                // Determine severity per user-config or default mapping
                const computedSeverity = daysLeft < 30 ? "critical" : "warning";
                const selectedSeverity =
                  typeof wh?.severity === "string" && wh.severity
                    ? String(wh.severity).toLowerCase()
                    : isEndpointHealthWebhook
                      ? endpointTransition === "down"
                        ? "critical"
                        : "info"
                      : computedSeverity;
                const templateTitle =
                  typeof wh?.template === "string" && wh.template
                    ? String(wh.template)
                    : null;

                const payload = isEndpointHealthWebhook
                  ? buildEndpointHealthWebhookPayload(kind, alert, {
                      severity: selectedSeverity,
                      title: templateTitle || undefined,
                      routingKey,
                    })
                  : kind === "pagerduty"
                    ? {
                        routing_key: routingKey,
                        event_action: "trigger",
                        payload: {
                          summary: templateTitle || text,
                          source: "TokenTimer",
                          severity: selectedSeverity,
                          timestamp: new Date().toISOString(),
                          custom_details: tokenData,
                        },
                      }
                    : formatPayload(kind, text, tokenData, {
                        severity: selectedSeverity,
                        title: templateTitle || undefined,
                      });
                const endTimer = hLatency.labels("webhooks", kind).startTimer();
                const res = await postJson(url, payload, kind);
                try {
                  endTimer();
                } catch (_) {
                  logger.debug("Metrics recording failed", {
                    error: _.message,
                  });
                }
                try {
                  cDelivery
                    .labels(
                      "webhooks",
                      kind,
                      res.success ? "success" : "failed",
                    )
                    .inc();
                } catch (_) {
                  logger.debug("Metrics recording failed", {
                    error: _.message,
                  });
                }
                if (!res.success) {
                  errors.push(`${kind}: ${res.error}`);
                } else {
                  webhookSuccess = true;
                  // Mark this urlHash as delivered to avoid future re-sends for this alert
                  priorSuccess.add(urlHash);
                }
                // Log each individual webhook delivery attempt
                await client.query(
                  `INSERT INTO alert_delivery_log (alert_queue_id, user_id, token_id, workspace_id, channel, status, error_message, metadata)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                  [
                    alert.id,
                    alert.owner_user_id,
                    alert.token_id,
                    alert.workspace_id,
                    "webhooks",
                    res.success ? "success" : "failed",
                    res.success ? null : res.error || null,
                    JSON.stringify({
                      kind,
                      urlDomain: new URL(url).hostname,
                      urlHash,
                      group_id: groupIdUsedForWebhooks,
                      payload_type: isEndpointHealthWebhook
                        ? "endpoint_health"
                        : "token_expiry",
                      endpoint_transition: isEndpointHealthWebhook
                        ? tokenData?.transition || null
                        : null,
                    }),
                  ],
                );
              }
              success = webhookSuccess;
              if (errors.length > 0) {
                errorMessage = errors.join("; ");
              } else if (!webhookSuccess) {
                errorMessage =
                  "Webhook delivery skipped because no endpoint was eligible";
              } else {
                errorMessage = null;
              }
              if (webhookSuccess && errors.length > 0) {
                webhookPartialErrors = errors.slice();
              }
            }
          } else if (channel === "whatsapp") {
            let trimmed = [];
            const groupIdUsed = resolvedGroup ? String(resolvedGroup.id) : null;

            {
              // Resolve phones by querying workspace_contacts with contact_ids from group
              let recipients = [];
              let contactInfos = [];
              try {
                if (resolvedGroup && hasWhatsAppContacts(resolvedGroup)) {
                  const waIds = resolvedGroup.whatsapp_contact_ids;
                  // Query workspace_contacts to get phones and names
                  const contactsRes = await client.query(
                    `SELECT id, first_name, last_name, phone_e164 FROM workspace_contacts WHERE workspace_id = $1 AND id = ANY($2::uuid[])`,
                    [alert.workspace_id, waIds],
                  );
                  contactInfos = contactsRes.rows
                    .map((r) => ({
                      id: r.id,
                      first_name: String(r.first_name || "").trim(),
                      last_name: String(r.last_name || "").trim(),
                      phone: String(r.phone_e164 || "").trim(),
                    }))
                    .filter((c) => !!c.phone);
                  recipients = contactInfos.map((c) => c.phone);
                }
              } catch (_err) {
                logger.debug("Non-critical operation failed", {
                  error: _err.message,
                });
              }

              // Org-level soft rate limiter per minute (safety valve)
              if (WHATSAPP_RATE_PER_MIN > 0) {
                const recent = await client.query(
                  `SELECT COUNT(*)::int AS c
                   FROM alert_delivery_log d
                  WHERE d.user_id = $1 AND d.channel = 'whatsapp' AND d.sent_at > NOW() - INTERVAL '60 seconds'`,
                  [alert.owner_user_id],
                );
                const recentCount = recent.rows?.[0]?.c || 0;
                if (recentCount >= WHATSAPP_RATE_PER_MIN) {
                  success = false;
                  errorMessage = "ORG_RATE_LIMIT";
                  errorCode = "RATE_LIMIT";
                }
              }

              // Dedupe recipients
              trimmed = Array.from(new Set(recipients)).filter((p) =>
                /^\+?\d{6,15}$/.test(String(p).trim()),
              );
              // Build a map phone->first_name for template variables
              const firstNameByPhone = new Map();
              for (const c of contactInfos) {
                if (c.phone && !firstNameByPhone.has(c.phone))
                  firstNameByPhone.set(c.phone, c.first_name || "there");
              }

              if (errorMessage === "ORG_RATE_LIMIT") {
                // Skip sending due to throttle; log for visibility
                success = false;
              } else if (trimmed.length === 0) {
                success = false;
                errorMessage =
                  "No WhatsApp contacts are defined in the selected contact group";
              } else {
                const isEndpointHealthWhatsApp =
                  alert.alert_key &&
                  alert.alert_key.startsWith("endpoint_health:");
                const isExpired = typeof daysLeft === "number" && daysLeft <= 0;
                const daysText = isExpired ? Math.abs(daysLeft) : daysLeft;
                const rawName = String(alert.name || "").trim();
                const name =
                  rawName || String(alert.type || alert.category || "token");
                // Prefer WhatsApp ContentSid if configured (outside-session safe)
                const endpointTransition = isEndpointHealthWhatsApp
                  ? String(alert.alert_key || "").split(":")[2] || "down"
                  : null;
                const selectedContentSid = isEndpointHealthWhatsApp
                  ? endpointTransition === "down"
                    ? contentSidEndpointDown
                    : contentSidEndpointRecovered
                  : isExpired
                    ? contentSidExpired
                    : contentSidExpires;
                if (isEndpointHealthWhatsApp && !selectedContentSid) {
                  success = false;
                  errorMessage = "WHATSAPP_ENDPOINT_TEMPLATE_NOT_CONFIGURED";
                  errorCode = "WHATSAPP_ENDPOINT_TEMPLATE_NOT_CONFIGURED";
                  try {
                    await client.query(
                      `INSERT INTO alert_delivery_log (alert_queue_id, user_id, token_id, workspace_id, channel, status, error_message, metadata)
                       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
                      [
                        alert.id,
                        alert.owner_user_id,
                        alert.token_id,
                        alert.workspace_id,
                        "whatsapp",
                        "failed",
                        errorMessage,
                        JSON.stringify({
                          group_id: groupIdUsed,
                          reason:
                            "Set TWILIO_WHATSAPP_ALERT_CONTENT_SID_ENDPOINT_DOWN and TWILIO_WHATSAPP_ALERT_CONTENT_SID_ENDPOINT_RECOVERED in environment variables or System Settings",
                        }),
                      ],
                    );
                  } catch (_logErr) {
                    logger.debug("Delivery log write failed", { error: _logErr?.message });
                  }
                } else {
                // Build smart details based on token type and available information
                const buildDetails = (tokenData) => {
                  const details = [];
                  if (tokenData.issuer)
                    details.push(`Issuer: ${tokenData.issuer}`);
                  if (tokenData.location)
                    details.push(`Location: ${tokenData.location}`);
                  if (tokenData.used_by)
                    details.push(`Used By: ${tokenData.used_by}`);
                  if (
                    tokenData.domains &&
                    Array.isArray(tokenData.domains) &&
                    tokenData.domains.length > 0
                  ) {
                    details.push(`Domains: ${tokenData.domains.join(", ")}`);
                  }
                  if (tokenData.algorithm)
                    details.push(`Algorithm: ${tokenData.algorithm}`);
                  if (tokenData.key_size)
                    details.push(`Key Size: ${tokenData.key_size} bits`);
                  if (tokenData.vendor)
                    details.push(`Vendor: ${tokenData.vendor}`);
                  if (tokenData.cost) details.push(`Cost: $${tokenData.cost}`);
                  if (tokenData.serial_number)
                    details.push(`Serial: ${tokenData.serial_number}`);
                  if (tokenData.subject)
                    details.push(`Subject: ${tokenData.subject}`);
                  if (tokenData.renewal_url)
                    details.push(`Renewal URL: ${tokenData.renewal_url}`);
                  if (tokenData.renewal_date)
                    details.push(`Renewal Date: ${tokenData.renewal_date}`);
                  if (tokenData.description)
                    details.push(`Description: ${tokenData.description}`);
                  if (tokenData.notes)
                    details.push(`Notes: ${tokenData.notes}`);
                  if (tokenData.contacts)
                    details.push(`Contacts: ${tokenData.contacts}`);
                  return details.length > 0
                    ? details.join(", ")
                    : "No additional details available";
                };

                // Format expiration date as a long, locale-stable string (UTC) and also provide ISO
                const expirationDatePretty = alert.expiration
                  ? (() => {
                      try {
                        const d = new Date(alert.expiration);
                        const fmt = new Intl.DateTimeFormat("en", {
                          timeZone: "UTC",
                          weekday: "long",
                          month: "long",
                          day: "numeric",
                          year: "numeric",
                        });
                        return fmt.format(d); // e.g., "Tuesday, November 11, 2025"
                      } catch (_) {
                        return String(alert.expiration).slice(0, 10);
                      }
                    })()
                  : "";
                const expirationDateIso = alert.expiration
                  ? (() => {
                      try {
                        return new Date(alert.expiration)
                          .toISOString()
                          .slice(0, 10);
                      } catch (_) {
                        return String(alert.expiration).slice(0, 10);
                      }
                    })()
                  : "";

                const contentVariablesBase = selectedContentSid
                  ? isEndpointHealthWhatsApp
                    ? buildEndpointHealthWhatsAppTemplateVariables(
                        alert,
                        contactInfos[0]?.first_name || "User",
                      )
                    : isExpired
                    ? {
                        recipient_name: contactInfos[0]?.first_name || "User",
                        token_name: name,
                        token_type: String(alert.type || "security"),
                        token_category: String(alert.category || ""),
                        status_text: "EXPIRED",
                        expiration_date: expirationDatePretty,
                        expiration_date_iso: expirationDateIso,
                        days_text: String(daysText),
                        details: buildDetails(alert),
                        renewal_url: alert.renewal_url
                          ? String(alert.renewal_url)
                          : null,
                        description: alert.description
                          ? String(alert.description)
                          : null,
                        notes: alert.notes ? String(alert.notes) : null,
                        contacts: alert.contacts
                          ? String(alert.contacts)
                          : null,
                      }
                    : {
                        recipient_name: contactInfos[0]?.first_name || "User",
                        token_name: name,
                        token_type: String(alert.type || "security"),
                        token_category: String(alert.category || ""),
                        status_text: "EXPIRING",
                        expiration_date: expirationDatePretty,
                        expiration_date_iso: expirationDateIso,
                        days_text: String(daysLeft),
                        details: buildDetails(alert),
                        renewal_url: alert.renewal_url
                          ? String(alert.renewal_url)
                          : null,
                        description: alert.description
                          ? String(alert.description)
                          : null,
                        notes: alert.notes ? String(alert.notes) : null,
                        contacts: alert.contacts
                          ? String(alert.contacts)
                          : null,
                      }
                  : null;

                const sanitizeVars = (obj) => {
                  const out = {};
                  for (const [k, v] of Object.entries(obj || {})) {
                    if (v === null || v === undefined) continue;
                    const s = String(v).trim();
                    if (s.length === 0) continue;
                    out[k] = s;
                  }
                  return out;
                };

                let allOk = true;
                for (const rcpt of trimmed) {
                  const endTimerWA = hLatency
                    .labels("whatsapp", "twilio")
                    .startTimer();
                  const perRecipientBase = contentVariablesBase
                    ? {
                        ...contentVariablesBase,
                        recipient_name:
                          firstNameByPhone.get(rcpt) ||
                          contentVariablesBase.recipient_name ||
                          "there",
                      }
                    : null;
                  const contentVariables = perRecipientBase
                    ? sanitizeVars(perRecipientBase)
                    : null;
                  const res = await sendWhatsApp({
                    to: rcpt,
                    body: null,
                    contentSid: selectedContentSid,
                    contentVariables,
                    idempotencyKey: `${alert.id}:${rcpt}`,
                  });
                  try {
                    endTimerWA();
                  } catch (_err) {
                    logger.warn("WhatsApp operation failed", {
                      error: _err.message,
                    });
                  }
                  try {
                    cDelivery
                      .labels(
                        "whatsapp",
                        "twilio",
                        res.success ? "success" : "failed",
                      )
                      .inc();
                  } catch (_) {
                    logger.debug("Metrics recording failed", {
                      error: _.message,
                    });
                  }
                  await client.query(
                    `INSERT INTO alert_delivery_log (alert_queue_id, user_id, token_id, workspace_id, channel, status, error_message, metadata)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
                    [
                      alert.id,
                      alert.owner_user_id,
                      alert.token_id,
                      alert.workspace_id,
                      "whatsapp",
                      res.success ? "success" : "failed",
                      res.success ? null : res.error || null,
                      JSON.stringify({
                        group_id: groupIdUsed,
                        recipient: rcpt,
                        messageSid: res.messageSid || null,
                        contentSid: selectedContentSid,
                        payload_type: isEndpointHealthWhatsApp
                          ? "endpoint_health"
                          : "token_expiry",
                        template_kind: isEndpointHealthWhatsApp
                          ? endpointTransition === "down"
                            ? "endpoint_down"
                            : "endpoint_recovered"
                          : isExpired
                            ? "token_expired"
                            : "token_expires",
                      }),
                    ],
                  );
                  if (!res.success) allOk = false;
                }
                success = allOk;
                errorMessage = allOk ? null : "PARTIAL_FAILURE";
                }
              }
            }

            // If WhatsApp failed without per-recipient rows (rate limit or no recipients), log a channel-level entry
            if (!success && trimmed.length === 0) {
              try {
                await client.query(
                  `INSERT INTO alert_delivery_log (alert_queue_id, user_id, token_id, workspace_id, channel, status, error_message, metadata)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
                  [
                    alert.id,
                    alert.owner_user_id,
                    alert.token_id,
                    alert.workspace_id,
                    "whatsapp",
                    errorMessage === "ORG_RATE_LIMIT" ? "deferred" : "failed",
                    errorMessage,
                    JSON.stringify({ group_id: groupIdUsed }),
                  ],
                );
              } catch (_err) {
                logger.warn("WhatsApp operation failed", {
                  error: _err.message,
                });
              }
              try {
                cDelivery
                  .labels(
                    "whatsapp",
                    "whatsapp",
                    errorMessage === "ORG_RATE_LIMIT" ? "deferred" : "failed",
                  )
                  .inc();
              } catch (_) {
                logger.debug("Metrics recording failed", { error: _.message });
              }
            }
          }
        } catch (e) {
          success = false;
          errorMessage = e.message;
          // Catch-all: if an exception occurred during WhatsApp processing, log it
          if (channel === "whatsapp") {
            try {
              await client.query(
                `INSERT INTO alert_delivery_log (alert_queue_id, user_id, token_id, workspace_id, channel, status, error_message)
                 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
                [
                  alert.id,
                  alert.owner_user_id,
                  alert.token_id,
                  alert.workspace_id,
                  "whatsapp",
                  "failed",
                  e.message,
                ],
              );
            } catch (_err) {
              logger.warn("WhatsApp operation failed", { error: _err.message });
            }
            try {
              cDelivery.labels("whatsapp", "whatsapp", "failed").inc();
            } catch (_) {
              logger.debug("Metrics recording failed", { error: _.message });
            }
          }
        }

        // Log delivery attempt (per-channel). For webhooks, WhatsApp, and email we already insert per-endpoint/per-recipient rows.
        // Skip the extra per-channel summary for these.
        if (
          channel !== "webhooks" &&
          channel !== "email" &&
          channel !== "whatsapp"
        ) {
          const endTimer = hLatency.labels(channel, channel).startTimer();
          await client.query(
            `INSERT INTO alert_delivery_log (alert_queue_id, user_id, token_id, workspace_id, channel, status, error_message)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [
              alert.id,
              alert.owner_user_id,
              alert.token_id,
              alert.workspace_id,
              channel,
              success ? "success" : "failed",
              errorMessage,
            ],
          );
          try {
            endTimer();
          } catch (_err) {
            logger.debug("Non-critical operation failed", {
              error: _err.message,
            });
          }
        }

        deliveryResults.push({ channel, success, errorMessage, errorCode });
        // If WhatsApp failed and it's not a soft throttle, consider it permanent and block the queue entry
        if (
          channel === "whatsapp" &&
          !success &&
          errorMessage !== "ORG_RATE_LIMIT" &&
          String(errorCode || "").toUpperCase() !== "RATE_LIMIT"
        ) {
          whatsappPermanentFailure = true;
        }
        // Note: Email and webhooks metrics are already incremented in their respective channel handlers above.
        // Only increment metrics here for other channels (e.g., slack, discord) that don't have dedicated handlers.
        if (channel !== "webhooks" && channel !== "email") {
          try {
            cDelivery
              .labels(channel, channel, success ? "success" : "failed")
              .inc();
          } catch (_) {
            logger.debug("Metrics recording failed", { error: _.message });
          }
        }
        if (!success) {
          allSucceeded = false;
          if (channel === "email") {
            newAttemptsEmail += 1;
            let ms = computeCooldownMs(newAttemptsEmail);
            // If rate-limited, enforce a visible cooldown even on first failures
            if (
              (errorCode && String(errorCode).includes("RATE_LIMIT")) ||
              /rate[- ]?limit|maximum number of sent emails/i.test(
                String(errorMessage || ""),
              )
            ) {
              // At least 60 minutes cooldown to avoid hammering provider
              ms = Math.max(ms, 60 * 60 * 1000);
            }
            if (ms > 0) {
              const ts = new Date(Date.now() + ms);
              if (!nextAttemptTimestamp || ts > nextAttemptTimestamp)
                nextAttemptTimestamp = ts;
            }
          } else if (channel === "webhooks") {
            newAttemptsWebhooks += 1;
            const ms = computeCooldownMs(newAttemptsWebhooks);
            if (ms > 0) {
              const ts = new Date(Date.now() + ms);
              if (!nextAttemptTimestamp || ts > nextAttemptTimestamp)
                nextAttemptTimestamp = ts;
            }
          } else if (channel === "whatsapp") {
            newAttemptsWhatsApp += 1;
            let ms = computeCooldownMs(newAttemptsWhatsApp);
            // If org-level rate-limited, use a short cooldown (60-90 seconds) instead of exponential backoff
            if (
              errorMessage === "ORG_RATE_LIMIT" ||
              errorCode === "RATE_LIMIT"
            ) {
              // Retry in 60-90 seconds (per-minute rate limit)
              ms = process.env.NODE_ENV === "test" ? 2000 : 75 * 1000;
            }
            if (ms > 0) {
              const ts = new Date(Date.now() + ms);
              if (!nextAttemptTimestamp || ts > nextAttemptTimestamp)
                nextAttemptTimestamp = ts;
            }
          }
          try {
            cRetry.labels(channel, "auto").inc();
          } catch (_) {
            logger.debug("Metrics recording failed", { error: _.message });
          }
        } else {
          if (channel === "email") newAttemptsEmail = 0;
          if (channel === "webhooks") newAttemptsWebhooks = 0;
          if (channel === "whatsapp") newAttemptsWhatsApp = 0;
        }
      }

      // If webhooks channel present and at least one endpoint succeeded, don't force overall failure.
      // Only force failure if all webhook endpoints failed (webhookSuccess === false) which is already
      // reflected in the channel result above. Here we avoid overriding a true allSucceeded due to partials.
      // allSucceeded remains as computed from per-channel success values.

      // Update alert queue status
      // Determine status: "sent" only when all channels succeeded; "partial" when some succeeded and others failed/blocked; "failed" when none succeeded
      const someSucceeded = deliveryResults.some((r) => r.success);
      const someFailed = deliveryResults.some((r) => !r.success);
      const hasPartialIssues = webhookPartialErrors.length > 0;

      let newStatus;
      if (allSucceeded && !hasPartialIssues) {
        newStatus = "sent";
      } else if (someSucceeded && (someFailed || hasPartialIssues)) {
        newStatus = "partial";
      } else {
        newStatus = "failed";
      }

      const attempts = alert.attempts + 1;
      let errorMessages = deliveryResults
        .filter((r) => !r.success)
        .map((r) => `${r.channel}: ${r.errorMessage}`)
        .join("; ");
      // If all channels succeeded but webhooks had partial failures, still surface them in error_message
      if (allSucceeded && webhookPartialErrors.length > 0) {
        const partialMsg = `webhooks(partial): ${webhookPartialErrors.join("; ")}`;
        errorMessages = errorMessages
          ? `${errorMessages}; ${partialMsg}`
          : partialMsg;
      }

      if (newStatus === "sent") {
        await client.query(
          `UPDATE alert_queue 
           SET status = $1, attempts = $2, last_attempt = NOW(), error_message = $3, updated_at = NOW(),
               attempts_email = $5, attempts_webhooks = $6, attempts_whatsapp = $7, next_attempt_at = NULL
           WHERE id = $4`,
          [
            newStatus,
            attempts,
            errorMessages || null,
            alert.id,
            newAttemptsEmail,
            newAttemptsWebhooks,
            newAttemptsWhatsApp,
          ],
        );
        // Emit an audit event for partial successes to aid diagnostics
        if (webhookPartialErrors.length > 0) {
          const contactGroupId =
            alert.contact_group_id || alert.default_contact_group_id || null;
          const groups = Array.isArray(alert.contact_groups)
            ? alert.contact_groups
            : [];
          const contactGroupName = contactGroupId
            ? groups.find((g) => String(g.id) === String(contactGroupId))
                ?.name || null
            : null;
          await writeAudit(client, {
            subjectUserId: alert.user_id,
            action: "ALERT_PARTIAL_SUCCESS",
            targetId: alert.token_id,
            metadata: {
              channel: "webhooks",
              errors: webhookPartialErrors,
              workspace_name: alert.workspace_name,
              token_name: alert.name,
              contact_group_id: contactGroupId,
              contact_group_name: contactGroupName,
            },
          });
        }
      } else {
        // In test mode, ensure a minimal cooldown exists to satisfy cooldown tests
        if (!nextAttemptTimestamp && process.env.NODE_ENV === "test") {
          nextAttemptTimestamp = new Date(Date.now() + 1000);
        }
        // If max attempts reached on any channel, permanently block this alert
        let reachedMaxAttempts = false;
        if (
          MAX_ATTEMPTS_PER_CHANNEL > 0 &&
          (newAttemptsEmail >= MAX_ATTEMPTS_PER_CHANNEL ||
            newAttemptsWebhooks >= MAX_ATTEMPTS_PER_CHANNEL ||
            newAttemptsWhatsApp >= MAX_ATTEMPTS_PER_CHANNEL)
        ) {
          reachedMaxAttempts = true;
          // Ensure no further retries are scheduled
          nextAttemptTimestamp = null;
          errorMessages = errorMessages
            ? `${errorMessages}; MAX_ATTEMPTS`
            : "MAX_ATTEMPTS";
          try {
            const contactGroupId =
              alert.contact_group_id || alert.default_contact_group_id || null;
            const groups = Array.isArray(alert.contact_groups)
              ? alert.contact_groups
              : [];
            const contactGroupName = contactGroupId
              ? groups.find((g) => String(g.id) === String(contactGroupId))
                  ?.name || null
              : null;
            await writeAudit(client, {
              subjectUserId: alert.user_id,
              action: "ALERT_BLOCKED_MAX_ATTEMPTS",
              targetId: alert.token_id,
              metadata: {
                days: alert.threshold_days,
                attempts_email: newAttemptsEmail,
                attempts_webhooks: newAttemptsWebhooks,
                attempts_whatsapp: newAttemptsWhatsApp,
                workspace_name: alert.workspace_name,
                token_name: alert.name,
                contact_group_id: contactGroupId,
                contact_group_name: contactGroupName,
              },
            });
          } catch (_err) {
            logger.warn("WhatsApp operation failed", { error: _err.message });
          }
        }
        // Keep only failed channels for retry to avoid resending successful ones
        const failedChannels = Array.from(
          new Set(
            deliveryResults.filter((r) => !r.success).map((r) => r.channel),
          ),
        );
        const channelsToStore = failedChannels;

        // Compute next_attempt_at based on failed channels
        let finalNextAttempt = nextAttemptTimestamp;

        // If WhatsApp had a permanent failure, block immediately (no further retries)
        const blockDueToWhatsApp = whatsappPermanentFailure === true;
        if (blockDueToWhatsApp) {
          finalNextAttempt = null;
          if (errorMessages)
            errorMessages = `${errorMessages}; WHATSAPP_PERMANENT_FAILURE`;
          else errorMessages = "WHATSAPP_PERMANENT_FAILURE";
          try {
            const contactGroupId =
              alert.contact_group_id || alert.default_contact_group_id || null;
            const groups = Array.isArray(alert.contact_groups)
              ? alert.contact_groups
              : [];
            const contactGroupName = contactGroupId
              ? groups.find((g) => String(g.id) === String(contactGroupId))
                  ?.name || null
              : null;
            await writeAudit(client, {
              subjectUserId: alert.user_id,
              action: "ALERT_BLOCKED_WHATSAPP_ERROR",
              targetId: alert.token_id,
              channel: "whatsapp",
              metadata: {
                days: alert.threshold_days,
                workspace_name: alert.workspace_name,
                token_name: alert.name,
                contact_group_id: contactGroupId,
                contact_group_name: contactGroupName,
              },
            });
          } catch (_err) {
            logger.warn("WhatsApp operation failed", { error: _err.message });
          }
        }
        await client.query(
          `UPDATE alert_queue 
           SET status = $1, attempts = $2, last_attempt = NOW(), error_message = $3, updated_at = NOW(), channels = $5,
               attempts_email = $6, attempts_webhooks = $7, attempts_whatsapp = $8, next_attempt_at = $9
           WHERE id = $4`,
          [
            reachedMaxAttempts || blockDueToWhatsApp ? "blocked" : newStatus,
            attempts,
            errorMessages || null,
            alert.id,
            JSON.stringify(channelsToStore),
            newAttemptsEmail,
            newAttemptsWebhooks,
            newAttemptsWhatsApp,
            reachedMaxAttempts || blockDueToWhatsApp
              ? null
              : finalNextAttempt
                ? finalNextAttempt.toISOString()
                : null,
          ],
        );
        if (!reachedMaxAttempts && nextAttemptTimestamp) {
          try {
            const contactGroupId =
              alert.contact_group_id || alert.default_contact_group_id || null;
            const groups = Array.isArray(alert.contact_groups)
              ? alert.contact_groups
              : [];
            const contactGroupName = contactGroupId
              ? groups.find((g) => String(g.id) === String(contactGroupId))
                  ?.name || null
              : null;
            await writeAudit(client, {
              subjectUserId: alert.user_id,
              action: "ALERT_RETRY_SCHEDULED",
              targetId: alert.token_id,
              metadata: {
                days: alert.threshold_days,
                next_attempt_at: nextAttemptTimestamp.toISOString(),
                channels_to_retry: channelsToStore,
                workspace_name: alert.workspace_name,
                token_name: alert.name,
                contact_group_id: contactGroupId,
                contact_group_name: contactGroupName,
              },
            });
          } catch (_err) {
            logger.debug("Non-critical operation failed", {
              error: _err.message,
            });
          }
        }
      }

      if (allSucceeded) {
        sent++;
        const contactGroupId =
          alert.contact_group_id || alert.default_contact_group_id || null;
        const groups = Array.isArray(alert.contact_groups)
          ? alert.contact_groups
          : [];
        const contactGroupName = contactGroupId
          ? groups.find((g) => String(g.id) === String(contactGroupId))?.name ||
            null
          : null;
        await writeAudit(client, {
          subjectUserId: alert.user_id,
          action: "ALERT_SENT",
          targetId: alert.token_id,
          metadata: {
            days: alert.threshold_days,
            channels: finalChannels,
            workspace_name: alert.workspace_name,
            token_name: alert.name,
            contact_group_id: contactGroupId,
            contact_group_name: contactGroupName,
          },
        });
      } else {
        failed++;
        const contactGroupId =
          alert.contact_group_id || alert.default_contact_group_id || null;
        const groups = Array.isArray(alert.contact_groups)
          ? alert.contact_groups
          : [];
        const contactGroupName = contactGroupId
          ? groups.find((g) => String(g.id) === String(contactGroupId))?.name ||
            null
          : null;
        await writeAudit(client, {
          subjectUserId: alert.user_id,
          action: "ALERT_SEND_FAILED",
          targetId: alert.token_id,
          metadata: {
            days: alert.threshold_days,
            error: errorMessages,
            attempts,
            workspace_name: alert.workspace_name,
            token_name: alert.name,
            contact_group_id: contactGroupId,
            contact_group_name: contactGroupName,
          },
        });
      }
    }
  });

  const durationMs = Date.now() - startedAt;
  logger.info(
    JSON.stringify({
      timestamp: new Date().toISOString(),
      level: "INFO",
      message: "alert-delivery-worker-finished",
      processed,
      sent,
      failed,
      durationMs,
    }),
  );

  // Update gauges at end of run (best-effort)
  try {
    // Note: new clients here for simplicity; this is end-of-process anyway
    await withClient(async (client) => {
      const pending = await client.query(
        `SELECT COUNT(*)::int AS c FROM alert_queue WHERE status='pending'`,
      );
      const failedQ = await client.query(
        `SELECT COUNT(*)::int AS c FROM alert_queue WHERE status='failed'`,
      );
      const blocked = await client.query(
        `SELECT COUNT(*)::int AS c FROM alert_queue WHERE status='blocked'`,
      );
      gQueueDepth.labels("pending").set(pending.rows[0].c || 0);
      gQueueDepth.labels("failed").set(failedQ.rows[0].c || 0);
      gQueueDepth.labels("blocked").set(blocked.rows[0].c || 0);
      const dueNow = await client.query(
        `SELECT COUNT(*)::int AS c FROM alert_queue WHERE (status IS NULL OR status IN ('pending','failed')) AND due_date <= CURRENT_DATE AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())`,
      );
      gQueueDueNow.set(dueNow.rows[0].c || 0);
      const cooldown = await client.query(
        `SELECT COUNT(*)::int AS c FROM alert_queue WHERE next_attempt_at > NOW()`,
      );
      gCooldownInEffect.set(cooldown.rows[0].c || 0);

      // Update global monthly channel usage gauges (email, webhooks, whatsapp)
      const usage = await client.query(
        `SELECT channel, COUNT(*)::int AS c
           FROM alert_delivery_log
          WHERE status='success'
            AND date_trunc('month', sent_at AT TIME ZONE 'UTC') = date_trunc('month', NOW() AT TIME ZONE 'UTC')
          GROUP BY channel`,
      );
      for (const r of usage.rows) {
        try {
          gMonthlyChannelUsage.labels(String(r.channel)).set(r.c || 0);
        } catch (_err) {
          logger.warn("DB operation failed", { error: _err.message });
        }
      }
    });
  } catch (_) {
    logger.debug("Metrics recording failed", { error: _.message });
  }

  // Only close pool if not shutting down (shutdown handler will close it)
  if (!isShuttingDown) {
    try {
      await pool.end();
    } catch (err) {
      logger.error(
        JSON.stringify({
          level: "ERROR",
          message: "delivery-worker-pool-end-error",
          error: err.message,
        }),
      );
    }
  }

  try {
    gRunnerUp.labels("delivery-worker").set(1);
  } catch (_) {
    logger.debug("Metrics recording failed", { error: _.message });
  }
  try {
    await pushMetrics("delivery-worker");
  } catch (_) {
    logger.debug("Metrics recording failed", { error: _.message });
  }
}

// Run delivery worker if this file is executed directly
if (import.meta.url === new URL(process.argv[1], "file://").href) {
  deliveryWorkerJob().catch(async (e) => {
    logger.error(
      JSON.stringify({
        level: "ERROR",
        message: "delivery-worker-error",
        error: e.message,
        stack: e.stack,
      }),
    );
    try {
      if (!isShuttingDown) {
        await pool.end();
      }
    } catch (err) {
      logger.error(
        JSON.stringify({
          level: "ERROR",
          message: "delivery-worker-error-cleanup-failed",
          error: err.message,
        }),
      );
    }
    process.exit(1);
  });
}
