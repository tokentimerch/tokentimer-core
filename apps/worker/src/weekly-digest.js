import { withClient } from "./db.js";
import { logger } from "./logger.js";
import {
  sendEmailNotification,
  generateEmailTemplate,
} from "./notify/email.js";
import { sendWhatsApp } from "./notify/whatsapp.js";
import { postJson } from "./notify/webhooks.js";
import {
  cWeeklyDigestSent,
  gWeeklyDigestProcessed,
  gWeeklyDigestTokensIncluded,
  gWeeklyDigestLastRun,
  gWeeklyDigestLastRunSuccess,
  gRunnerUp,
  pushMetrics,
} from "./metrics.js";
import { computeDaysLeft } from "./shared/thresholds.js";

const APP_URL = (process.env.APP_URL || "http://localhost:5173").replace(
  /\/$/,
  "",
);

function getWeekStartDate() {
  const now = new Date();
  const day = now.getUTCDay();
  const diff = day === 0 ? 6 : day - 1;
  const monday = new Date(now);
  monday.setUTCDate(now.getUTCDate() - diff);
  monday.setUTCHours(0, 0, 0, 0);
  return monday.toISOString().slice(0, 10);
}

async function writeAudit(
  client,
  {
    actorUserId = null,
    subjectUserId,
    action,
    targetType = "workspace",
    targetId = null,
    workspaceId = null,
    channel = null,
    metadata = {},
  },
) {
  await client.query(
    `INSERT INTO audit_events (actor_user_id, subject_user_id, action, target_type, target_id, channel, metadata, workspace_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [
      actorUserId,
      subjectUserId,
      action,
      targetType,
      targetId,
      channel,
      metadata,
      workspaceId,
    ],
  );
}

function maskWebhookUrl(url) {
  try {
    const parsed = new URL(url);
    // Show protocol and hostname, mask the path
    const path = parsed.pathname;
    const maskedPath =
      path.length > 10 ? `${path.slice(0, 5)}...${path.slice(-5)}` : path;
    return `${parsed.protocol}//${parsed.hostname}${maskedPath}`;
  } catch (_) {
    // If URL parsing fails, just show first and last 10 chars
    if (url.length > 30) {
      return `${url.slice(0, 15)}...${url.slice(-15)}`;
    }
    return url;
  }
}

function buildDigestEmailContent(tokens, groupName, workspaceName) {
  const subject = `Weekly Digest: ${tokens.length} token(s) expiring soon in ${workspaceName}`;

  const lines = [];
  lines.push(`Weekly Digest for Contact Group: ${groupName}`);
  lines.push(`Workspace: ${workspaceName}`);
  lines.push("");
  lines.push(`You have ${tokens.length} token(s) that are expiring soon:`);
  lines.push("");

  for (const token of tokens) {
    const days = computeDaysLeft(token.expiration);
    const expires = token.expiration
      ? new Date(token.expiration).toISOString().slice(0, 10)
      : "Unknown";
    lines.push(`- ${token.name}`);
    lines.push(`  Expires in: ${days} day(s) on ${expires}`);
    if (token.type) lines.push(`  Type: ${token.type}`);
    if (token.location) lines.push(`  Location: ${token.location}`);
    lines.push("");
  }

  lines.push("");
  lines.push(`View your tokens: ${APP_URL}/dashboard`);

  const text = lines.join("\n");

  // Build HTML content for template
  const htmlContentLines = [];
  htmlContentLines.push(
    `<h2 style="color: #1a202c; font-size: 20px; font-weight: 600; margin: 0 0 15px;">Weekly Digest for Contact Group: ${groupName}</h2>`,
  );
  htmlContentLines.push(
    `<p style="margin: 0 0 15px;"><strong>Workspace:</strong> ${workspaceName}</p>`,
  );
  htmlContentLines.push(
    `<p style="margin: 0 0 15px;">You have <strong>${tokens.length}</strong> token(s) that are expiring soon:</p>`,
  );
  htmlContentLines.push(
    '<ul style="color: #4a5568; line-height: 1.8; padding-left: 20px; margin: 0 0 20px;">',
  );

  for (const token of tokens) {
    const days = computeDaysLeft(token.expiration);
    const expires = token.expiration
      ? new Date(token.expiration).toISOString().slice(0, 10)
      : "Unknown";
    htmlContentLines.push('<li style="margin-bottom: 10px;">');
    htmlContentLines.push(`<strong>${token.name}</strong><br/>`);
    htmlContentLines.push(
      `Expires in: <strong>${days}</strong> day(s) on ${expires}`,
    );
    if (token.type) htmlContentLines.push(`<br/>Type: ${token.type}`);
    if (token.location)
      htmlContentLines.push(`<br/>Location: ${token.location}`);
    htmlContentLines.push("</li>");
  }

  htmlContentLines.push("</ul>");
  htmlContentLines.push(
    `<p style="margin-top: 20px;"><a href="${APP_URL}/dashboard" style="color: #2B6CB0; text-decoration: none; font-weight: 500;">View your tokens in TokenTimer</a></p>`,
  );
  const htmlContent = htmlContentLines.join("");

  // Use the email template generator to wrap content in proper template
  const { html, text: templateText } = generateEmailTemplate({
    title: subject,
    content: htmlContent,
    plainTextContent: text,
  });

  return { subject, text: templateText, html };
}

function buildDigestWhatsAppText(tokens, groupName, workspaceName) {
  const lines = [];
  lines.push(`*Weekly Digest*`);
  lines.push(`Group: ${groupName}`);
  lines.push(`Workspace: ${workspaceName}`);
  lines.push("");
  lines.push(`${tokens.length} token(s) expiring soon:`);
  lines.push("");

  for (const token of tokens.slice(0, 10)) {
    const days = computeDaysLeft(token.expiration);
    const expires = token.expiration
      ? new Date(token.expiration).toISOString().slice(0, 10)
      : "Unknown";
    lines.push(`• ${token.name}`);
    lines.push(`  ${days} day(s) - ${expires}`);
  }

  if (tokens.length > 10) {
    lines.push("");
    lines.push(`...and ${tokens.length - 10} more`);
  }

  return lines.join("\n");
}

function buildSlackDigestPayload(count, tokensList, groupName, workspaceName) {
  const blocks = [
    {
      type: "header",
      text: {
        type: "plain_text",
        text: `📊 Weekly Digest: ${count} token(s) expiring soon`,
        emoji: true,
      },
    },
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: `*Workspace:* ${workspaceName}\n*Contact Group:* ${groupName}`,
      },
    },
    { type: "divider" },
  ];

  // Add token list (max 10 for brevity)
  const displayTokens = tokensList.slice(0, 10);
  for (const t of displayTokens) {
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: `*${t.name}*\n• Type: ${t.type}\n• Expires in: *${t.days_until} day(s)* (${t.expiration})`,
      },
    });
  }

  if (count > 10) {
    blocks.push({
      type: "context",
      elements: [
        {
          type: "mrkdwn",
          text: `_...and ${count - 10} more token(s)_`,
        },
      ],
    });
  }

  blocks.push({
    type: "actions",
    elements: [
      {
        type: "button",
        text: {
          type: "plain_text",
          text: "View in TokenTimer",
          emoji: true,
        },
        url: `${APP_URL}/dashboard`,
        style: "primary",
      },
    ],
  });

  blocks.push({
    type: "context",
    elements: [
      {
        type: "mrkdwn",
        text: `🔔 Weekly Digest • ${new Date().toISOString()}`,
      },
    ],
  });

  return {
    text: `Weekly Digest: ${count} token(s) expiring soon in ${workspaceName}`,
    blocks,
  };
}

function buildDiscordDigestPayload(
  count,
  tokensList,
  groupName,
  workspaceName,
) {
  const fields = [];

  // Add token list (max 10)
  const displayTokens = tokensList.slice(0, 10);
  for (const t of displayTokens) {
    fields.push({
      name: t.name,
      value: `Type: ${t.type}\nExpires in: **${t.days_until} day(s)** (${t.expiration})`,
      inline: false,
    });
  }

  if (count > 10) {
    fields.push({
      name: "And more...",
      value: `_...plus ${count - 10} additional token(s)_`,
      inline: false,
    });
  }

  return {
    content: `📊 **Weekly Digest: ${count} token(s) expiring soon**`,
    embeds: [
      {
        title: `Weekly Digest for ${groupName}`,
        url: `${APP_URL}/dashboard`,
        description: `**Workspace:** ${workspaceName}\n\nYou have **${count}** token(s) that are expiring soon:`,
        color: 16776960, // Yellow
        fields,
        timestamp: new Date().toISOString(),
        footer: {
          text: "Click title to view in TokenTimer",
        },
      },
    ],
  };
}

function buildTeamsDigestPayload(count, tokensList, groupName, workspaceName) {
  const facts = [
    { name: "📊 Workspace", value: workspaceName },
    { name: "👥 Contact Group", value: groupName },
    { name: "🔢 Tokens Count", value: String(count) },
  ];

  const sections = [
    {
      activityTitle: `📊 Weekly Digest: ${count} token(s) expiring soon`,
      activitySubtitle: `${groupName} - ${workspaceName}`,
      text: `You have **${count}** token(s) expiring soon. Review them below:`,
      facts,
      markdown: true,
    },
  ];

  // Add token list (max 10)
  const displayTokens = tokensList.slice(0, 10);
  for (const t of displayTokens) {
    sections.push({
      activityTitle: t.name,
      facts: [
        { name: "📋 Type", value: t.type },
        { name: "⏰ Expires in", value: `${t.days_until} day(s)` },
        { name: "📅 Expiration Date", value: t.expiration },
      ],
      markdown: true,
    });
  }

  if (count > 10) {
    sections.push({
      activitySubtitle: `_...and ${count - 10} more token(s)_`,
      markdown: true,
    });
  }

  return {
    "@type": "MessageCard",
    "@context": "https://schema.org/extensions",
    summary: `Weekly Digest: ${count} token(s) expiring soon`,
    themeColor: "FFA500", // Orange
    sections,
    potentialAction: [
      {
        "@type": "OpenUri",
        name: "View in TokenTimer",
        targets: [
          {
            os: "default",
            uri: `${APP_URL}/dashboard`,
          },
        ],
      },
    ],
  };
}

export async function weeklyDigestJob() {
  const startedAt = Date.now();
  let processed = 0,
    sent = 0,
    skipped = 0,
    totalTokensIncluded = 0,
    digestCount = 0;

  const weekStartDate = getWeekStartDate();

  logger.info(
    JSON.stringify({
      timestamp: new Date().toISOString(),
      level: "INFO",
      message: "weekly-digest-job-started",
      weekStartDate,
    }),
  );

  // Set heartbeat
  try {
    gRunnerUp.labels("weekly-digest").set(1);
  } catch (_) {}

  await withClient(async (client) => {
    let weeklyDigestTemplateSid =
      process.env.TWILIO_WHATSAPP_WEEKLY_DIGEST_CONTENT_SID || null;
    if (!weeklyDigestTemplateSid) {
      try {
        const sidRes = await client.query(
          "SELECT twilio_whatsapp_weekly_digest_content_sid FROM system_settings WHERE id = 1",
        );
        weeklyDigestTemplateSid =
          sidRes.rows?.[0]?.twilio_whatsapp_weekly_digest_content_sid || null;
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }
    }

    const workspacesRes = await client.query(
      `SELECT 
         w.id AS workspace_id,
         w.name AS workspace_name,
         w.created_by AS owner_user_id,
         u.email AS owner_email,
         ws.contact_groups,
         ws.default_contact_group_id,
         ws.alert_thresholds,
         ws.webhook_urls,
         ws.delivery_window_start,
         ws.delivery_window_end,
         ws.delivery_window_tz
       FROM workspaces w
       JOIN workspace_settings ws ON ws.workspace_id = w.id
       JOIN users u ON u.id = w.created_by
       WHERE ws.contact_groups IS NOT NULL
         AND jsonb_array_length(ws.contact_groups) > 0
       ORDER BY w.id`,
    );

    for (const ws of workspacesRes.rows) {
      const contactGroups = ws.contact_groups || [];
      if (!Array.isArray(contactGroups)) continue;

      for (const group of contactGroups) {
        if (!group || !group.id || !group.name) continue;

        const weeklyDigestEmail =
          group.weekly_digest_email === true ||
          group.weekly_digest_email === "true";
        const weeklyDigestWhatsapp =
          group.weekly_digest_whatsapp === true ||
          group.weekly_digest_whatsapp === "true";
        const weeklyDigestWebhooks =
          group.weekly_digest_webhooks === true ||
          group.weekly_digest_webhooks === "true";

        if (
          !weeklyDigestEmail &&
          !weeklyDigestWhatsapp &&
          !weeklyDigestWebhooks
        ) {
          continue;
        }

        // Check if we're within the workspace delivery window
        try {
          let start = String(ws.delivery_window_start || "").trim();
          let end = String(ws.delivery_window_end || "").trim();
          const tzInput = String(ws.delivery_window_tz || "").trim();

          // Use default delivery window if not configured
          if (!start && !end) {
            start = process.env.DELIVERY_WINDOW_DEFAULT_START || "00:00";
            end = process.env.DELIVERY_WINDOW_DEFAULT_END || "23:59";
          }

          if (start && end) {
            const now = new Date();
            let hh, mm;

            if (tzInput) {
              try {
                const fmt = new Intl.DateTimeFormat("en-US", {
                  timeZone: tzInput,
                  hour: "2-digit",
                  minute: "2-digit",
                  hour12: false,
                });
                const parts = fmt.formatToParts(now);
                hh = parts.find((p) => p.type === "hour")?.value || "00";
                mm = parts.find((p) => p.type === "minute")?.value || "00";
              } catch (_err) {
                // Invalid timezone; fall back to UTC
                hh = String(now.getUTCHours()).padStart(2, "0");
                mm = String(now.getUTCMinutes()).padStart(2, "0");
                if (tzInput) {
                  logger.warn(
                    `Invalid delivery_window_tz: ${tzInput}, falling back to UTC`,
                  );
                }
              }
            } else {
              // No timezone configured, use UTC
              hh = String(now.getUTCHours()).padStart(2, "0");
              mm = String(now.getUTCMinutes()).padStart(2, "0");
            }

            const cur = `${hh}:${mm}`;
            const inWindow =
              start <= end
                ? cur >= start && cur <= end
                : cur >= start || cur <= end;

            if (!inWindow) {
              logger.info(
                `Skipping weekly digest for workspace ${ws.workspace_id}, group ${group.id}: outside delivery window (${cur} not in ${start}-${end} ${tzInput || "UTC"})`,
              );
              skipped++;
              continue;
            }
          }
        } catch (err) {
          logger.warn(
            `Error checking delivery window for workspace ${ws.workspace_id}: ${err.message}`,
          );
          // Continue anyway if delivery window check fails
        }

        processed++;

        const alreadySentRes = await client.query(
          `SELECT id FROM weekly_digest_log
           WHERE workspace_id = $1 AND contact_group_id = $2 AND week_start_date = $3`,
          [ws.workspace_id, group.id, weekStartDate],
        );

        if (alreadySentRes.rows.length > 0) {
          skipped++;
          continue;
        }

        const thresholds = Array.isArray(ws.alert_thresholds)
          ? ws.alert_thresholds
          : [30, 14, 7, 1, 0];
        const validThresholds = thresholds.filter((t) => t >= 1);
        if (validThresholds.length === 0) {
          logger.info(
            `Skipping weekly digest for workspace ${ws.workspace_id}, group ${group.id}: no valid future thresholds (all thresholds are <= 0)`,
          );
          skipped++;
          continue;
        }
        const maxThreshold = Math.max(...validThresholds);

        const tokensRes = await client.query(
          `SELECT 
             t.id AS token_id,
             t.name,
             t.type,
             t.category,
             t.expiration::date AS expiration,
             t.location,
             t.used_by,
             t.issuer,
             t.description
           FROM tokens t
           WHERE t.workspace_id = $1
             AND (t.contact_group_id = $2 OR (t.contact_group_id IS NULL AND $2 = $3))
             AND t.expiration IS NOT NULL
             AND t.expiration BETWEEN CURRENT_DATE AND CURRENT_DATE + ($4::integer)
           ORDER BY t.expiration ASC`,
          [
            ws.workspace_id,
            group.id,
            ws.default_contact_group_id,
            maxThreshold,
          ],
        );

        const tokens = tokensRes.rows;

        if (tokens.length === 0) {
          skipped++;
          continue;
        }

        const channels = [];
        const successfulChannels = new Set();
        let successCount = 0;

        // Track per-channel metrics for accurate reporting
        const channelMetrics = {
          email: { success: 0, failure: 0 },
          whatsapp: { success: 0, failure: 0 },
          webhook: { success: 0, failure: 0 },
        };

        if (weeklyDigestEmail) {
          const emailContactIds = Array.isArray(group.email_contact_ids)
            ? group.email_contact_ids
            : [];

          if (emailContactIds.length > 0) {
            const contactsRes = await client.query(
              `SELECT details FROM workspace_contacts
               WHERE workspace_id = $1 AND id = ANY($2::uuid[])`,
              [ws.workspace_id, emailContactIds],
            );

            const emails = contactsRes.rows
              .map((c) => c.details?.email)
              .filter(Boolean);

            if (emails.length > 0) {
              channels.push("email");
              const { subject, text, html } = buildDigestEmailContent(
                tokens,
                group.name,
                ws.workspace_name,
              );

              for (const email of emails) {
                const res = await sendEmailNotification({
                  to: email,
                  subject,
                  text,
                  html,
                });

                if (res.success) {
                  successCount++;
                  successfulChannels.add("email");
                  channelMetrics.email.success++;
                } else {
                  channelMetrics.email.failure++;
                }
              }
            }
          }
        }

        if (weeklyDigestWhatsapp) {
          const whatsappContactIds = Array.isArray(group.whatsapp_contact_ids)
            ? group.whatsapp_contact_ids
            : [];

          if (whatsappContactIds.length > 0) {
            const contactsRes = await client.query(
              `SELECT id, phone_e164, first_name, last_name FROM workspace_contacts
               WHERE workspace_id = $1 AND id = ANY($2::uuid[]) AND phone_e164 IS NOT NULL`,
              [ws.workspace_id, whatsappContactIds],
            );

            const contacts = contactsRes.rows.filter((c) => c.phone_e164);

            if (contacts.length > 0) {
              channels.push("whatsapp");

              // Use Twilio Content Template if configured
              const contentSid = weeklyDigestTemplateSid;

              // Build tokens list for template (all tokens, single line with semicolon separator)
              // Note: Twilio Content Templates don't support multiline values
              const tokensList = tokens.map((t) => {
                const days = computeDaysLeft(t.expiration);
                const expires = t.expiration
                  ? new Date(t.expiration).toISOString().slice(0, 10)
                  : "Unknown";
                return `${t.name}: ${expires} (${days}d)`;
              });

              const tokensListText = tokensList.join("; ");

              for (const contact of contacts) {
                const firstName = String(contact.first_name || "").trim();
                const lastName = String(contact.last_name || "").trim();
                const recipientName =
                  [firstName, lastName].filter(Boolean).join(" ") || "User";
                const idempotencyKey = `weekly-digest:${ws.workspace_id}:${group.id}:${weekStartDate}:${contact.phone_e164}`;

                let res;
                if (contentSid) {
                  // Use Twilio Content Template
                  // Sanitize variables (remove null/undefined/empty)
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

                  const contentVariables = sanitizeVars({
                    recipient_name: recipientName,
                    workspace_name: ws.workspace_name,
                    contact_group_name: group.name,
                    tokens_count: String(tokens.length),
                    tokens_list: tokensListText,
                  });

                  res = await sendWhatsApp({
                    to: contact.phone_e164,
                    contentSid,
                    contentVariables,
                    idempotencyKey,
                  });
                } else {
                  // Fallback to plain text
                  const body = buildDigestWhatsAppText(
                    tokens,
                    group.name,
                    ws.workspace_name,
                  );

                  res = await sendWhatsApp({
                    to: contact.phone_e164,
                    body,
                    idempotencyKey,
                  });
                }

                if (res.success) {
                  successCount++;
                  successfulChannels.add("whatsapp");
                  channelMetrics.whatsapp.success++;
                } else {
                  channelMetrics.whatsapp.failure++;
                }
              }
            }
          }
        }

        if (weeklyDigestWebhooks) {
          const webhookNames = Array.isArray(group.webhook_names)
            ? group.webhook_names
            : [];
          const webhookUrls = Array.isArray(ws.webhook_urls)
            ? ws.webhook_urls
            : [];

          let webhookChannelPushed = false;

          for (const whName of webhookNames) {
            const wh = webhookUrls.find((w) => w.name === whName);
            if (!wh || !wh.url) continue;

            const kind = (wh.kind || "generic").toLowerCase();

            // Skip PagerDuty - it's for incident alerting, not digest summaries
            if (kind === "pagerduty") continue;

            // Only push "webhook" channel once, even if multiple webhooks configured
            if (!webhookChannelPushed) {
              channels.push("webhook");
              webhookChannelPushed = true;
            }

            const tokensList = tokens.slice(0, 20).map((t) => {
              const days = computeDaysLeft(t.expiration);
              return {
                name: t.name,
                type: t.type || "Unknown",
                expiration: t.expiration
                  ? new Date(t.expiration).toISOString().slice(0, 10)
                  : "Unknown",
                days_until: days,
              };
            });

            // Build custom payload for weekly digest (not individual token alerts)
            let payload;
            if (kind === "slack") {
              payload = buildSlackDigestPayload(
                tokens.length,
                tokensList,
                group.name,
                ws.workspace_name,
              );
            } else if (kind === "discord") {
              payload = buildDiscordDigestPayload(
                tokens.length,
                tokensList,
                group.name,
                ws.workspace_name,
              );
            } else if (kind === "teams") {
              payload = buildTeamsDigestPayload(
                tokens.length,
                tokensList,
                group.name,
                ws.workspace_name,
              );
            } else {
              // Generic webhook
              payload = {
                type: "weekly_digest",
                title: `Weekly Digest: ${tokens.length} token(s) expiring soon`,
                workspace: ws.workspace_name,
                contact_group: group.name,
                tokens_count: tokens.length,
                tokens: tokensList,
                week_start_date: weekStartDate,
                timestamp: new Date().toISOString(),
                url: `${APP_URL}/dashboard`,
              };
            }

            const res = await postJson(wh.url, payload, kind);

            // Log webhook send result
            if (res.success) {
              successCount++;
              successfulChannels.add("webhook");
              channelMetrics.webhook.success++;
              try {
                logger.info(
                  JSON.stringify({
                    level: "INFO",
                    message: "webhook-send-succeeded",
                    kind,
                    url: maskWebhookUrl(wh.url),
                    tokens_count: tokens.length,
                    workspace: ws.workspace_name,
                    contact_group: group.name,
                  }),
                );
              } catch (_err) {
                logger.debug("Non-critical operation failed", {
                  error: _err.message,
                });
              }
            } else {
              channelMetrics.webhook.failure++;
              try {
                logger.error(
                  JSON.stringify({
                    level: "ERROR",
                    message: "webhook-send-failed",
                    kind,
                    url: maskWebhookUrl(wh.url),
                    error: res.error || "Unknown error",
                    tokens_count: tokens.length,
                    workspace: ws.workspace_name,
                    contact_group: group.name,
                  }),
                );
              } catch (_err) {
                logger.debug("Non-critical operation failed", {
                  error: _err.message,
                });
              }
            }
          }
        }

        if (successCount > 0) {
          sent++;
          digestCount++;
          totalTokensIncluded += tokens.length;

          // Track metrics per channel (with accurate per-channel success/failure counts)
          try {
            for (const [channel, metrics] of Object.entries(channelMetrics)) {
              if (metrics.success > 0) {
                cWeeklyDigestSent
                  .labels(channel, "success")
                  .inc(metrics.success);
              }
              if (metrics.failure > 0) {
                cWeeklyDigestSent
                  .labels(channel, "failure")
                  .inc(metrics.failure);
              }
            }
          } catch (_) {}

          await client.query(
            `INSERT INTO weekly_digest_log (workspace_id, contact_group_id, week_start_date, tokens_count, channels, metadata)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [
              ws.workspace_id,
              group.id,
              weekStartDate,
              tokens.length,
              JSON.stringify(channels),
              JSON.stringify({
                sent_to_count: successCount,
              }),
            ],
          );

          await writeAudit(client, {
            subjectUserId: ws.owner_user_id,
            action: "WEEKLY_DIGEST_SENT",
            targetType: "workspace",
            targetId: null,
            workspaceId: ws.workspace_id,
            metadata: {
              contact_group_id: group.id,
              contact_group_name: group.name,
              tokens_count: tokens.length,
              channels,
              week_start_date: weekStartDate,
            },
          });
        }
      }
    }
  });

  const durationMs = Date.now() - startedAt;
  const success = true;

  // Update metrics
  try {
    gWeeklyDigestProcessed.set(processed);
    if (digestCount > 0) {
      gWeeklyDigestTokensIncluded.set(totalTokensIncluded / digestCount);
    }
    gWeeklyDigestLastRun.set(Date.now() / 1000); // Unix timestamp in seconds
    gWeeklyDigestLastRunSuccess.set(success ? 1 : 0);
  } catch (_err) {
    logger.warn("DB operation failed", { error: _err.message });
  }

  // Push metrics to Pushgateway
  try {
    await pushMetrics("weekly-digest");
  } catch (err) {
    logger.error("Failed to push metrics", { error: err.message });
  }

  logger.info(
    JSON.stringify({
      timestamp: new Date().toISOString(),
      level: "INFO",
      message: "weekly-digest-job-finished",
      processed,
      sent,
      skipped,
      digestCount,
      avgTokensPerDigest:
        digestCount > 0 ? (totalTokensIncluded / digestCount).toFixed(1) : 0,
      durationMs,
    }),
  );
}
