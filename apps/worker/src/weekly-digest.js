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
  gWeeklyDigestLastSentUnix,
  gRunnerUp,
  pushMetrics,
} from "./metrics.js";
import { computeDaysLeft } from "./shared/thresholds.js";
import {
  buildWeeklyDigestWhatsAppTemplateVariables,
  sanitizeWhatsAppTemplateVars,
  WHATSAPP_WEEKLY_DIGEST_TOKENS_LIST_MAX_LEN,
} from "./shared/whatsappTemplateVars.js";
import {
  dedupeNormalizedDestinations,
  getWebhookNames,
  resolveContactGroupsForAsset,
} from "./shared/contactGroups.js";
import { loadAssignedGroupIdsForAssets } from "./shared/replaceAssetContactGroups.js";
import {
  invertDigestCandidates,
  claimWeeklyDigestRecipient,
  markWeeklyDigestRecipientSent,
  weeklyDigestWhatsAppIdempotencyKey,
} from "./shared/weeklyDigestRecipients.js";

const APP_URL = (process.env.APP_URL || "http://localhost:5173").replace(
  /\/$/,
  "",
);

const WEEKLY_DIGEST_CLAIM_LEASE_MS = 300000;

function getWeekStartDate() {
  const now = new Date();
  const day = now.getUTCDay();
  const diff = day === 0 ? 6 : day - 1;
  const monday = new Date(now);
  monday.setUTCDate(now.getUTCDate() - diff);
  monday.setUTCHours(0, 0, 0, 0);
  return monday.toISOString().slice(0, 10);
}

function flagOn(value) {
  return value === true || value === "true";
}

function isDigestEnabled(group) {
  return (
    flagOn(group && group.weekly_digest_email) ||
    flagOn(group && group.weekly_digest_whatsapp) ||
    flagOn(group && group.weekly_digest_webhooks)
  );
}

function formatGroupNames(names) {
  const list = Array.isArray(names) ? names : names ? [names] : [];
  const unique = [];
  const seen = new Set();
  for (const raw of list) {
    const name = String(raw || "").trim();
    if (!name || seen.has(name)) continue;
    seen.add(name);
    unique.push(name);
  }
  return unique;
}

function contributingGroupNames(groupById, contributingGroupIds) {
  const names = [];
  for (const id of Array.isArray(contributingGroupIds)
    ? contributingGroupIds
    : []) {
    const group = groupById.get(String(id));
    if (group && group.name) names.push(group.name);
  }
  return formatGroupNames(names);
}

function contactDisplayName(contact) {
  const firstName = String(
    contact && contact.first_name ? contact.first_name : "",
  ).trim();
  const lastName = String(
    contact && contact.last_name ? contact.last_name : "",
  ).trim();
  return [firstName, lastName].filter(Boolean).join(" ") || "User";
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

function isWithinDeliveryWindow(ws) {
  let start = String(ws.delivery_window_start || "").trim();
  let end = String(ws.delivery_window_end || "").trim();
  const tzInput = String(ws.delivery_window_tz || "").trim();

  if (!start && !end) {
    start = process.env.DELIVERY_WINDOW_DEFAULT_START || "00:00";
    end = process.env.DELIVERY_WINDOW_DEFAULT_END || "23:59";
  }

  if (!start || !end) {
    return { inWindow: true, cur: null, start, end, tzInput };
  }

  const now = new Date();
  let hh;
  let mm;

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
      hh = String(now.getUTCHours()).padStart(2, "0");
      mm = String(now.getUTCMinutes()).padStart(2, "0");
      if (tzInput) {
        logger.warn(
          `Invalid delivery_window_tz: ${tzInput}, falling back to UTC`,
        );
      }
    }
  } else {
    hh = String(now.getUTCHours()).padStart(2, "0");
    mm = String(now.getUTCMinutes()).padStart(2, "0");
  }

  const cur = `${hh}:${mm}`;
  const inWindow =
    start <= end ? cur >= start && cur <= end : cur >= start || cur <= end;
  return { inWindow, cur, start, end, tzInput };
}

function buildDigestEmailContent(
  tokens,
  contributingGroupNames,
  workspaceName,
) {
  const subject = `Weekly Digest: ${tokens.length} token(s) expiring soon in ${workspaceName}`;
  const groupNames = formatGroupNames(contributingGroupNames);

  const lines = [];
  lines.push("Weekly Digest");
  lines.push(`Workspace: ${workspaceName}`);
  if (groupNames.length > 0) {
    lines.push(`Contact groups: ${groupNames.join(", ")}`);
  }
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

  const htmlContentLines = [];
  htmlContentLines.push(
    '<h2 style="color: #1a202c; font-size: 20px; font-weight: 600; margin: 0 0 15px;">Weekly Digest</h2>',
  );
  htmlContentLines.push(
    `<p style="margin: 0 0 15px;"><strong>Workspace:</strong> ${workspaceName}</p>`,
  );
  if (groupNames.length > 0) {
    htmlContentLines.push(
      `<p style="margin: 0 0 15px;"><strong>Contact groups:</strong> ${groupNames.join(", ")}</p>`,
    );
  }
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

  const { html, text: templateText } = generateEmailTemplate({
    title: subject,
    content: htmlContent,
    plainTextContent: text,
  });

  return { subject, text: templateText, html };
}

function buildDigestWhatsAppText(
  tokens,
  contributingGroupNames,
  workspaceName,
) {
  const groupNames = formatGroupNames(contributingGroupNames);
  const lines = [];
  lines.push(`*Weekly Digest*`);
  lines.push(`Workspace: ${workspaceName}`);
  if (groupNames.length > 0) {
    lines.push(`Groups: ${groupNames.join(", ")}`);
  }
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

function buildSlackDigestPayload(
  count,
  tokensList,
  contributingGroupNames,
  workspaceName,
) {
  const groupNames = formatGroupNames(contributingGroupNames);
  const groupLine =
    groupNames.length > 0
      ? `\n*Contact groups:* ${groupNames.join(", ")}`
      : "";
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
        text: `*Workspace:* ${workspaceName}${groupLine}`,
      },
    },
    { type: "divider" },
  ];

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
  contributingGroupNames,
  workspaceName,
) {
  const groupNames = formatGroupNames(contributingGroupNames);
  const fields = [];

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

  const groupLine =
    groupNames.length > 0
      ? `\n**Contact groups:** ${groupNames.join(", ")}`
      : "";

  return {
    content: `📊 **Weekly Digest: ${count} token(s) expiring soon**`,
    embeds: [
      {
        title: "Weekly Digest",
        url: `${APP_URL}/dashboard`,
        description: `**Workspace:** ${workspaceName}${groupLine}\n\nYou have **${count}** token(s) that are expiring soon:`,
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

function buildTeamsDigestPayload(
  count,
  tokensList,
  contributingGroupNames,
  workspaceName,
) {
  const groupNames = formatGroupNames(contributingGroupNames);
  const facts = [
    { name: "📊 Workspace", value: workspaceName },
    { name: "🔢 Tokens Count", value: String(count) },
  ];
  if (groupNames.length > 0) {
    facts.splice(1, 0, {
      name: "👥 Contact groups",
      value: groupNames.join(", "),
    });
  }

  const sections = [
    {
      activityTitle: `📊 Weekly Digest: ${count} token(s) expiring soon`,
      activitySubtitle: workspaceName,
      text: `You have **${count}** token(s) expiring soon. Review them below:`,
      facts,
      markdown: true,
    },
  ];

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

function buildGenericWebhookPayload({
  tokens,
  tokensList,
  contributingGroupNames,
  workspaceName,
  weekStartDate,
}) {
  const groupNames = formatGroupNames(contributingGroupNames);
  return {
    type: "weekly_digest",
    title: `Weekly Digest: ${tokens.length} token(s) expiring soon`,
    workspace: workspaceName,
    contact_groups: groupNames,
    tokens_count: tokens.length,
    tokens: tokensList,
    week_start_date: weekStartDate,
    timestamp: new Date().toISOString(),
    url: `${APP_URL}/dashboard`,
  };
}

function webhookTokensList(tokens) {
  return tokens.slice(0, 20).map((t) => {
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
}

function whatsappTokensListText(tokens) {
  return tokens
    .map((t) => {
      const days = computeDaysLeft(t.expiration);
      const expires = t.expiration
        ? new Date(t.expiration).toISOString().slice(0, 10)
        : "Unknown";
      return `${t.name}: ${expires} (${days}d)`;
    })
    .join("; ");
}

function loadAssignedIdsByToken(client, workspaceId, tokens) {
  const assetIds = [];
  for (const token of Array.isArray(tokens) ? tokens : []) {
    const tokenId = token.token_id ?? token.id;
    if (tokenId == null) continue;
    assetIds.push(Number(tokenId));
  }
  return loadAssignedGroupIdsForAssets({
    client,
    kind: "token",
    assetIds,
    workspaceId,
  });
}

function isCandidateForGroup(
  token,
  groupId,
  assignedByToken,
  defaultGroupId,
  contactGroups,
) {
  const assigned = assignedByToken.get(String(token.token_id ?? token.id));
  const resolved = resolveContactGroupsForAsset({
    contactGroups,
    assignedIds: assigned,
    defaultContactGroupId: defaultGroupId,
  });
  return resolved.some((group) => String(group.id) === String(groupId));
}

function emailsForGroup(group, contactsById) {
  const ids = Array.isArray(group.email_contact_ids)
    ? group.email_contact_ids
    : [];
  const emails = [];
  for (const id of ids) {
    const contact = contactsById.get(String(id));
    const email = contact && contact.details && contact.details.email;
    if (email) emails.push(email);
  }
  return dedupeNormalizedDestinations(emails, "email");
}

function phonesForGroup(group, contactsById) {
  const ids = Array.isArray(group.whatsapp_contact_ids)
    ? group.whatsapp_contact_ids
    : [];
  const phones = [];
  for (const id of ids) {
    const contact = contactsById.get(String(id));
    if (contact && contact.phone_e164) phones.push(contact.phone_e164);
  }
  return dedupeNormalizedDestinations(phones, "phone");
}

function webhookUrlsForGroup(group, webhookUrls) {
  const names = getWebhookNames(group);
  const list = Array.isArray(webhookUrls) ? webhookUrls : [];
  const urls = [];
  for (const name of names) {
    const wh = list.find((w) => w && w.name === name);
    if (!wh || !wh.url) continue;
    if (String(wh.kind || "generic").toLowerCase() === "pagerduty") continue;
    urls.push(wh.url);
  }
  return dedupeNormalizedDestinations(urls, "webhook");
}

function indexWebhooksByUrl(webhookUrls) {
  const map = new Map();
  for (const wh of Array.isArray(webhookUrls) ? webhookUrls : []) {
    if (!wh || !wh.url) continue;
    const key = String(wh.url).trim();
    if (!key || map.has(key)) continue;
    map.set(key, wh);
  }
  return map;
}

async function deliverRecipientDigest({
  row,
  ws,
  weekStartDate,
  groupNames,
  phoneNameByKey,
  webhookByUrl,
  weeklyDigestTemplateSid,
}) {
  const tokens = row.tokens;
  if (row.channel === "email") {
    const { subject, text, html } = buildDigestEmailContent(
      tokens,
      groupNames,
      ws.workspace_name,
    );
    return sendEmailNotification({
      to: row.recipientKey,
      subject,
      text,
      html,
    });
  }

  if (row.channel === "whatsapp") {
    const recipientName = phoneNameByKey.get(row.recipientKey) || "User";
    const idempotencyKey = weeklyDigestWhatsAppIdempotencyKey({
      workspaceId: ws.workspace_id,
      weekStartDate,
      phone: row.recipientKey,
    });
    const contentSid = weeklyDigestTemplateSid;
    if (contentSid) {
      const contentVariables = sanitizeWhatsAppTemplateVars(
        buildWeeklyDigestWhatsAppTemplateVariables({
          recipientName,
          workspaceName: ws.workspace_name,
          contactGroupName:
            groupNames.length > 0
              ? groupNames.join(", ")
              : ws.workspace_name,
          tokensCount: tokens.length,
          tokensListText: whatsappTokensListText(tokens),
        }),
        {
          maxLens: {
            tokens_list: WHATSAPP_WEEKLY_DIGEST_TOKENS_LIST_MAX_LEN,
          },
        },
      );
      return sendWhatsApp({
        to: row.recipientKey,
        contentSid,
        contentVariables,
        idempotencyKey,
      });
    }
    return sendWhatsApp({
      to: row.recipientKey,
      body: buildDigestWhatsAppText(tokens, groupNames, ws.workspace_name),
      idempotencyKey,
    });
  }

  if (row.channel === "webhook") {
    const wh = webhookByUrl.get(row.recipientKey) || {
      url: row.recipientKey,
      kind: "generic",
    };
    const kind = (wh.kind || "generic").toLowerCase();
    const tokensList = webhookTokensList(tokens);
    let payload;
    if (kind === "slack") {
      payload = buildSlackDigestPayload(
        tokens.length,
        tokensList,
        groupNames,
        ws.workspace_name,
      );
    } else if (kind === "discord") {
      payload = buildDiscordDigestPayload(
        tokens.length,
        tokensList,
        groupNames,
        ws.workspace_name,
      );
    } else if (kind === "teams") {
      payload = buildTeamsDigestPayload(
        tokens.length,
        tokensList,
        groupNames,
        ws.workspace_name,
      );
    } else {
      payload = buildGenericWebhookPayload({
        tokens,
        tokensList,
        contributingGroupNames: groupNames,
        workspaceName: ws.workspace_name,
        weekStartDate,
      });
    }

    const res = await postJson(wh.url || row.recipientKey, payload, kind);
    if (res.success) {
      try {
        logger.info(
          JSON.stringify({
            level: "INFO",
            message: "webhook-send-succeeded",
            kind,
            url: maskWebhookUrl(wh.url || row.recipientKey),
            tokens_count: tokens.length,
            workspace: ws.workspace_name,
            contact_groups: groupNames,
          }),
        );
      } catch (_err) {
        logger.debug("Non-critical operation failed", {
          error: _err.message,
        });
      }
    } else {
      try {
        logger.error(
          JSON.stringify({
            level: "ERROR",
            message: "webhook-send-failed",
            kind,
            url: maskWebhookUrl(wh.url || row.recipientKey),
            error: res.error || "Unknown error",
            tokens_count: tokens.length,
            workspace: ws.workspace_name,
            contact_groups: groupNames,
          }),
        );
      } catch (_err) {
        logger.debug("Non-critical operation failed", {
          error: _err.message,
        });
      }
    }
    return res;
  }

  return { success: false, error: `unknown digest channel: ${row.channel}` };
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

      const digestGroups = contactGroups.filter(
        (group) => group && group.id != null && isDigestEnabled(group),
      );
      if (digestGroups.length === 0) continue;

      try {
        const window = isWithinDeliveryWindow(ws);
        if (!window.inWindow) {
          logger.info(
            `Skipping weekly digest for workspace ${ws.workspace_id}: outside delivery window (${window.cur} not in ${window.start}-${window.end} ${window.tzInput || "UTC"})`,
          );
          skipped++;
          continue;
        }
      } catch (err) {
        logger.warn(
          `Error checking delivery window for workspace ${ws.workspace_id}: ${err.message}`,
        );
      }

      const thresholds = Array.isArray(ws.alert_thresholds)
        ? ws.alert_thresholds
        : [30, 14, 7, 1, 0];
      const validThresholds = thresholds.filter((t) => t >= 1);
      if (validThresholds.length === 0) {
        logger.info(
          `Skipping weekly digest for workspace ${ws.workspace_id}: no valid future thresholds (all thresholds are <= 0)`,
        );
        skipped++;
        continue;
      }
      const maxThreshold = Math.max(...validThresholds);

      const tokensRes = await client.query(
        `SELECT 
           t.id,
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
           AND t.expiration IS NOT NULL
           AND t.expiration BETWEEN CURRENT_DATE AND CURRENT_DATE + ($2::integer)
           AND (
             t.cert_lifecycle_status IS NULL
             OR t.cert_lifecycle_status NOT IN ('revoked', 'decommissioned')
           )
         ORDER BY t.expiration ASC`,
        [ws.workspace_id, maxThreshold],
      );

      const tokens = tokensRes.rows;
      if (tokens.length === 0) {
        skipped++;
        continue;
      }

      const defaultGroupId =
        ws.default_contact_group_id != null &&
        String(ws.default_contact_group_id).trim()
          ? String(ws.default_contact_group_id)
          : null;

      const assignedByToken = await loadAssignedIdsByToken(
        client,
        ws.workspace_id,
        tokens,
      );

      const contactIds = [];
      const seenContactIds = new Set();
      for (const group of digestGroups) {
        const idLists = [
          group.email_contact_ids,
          group.whatsapp_contact_ids,
        ];
        for (const list of idLists) {
          for (const id of Array.isArray(list) ? list : []) {
            if (id == null) continue;
            const key = String(id);
            if (seenContactIds.has(key)) continue;
            seenContactIds.add(key);
            contactIds.push(id);
          }
        }
      }

      const contactsById = new Map();
      const phoneNameByKey = new Map();
      if (contactIds.length > 0) {
        const contactsRes = await client.query(
          `SELECT id, details, phone_e164, first_name, last_name
             FROM workspace_contacts
            WHERE workspace_id = $1 AND id = ANY($2::uuid[])`,
          [ws.workspace_id, contactIds],
        );
        for (const contact of contactsRes.rows) {
          contactsById.set(String(contact.id), contact);
          if (!contact.phone_e164) continue;
          const phoneKey = String(contact.phone_e164).trim();
          if (!phoneKey || phoneNameByKey.has(phoneKey)) continue;
          phoneNameByKey.set(phoneKey, contactDisplayName(contact));
        }
      }

      const webhookByUrl = indexWebhooksByUrl(ws.webhook_urls);
      const groupById = new Map(
        digestGroups.map((group) => [String(group.id), group]),
      );
      const groupCandidateCount = new Map();
      const groupCandidates = [];

      for (const group of digestGroups) {
        const groupId = String(group.id);
        const candidateTokens = tokens.filter((token) =>
          isCandidateForGroup(
            token,
            groupId,
            assignedByToken,
            defaultGroupId,
            ws.contact_groups,
          ),
        );
        groupCandidateCount.set(groupId, candidateTokens.length);
        if (candidateTokens.length === 0) continue;

        groupCandidates.push({
          group,
          tokens: candidateTokens,
          emails: emailsForGroup(group, contactsById),
          phones: phonesForGroup(group, contactsById),
          webhookUrls: webhookUrlsForGroup(group, ws.webhook_urls),
        });
      }

      const inverted = invertDigestCandidates({ groupCandidates }).filter(
        (row) => row && Array.isArray(row.tokens) && row.tokens.length > 0,
      );

      if (inverted.length === 0) {
        skipped++;
        continue;
      }

      const successfulGroupIds = new Set();
      const groupChannelsSent = new Map();
      const groupSuccessCount = new Map();

      for (const row of inverted) {
        processed++;
        const claim = await claimWeeklyDigestRecipient(client, {
          workspaceId: ws.workspace_id,
          weekStartDate,
          channel: row.channel,
          recipientKey: row.recipientKey,
          tokensCount: row.tokens.length,
          leaseMs: WEEKLY_DIGEST_CLAIM_LEASE_MS,
        });
        if (!claim) {
          skipped++;
          continue;
        }

        const groupNames = contributingGroupNames(
          groupById,
          row.contributingGroupIds,
        );

        let res;
        try {
          res = await deliverRecipientDigest({
            row,
            ws,
            weekStartDate,
            groupNames,
            phoneNameByKey,
            webhookByUrl,
            weeklyDigestTemplateSid,
          });
        } catch (err) {
          logger.error(
            JSON.stringify({
              level: "ERROR",
              message: "weekly-digest-recipient-send-failed",
              workspace: ws.workspace_id,
              channel: row.channel,
              error: err.message,
            }),
          );
          res = { success: false };
        }

        try {
          cWeeklyDigestSent
            .labels(row.channel, res && res.success ? "success" : "failure")
            .inc();
        } catch (_) {}

        if (!res || !res.success) {
          continue;
        }

        await markWeeklyDigestRecipientSent(client, {
          workspaceId: ws.workspace_id,
          weekStartDate,
          channel: row.channel,
          recipientKey: row.recipientKey,
        });

        sent++;
        digestCount++;
        totalTokensIncluded += row.tokens.length;

        for (const gid of row.contributingGroupIds || []) {
          const groupId = String(gid);
          successfulGroupIds.add(groupId);
          if (!groupChannelsSent.has(groupId)) {
            groupChannelsSent.set(groupId, new Set());
          }
          groupChannelsSent.get(groupId).add(row.channel);
          groupSuccessCount.set(
            groupId,
            (groupSuccessCount.get(groupId) || 0) + 1,
          );
        }
      }

      for (const groupId of successfulGroupIds) {
        const group = groupById.get(groupId);
        const channels = [...(groupChannelsSent.get(groupId) || [])];
        await client.query(
          `INSERT INTO weekly_digest_log (workspace_id, contact_group_id, week_start_date, tokens_count, channels, metadata)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (workspace_id, contact_group_id, week_start_date) DO NOTHING`,
          [
            ws.workspace_id,
            groupId,
            weekStartDate,
            groupCandidateCount.get(groupId) || 0,
            JSON.stringify(channels),
            JSON.stringify({
              sent_to_count: groupSuccessCount.get(groupId) || 0,
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
            contact_group_id: groupId,
            contact_group_name: group && group.name,
            tokens_count: groupCandidateCount.get(groupId) || 0,
            channels,
            week_start_date: weekStartDate,
          },
        });
      }
    }
  });

  const durationMs = Date.now() - startedAt;
  const success = true;

  try {
    gWeeklyDigestProcessed.set(processed);
    if (digestCount > 0) {
      gWeeklyDigestTokensIncluded.set(totalTokensIncluded / digestCount);
    }
    gWeeklyDigestLastRun.set(Date.now() / 1000);
    gWeeklyDigestLastRunSuccess.set(success ? 1 : 0);
  } catch (_err) {
    logger.warn("DB operation failed", { error: _err.message });
  }

  try {
    await withClient(async (client) => {
      const res = await client.query(
        `SELECT EXTRACT(EPOCH FROM MAX(sent_at))::bigint AS ts FROM weekly_digest_log`,
      );
      const ts = res.rows[0]?.ts;
      if (ts) gWeeklyDigestLastSentUnix.set(Number(ts));
    });
  } catch (_err) {
    logger.debug("Non-critical operation failed", { error: _err.message });
  }

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
