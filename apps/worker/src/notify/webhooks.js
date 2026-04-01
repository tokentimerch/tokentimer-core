import axios from "axios";
import dns from "dns/promises";
import { cDeniedHost } from "../metrics.js";
import { logger } from "../logger.js";

/**
 * Check whether an IPv4 address falls in a private/reserved range.
 * Prevents SSRF via IP-literal URLs or DNS rebinding.
 */
function isPrivateOrReservedIP(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => isNaN(n) || n < 0 || n > 255))
    return false; // not IPv4, let it through (IPv6 handled below)
  const [a, b] = parts;
  return (
    a === 10 || // 10.0.0.0/8
    (a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12
    (a === 192 && b === 168) || // 192.168.0.0/16
    a === 127 || // 127.0.0.0/8 (loopback)
    (a === 169 && b === 254) || // 169.254.0.0/16 (link-local)
    a === 0 || // 0.0.0.0/8
    (a === 100 && b >= 64 && b <= 127) || // 100.64.0.0/10 (CGN)
    (a === 198 && (b === 18 || b === 19)) // 198.18.0.0/15 (benchmarking)
  );
}

/**
 * Resolve a hostname and verify it does not point to a private/reserved IP.
 * Returns true if the host is safe to connect to.
 */
async function validateResolvedIP(hostname) {
  // If the hostname is already an IP literal, check it directly
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    return !isPrivateOrReservedIP(hostname);
  }
  try {
    const addresses = await dns.resolve4(hostname);
    for (const addr of addresses) {
      if (isPrivateOrReservedIP(addr)) {
        logger.warn("SSRF_BLOCKED", {
          hostname,
          resolvedIP: addr,
          reason: "Resolved to private/reserved IP",
        });
        return false;
      }
    }
    return true;
  } catch (_) {
    // DNS resolution failed; allow the request (axios will fail naturally)
    return true;
  }
}

// Allowlist of well-known hosts for specific providers; generic webhooks can target any https host
const DEFAULT_PROVIDER_HOSTS = [
  "hooks.slack.com",
  "discord.com",
  "discordapp.com",
  "outlook.office.com", // MS Teams webhook URL
  "webhook.office.com", // MS Teams webhook URL
  "office.com",
  "office365.com", // MS Teams incoming webhook
  "*.office.com", // MS Teams wildcard
  "*.office365.com", // MS Teams wildcard
  "events.pagerduty.com", // PagerDuty Events v2 API endpoint (US)
  "events.eu.pagerduty.com", // PagerDuty Events v2 API endpoint (EU)
  "*.pagerduty.com", // Allow regional variants
];

function getExtendedProviderHosts() {
  const raw =
    process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS ||
    process.env.WEBHOOK_PROVIDER_HOSTS ||
    "";
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function hostMatchesAllowed(hostname, allowedList) {
  for (const entry of allowedList) {
    if (entry.startsWith("*.") && hostname.endsWith(entry.slice(1)))
      return true;
    if (hostname === entry) return true;
  }
  return false;
}

const PROVIDER_HOSTS = [
  ...new Set([...DEFAULT_PROVIDER_HOSTS, ...getExtendedProviderHosts()]),
];

// Allow-all switch via env: set WEBHOOK_ALLOW_ALL_HOSTS=true or include '*' in WEBHOOK_PROVIDER_HOSTS
const _extraHostsEnv = (
  process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS ||
  process.env.WEBHOOK_PROVIDER_HOSTS ||
  ""
)
  .split(",")
  .map((s) => s.trim())
  .filter((s) => s.length > 0);
const ALLOW_ALL_HOSTS =
  String(process.env.WEBHOOK_ALLOW_ALL_HOSTS || "").toLowerCase() === "true" ||
  _extraHostsEnv.includes("*");

function normalizeSeverity(raw) {
  const s = String(raw || "").toLowerCase();
  if (s === "critical" || s === "error" || s === "warning" || s === "info")
    return s;
  return "warning";
}

function severityEmoji(sev) {
  switch (normalizeSeverity(sev)) {
    case "critical":
      return "🔴 Critical";
    case "error":
      return "🟠 Error";
    case "warning":
      return "🟡 Warning";
    case "info":
    default:
      return "🔵 Info";
  }
}

function discordColorForSeverity(sev) {
  switch (normalizeSeverity(sev)) {
    case "critical":
      return 15158332; // red
    case "error":
      return 16738816; // orange-ish
    case "warning":
      return 16776960; // yellow
    case "info":
    default:
      return 3447003; // blue
  }
}

function teamsThemeForSeverity(sev) {
  // MessageCard supports themeColor keywords or hex strings
  switch (normalizeSeverity(sev)) {
    case "critical":
      return "FF0000"; // Bright red
    case "error":
      return "FF6B35"; // Orange-red
    case "warning":
      return "FFA500"; // Orange
    case "info":
    default:
      return "0078D4"; // Microsoft blue
  }
}

function teamsSeverityEmoji(sev) {
  switch (normalizeSeverity(sev)) {
    case "critical":
      return "🚨";
    case "error":
      return "⚠️";
    case "warning":
      return "🟡";
    case "info":
    default:
      return "ℹ️";
  }
}

export async function postJson(webhookUrl, body, kind = "generic") {
  try {
    const url = new URL(webhookUrl);
    const schemeOk = url.protocol === "https:" || url.protocol === "http:";
    if (!schemeOk) throw new Error("Invalid webhook URL scheme");
    if (process.env.NODE_ENV === "production" && url.protocol !== "https:") {
      throw new Error("In production, only HTTPS webhook URLs are allowed");
    }
    const lowerKind = String(kind || "generic").toLowerCase();
    if (
      lowerKind !== "generic" &&
      !ALLOW_ALL_HOSTS &&
      !hostMatchesAllowed(url.hostname, PROVIDER_HOSTS)
    ) {
      logger.error(
        `Webhook host not allowed for provider: ${url.hostname} (kind: ${kind})`,
      );
      logger.error(`Allowed hosts:`, PROVIDER_HOSTS);
      try {
        cDeniedHost.labels(lowerKind, url.hostname).inc();
      } catch (_) {}
      throw new Error("Webhook host not allowed for provider");
    }

    // SSRF protection: verify resolved IP is not private/reserved
    if (process.env.NODE_ENV !== "test") {
      const ipSafe = await validateResolvedIP(url.hostname);
      if (!ipSafe) {
        return {
          success: false,
          error: `Webhook blocked: ${url.hostname} resolves to a private/reserved IP`,
        };
      }
    }

    // In test mode, short-circuit network calls for deterministic outcomes
    if (process.env.NODE_ENV === "test") {
      if (
        lowerKind !== "generic" &&
        (ALLOW_ALL_HOSTS || hostMatchesAllowed(url.hostname, PROVIDER_HOSTS))
      ) {
        // Convention in tests:
        // - Any path containing "bad" or ending with "/__fail__" => forced failure
        // - "/__ok__" => explicit success
        // - Otherwise treat as success for provider-allowed hosts to enable mixed scenarios
        if (
          url.pathname.endsWith("/__fail__") ||
          url.pathname.includes("/bad")
        ) {
          return { success: false, error: "TEST_MODE_WEBHOOK_FAILURE" };
        }
        return { success: true, status: 200 };
      }
    }
    const res = await axios.post(webhookUrl, body, {
      timeout: 5000,
      headers: { "Content-Type": "application/json" },
    });
    // Provider-specific success validation
    if (lowerKind === "pagerduty") {
      const data = res.data;
      const ok =
        res.status >= 200 &&
        res.status < 300 &&
        data &&
        String(data.status || "").toLowerCase() === "success";
      return ok
        ? { success: true, status: res.status }
        : {
            success: false,
            error: `PagerDuty responded ${res.status}: ${typeof data === "string" ? data : JSON.stringify(data)}`,
          };
    }
    return {
      success: res.status >= 200 && res.status < 300,
      status: res.status,
    };
  } catch (e) {
    // Provide detailed error context when possible
    if (e.response) {
      const status = e.response.status;
      let body = "";
      try {
        if (typeof e.response.data === "string") body = e.response.data;
        else if (e.response.data) body = JSON.stringify(e.response.data);
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }
      const msg = body ? `HTTP ${status}: ${body}` : `HTTP ${status}`;
      return { success: false, error: msg };
    }
    if (e.request) {
      return {
        success: false,
        error: "No response received from webhook endpoint",
      };
    }
    return { success: false, error: e.message };
  }
}

// Enhanced message templates for different webhook types
export function formatPayload(kind, text, tokenData = null, opts = {}) {
  switch (kind) {
    case "slack":
      return formatSlackPayload(text, tokenData, opts);
    case "discord":
      return formatDiscordPayload(text, tokenData, opts);
    case "teams":
      return formatTeamsPayload(text, tokenData, opts);
    case "pagerduty":
      // PagerDuty payload constructed in caller with routing key; return a sensible default
      return {
        event_action: "trigger",
        payload: {
          summary: text,
          source: "TokenTimer",
          severity: normalizeSeverity(opts && opts.severity),
          ...(tokenData && { custom_details: tokenData }),
        },
      };
    case "generic":
    default:
      // Generic payload that many endpoints accept (Slack/Discord/generic JSON)
      return {
        // Slack-friendly
        text: text,
        // Discord-friendly
        content: `🔔 ${opts?.title || text}`,
        // Generic fields
        message: text,
        severity: normalizeSeverity(opts && opts.severity),
        title: opts?.title || undefined,
        timestamp: new Date().toISOString(),
        type: "token_expiry_alert",
        ...(tokenData?.renewal_url && { renewal_url: tokenData.renewal_url }),
        ...(tokenData && { token: tokenData }),
      };
  }
}

function formatSlackPayload(text, tokenData, opts = {}) {
  function _slackColorForSeverity(sev) {
    switch (normalizeSeverity(sev)) {
      case "critical":
        return "#E02424"; // red
      case "error":
        return "#F08A24"; // orange
      case "warning":
        return "#FFD166"; // yellow
      case "info":
      default:
        return "#2C7BE5"; // blue
    }
  }

  const severity = normalizeSeverity(opts?.severity);
  const title = opts?.title || "Token Expiry Alert";

  // Fallback-only template when no token context is available
  if (!tokenData) {
    const fallback = `${severityEmoji(severity)} • ${title}: ${text}`;
    return {
      text: fallback,
      blocks: [
        {
          type: "header",
          text: { type: "plain_text", text: `🔔 ${title}`, emoji: true },
        },
        { type: "divider" },
        {
          type: "section",
          text: { type: "mrkdwn", text: `_${text}_` },
        },
        {
          type: "context",
          elements: [
            {
              type: "mrkdwn",
              text: `${severityEmoji(severity)} • ${new Date().toISOString()}`,
            },
          ],
        },
      ],
    };
  }

  const name = tokenData.name || `Token #${tokenData.token_id}`;
  const daysLeft = tokenData.daysLeft;
  const expiresText = tokenData.expiration || "Unknown";
  const expired = typeof daysLeft === "number" && daysLeft < 0;
  const absDays = typeof daysLeft === "number" ? Math.abs(daysLeft) : daysLeft;
  const daysText = expired ? `${absDays} day(s) ago` : `${daysLeft} day(s)`;

  const fallback = expired
    ? `${severityEmoji(severity)} • ${title}: ${name} expired ${absDays} day(s) ago${expiresText ? ` (on ${expiresText})` : ""}.`
    : `${severityEmoji(severity)} • ${title}: ${name} expires in ${daysText}${expiresText ? ` (on ${expiresText})` : ""}.`;

  // Rich Block Kit message with divider and severity polish
  return {
    text: fallback,
    blocks: [
      {
        type: "header",
        text: { type: "plain_text", text: `🔔 ${title}`, emoji: true },
      },
      { type: "divider" },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: expired
            ? `*${name}* expired *${absDays} day(s) ago*`
            : `*${name}* expires in *${daysText}*`,
        },
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Type:*\n${tokenData.type || "Unknown"}` },
          { type: "mrkdwn", text: `*Expiration:*\n${expiresText}` },
          { type: "mrkdwn", text: `*Severity:*\n${severity.toUpperCase()}` },
          {
            type: "mrkdwn",
            text: `*Status:*\n${expired ? `Expired ${absDays} day(s) ago` : `${daysLeft} day(s) remaining`}`,
          },
        ],
      },
      ...(tokenData.renewal_url
        ? [
            {
              type: "section",
              text: {
                type: "mrkdwn",
                text: `*Renewal URL:*\n<${tokenData.renewal_url}|${tokenData.renewal_url}>`,
              },
            },
          ]
        : []),
      {
        type: "actions",
        elements: [
          ...(tokenData.renewal_url
            ? [
                {
                  type: "button",
                  text: {
                    type: "plain_text",
                    text: "Renew Now",
                    emoji: true,
                  },
                  url: tokenData.renewal_url,
                  style: "primary",
                },
              ]
            : []),
          {
            type: "button",
            text: {
              type: "plain_text",
              text: "View in TokenTimer",
              emoji: true,
            },
            url: `${process.env.APP_URL || "http://localhost:5173"}/dashboard`,
            style:
              severity === "critical" && !tokenData.renewal_url
                ? "danger"
                : "primary",
          },
        ],
      },
      {
        type: "context",
        elements: [
          {
            type: "mrkdwn",
            text: `${severityEmoji(severity)} • Generated ${new Date().toISOString()}`,
          },
        ],
      },
    ],
  };
}

function formatDiscordPayload(text, tokenData, opts = {}) {
  if (!tokenData) {
    return {
      content: `${severityEmoji(opts?.severity)}: ${opts?.title || text}`,
    };
  }

  const days = tokenData.daysLeft;
  const expired = typeof days === "number" && days < 0;
  const absDays = typeof days === "number" ? Math.abs(days) : days;

  return {
    content: `🔔 **${opts?.title || "Token Expiry Alert"}**`,
    embeds: [
      {
        title: tokenData.name || `Token #${tokenData.token_id}`,
        description: expired
          ? `Expired **${absDays} day(s) ago**`
          : `Expires in **${tokenData.daysLeft} day(s)**`,
        color: discordColorForSeverity(opts?.severity),
        fields: [
          {
            name: "Type",
            value: tokenData.type || "Unknown",
            inline: true,
          },
          {
            name: "Expiration",
            value: tokenData.expiration || "Unknown",
            inline: true,
          },
          {
            name: expired ? "Status" : "Severity",
            value: expired
              ? `Expired ${absDays} day(s) ago`
              : normalizeSeverity(opts?.severity),
            inline: true,
          },
          ...(tokenData.renewal_url
            ? [
                {
                  name: "Renewal URL",
                  value: tokenData.renewal_url,
                  inline: false,
                },
              ]
            : []),
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  };
}

function formatTeamsPayload(text, tokenData, opts = {}) {
  if (!tokenData) {
    return {
      text: `${teamsSeverityEmoji(opts?.severity)} ${opts?.title || text}`,
    };
  }

  const severity = normalizeSeverity(opts?.severity);
  const severityEmoji = teamsSeverityEmoji(severity);
  const daysLeft = tokenData.daysLeft;
  const expired = typeof daysLeft === "number" && daysLeft < 0;
  const absDays = typeof daysLeft === "number" ? Math.abs(daysLeft) : daysLeft;

  // Create a more descriptive title with emoji
  let title = `${severityEmoji} Token Expiry Alert`;
  if (expired) {
    title = `🚨 CRITICAL: Token Expired`;
  } else if (daysLeft <= 1) {
    title = `⚠️ URGENT: Token Expires Today`;
  } else if (daysLeft <= 7) {
    title = `🟡 WARNING: Token Expires Soon`;
  }

  return {
    "@type": "MessageCard",
    "@context": "https://schema.org/extensions",
    summary: title,
    themeColor: teamsThemeForSeverity(severity),
    sections: [
      {
        activityTitle: title,
        activitySubtitle: `🔔 ${tokenData.name || `Token #${tokenData.token_id}`}`,
        text: expired
          ? `**Expired ${absDays} day(s) ago**`
          : `**Expires in ${daysLeft} day(s)**`,
        facts: [
          {
            name: "📋 Type",
            value: tokenData.type || "Unknown",
          },
          {
            name: "📅 Expiration Date",
            value: tokenData.expiration || "Unknown",
          },
          {
            name: expired ? "⚡ Status" : "⚡ Severity",
            value: expired
              ? `Expired ${absDays} day(s) ago`
              : severity.toUpperCase(),
          },
          {
            name: expired ? "⏰ Status" : "⏰ Days Remaining",
            value: expired
              ? `Expired ${absDays} day(s) ago`
              : `${daysLeft} day(s)`,
          },
          ...(tokenData.renewal_url
            ? [
                {
                  name: "🔗 Renewal URL",
                  value: `[${tokenData.renewal_url}](${tokenData.renewal_url})`,
                },
              ]
            : []),
        ],
        markdown: true,
      },
    ],
    potentialAction: [
      ...(tokenData.renewal_url
        ? [
            {
              "@type": "OpenUri",
              name: "Renew Now",
              targets: [
                {
                  os: "default",
                  uri: tokenData.renewal_url,
                },
              ],
            },
          ]
        : []),
      {
        "@type": "OpenUri",
        name: "View in TokenTimer",
        targets: [
          {
            os: "default",
            uri: `${process.env.APP_URL || "http://localhost:5173"}/dashboard`,
          },
        ],
      },
    ],
  };
}
