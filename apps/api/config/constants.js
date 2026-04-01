const { parseLimits } = require("../services/planLimits");
const { logger } = require("../utils/logger");

const normalizeUrl = (value) => String(value || "").replace(/\/$/, "");
const APP_URL = normalizeUrl(process.env.APP_URL) || "http://localhost:5173";
const API_URL = normalizeUrl(process.env.API_URL) || "http://localhost:4000";

// Core: no usage limits. All features available.
const TOKEN_LIMITS = parseLimits(process.env.PLAN_TOKEN_LIMITS, {
  oss: Number.POSITIVE_INFINITY,
});

const ALERT_LIMITS = parseLimits(process.env.PLAN_ALERT_LIMITS, {
  oss: Number.POSITIVE_INFINITY,
});

/**
 * Test a webhook URL by sending a test payload.
 * Supports Slack, Discord, Teams, PagerDuty, and generic webhook targets.
 *
 * @param {string} url - Webhook URL to test
 * @param {string} kind - Webhook type: "slack", "discord", "teams", "pagerduty", "generic"
 * @param {string|null} routingKey - PagerDuty routing key (required for pagerduty kind)
 * @param {AbortSignal} [signal] - Optional abort signal for request cancellation
 * @returns {Promise<{success: boolean, error?: string}>}
 */
async function testWebhookUrl(
  url,
  kind = "generic",
  routingKey = null,
  signal = undefined,
) {
  try {
    const target = new URL(url);
    if (!/^https?:$/.test(target.protocol))
      return { success: false, error: "Webhook URL must be http(s)" };
    const DEFAULT_PROVIDER_HOSTS = [
      "hooks.slack.com",
      "discord.com",
      "discordapp.com",
      "outlook.office.com",
      "webhook.office.com",
      "office.com",
      "office365.com",
      "events.eu.pagerduty.com",
      "*.office.com",
      "*.office365.com",
      "events.pagerduty.com",
      "*.pagerduty.com",
    ];
    const hostMatchesAllowed = (hostname, allowedList) => {
      for (const entry of allowedList) {
        if (entry.startsWith("*.") && hostname.endsWith(entry.slice(1)))
          return true;
        if (hostname === entry) return true;
      }
      return false;
    };
    const lowerKind = String(kind || "generic").toLowerCase();
    if (
      lowerKind !== "generic" &&
      !hostMatchesAllowed(target.hostname, DEFAULT_PROVIDER_HOSTS)
    ) {
      return { success: false, error: "Webhook host not allowed for provider" };
    }
    if (lowerKind === "pagerduty") {
      const key = String(routingKey || "").trim();
      if (!key || key.length !== 32 || !/^[A-Za-z0-9]{32}$/.test(key)) {
        return { success: false, error: "Invalid PagerDuty routing key" };
      }
    }
    const text = "This is a test message from TokenTimer";
    let payload;
    if (lowerKind === "slack") {
      payload = { text };
    } else if (lowerKind === "discord") {
      payload = { content: `\u{1F514} ${text}` };
    } else if (lowerKind === "teams") {
      payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        summary: "TokenTimer Test",
        themeColor: "0078D4",
        sections: [{ activityTitle: text }],
      };
    } else if (lowerKind === "pagerduty") {
      payload = {
        routing_key: routingKey,
        event_action: "trigger",
        payload: {
          summary: text,
          source: "TokenTimer",
          severity: "info",
          timestamp: new Date().toISOString(),
        },
      };
    } else {
      payload = { message: text, severity: "info" };
    }
    const controller = new AbortController();
    const to = setTimeout(() => controller.abort(), 5000);
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: signal || controller.signal,
    });
    clearTimeout(to);
    const { status } = resp;
    const bodyText = await resp.text().catch(() => "");
    if (lowerKind === "slack") {
      if (status === 200 && bodyText.trim().toLowerCase() === "ok")
        return { success: true };
      return {
        success: false,
        error: `Slack responded ${status}: ${bodyText}`,
      };
    }
    if (lowerKind === "discord") {
      if (status === 204 || status === 200) return { success: true };
      return {
        success: false,
        error: `Discord responded ${status}: ${bodyText}`,
      };
    }
    if (lowerKind === "teams") {
      if (status === 200) return { success: true };
      return {
        success: false,
        error: `Teams responded ${status}: ${bodyText}`,
      };
    }
    if (lowerKind === "pagerduty") {
      let parsed = {};
      try {
        parsed = JSON.parse(bodyText || "{}");
      } catch (_err) {
        logger.debug("Parse failed", { error: _err.message });
      }
      const ok =
        status >= 200 &&
        status < 300 &&
        String(parsed.status || "").toLowerCase() === "success";
      return ok
        ? { success: true }
        : {
            success: false,
            error: `PagerDuty responded ${status}: ${bodyText || "no body"}`,
          };
    }
    return status >= 200 && status < 300
      ? { success: true }
      : { success: false, error: `HTTP ${status}: ${bodyText}` };
  } catch (e) {
    if (e.name === "AbortError")
      return { success: false, error: "Timed out (5s)" };
    return { success: false, error: e.message };
  }
}

module.exports = {
  APP_URL,
  API_URL,
  TOKEN_LIMITS,
  ALERT_LIMITS,
  testWebhookUrl,
};
