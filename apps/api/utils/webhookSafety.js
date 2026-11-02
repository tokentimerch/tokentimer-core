/**
 * Webhook SSRF safety helpers for the API.
 *
 * Canonical classification lives in @tokentimer/webhook-safety so the Test
 * button, save-time validation, and worker delivery share one policy.
 */
const { logger } = require("./logger");
const shared = require("@tokentimer/webhook-safety");

const {
  isPrivateOrReservedIP,
  allowPrivateWebhookIPs,
  shouldEnforcePrivateIpCheck,
  DEFAULT_WEBHOOK_PROVIDER_HOSTS,
  getWebhookProviderHosts,
  allowAllWebhookHosts,
  webhookHostAllowed,
  WebhookRequestError,
} = shared;

async function validateResolvedIP(hostname, options = {}) {
  return await shared.validateResolvedIP(hostname, {
    ...options,
    onBlocked(info) {
      logger.warn("SSRF_BLOCKED", {
        hostname: info.hostname,
        resolvedIP: info.resolvedIP,
        reason: "Resolved to private/reserved IP",
      });
      if (typeof options.onBlocked === "function") options.onBlocked(info);
    },
  });
}

async function postWebhook(url, options = {}) {
  return await shared.postWebhook(url, {
    ...options,
    // Match fetch: only honor HTTP(S)_PROXY when NODE_USE_ENV_PROXY is set.
    proxyMode: options.proxyMode || "node-flag",
    onBlocked(info) {
      logger.warn("SSRF_BLOCKED", {
        hostname: info.hostname,
        resolvedIP: info.resolvedIP,
        reason: "Resolved to private/reserved IP",
      });
      if (typeof options.onBlocked === "function") options.onBlocked(info);
    },
  });
}

function validateWebhookConfigurationEntry(entry) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
    return {
      ok: false,
      code: "WEBHOOK_INVALID_URL",
      error: "Each webhook must include an http(s) URL",
    };
  }
  const url = typeof entry.url === "string" ? entry.url.trim() : "";
  if (!url) {
    return {
      ok: false,
      code: "WEBHOOK_INVALID_URL",
      error: "Webhook URL is required",
    };
  }
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return {
      ok: false,
      code: "WEBHOOK_INVALID_URL",
      error: "Invalid webhook URL",
    };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return {
      ok: false,
      code: "WEBHOOK_INVALID_URL",
      error: "Webhook URL must use http or https",
    };
  }
  if (parsed.username || parsed.password) {
    return {
      ok: false,
      code: "WEBHOOK_INVALID_URL",
      error: "Webhook URL must not include credentials",
    };
  }
  const kind = String(entry.kind || "generic").toLowerCase();
  if (kind !== "generic" && !webhookHostAllowed(parsed.hostname)) {
    return {
      ok: false,
      code: "WEBHOOK_HOST_NOT_ALLOWED",
      error: "Webhook host not allowed for provider",
    };
  }
  if (shouldEnforcePrivateIpCheck()) {
    const host = String(parsed.hostname || "").replace(/^\[|\]$/g, "");
    if (host.toLowerCase() === "localhost" || isPrivateOrReservedIP(host)) {
      return {
        ok: false,
        code: "WEBHOOK_PRIVATE_IP_BLOCKED",
        error: "Webhook URL must not target a private or reserved address",
      };
    }
  }
  return { ok: true };
}

function validateWebhookConfiguration(list) {
  if (!Array.isArray(list)) {
    return {
      ok: false,
      code: "VALIDATION_ERROR",
      error: "webhook_urls must be an array",
    };
  }
  for (const entry of list) {
    const checked = validateWebhookConfigurationEntry(entry);
    if (!checked.ok) return checked;
  }
  return { ok: true };
}

module.exports = {
  isPrivateOrReservedIP,
  allowPrivateWebhookIPs,
  shouldEnforcePrivateIpCheck,
  validateResolvedIP,
  DEFAULT_WEBHOOK_PROVIDER_HOSTS,
  getWebhookProviderHosts,
  allowAllWebhookHosts,
  webhookHostAllowed,
  postWebhook,
  WebhookRequestError,
  validateWebhookConfiguration,
  validateWebhookConfigurationEntry,
};
