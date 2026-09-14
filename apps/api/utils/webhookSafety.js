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
};
