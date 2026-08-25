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

module.exports = {
  isPrivateOrReservedIP,
  allowPrivateWebhookIPs,
  shouldEnforcePrivateIpCheck,
  validateResolvedIP,
  DEFAULT_WEBHOOK_PROVIDER_HOSTS,
  getWebhookProviderHosts,
  allowAllWebhookHosts,
  webhookHostAllowed,
};
