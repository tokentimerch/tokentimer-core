/**
 * Webhook SSRF safety helpers for the API.
 *
 * Mirrors the worker-side logic in apps/worker/src/notify/webhooks.js so the
 * "Test" button and save-time validation behave exactly like real alert
 * delivery. Keep the two implementations in sync when changing ranges.
 */
const dns = require("dns/promises");
const { logger } = require("./logger");

/**
 * Check whether an IPv4 address falls in a private/reserved range.
 * Prevents SSRF via IP-literal URLs or DNS rebinding.
 */
function isPrivateOrReservedIP(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => isNaN(n) || n < 0 || n > 255))
    return false; // not IPv4, let it through
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
 * Self-hosted escape hatch for the private/reserved IP block.
 * TokenTimer Cloud must never set this; for self-hosted deployments whose
 * alert targets (e.g. RocketChat) live on RFC1918 addresses, setting
 * WEBHOOK_ALLOW_PRIVATE_IPS=true permits webhook delivery to private and
 * reserved IP ranges. Read at call time so tests see the current value.
 */
function allowPrivateWebhookIPs() {
  return (
    String(process.env.WEBHOOK_ALLOW_PRIVATE_IPS || "").toLowerCase() ===
    "true"
  );
}

/**
 * Whether the private/reserved IP check should run at all.
 *
 * Enforcement is skipped in test mode (NODE_ENV=test) so integration suites
 * can post to local mock servers, unless WEBHOOK_ENFORCE_PRIVATE_IP_CHECK=true
 * explicitly turns it on (used by the integration test stack to exercise the
 * SSRF guard). WEBHOOK_ALLOW_PRIVATE_IPS=true always disables the check.
 */
function shouldEnforcePrivateIpCheck() {
  if (allowPrivateWebhookIPs()) return false;
  if (
    String(
      process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK || "",
    ).toLowerCase() === "true"
  ) {
    return true;
  }
  return process.env.NODE_ENV !== "test";
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
    // DNS resolution failed; allow the request (fetch will fail naturally)
    return true;
  }
}

module.exports = {
  isPrivateOrReservedIP,
  allowPrivateWebhookIPs,
  shouldEnforcePrivateIpCheck,
  validateResolvedIP,
};
