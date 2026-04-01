/**
 * Network configuration for TokenTimer
 *
 * Supports offline mode with allowlist for air-gapped deployments.
 *
 * TODO: Wire getNetworkConfig / isAllowedHost into the API and worker code.
 * Currently these functions are exported but not imported by any running
 * application code. The API uses its own inline allowlist in
 * apps/api/config/constants.js (testWebhookUrl). Once wired up, re-add
 * OFFLINE_MODE / OUTBOUND_ALLOWLIST to the Helm chart configmap and values.
 */

/**
 * Get network configuration
 * @returns {Object} Network configuration object with offline mode, allowlist, analytics, auth, and webhook settings
 */
export function getNetworkConfig() {
  const offlineMode = process.env.OFFLINE_MODE === "true";

  // Parse allowlist: OUTBOUND_ALLOWLIST=10.0.0.0/8,*.corp.local,smtp.internal
  const allowlistRaw = process.env.OUTBOUND_ALLOWLIST || "";
  const allowlist = allowlistRaw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  return {
    offlineMode,
    allowlist,

    // Convenience checks
    updateCheckEnabled:
      !offlineMode && process.env.UPDATE_CHECK_ENABLED !== "false",

    // Webhook settings
    webhookAllowAllHosts: process.env.WEBHOOK_ALLOW_ALL_HOSTS === "true",
    webhookProviderHosts: (process.env.WEBHOOK_PROVIDER_HOSTS || "")
      .split(",")
      .filter(Boolean),
    webhookExtraHosts: (process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS || "")
      .split(",")
      .filter(Boolean),
  };
}

/**
 * Check if a hostname is allowed for outbound connections
 * @param {string} hostname - Hostname to check
 * @returns {boolean}
 */
export function isAllowedHost(hostname) {
  const { offlineMode, allowlist } = getNetworkConfig();

  // No restrictions if not in offline mode
  if (!offlineMode) return true;

  // Block all if no allowlist
  if (allowlist.length === 0) return false;

  return allowlist.some((pattern) => matchPattern(hostname, pattern));
}

/**
 * Match a hostname against a pattern
 * @param {string} hostname
 * @param {string} pattern - Can be exact, wildcard (*.domain), or CIDR
 */
function matchPattern(hostname, pattern) {
  // Wildcard pattern: *.corp.local
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(1); // .corp.local
    return hostname.endsWith(suffix) || hostname === pattern.slice(2);
  }

  // CIDR pattern: 10.0.0.0/8
  if (pattern.includes("/")) {
    return isInCIDR(hostname, pattern);
  }

  // Exact match
  return hostname === pattern;
}

/**
 * Check if an IP address is within a CIDR range
 * @param {string} ip - IP address
 * @param {string} cidr - CIDR notation (e.g., 10.0.0.0/8)
 */
function isInCIDR(ip, cidr) {
  // Only handle IPv4 for simplicity
  const ipParts = ip.split(".").map(Number);
  if (ipParts.length !== 4 || ipParts.some(isNaN)) {
    return false; // Not a valid IPv4
  }

  const [range, bits] = cidr.split("/");
  const rangeParts = range.split(".").map(Number);
  if (rangeParts.length !== 4) return false;

  const mask = parseInt(bits, 10);
  if (isNaN(mask) || mask < 0 || mask > 32) return false;

  // Convert to 32-bit integers
  const ipInt =
    (ipParts[0] << 24) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
  const rangeInt =
    (rangeParts[0] << 24) +
    (rangeParts[1] << 16) +
    (rangeParts[2] << 8) +
    rangeParts[3];

  // Create mask
  const maskInt = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;

  return (ipInt & maskInt) === (rangeInt & maskInt);
}

/**
 * Get default webhook provider hosts
 * @returns {string[]} Array of default webhook provider hostnames and patterns
 */
export function getDefaultWebhookHosts() {
  return [
    "hooks.slack.com",
    "discord.com",
    "discordapp.com",
    "outlook.office.com",
    "webhook.office.com",
    "*.office.com",
    "*.office365.com",
    "events.pagerduty.com",
    "events.eu.pagerduty.com",
    "*.pagerduty.com",
  ];
}

/**
 * Check if a webhook URL is allowed
 * @param {string} url - Webhook URL
 * @returns {boolean} True if the webhook URL is allowed, false otherwise
 */
export function isWebhookAllowed(url) {
  const config = getNetworkConfig();

  // Allow all if configured
  if (config.webhookAllowAllHosts) return true;

  try {
    const { hostname } = new URL(url);

    // Check against allowed hosts
    const allowedHosts = [
      ...getDefaultWebhookHosts(),
      ...config.webhookProviderHosts,
      ...config.webhookExtraHosts,
    ];

    return allowedHosts.some((pattern) => matchPattern(hostname, pattern));
  } catch {
    return false;
  }
}
