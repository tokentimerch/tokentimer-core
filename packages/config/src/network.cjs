"use strict";

const { BlockList, isIP } = require("node:net");
const { domainToASCII } = require("node:url");
const http = require("node:http");
const https = require("node:https");
const { getProxyForUrl } = require("proxy-from-env");

/**
 * Network configuration for TokenTimer
 *
 * Supports offline mode with an explicit allowlist.
 */

/**
 * Get network configuration
 * @returns {Object} Offline mode, outbound allowlist, and webhook policy settings
 */
function getNetworkConfig() {
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
    outboundPolicyEnabled: offlineMode || allowlistRaw.trim() !== "",

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
function isAllowedHost(hostname) {
  const { outboundPolicyEnabled, allowlist } = getNetworkConfig();
  if (!outboundPolicyEnabled) return true;
  const host = normalizeHostname(hostname);
  return host !== "" && allowlist.some((pattern) => matchPattern(host, pattern));
}

const OUTBOUND_POLICY_DENIED = "OUTBOUND_POLICY_DENIED";

function policyError(message = "Destination is blocked by the outbound policy") {
  const error = new Error(message);
  error.code = OUTBOUND_POLICY_DENIED;
  return error;
}

function nativeFetchProxyEnabled() {
  const [major, minor] = process.versions.node.split(".").map(Number);
  const supported = major >= 24 || (major === 22 && minor >= 21);
  return supported && (process.env.NODE_USE_ENV_PROXY === "1" ||
    process.execArgv.includes("--use-env-proxy") ||
    (process.env.NODE_OPTIONS || "").split(/\s+/).includes("--use-env-proxy"));
}

function proxyForUrl(url, mode) {
  const secure = url.protocol === "https:";
  const agentEnv = (secure ? https : http).globalAgent.options.proxyEnv;
  const env = mode === "fetch"
    ? (http.globalAgent.options.proxyEnv ?? https.globalAgent.options.proxyEnv ??
      (nativeFetchProxyEnabled() ? process.env : null))
    : agentEnv;
  if (!env) return mode === "axios" ? getProxyForUrl(url) : "";

  const port = url.port || (secure ? "443" : "80");
  const fetchMode = mode === "fetch";
  const hostname = (fetchMode ? url.hostname : url.hostname.replace(/^\[|\]$/g, "")).toLowerCase();
  const noProxy = (fetchMode ? (env.no_proxy ?? env.NO_PROXY) : (env.no_proxy || env.NO_PROXY)) || "";
  const exclusions = noProxy.toLowerCase().split(fetchMode ? /[\s,]+/ : ",");
  if (noProxy === "*" || exclusions.some((raw) => {
    const entry = raw.trim();
    if (fetchMode) {
      const match = /^(.*):(\d+)$/.exec(entry);
      if (match && Number(match[2]) !== Number(port)) return false;
      const suffix = (match ? match[1] : entry).replace(/^\*?\./, "");
      return hostname === suffix || hostname.endsWith("." + suffix);
    }
    return entry === "*" || entry === hostname ||
      entry === hostname + ":" + port ||
      (entry.startsWith(".") && (hostname === entry.slice(1) || hostname.endsWith(entry))) ||
      (entry.startsWith("*.") && hostname.endsWith(entry.slice(1)));
  })) return "";

  const httpProxy = fetchMode ? (env.http_proxy ?? env.HTTP_PROXY) : (env.http_proxy || env.HTTP_PROXY);
  const httpsProxy = fetchMode ? (env.https_proxy ?? env.HTTPS_PROXY) : (env.https_proxy || env.HTTPS_PROXY);
  return secure ? httpsProxy || (fetchMode ? httpProxy : "") : httpProxy;
}

function assertOutboundUrl(target, { proxyMode = "direct" } = {}) {
  if (!getNetworkConfig().outboundPolicyEnabled) return;
  const url = new URL(target);
  assertOutboundHost(url.hostname);
  if (proxyMode === "direct") return;
  const proxy = proxyForUrl(url, proxyMode);
  if (!proxy) return;

  let proxyHost;
  try {
    proxyHost = new URL(proxy).hostname;
  } catch {
    throw policyError("Configured forward proxy is invalid for the outbound policy");
  }
  if (!isAllowedHost(proxyHost)) {
    throw policyError("Configured forward proxy is blocked by the outbound policy");
  }
}

function isAllowedOutboundUrl(target, options) {
  try {
    assertOutboundUrl(target, options);
    return true;
  } catch (error) {
    if (error.code === OUTBOUND_POLICY_DENIED || error.code === "ERR_INVALID_URL") return false;
    throw error;
  }
}

function assertOutboundHost(hostname) {
  if (!isAllowedHost(hostname)) {
    throw policyError();
  }
}

function normalizeHostname(value) {
  const host = typeof value === "string" ? value.trim().toLowerCase() : "";
  const bare = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  if (bare.includes("%")) return "";
  if (isIP(bare) === 6) {
    return new URL("http://[" + bare + "]").hostname.slice(1, -1);
  }
  if (isIP(bare) === 4) return bare;
  if (!/^[^\s/:?#[\]@\\]+$/.test(bare)) return "";
  return domainToASCII(bare.replace(/\.$/, ""));
}

function matchPattern(hostname, pattern) {
  if (pattern.startsWith("*.")) {
    const domain = normalizeHostname(pattern.slice(2));
    return domain !== "" && (hostname === domain || hostname.endsWith("." + domain));
  }
  if (pattern.includes("/")) return isInCIDR(hostname, pattern);
  return hostname === normalizeHostname(pattern);
}

function isInCIDR(ip, cidr) {
  const [subnet, prefix, ...extra] = cidr.split("/");
  const family = isIP(ip);
  if (!family || family !== isIP(subnet) || subnet.includes("%") || extra.length || !/^\d+$/.test(prefix)) return false;
  const bits = Number(prefix);
  const type = family === 4 ? "ipv4" : "ipv6";
  if (bits > (family === 4 ? 32 : 128)) return false;
  const addresses = new BlockList();
  addresses.addSubnet(subnet, bits, type);
  return addresses.check(ip, type);
}

/**
 * Get default webhook provider hosts
 * @returns {string[]} Array of default webhook provider hostnames and patterns
 */
function getDefaultWebhookHosts() {
  return [
    "hooks.slack.com",
    "discord.com",
    "discordapp.com",
    "outlook.office.com",
    "webhook.office.com",
    "office.com",
    "office365.com",
    "*.office.com",
    "*.office365.com",
    "events.pagerduty.com",
    "events.eu.pagerduty.com",
    "*.pagerduty.com",
    "*.logic.azure.com",
    "*.environment.api.powerplatform.com",
  ];
}

/**
 * Check if a webhook URL is allowed
 * @param {string} url - Webhook URL
 * @returns {boolean} True if the webhook URL is allowed, false otherwise
 */
function isWebhookAllowed(url) {
  const config = getNetworkConfig();

  // Allow all if configured
  try {
    const hostname = normalizeHostname(new URL(url).hostname);
    if (!hostname || !isAllowedHost(hostname)) return false;
    if (config.webhookAllowAllHosts) return true;

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

module.exports = {
  assertOutboundHost,
  assertOutboundUrl,
  getNetworkConfig,
  isAllowedHost,
  isAllowedOutboundUrl,
  getDefaultWebhookHosts,
  isWebhookAllowed,
  OUTBOUND_POLICY_DENIED,
};
