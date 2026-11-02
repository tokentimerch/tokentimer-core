"use strict";

/**
 * SSRF guard for user-supplied integration addresses (Vault, GitLab, GitHub,
 * Azure Key Vault). Same classifier and the same default as the webhook
 * guard: private, loopback, link-local and other reserved destinations are
 * refused unless the operator opts in with INTEGRATION_ALLOW_PRIVATE_IPS.
 */
const { isIP } = require("node:net");
const dns = require("node:dns/promises");
const { isPrivateOrReservedIP } = require("./webhookSafety");

const BLOCKED_CODE = "INTEGRATION_PRIVATE_ADDRESS_BLOCKED";

function allowPrivateIntegrationAddresses() {
  return (
    String(process.env.INTEGRATION_ALLOW_PRIVATE_IPS || "").toLowerCase() ===
    "true"
  );
}

/**
 * Enforcement is off in NODE_ENV=test unless
 * INTEGRATION_ENFORCE_PRIVATE_IP_CHECK=true, so suites can use local mocks.
 * INTEGRATION_ALLOW_PRIVATE_IPS=true always disables the check.
 */
function shouldEnforceIntegrationAddressCheck() {
  if (allowPrivateIntegrationAddresses()) return false;
  if (
    String(
      process.env.INTEGRATION_ENFORCE_PRIVATE_IP_CHECK || "",
    ).toLowerCase() === "true"
  ) {
    return true;
  }
  return process.env.NODE_ENV !== "test";
}

function bareHostname(hostname) {
  const value = String(hostname || "")
    .trim()
    .toLowerCase();
  return value.startsWith("[") && value.endsWith("]")
    ? value.slice(1, -1)
    : value;
}

function blockedResult(host) {
  return {
    allowed: false,
    code: BLOCKED_CODE,
    message:
      `The address "${host}" points to a private or internal network, which ` +
      "this server does not connect to by default. If this is a self-hosted " +
      "instance on your own network, ask your administrator to set " +
      "INTEGRATION_ALLOW_PRIVATE_IPS=true.",
  };
}

/**
 * Check a parsed integration URL. Resolution uses the system resolver (the
 * same one the HTTP client uses) and any private answer blocks the address.
 * A name that does not resolve is let through so the scan reports the normal
 * connection error.
 *
 * @param {URL} url
 * @param {{ lookup?: Function }} [options]
 * @returns {Promise<{ allowed: true } | { allowed: false, code: string, message: string }>}
 */
async function checkIntegrationAddress(url, options = {}) {
  if (!shouldEnforceIntegrationAddressCheck()) return { allowed: true };

  const host = bareHostname(url?.hostname);
  if (!host) return { allowed: true };
  if (host === "localhost" || host.endsWith(".localhost")) {
    return blockedResult(host);
  }
  if (isIP(host)) {
    return isPrivateOrReservedIP(host)
      ? blockedResult(host)
      : { allowed: true };
  }

  const lookup = options.lookup || ((name) => dns.lookup(name, { all: true }));
  let answers;
  try {
    answers = await lookup(host);
  } catch (_) {
    return { allowed: true };
  }
  for (const answer of Array.isArray(answers) ? answers : []) {
    if (isPrivateOrReservedIP(answer?.address)) return blockedResult(host);
  }
  return { allowed: true };
}

module.exports = {
  BLOCKED_CODE,
  allowPrivateIntegrationAddresses,
  shouldEnforceIntegrationAddressCheck,
  checkIntegrationAddress,
};
