"use strict";

/**
 * Shared webhook SSRF destination checks for the API and worker.
 *
 * Classifies IPv4 and IPv6 literals (including IPv4-mapped / translated
 * forms), then validates every A and AAAA answer for hostnames. A single
 * private or reserved candidate is enough to reject.
 */
const { isIP } = require("node:net");
const dns = require("node:dns/promises");

function canonicalizeHost(host) {
  let value = String(host || "").trim();
  if (value.startsWith("[") && value.endsWith("]")) {
    value = value.slice(1, -1);
  }
  const zone = value.indexOf("%");
  if (zone !== -1) value = value.slice(0, zone);
  return value;
}

function isPrivateIpv4(a, b) {
  return (
    a === 10 || // 10.0.0.0/8
    (a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12
    (a === 192 && b === 168) || // 192.168.0.0/16
    a === 127 || // 127.0.0.0/8
    (a === 169 && b === 254) || // 169.254.0.0/16
    a === 0 || // 0.0.0.0/8
    (a === 100 && b >= 64 && b <= 127) || // 100.64.0.0/10
    (a === 198 && (b === 18 || b === 19)) // 198.18.0.0/15
  );
}

function parseIpv4Octets(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map((part) => Number(part));
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return octets;
}

function parseGroups(section) {
  if (section === "") return [];
  return section.split(":").filter((group) => group !== "");
}

function ipv6ToBytes(ip) {
  let str = String(ip || "").toLowerCase();
  if (str.split("::").length > 2) return null;

  let ipv4Tail = null;
  const lastColon = str.lastIndexOf(":");
  const after = lastColon === -1 ? str : str.slice(lastColon + 1);
  if (after.includes(".")) {
    ipv4Tail = parseIpv4Octets(after);
    if (!ipv4Tail) return null;
    str = str.slice(0, lastColon + 1);
  }

  const dbl = str.indexOf("::");
  let head;
  let tail;
  if (dbl !== -1) {
    head = str.slice(0, dbl);
    tail = str.slice(dbl + 2);
  } else {
    head = str;
    tail = "";
  }

  const headGroups = parseGroups(head);
  const tailGroups = parseGroups(tail);
  const allGroups = [...headGroups, ...tailGroups];
  if (allGroups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null;

  const needed = 8 - (ipv4Tail ? 2 : 0);
  const missing = needed - headGroups.length - tailGroups.length;
  if (dbl === -1) {
    if (missing !== 0) return null;
  } else if (missing < 0) {
    return null;
  }

  const groups = [
    ...headGroups,
    ...Array(dbl === -1 ? 0 : missing).fill("0"),
    ...tailGroups,
  ];
  if (groups.length !== needed) return null;

  const bytes = [];
  for (const group of groups) {
    const n = parseInt(group, 16);
    bytes.push((n >> 8) & 255, n & 255);
  }
  if (ipv4Tail) bytes.push(...ipv4Tail);
  if (bytes.length !== 16) return null;
  return bytes;
}

function allZero(bytes, start, end) {
  for (let i = start; i < end; i++) {
    if (bytes[i] !== 0) return false;
  }
  return true;
}

function embeddedIpv4(bytes) {
  // IPv4-mapped ::ffff:0:0/96
  if (allZero(bytes, 0, 10) && bytes[10] === 0xff && bytes[11] === 0xff) {
    return bytes.slice(12, 16);
  }
  // IPv4-translated SIIT ::ffff:0:0:0/96
  if (
    allZero(bytes, 0, 8) &&
    bytes[8] === 0xff &&
    bytes[9] === 0xff &&
    bytes[10] === 0 &&
    bytes[11] === 0
  ) {
    return bytes.slice(12, 16);
  }
  // NAT64 well-known prefix 64:ff9b::/96
  if (
    bytes[0] === 0x00 &&
    bytes[1] === 0x64 &&
    bytes[2] === 0xff &&
    bytes[3] === 0x9b &&
    allZero(bytes, 4, 12)
  ) {
    return bytes.slice(12, 16);
  }
  // 6to4 2002::/16 embeds IPv4 in the next 32 bits
  if (bytes[0] === 0x20 && bytes[1] === 0x02) {
    return bytes.slice(2, 6);
  }
  // Deprecated IPv4-compatible ::/96 (excludes :: and ::1, which are
  // classified as IPv6 unspecified/loopback below when not extracted)
  if (
    allZero(bytes, 0, 12) &&
    !(allZero(bytes, 12, 16) || (allZero(bytes, 12, 15) && bytes[15] === 1))
  ) {
    return bytes.slice(12, 16);
  }
  return null;
}

function isPrivateIpv6(bytes) {
  // Unspecified ::/128
  if (allZero(bytes, 0, 16)) return true;
  // Loopback ::1/128
  if (allZero(bytes, 0, 15) && bytes[15] === 1) return true;
  // Multicast ff00::/8
  if (bytes[0] === 0xff) return true;
  // Link-local fe80::/10
  if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80) return true;
  // Unique local fc00::/7
  if ((bytes[0] & 0xfe) === 0xfc) return true;
  // Deprecated site-local fec0::/10
  if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0xc0) return true;
  // Documentation 2001:db8::/32
  if (
    bytes[0] === 0x20 &&
    bytes[1] === 0x01 &&
    bytes[2] === 0x0d &&
    bytes[3] === 0xb8
  ) {
    return true;
  }
  // Discard-only 100::/64
  if (bytes[0] === 0x01 && bytes[1] === 0x00 && allZero(bytes, 2, 8)) {
    return true;
  }
  return false;
}

/**
 * Check whether an IP address falls in a private/reserved range.
 * IPv4-mapped and other IPv4-embedded IPv6 forms are classified as IPv4.
 */
function isPrivateOrReservedIP(ip) {
  const host = canonicalizeHost(ip);
  if (!host) return false;

  const family = isIP(host);
  if (family === 4) {
    const octets = parseIpv4Octets(host);
    if (!octets) return false;
    return isPrivateIpv4(octets[0], octets[1]);
  }

  if (family === 6) {
    const bytes = ipv6ToBytes(host);
    if (!bytes) return true;
    const v4 = embeddedIpv4(bytes);
    if (v4) return isPrivateIpv4(v4[0], v4[1]);
    return isPrivateIpv6(bytes);
  }

  return false;
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

async function collectResolvedAddresses(hostname, resolve4, resolve6) {
  const results = await Promise.allSettled([
    resolve4(hostname),
    resolve6(hostname),
  ]);
  const addresses = [];
  let resolved = false;
  for (const result of results) {
    if (result.status !== "fulfilled") continue;
    const value = result.value;
    if (!Array.isArray(value) || value.length === 0) continue;
    resolved = true;
    addresses.push(...value);
  }
  return { addresses, resolved };
}

/**
 * Resolve a hostname and verify it does not point to a private/reserved IP.
 * Returns true if the host is safe to connect to.
 *
 * Any A or AAAA candidate that violates the policy causes a rejection.
 * DNS failure on both families is tolerated so the HTTP client can fail
 * the request naturally.
 *
 * @param {string} hostname
 * @param {{ resolve4?: Function, resolve6?: Function, onBlocked?: Function }} [options]
 */
async function validateResolvedIP(hostname, options = {}) {
  const host = canonicalizeHost(hostname);
  if (isIP(host)) {
    return !isPrivateOrReservedIP(host);
  }

  const resolve4 = options.resolve4 || ((name) => dns.resolve4(name));
  const resolve6 = options.resolve6 || ((name) => dns.resolve6(name));

  try {
    const { addresses, resolved } = await collectResolvedAddresses(
      host,
      resolve4,
      resolve6,
    );
    if (!resolved) return true;
    for (const addr of addresses) {
      if (isPrivateOrReservedIP(addr)) {
        if (typeof options.onBlocked === "function") {
          options.onBlocked({ hostname: host, resolvedIP: addr });
        }
        return false;
      }
    }
    return true;
  } catch (_) {
    return true;
  }
}

module.exports = {
  isPrivateOrReservedIP,
  allowPrivateWebhookIPs,
  shouldEnforcePrivateIpCheck,
  validateResolvedIP,
};
