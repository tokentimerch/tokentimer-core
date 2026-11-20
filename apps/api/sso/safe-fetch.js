"use strict";

const https = require("https");
const http = require("http");
const dns = require("dns").promises;
const net = require("net");
const tls = require("tls");
const { URL } = require("url");

const DEFAULT_TOTAL_TIMEOUT_MS = 20_000;
const MAX_REDIRECTS = 3;

const BLOCKED_HOSTNAMES = new Set([
  "metadata.google.internal",
  "metadata.goog",
]);

const METADATA_IPS = new Set(["169.254.169.254", "fd00:ec2::254"]);

function ipv4ToInt(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isFinite(p) || p < 0 || p > 255)) {
    return null;
  }
  return (
    ((parts[0] << 24) >>> 0) +
    ((parts[1] << 16) >>> 0) +
    ((parts[2] << 8) >>> 0) +
    (parts[3] >>> 0)
  );
}

function ipInCidrV4(ip, network, prefix) {
  const ipInt = ipv4ToInt(ip);
  const netInt = ipv4ToInt(network);
  if (ipInt == null || netInt == null) return false;
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

function parseAllowedCidrs(raw) {
  if (!raw || !String(raw).trim()) return [];
  return String(raw)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function buildAllowPolicy(env = process.env) {
  const { resolveAllowPrivateIdpUrls, resolveAllowedIdpCidrs } = require("./sso-global-settings.js");
  const allowAllPrivate = resolveAllowPrivateIdpUrls(env);
  const allowedCidrs = parseAllowedCidrs(resolveAllowedIdpCidrs(env));
  return {
    allowAllPrivate,
    allowedCidrs,
    ranges: allowAllPrivate,
    localhost: true,
  };
}

function isLocalhostHost(hostname) {
  const h = canonicalDestinationIp(hostname);
  return h === "localhost" || h === "127.0.0.1" || h === "::1";
}

function canonicalDestinationIp(value) {
  const bare = String(value || "").toLowerCase().replace(/^\[|\]$/g, "");
  if (net.isIP(bare) !== 6) return bare;
  const canonical = new URL(`http://[${bare.replace(/%.*$/, "")}]`).hostname.slice(1, -1);
  // URL parsing canonicalizes dotted and expanded IPv6 forms. Apply the same
  // IPv4 policy to mapped, translated and well-known NAT64 destinations.
  const embedded = canonical.match(/^(?:::ffff:|::ffff:0:|64:ff9b::)([0-9a-f]+):([0-9a-f]+)$/);
  if (!embedded) return canonical;
  const high = Number.parseInt(embedded[1], 16);
  const low = Number.parseInt(embedded[2], 16);
  return `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`;
}

function isPrivateOrBlockedIp(ip, allowPrivate) {
  ip = canonicalDestinationIp(ip);
  if (METADATA_IPS.has(ip)) return true;
  const family = net.isIP(ip);
  if (family === 4) {
    const cidrs = [
      ["10.0.0.0", 8],
      ["172.16.0.0", 12],
      ["192.168.0.0", 16],
      ["127.0.0.0", 8],
      ["169.254.0.0", 16],
    ];
    for (const [network, prefix] of cidrs) {
      if (ipInCidrV4(ip, network, prefix)) {
        if (network === "127.0.0.0" && prefix === 8) return !allowPrivate.localhost;
        return !allowPrivate.ranges;
      }
    }
    return false;
  }
  if (family === 6) {
    const lower = ip.toLowerCase();
    if (lower === "::1") return !allowPrivate.localhost;
    if (lower.startsWith("fc") || lower.startsWith("fd")) return !allowPrivate.ranges;
    if (/^fe[89ab]/.test(lower)) return !allowPrivate.ranges;
  }
  return false;
}

function ipMatchesAllowedCidr(ip, cidrs) {
  for (const cidr of cidrs) {
    const [network, prefixStr] = cidr.split("/");
    const prefix = Number(prefixStr);
    if (net.isIP(network) === 4 && net.isIP(ip) === 4 && ipInCidrV4(ip, network, prefix)) {
      return true;
    }
  }
  return false;
}

function allowPrivateUrls() {
  const { resolveAllowPrivateIdpUrls } = require("./sso-global-settings.js");
  return resolveAllowPrivateIdpUrls(process.env);
}

function validateUrlScheme(parsed, env = process.env) {
  const isProduction = env.NODE_ENV === "production";
  if (parsed.protocol === "https:") return;
  if (parsed.protocol === "http:" && !isProduction && isLocalhostHost(parsed.hostname)) {
    return;
  }
  throw safeFetchError("scheme_not_allowed", `URL scheme not allowed: ${parsed.protocol}`);
}

function validateResolvedIp(hostname, ip, allow) {
  ip = canonicalDestinationIp(ip);
  if (BLOCKED_HOSTNAMES.has(String(hostname).toLowerCase())) {
    throw safeFetchError("blocked_host", `Blocked hostname: ${hostname}`);
  }
  if (METADATA_IPS.has(ip)) {
    throw safeFetchError("blocked_ip", `Blocked metadata IP: ${ip}`);
  }
  if (allow.allowedCidrs.length > 0 && ipMatchesAllowedCidr(ip, allow.allowedCidrs)) {
    return;
  }
  const hostnameIsLocalhost = isLocalhostHost(hostname);
  const ipIsLoopback = ip === "127.0.0.1" || ip === "::1";
  if (ipIsLoopback && !hostnameIsLocalhost) {
    throw safeFetchError(
      "blocked_ip",
      `Resolved loopback for non-localhost hostname: ${hostname}`,
    );
  }
  if (isPrivateOrBlockedIp(ip, {
    ranges: allow.allowAllPrivate,
    localhost: allow.localhost && (hostnameIsLocalhost || ipIsLoopback),
  })) {
    throw safeFetchError("blocked_ip", `Blocked private or link-local IP: ${ip}`);
  }
}

function pickPreferredAddress(addresses) {
  if (!addresses?.length) return null;
  const ipv4 = addresses.find(
    (entry) => entry.family === 4 || net.isIP(entry.address) === 4,
  );
  return ipv4 || addresses[0];
}

async function resolveAndValidateHost(parsed, allow) {
  const hostname = parsed.hostname;
  if (BLOCKED_HOSTNAMES.has(hostname.toLowerCase())) {
    throw safeFetchError("blocked_host", `Blocked hostname: ${hostname}`);
  }
  let addresses;
  try {
    addresses = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch (err) {
    throw safeFetchError("dns_failed", `DNS lookup failed: ${err.message}`);
  }
  if (!addresses.length) {
    throw safeFetchError("dns_failed", "DNS lookup returned no addresses");
  }
  for (const entry of addresses) {
    validateResolvedIp(hostname, entry.address, allow);
  }
  return pickPreferredAddress(addresses).address;
}

function safeFetchError(code, message) {
  const err = new Error(message);
  err.code = code;
  err.reason = code;
  return err;
}

/**
 * Operator-facing remediation for guard rejections, appended to logs and
 * provider Test details so "blocked_ip" is not a dead end.
 *
 * @param {string} reason safeFetch reason code
 * @returns {string|null}
 */
function outboundBlockHint(reason) {
  if (reason !== "blocked_ip") return null;
  return (
    "The IdP resolved to a private address, which the SSO outbound guard blocks by default. " +
    "For a private IPv4 IdP, set SSO_ALLOWED_IDP_CIDRS on the API to the intended subnet."
  );
}

async function validateOutboundUrl(urlStr, env = process.env) {
  let parsed;
  try {
    parsed = new URL(urlStr);
  } catch {
    return { ok: false, reason: "invalid_url" };
  }
  try {
    validateUrlScheme(parsed, env);
    const allow = buildAllowPolicy(env);
    await resolveAndValidateHost(parsed, allow);
    return { ok: true, parsed };
  } catch (err) {
    return { ok: false, reason: err.code || err.reason || "blocked" };
  }
}

function resolveSafeFetchTimeoutMs(opts = {}, env = process.env) {
  const explicit = Number(opts.timeoutMs);
  if (Number.isFinite(explicit) && explicit > 0) {
    return Math.trunc(explicit);
  }
  const { resolveIdpHttpTimeoutMs } = require("./sso-global-settings.js");
  return resolveIdpHttpTimeoutMs(env);
}

function performRequest(parsedUrl, resolvedIp, opts) {
  const env = opts.env || process.env;
  const isHttps = parsedUrl.protocol === "https:";
  const hostname = parsedUrl.hostname;
  const port = parsedUrl.port || (isHttps ? 443 : 80);
  const path = `${parsedUrl.pathname}${parsedUrl.search}`;
  const method = opts.method || "GET";
  const headers = { Host: parsedUrl.host, ...(opts.headers || {}) };

  return new Promise((resolve, reject) => {
    let settled = false;
    const chunks = [];
    const timeoutMs = resolveSafeFetchTimeoutMs(opts, env);
    let totalTimer;

    function finish(err, result) {
      if (settled) return;
      settled = true;
      clearTimeout(totalTimer);
      if (err) reject(err);
      else resolve(result);
    }

    const reqOptions = {
      host: resolvedIp,
      port: Number(port),
      path,
      method,
      headers,
      servername: isHttps ? hostname : undefined,
    };
    if (isHttps) {
      reqOptions.rejectUnauthorized = true;
      reqOptions.checkServerIdentity = (_host, cert) =>
        tls.checkServerIdentity(hostname, cert);
    }

    const transport = isHttps ? https : http;
    const req = transport.request(reqOptions, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return finish(null, { redirectTo: res.headers.location, status: res.statusCode });
      }
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        finish(null, {
          status: res.statusCode || 0,
          body: Buffer.concat(chunks).toString("utf8"),
          headers: res.headers,
        });
      });
    });
    req.on("error", (err) => finish(safeFetchError("unreachable", err.message)));
    totalTimer = setTimeout(() => {
      finish(safeFetchError("timeout", "Request timed out"));
      req.destroy();
    }, timeoutMs);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

/**
 * Single outbound HTTP entry point for admin-supplied IdP URLs.
 * Returns { ok, status?, body?, reason? } for provider-test.js compatibility.
 *
 * @param {string} urlString
 * @param {object} [opts]
 */
async function safeFetch(urlString, opts = {}) {
  const env = opts.env || process.env;
  const allow = buildAllowPolicy(env);
  let currentUrl = urlString;
  let redirects = 0;

  while (true) {
    let parsed;
    try {
      parsed = new URL(currentUrl);
      validateUrlScheme(parsed, env);
    } catch (err) {
      return { ok: false, reason: err.code || "invalid_url" };
    }

    let resolvedIp;
    try {
      resolvedIp = await resolveAndValidateHost(parsed, allow);
    } catch (err) {
      return { ok: false, reason: err.code || err.reason || "blocked_ip" };
    }

    let result;
    try {
      result = await performRequest(parsed, resolvedIp, { ...opts, env });
    } catch (err) {
      return { ok: false, reason: err.code || err.reason || "unreachable" };
    }

    if (result.redirectTo && redirects < MAX_REDIRECTS) {
      redirects += 1;
      currentUrl = new URL(result.redirectTo, parsed).toString();
      continue;
    }

    const status = result.status || 0;
    return {
      ok: status >= 200 && status < 300,
      status,
      body: result.body,
      reason: status >= 200 && status < 300 ? undefined : `http_${status}`,
    };
  }
}

function isPrivateIpv4(ip) {
  return isPrivateOrBlockedIp(ip, { ranges: false, localhost: false });
}

function createSafeHttpLookup(env = process.env) {
  return function safeLookup(hostname, options, callback) {
    if (typeof options === "function") {
      callback = options;
    }
    const allow = buildAllowPolicy(env);
    dns.lookup(hostname, { all: true, verbatim: true }, (err, addresses) => {
      if (err) return callback(err);
      try {
        if (!addresses.length) {
          throw safeFetchError("dns_failed", "DNS lookup returned no addresses");
        }
        for (const entry of addresses) {
          validateResolvedIp(hostname, entry.address, allow);
        }
        const preferred = pickPreferredAddress(addresses);
        callback(
          null,
          preferred.address,
          preferred.family === 6 ? 6 : 4,
        );
      } catch (e) {
        callback(e);
      }
    });
  };
}

module.exports = {
  safeFetch,
  validateOutboundUrl,
  buildAllowPolicy,
  validateUrlScheme,
  validateResolvedIp,
  resolveAndValidateHost,
  pickPreferredAddress,
  createSafeHttpLookup,
  isLocalhostHost,
  isPrivateOrBlockedIp,
  isPrivateIpv4,
  ipInCidrV4,
  allowPrivateUrls,
  safeFetchError,
  outboundBlockHint,
  resolveSafeFetchTimeoutMs,
  DEFAULT_TOTAL_TIMEOUT_MS,
  MAX_REDIRECTS,
};
