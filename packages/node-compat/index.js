"use strict";

/**
 * Shared Node.js version predicates for the API and worker. Kept as a tiny
 * standalone CJS package (mirrors @tokentimer/log-scrub / webhook-safety)
 * so both the CJS API and the ESM worker can consume the same logic without
 * duplicating semver parsing.
 */

/**
 * Parse a Node.js version string into numeric major/minor/patch parts.
 * Accepts an optional leading "v" (e.g. "v22.21.0" or "22.21.0"). Missing
 * or non-numeric parts fall back to 0.
 */
function parseNodeVersion(versionString) {
  const cleaned = String(versionString || "").replace(/^v/, "");
  const [majorStr, minorStr, patchStr] = cleaned.split(".");
  const toInt = (value) => {
    const n = Number.parseInt(value, 10);
    return Number.isFinite(n) ? n : 0;
  };
  return {
    major: toInt(majorStr),
    minor: toInt(minorStr),
    patch: toInt(patchStr),
  };
}

/**
 * Whether this Node.js version's fetch()/undici honors NODE_USE_ENV_PROXY=1.
 * This is the floor that matters for TokenTimer: the API's webhook Test
 * button and OAuth/SAML callbacks go through fetch. Supported on 22.21.0+
 * or 24.0.0+, not on any 23.x release.
 *
 * Native node:http/node:https (and the --use-env-proxy CLI flag) need a
 * later 24.5.0+ floor instead; see isNodeHttpProxySupported() below. The
 * worker uses axios, which reads HTTP_PROXY/HTTPS_PROXY itself regardless
 * of Node version, so that later floor doesn't gate anything here.
 *
 * @param {string} [nodeVersion] - Defaults to process.version; accepts an
 *   explicit version string so this is unit-testable without mocking
 *   process.version.
 * @returns {boolean}
 */
function isNodeUseEnvProxySupported(nodeVersion = process.version) {
  const { major, minor, patch } = parseNodeVersion(nodeVersion);
  if (major < 22) return false;
  if (major === 22) return minor > 21 || (minor === 21 && patch >= 0);
  if (major === 23) return false;
  return major >= 24; // fetch/undici: NODE_USE_ENV_PROXY works from 24.0.0
}

/**
 * Whether this Node.js version's native node:http/node:https (and the
 * --use-env-proxy CLI flag) honor NODE_USE_ENV_PROXY=1. Needs 22.21.0+ or
 * 24.5.0+, a later floor than isNodeUseEnvProxySupported() above since raw
 * http/https proxy support landed five months after fetch-only support in
 * the 24.x line. Not currently consulted by TokenTimer's own code (the API
 * uses fetch, the worker uses axios); exported for any future consumer that
 * adds a raw http.request()/https.request()-based outbound call.
 *
 * @param {string} [nodeVersion]
 * @returns {boolean}
 */
function isNodeHttpProxySupported(nodeVersion = process.version) {
  const { major, minor, patch } = parseNodeVersion(nodeVersion);
  if (major < 22) return false;
  if (major === 22) return minor > 21 || (minor === 21 && patch >= 0);
  if (major === 23) return false;
  if (major === 24) return minor > 5 || (minor === 5 && patch >= 0);
  return true; // major >= 25: assume forward compatibility
}

module.exports = {
  parseNodeVersion,
  isNodeUseEnvProxySupported,
  isNodeHttpProxySupported,
};
