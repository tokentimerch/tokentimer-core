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
 * Whether this Node.js version honors NODE_USE_ENV_PROXY=1 (proxy support
 * for fetch/undici and global proxy env vars). Only supported on 22.21.0+
 * or 24.5.0+ — NOT on any 23.x release, and NOT on 24.0.0-24.4.x.
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
  if (major === 24) return minor > 5 || (minor === 5 && patch >= 0);
  return true; // major >= 25: assume forward compatibility
}

module.exports = {
  parseNodeVersion,
  isNodeUseEnvProxySupported,
};
