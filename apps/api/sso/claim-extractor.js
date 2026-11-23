/**
 * Generic claim extractor used by both the OIDC and SAML strategies.
 *
 * Admins configure each claim as a comma-separated path string in
 * SSO Providers, e.g. for email under SAML:
 *
 *   "email,nameID,urn:oid:0.9.2342.19200300.100.1.3"
 *
 * Each path is tried in order against both `profile._json` (the raw
 * IdP-emitted payload in `profile._json`) and `profile`
 * itself (the normalised passport profile, used by both strategies).
 * Empty / null values fall through to the next path. The first non-empty
 * value wins.
 *
 * Dot navigation is supported, so paths like
 * `https://hasura.io/jwt/claims.x-hasura-allowed-roles` walk into nested
 * objects. Numeric segments index into arrays.
 *
 * Two entry points:
 *   - extractFirst(profile, paths)  -> string | null
 *   - extractAll(profile, paths)    -> string[]
 *
 * `extractAll` is used for group claims where multiple sources may carry
 * an array; results are flattened, trimmed, deduped (case-insensitive),
 * and returned in order of first appearance.
 *
 * This module is pure (no DB, no I/O) and trivially unit-testable.
 */

"use strict";

function splitPaths(paths) {
  if (Array.isArray(paths)) {
    return paths.map((p) => String(p || "").trim()).filter(Boolean);
  }
  return String(paths || "")
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);
}

function navigate(root, path) {
  if (!root || typeof root !== "object") return undefined;
  // Direct hit (common for SAML attributes named with dots).
  if (Object.prototype.hasOwnProperty.call(root, path)) {
    return root[path];
  }
  const segments = path.split(".");
  let cursor = root;
  for (const segment of segments) {
    if (cursor === null || cursor === undefined) return undefined;
    if (typeof cursor !== "object") return undefined;
    if (Array.isArray(cursor) && /^\d+$/.test(segment)) {
      cursor = cursor[Number(segment)];
      continue;
    }
    cursor = cursor[segment];
  }
  return cursor;
}

function isEmpty(value) {
  if (value === null || value === undefined) return true;
  if (typeof value === "string" && value.trim() === "") return true;
  if (Array.isArray(value) && value.length === 0) return true;
  return false;
}

function toStringList(value) {
  if (value === null || value === undefined) return [];
  if (Array.isArray(value)) {
    return value
      .flatMap((entry) => toStringList(entry))
      .filter((s) => s.length > 0);
  }
  if (typeof value === "object") {
    if (typeof value.value === "string") return toStringList(value.value);
    return [];
  }
  const str = String(value).trim();
  if (!str) return [];
  return str.split(/[;,]/).map((s) => s.trim()).filter(Boolean);
}

function attributeRoots(profile) {
  if (!profile || typeof profile !== "object") return [];
  const roots = [];
  if (profile._json && typeof profile._json === "object") roots.push(profile._json);
  roots.push(profile);
  if (profile.attributes && typeof profile.attributes === "object") {
    roots.push(profile.attributes);
  }
  return roots;
}

function lookupInRoot(root, path) {
  if (!root || typeof root !== "object") return undefined;
  const direct = navigate(root, path);
  if (!isEmpty(direct)) return direct;
  const lc = String(path || "").toLowerCase();
  if (!lc) return undefined;
  for (const [key, value] of Object.entries(root)) {
    if (String(key).toLowerCase() === lc && !isEmpty(value)) {
      return value;
    }
  }
  const pathLooksQualified =
    lc.includes("/") || lc.includes(":") || lc.startsWith("urn:");
  if (pathLooksQualified) {
    const leaf = lc.split("/").pop();
    if (leaf) {
      for (const [key, value] of Object.entries(root)) {
        const keyLc = String(key).toLowerCase();
        if (
          (keyLc === leaf || keyLc.endsWith(`/${leaf}`)) &&
          !isEmpty(value)
        ) {
          return value;
        }
      }
    }
  }
  return undefined;
}

function lookup(profile, path) {
  if (!path) return undefined;
  for (const root of attributeRoots(profile)) {
    const value = lookupInRoot(root, path);
    if (!isEmpty(value)) return value;
  }
  return undefined;
}

/**
 * First non-empty value along the path chain, or `null`.
 * Always returns a string (for primitives) or `null`.
 */
function extractFirst(profile, paths) {
  for (const path of splitPaths(paths)) {
    const value = lookup(profile, path);
    if (isEmpty(value)) continue;
    if (typeof value === "object") {
      if (Array.isArray(value)) {
        const flat = toStringList(value);
        if (flat.length > 0) return flat[0];
        continue;
      }
      if (typeof value.value === "string" && value.value.trim()) {
        return value.value.trim();
      }
      continue;
    }
    const str = String(value).trim();
    if (str) return str;
  }
  return null;
}

/**
 * Union of all matched paths, deduped case-insensitively.
 * Comma- and semicolon-separated strings are split.
 */
function extractAll(profile, paths) {
  const seen = new Set();
  const result = [];
  for (const path of splitPaths(paths)) {
    const value = lookup(profile, path);
    if (isEmpty(value)) continue;
    for (const item of toStringList(value)) {
      const lc = item.toLowerCase();
      if (seen.has(lc)) continue;
      seen.add(lc);
      result.push(item);
    }
  }
  return result;
}

module.exports = {
  extractFirst,
  extractAll,
  // exported for unit tests
  splitPaths,
  navigate,
  toStringList,
};
