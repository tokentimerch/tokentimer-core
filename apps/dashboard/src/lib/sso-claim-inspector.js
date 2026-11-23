/**
 * ESM claim extraction for admin claim inspector (local-only, never POSTed).
 */

function splitPaths(paths) {
  if (Array.isArray(paths)) {
    return paths.map(p => String(p || '').trim()).filter(Boolean);
  }
  return String(paths || '')
    .split(',')
    .map(p => p.trim())
    .filter(Boolean);
}

function navigate(root, path) {
  if (!root || typeof root !== 'object') return undefined;
  if (Object.prototype.hasOwnProperty.call(root, path)) {
    return root[path];
  }
  const segments = path.split('.');
  let cursor = root;
  for (const segment of segments) {
    if (cursor === null || cursor === undefined) return undefined;
    if (typeof cursor !== 'object') return undefined;
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
  if (typeof value === 'string' && value.trim() === '') return true;
  if (Array.isArray(value) && value.length === 0) return true;
  return false;
}

function toStringList(value) {
  if (value === null || value === undefined) return [];
  if (Array.isArray(value)) {
    return value
      .flatMap(entry => toStringList(entry))
      .filter(s => s.length > 0);
  }
  if (typeof value === 'object') {
    if (typeof value.value === 'string') return toStringList(value.value);
    return [];
  }
  const str = String(value).trim();
  if (!str) return [];
  return str
    .split(/[;,]/)
    .map(s => s.trim())
    .filter(Boolean);
}

function lookup(profile, path) {
  if (!path) return undefined;
  if (profile && typeof profile === 'object') {
    const fromJson = navigate(profile._json, path);
    if (!isEmpty(fromJson)) return fromJson;
    const fromRoot = navigate(profile, path);
    if (!isEmpty(fromRoot)) return fromRoot;
  }
  return undefined;
}

export function extractFirst(profile, paths) {
  for (const path of splitPaths(paths)) {
    const value = lookup(profile, path);
    if (isEmpty(value)) continue;
    if (typeof value === 'object') {
      if (Array.isArray(value)) {
        const flat = toStringList(value);
        if (flat.length > 0) return flat[0];
        continue;
      }
      if (typeof value.value === 'string' && value.value.trim()) {
        return value.value.trim();
      }
      continue;
    }
    const str = String(value).trim();
    if (str) return str;
  }
  return null;
}

export function extractAll(profile, paths) {
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

const DEFAULT_CLAIM_MAPPING = {
  email: 'email',
  display_name: 'name,preferred_username',
  groups: 'groups',
  subject: 'sub',
};

const ENTRA_GIVEN_NAME_PATHS =
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname,givenName,firstName';
const ENTRA_SURNAME_PATHS =
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname,surname,lastName';

function resolveClaimMapping(type, claimMapping = {}) {
  const nested = claimMapping?.[type];
  if (nested && typeof nested === 'object') {
    return { ...DEFAULT_CLAIM_MAPPING, ...nested };
  }
  if (
    claimMapping?.email ||
    claimMapping?.display_name ||
    claimMapping?.groups ||
    claimMapping?.subject
  ) {
    return { ...DEFAULT_CLAIM_MAPPING, ...claimMapping };
  }
  return { ...DEFAULT_CLAIM_MAPPING };
}

/**
 * @param {'oidc'|'saml'} type
 * @param {object} claimMapping provider.claim_mapping
 * @param {object} payload parsed JSON profile
 */
export function inspectClaims(type, claimMapping = {}, payload = {}) {
  const mapping = resolveClaimMapping(type, claimMapping);
  const profile =
    type === 'saml'
      ? { ...payload, _json: payload._json || payload }
      : { ...payload, _json: payload };

  const subject = extractFirst(profile, mapping.subject);
  const email = extractFirst(profile, mapping.email);
  const displayName = extractFirst(profile, mapping.display_name);
  const givenName =
    type === 'saml' ? extractFirst(profile, ENTRA_GIVEN_NAME_PATHS) : null;
  const surname =
    type === 'saml' ? extractFirst(profile, ENTRA_SURNAME_PATHS) : null;
  const groups = extractAll(profile, mapping.groups);

  return {
    subject,
    email,
    displayName,
    givenName,
    surname,
    groups,
    mappingUsed: mapping,
  };
}
