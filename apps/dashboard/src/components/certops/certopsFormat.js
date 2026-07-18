/** Shared formatting helpers for the CertOps inventory UI. */

const MS_PER_DAY = 24 * 60 * 60 * 1000;

const CERT_TOKEN_TYPES = new Set([
  'ssl_cert',
  'tls_cert',
  'code_signing',
  'client_cert',
]);

/** Whether a token row is a certificate asset (category or type). */
export function isCertToken(token) {
  if (!token) return false;
  if (token.category === 'cert') return true;
  return CERT_TOKEN_TYPES.has(String(token.type || '').toLowerCase());
}

export function formatDate(value) {
  if (!value) return '--';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '--';
  return date.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

export function daysUntil(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return Math.round((date.getTime() - Date.now()) / MS_PER_DAY);
}

/**
 * Derives an expiry descriptor from the certificate's notAfter date.
 * @returns {{ label: string, scheme: string, days: number|null }}
 */
export function expiryDescriptor(notAfter) {
  const days = daysUntil(notAfter);
  if (days === null) return { label: 'Unknown', scheme: 'gray', days: null };
  if (days < 0)
    return { label: `Expired ${Math.abs(days)}d ago`, scheme: 'red', days };
  if (days === 0) return { label: 'Expires today', scheme: 'red', days };
  if (days <= 14) return { label: `${days}d left`, scheme: 'red', days };
  if (days <= 30) return { label: `${days}d left`, scheme: 'orange', days };
  return { label: `${days}d left`, scheme: 'green', days };
}

const STATUS_SCHEMES = {
  active: 'green',
  discovered: 'blue',
  renewing: 'blue',
  expiring: 'orange',
  expired: 'red',
  revoked: 'red',
  decommissioned: 'gray',
};

export function statusScheme(status) {
  return STATUS_SCHEMES[String(status || '').toLowerCase()] || 'gray';
}

const STATUS_LABELS = {
  active: 'Active',
  discovered: 'Discovered',
  renewing: 'Renewing',
  expiring: 'Expiring',
  expired: 'Expired',
  revoked: 'Revoked',
  decommissioned: 'Decommissioned',
};

export function statusLabel(status) {
  const key = String(status || '').toLowerCase();
  return STATUS_LABELS[key] || (status ? String(status) : 'Unknown');
}

/**
 * Retired lifecycle states (plan D7 / section 10.1). A managed certificate in
 * one of these states is hidden from the dashboard by default and its linked
 * token can no longer be hard-deleted, only revoked/decommissioned.
 */
export const RETIRE_STATUSES = ['revoked', 'decommissioned'];

export function isRetiredStatus(status) {
  return RETIRE_STATUSES.includes(String(status || '').toLowerCase());
}

/**
 * Deterministic ordering for multiple managed certificates that reference the
 * same token (backend D8 allows e.g. one imported + one monitor-observed row).
 * Ordering: active (non-retired) certificates before retired ones, then most
 * recently updated first (updatedAt, falling back to createdAt), then id
 * ascending as a stable tie-breaker.
 */
export function sortCertificatesForToken(certificates) {
  const items = Array.isArray(certificates) ? [...certificates] : [];
  const ts = cert => {
    const value = cert?.updatedAt || cert?.createdAt || null;
    const time = value ? new Date(value).getTime() : NaN;
    return Number.isFinite(time) ? time : 0;
  };
  return items.sort((a, b) => {
    const aRetired = isRetiredStatus(a?.status) ? 1 : 0;
    const bRetired = isRetiredStatus(b?.status) ? 1 : 0;
    if (aRetired !== bRetired) return aRetired - bRetired;
    const diff = ts(b) - ts(a);
    if (diff !== 0) return diff;
    return String(a?.id || '').localeCompare(String(b?.id || ''));
  });
}

/**
 * Deterministic pick for single-certificate display contexts when a token is
 * referenced by several managed certificates: first entry of
 * `sortCertificatesForToken` (active preferred, most recently updated).
 */
export function pickPrimaryCertificate(certificates) {
  const sorted = sortCertificatesForToken(certificates);
  return sorted.length > 0 ? sorted[0] : null;
}

/** Matches apps/api/services/certops/inventory.js KEY_REFERENCE_MAX_LENGTH. */
export const KEY_REFERENCE_MAX_LENGTH = 256;

/** Separator between location block and shared technical reference in keyReference. */
const KEY_REFERENCE_TECH_SEP = ' — ';

/**
 * Split user-entered location text into distinct labels (one per line or comma).
 */
export function parseKeyLocationInput(text) {
  if (!text || typeof text !== 'string') return [];
  return text
    .split(/[\n,]+/)
    .map(part => part.trim())
    .filter(Boolean);
}

/**
 * Build the keyReference string stored by the API from location labels and an
 * optional shared technical pointer (same key mode for all locations).
 */
export function buildKeyReferenceFromLocations(locations, technicalReference) {
  const labels = Array.isArray(locations)
    ? locations.map(part => String(part || '').trim()).filter(Boolean)
    : parseKeyLocationInput(locations);
  const tech = String(technicalReference || '').trim();
  if (labels.length === 0) return tech || null;
  const block = labels.join('\n');
  if (!tech) return block;
  return `${block}${KEY_REFERENCE_TECH_SEP}${tech}`;
}

/**
 * Parse a stored keyReference back into location labels and optional technical ref.
 */
export function parseStoredKeyReference(keyReference) {
  const raw = String(keyReference || '').trim();
  if (!raw) return { locations: [], technicalReference: null };

  const sepIndex = raw.lastIndexOf(KEY_REFERENCE_TECH_SEP);
  if (sepIndex !== -1) {
    const locPart = raw.slice(0, sepIndex).trim();
    const tech = raw.slice(sepIndex + KEY_REFERENCE_TECH_SEP.length).trim();
    return {
      locations: parseKeyLocationInput(locPart),
      technicalReference: tech || null,
    };
  }

  return { locations: parseKeyLocationInput(raw), technicalReference: null };
}

const KEY_MODE_LABELS = {
  'agent-local': 'Agent-local',
  'proxy-agent-local': 'Proxy agent-local',
  'cert-manager-managed': 'cert-manager (Kubernetes)',
  'appliance-managed': 'Appliance',
  'hsm-managed': 'HSM',
  'vault-managed': 'Vault',
  'os-store-managed': 'OS store',
  'external-unknown': 'External (unknown)',
};

export function keyModeLabel(keyMode) {
  if (!keyMode) return 'Not recorded';
  return KEY_MODE_LABELS[keyMode] || keyMode;
}

/** Sentinel value for the import form "Custom..." key locality option. */
export const KEY_MODE_CUSTOM = '__custom__';

/** Select options for recording key locality during PEM import. */
export const KEY_MODE_SELECT_OPTIONS = [
  { value: '', label: 'Not recorded' },
  ...Object.entries(KEY_MODE_LABELS).map(([value, label]) => ({
    value,
    label,
  })),
  { value: KEY_MODE_CUSTOM, label: 'Custom...' },
];

/**
 * User-facing toast copy after POST /certops/imports.
 * The API upserts by fingerprint; existingCount reflects ids known before submit.
 */
export function describeCertificateImportOutcome({
  existingCount = 0,
  newCount = 0,
  totalCount = 0,
} = {}) {
  if (newCount === 0 && existingCount > 0) {
    return existingCount === 1
      ? 'Certificate already registered. Existing record updated.'
      : `${existingCount} certificates already registered. Existing records updated.`;
  }
  if (newCount > 0 && existingCount > 0) {
    return newCount === 1 && existingCount === 1
      ? '1 certificate imported. 1 was already registered.'
      : `${newCount} certificate(s) imported. ${existingCount} already registered.`;
  }
  const count = totalCount || newCount;
  return count === 1
    ? 'Certificate imported.'
    : `${count} certificates imported.`;
}
