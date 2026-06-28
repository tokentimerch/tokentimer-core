/** Shared formatting helpers for the CertOps inventory UI. */

const MS_PER_DAY = 24 * 60 * 60 * 1000;

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
