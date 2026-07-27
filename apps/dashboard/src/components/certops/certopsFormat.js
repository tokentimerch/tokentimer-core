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
  provisioning: 'purple',
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
  provisioning: 'Provisioning',
  active: 'Active',
  discovered: 'Discovered',
  renewing: 'Renewing',
  expiring: 'Expiring',
  expired: 'Expired',
  revoked: 'Revoked',
  decommissioned: 'Decommissioned',
};

/** Mirrors MANAGED_CERTIFICATE_STATUSES in apps/api/services/certops/inventory.js. */
export const MANAGED_CERTIFICATE_STATUSES = Object.keys(STATUS_LABELS);

export function statusLabel(status) {
  const key = String(status || '').toLowerCase();
  return STATUS_LABELS[key] || (status ? String(status) : 'Unknown');
}

// Mirrors MANAGED_CERTIFICATE_SOURCES in
// apps/api/services/certops/inventory.js.
const SOURCE_LABELS = {
  manual: 'Manual',
  api: 'API',
  import: 'Imported',
  domain_checker: 'Domain checker',
  endpoint_monitor: 'Endpoint monitor',
  integration: 'Integration',
  auto_sync: 'Auto sync',
  cert_manager: 'cert-manager',
  agent_filesystem: 'Agent (filesystem)',
  agent_issuance: 'Agent (issuance)',
};

export const MANAGED_CERTIFICATE_SOURCES = Object.keys(SOURCE_LABELS);

export function sourceLabel(source) {
  const key = String(source || '').toLowerCase();
  return SOURCE_LABELS[key] || (source ? String(source) : 'Unknown');
}

/**
 * Renewal-automation states returned as `certificate.renewal.state` by
 * GET /certops/certificates. Kept in sync with
 * apps/api/routes/certops.js deriveCertificateRenewalState.
 */
export const RENEWAL_STATES = {
  auto: 'auto',
  disabled: 'disabled',
  notConfigured: 'not-configured',
  notEligible: 'not-eligible',
  notApplicable: 'not-applicable',
};

const RENEWAL_STATE_FALLBACK_HELP =
  'TokenTimer could not determine whether this certificate renews automatically. Treat it as manual until confirmed.';

/**
 * Presentation descriptor for a certificate's renewal automation.
 *
 * `not-configured` is the state this whole surface exists for: the scheduler
 * will not touch such a certificate, so it silently expires unless an operator
 * renews it by hand. It is therefore the only warning-level scheme here.
 * An unknown or missing `renewal` object (older API build, or a response that
 * predates the field) is also shown as a caution rather than silently as
 * "fine", so a stale server never renders a reassuring badge.
 *
 * @returns {{ state: string, label: string, scheme: string, help: string, isWarning: boolean }}
 */
export function renewalDescriptor(renewal) {
  const state = renewal?.state ? String(renewal.state) : null;
  const workspacePaused = renewal?.workspacePaused === true;

  if (state === RENEWAL_STATES.auto) {
    const from = renewal?.renewsFrom ? formatDate(renewal.renewsFrom) : null;
    const days = Number.isFinite(Number(renewal?.renewBeforeDays))
      ? Number(renewal.renewBeforeDays)
      : null;
    // The profile itself is genuinely enabled here - that's what earned
    // 'auto' - but a paused workspace kill switch means the scheduler will
    // not act on it until resumed. Surfacing that on the badge itself
    // (rather than only via the separate kill-switch banner) means an
    // operator reading one row does not have to cross-reference workspace
    // state elsewhere to know a renewal will not actually run (13.12).
    if (workspacePaused) {
      return {
        state,
        label: 'Auto-renew on (workspace paused)',
        scheme: 'yellow',
        help:
          'Automatic renewal is configured for this certificate, but CertOps is paused for this workspace, so no renewal will run until it is resumed.',
        isWarning: true,
      };
    }
    return {
      state,
      label: from ? `Auto-renews from ${from}` : 'Auto-renews',
      scheme: 'green',
      help:
        renewal?.detail ||
        (days
          ? `Renewal is attempted automatically from ${days} days before expiry.`
          : 'Renewal is attempted automatically before expiry.'),
      isWarning: false,
    };
  }

  if (state === RENEWAL_STATES.disabled) {
    // Chosen, not broken, so this is not warning-level like 'not-configured'.
    // It is still shown in a colour that reads as "acting on your instruction"
    // rather than green, because the certificate does expire on its own.
    return {
      state,
      label: 'Auto-renewal off',
      scheme: 'yellow',
      help:
        renewal?.detail ||
        'Automatic renewal is switched off for this certificate. It will expire unless it is renewed manually.',
      isWarning: false,
    };
  }

  if (state === RENEWAL_STATES.notConfigured) {
    return {
      state,
      label: 'No auto-renewal',
      scheme: 'orange',
      help:
        renewal?.detail ||
        'This certificate will not renew automatically and will expire unless it is renewed manually.',
      isWarning: true,
    };
  }

  if (state === RENEWAL_STATES.notEligible) {
    return {
      state,
      label: 'Monitored only',
      scheme: 'gray',
      help:
        renewal?.detail ||
        'TokenTimer does not hold this certificate key, so it is monitored only and cannot be renewed by an agent.',
      isWarning: false,
    };
  }

  if (state === RENEWAL_STATES.notApplicable) {
    return {
      state,
      label: 'Renewal not applicable',
      scheme: 'gray',
      help:
        renewal?.detail ||
        'Automatic renewal does not apply to this certificate lifecycle state.',
      isWarning: false,
    };
  }

  return {
    state: state || 'unknown',
    label: 'Renewal unknown',
    scheme: 'yellow',
    help: RENEWAL_STATE_FALLBACK_HELP,
    isWarning: true,
  };
}

/**
 * `renewalSetup` states, mirroring `RENEWAL_SETUP_STATES` in
 * apps/api/services/certops/renewalAdoption.js: the lifecycle of an
 * adopt-via-issuance intent ("Set up automatic renewal"), distinct from
 * `renewal.state` above, which describes the certificate's steady-state
 * renewal coverage once (or if) that intent resolves.
 */
export const RENEWAL_SETUP_STATES = {
  none: 'none',
  waiting: 'waiting',
  configured: 'configured',
  skipped: 'skipped',
  failed: 'failed',
};

/**
 * Presentation descriptor for `certificate.renewalSetup`. Returns `null` for
 * `none`/missing, the ordinary case for a certificate nobody has tried to
 * adopt yet, so callers can render nothing rather than an empty badge.
 */
export function renewalSetupDescriptor(renewalSetup) {
  const state = renewalSetup?.state;
  if (!state || state === RENEWAL_SETUP_STATES.none) return null;

  if (state === RENEWAL_SETUP_STATES.waiting) {
    return {
      state,
      label: 'Setting up automatic renewal',
      scheme: 'blue',
      message:
        'TokenTimer is waiting on the renewal job this setup started to finish.',
      canRetry: false,
    };
  }
  if (state === RENEWAL_SETUP_STATES.configured) {
    return {
      state,
      label: 'Automatic renewal configured',
      scheme: 'green',
      message: 'A renewal profile was created from this setup.',
      canRetry: false,
    };
  }
  if (state === RENEWAL_SETUP_STATES.skipped) {
    return {
      state,
      label: 'Setup skipped',
      scheme: 'gray',
      message:
        renewalSetup?.message ||
        'Automatic renewal was not configured from this setup attempt.',
      canRetry: false,
    };
  }
  return {
    state,
    label: 'Setup failed',
    scheme: 'red',
    message:
      renewalSetup?.message ||
      'Automatic renewal could not be configured from this setup attempt.',
    canRetry: Boolean(renewalSetup?.intentId),
  };
}

/**
 * Retired lifecycle states. A managed certificate in
 * one of these states is hidden from the dashboard by default and its linked
 * token can no longer be hard-deleted, only revoked/decommissioned.
 */
export const RETIRE_STATUSES = ['revoked', 'decommissioned'];
export function isRetiredStatus(status) {
  return RETIRE_STATUSES.includes(String(status || '').toLowerCase());
}

/**
 * Partitions the workspace CertOps inventory for the Control Center summary.
 *
 * The panel is titled around certificates linked to the token inventory, so
 * only linked rows are listed and counted. A certificate is linked the moment
 * it becomes real: discovery creates the token up front, and issuance links it
 * at reconciliation, because tokens.expiration is NOT NULL and an unissued
 * certificate has no honest expiry to record.
 *
 * Unlinked rows are reported as counts rather than listed: with no expiry they
 * cannot be sorted or badged, and would read as broken inventory instead of
 * work in flight. They are split by whether being unlinked is expected:
 *
 * - `provisioningCount` is the normal case, an issuance still in flight.
 * - `unlinkedCount` is everything else. No product path should produce it
 *   (reconciliation promotes to active and links the token in one
 *   transaction), so it is surfaced instead of being filtered into silence.
 *   Dropping such a row from both the list and every count is what made the
 *   original inventory bug invisible.
 *
 * @param {Array<object>} certificates
 * @param {{ highlightLimit?: number }} [options]
 * @returns {{
 *   linked: Array<object>,
 *   highlights: Array<object>,
 *   linkedCount: number,
 *   provisioningCount: number,
 *   unlinkedCount: number,
 * }}
 */
export function summarizeManagedCertificates(certificates, options = {}) {
  const highlightLimit = Number.isFinite(options.highlightLimit)
    ? options.highlightLimit
    : 5;
  const items = Array.isArray(certificates) ? certificates : [];
  const active = items.filter(cert => !isRetiredStatus(cert?.status));

  const linked = active.filter(cert => cert?.tokenId != null);
  const unlinked = active.filter(cert => cert?.tokenId == null);
  const provisioningCount = unlinked.filter(
    cert => String(cert?.status || '').toLowerCase() === 'provisioning'
  ).length;

  // Soonest expiry first; a missing expiry sorts last rather than first, so an
  // unparseable date cannot masquerade as the most urgent certificate.
  const highlights = [...linked]
    .sort((a, b) => {
      const left = a?.notAfter ? new Date(a.notAfter).getTime() : Infinity;
      const right = b?.notAfter ? new Date(b.notAfter).getTime() : Infinity;
      const l = Number.isFinite(left) ? left : Infinity;
      const r = Number.isFinite(right) ? right : Infinity;
      return l - r;
    })
    .slice(0, highlightLimit);

  return {
    linked,
    highlights,
    linkedCount: linked.length,
    provisioningCount,
    unlinkedCount: unlinked.length - provisioningCount,
  };
}

/**
 * Deterministic ordering for multiple managed certificates that reference the
 * same token (the backend allows e.g. one imported + one monitor-observed row).
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
