/** Shared formatting helpers for CertOps job / evidence timeline UI. */

const JOB_STATUS_SCHEMES = {
  pending_approval: 'purple',
  approved: 'gray',
  rejected: 'red',
  pending: 'gray',
  claimed: 'blue',
  running: 'blue',
  succeeded: 'green',
  failed: 'red',
  blocked: 'orange',
  cancelled: 'gray',
};

const JOB_STATUS_LABELS = {
  pending_approval: 'Pending approval',
  approved: 'Approved',
  rejected: 'Rejected',
  pending: 'Pending',
  claimed: 'Claimed',
  running: 'Running',
  succeeded: 'Succeeded',
  failed: 'Failed',
  blocked: 'Blocked',
  cancelled: 'Cancelled',
};

const JOB_OPERATION_LABELS = {
  renew: 'Renew',
  deploy: 'Deploy',
  reload: 'Reload',
  revoke: 'Revoke',
  noop: 'No-op',
};

const EVENT_TYPE_LABELS = {
  'job.created': 'Job created',
  'job.accepted': 'Job accepted',
  'job.started': 'Job started',
  'job.progress': 'Job progress',
  'job.completed': 'Job completed',
  'job.failed': 'Job failed',
  'job.rejected': 'Job rejected',
  'job.cancelled': 'Job cancelled',
  'job.status_updated': 'Status updated',
  'evidence.attached': 'Evidence attached',
};

const EVIDENCE_TYPE_LABELS = {
  'certificate.observed': 'Certificate observed',
  'deployment.checked': 'Deployment checked',
  'deployment.updated': 'Deployment updated',
  'validation.passed': 'Validation passed',
  'validation.failed': 'Validation failed',
  'policy.checked': 'Policy checked',
};

const EVIDENCE_TYPE_SCHEMES = {
  'certificate.observed': 'blue',
  'deployment.checked': 'blue',
  'deployment.updated': 'blue',
  'validation.passed': 'green',
  'validation.failed': 'red',
  'policy.checked': 'gray',
};

const SUBJECT_TYPE_LABELS = {
  managed_certificate: 'Managed certificate',
  certificate_instance: 'Certificate instance',
  certificate_target: 'Certificate target',
  token: 'Token',
  domain: 'Domain',
  endpoint: 'Endpoint',
  external: 'External',
};

const REDACTED_LITERAL = '[REDACTED]';
const REDACTION_SCAN_MAX_DEPTH = 6;

export function jobStatusScheme(status) {
  return JOB_STATUS_SCHEMES[String(status || '').toLowerCase()] || 'gray';
}

export function jobStatusLabel(status) {
  const key = String(status || '').toLowerCase();
  return JOB_STATUS_LABELS[key] || (status ? String(status) : 'Unknown');
}

export function jobOperationLabel(operation) {
  const key = String(operation || '').toLowerCase();
  return (
    JOB_OPERATION_LABELS[key] || (operation ? String(operation) : 'Unknown')
  );
}

export function eventTypeLabel(eventType) {
  const key = String(eventType || '');
  return EVENT_TYPE_LABELS[key] || (eventType ? String(eventType) : 'Event');
}

export function evidenceTypeLabel(evidenceType) {
  const key = String(evidenceType || '');
  return (
    EVIDENCE_TYPE_LABELS[key] ||
    (evidenceType ? String(evidenceType) : 'Evidence')
  );
}

export function evidenceTypeScheme(evidenceType) {
  return EVIDENCE_TYPE_SCHEMES[String(evidenceType || '')] || 'gray';
}

/** Human label for a CertOps subject type; falls back to the raw value. */
export function subjectTypeLabel(subjectType) {
  const key = String(subjectType || '');
  return SUBJECT_TYPE_LABELS[key] || (subjectType ? String(subjectType) : '');
}

/**
 * Shortens a UUID-like id for compact display, keeping enough of the start
 * and end to distinguish rows at a glance (e.g. `4a30d1e2...9f0c`). Ids
 * shorter than the threshold are returned unchanged.
 */
export function truncateId(id, { head = 8, tail = 4 } = {}) {
  const value = String(id ?? '').trim();
  if (!value) return '';
  if (value.length <= head + tail + 3) return value;
  return `${value.slice(0, head)}...${value.slice(-tail)}`;
}

/**
 * Detect redaction markers in job-log or evidence metadata.
 *
 * The evidence service persists a server-owned nested marker
 * `metadata.redaction = { applied: true, count: N }` (takes precedence);
 * older executor-path rows carry flat `redactionApplied` / `redactionCount`.
 * Also checks `status === 'redacted'`, `redacted === true`, and nested
 * string values containing `[REDACTED]`, with a recursion depth cap.
 */
export function hasRedactionMarkers(metadata) {
  if (!metadata || typeof metadata !== 'object') return false;
  const nested = metadata.redaction;
  if (nested && typeof nested === 'object' && !Array.isArray(nested)) {
    if (nested.applied === true) return true;
    if (typeof nested.count === 'number' && nested.count > 0) return true;
  }
  if (metadata.redactionApplied === true) return true;
  if (metadata.redacted === true) return true;
  if (String(metadata.status || '').toLowerCase() === 'redacted') return true;
  if (
    typeof metadata.redactionCount === 'number' &&
    metadata.redactionCount > 0
  ) {
    return true;
  }
  return scanForRedactedLiteral(metadata, 0);
}

/**
 * Extract the redaction count from metadata, supporting the nested
 * `metadata.redaction.count` shape (precedence) and the flat legacy
 * `metadata.redactionCount`. Returns 0 when no count is recorded.
 */
export function redactionCount(metadata) {
  if (!metadata || typeof metadata !== 'object') return 0;
  const nested = metadata.redaction;
  if (
    nested &&
    typeof nested === 'object' &&
    !Array.isArray(nested) &&
    typeof nested.count === 'number' &&
    Number.isFinite(nested.count) &&
    nested.count > 0
  ) {
    return nested.count;
  }
  if (
    typeof metadata.redactionCount === 'number' &&
    Number.isFinite(metadata.redactionCount) &&
    metadata.redactionCount > 0
  ) {
    return metadata.redactionCount;
  }
  return 0;
}

function scanForRedactedLiteral(value, depth) {
  if (depth > REDACTION_SCAN_MAX_DEPTH) return false;
  if (typeof value === 'string') {
    return value.includes(REDACTED_LITERAL);
  }
  if (!value || typeof value !== 'object') return false;
  if (Array.isArray(value)) {
    return value.some(item => scanForRedactedLiteral(item, depth + 1));
  }
  return Object.values(value).some(item =>
    scanForRedactedLiteral(item, depth + 1)
  );
}

/** Locale date + time string; '--' when missing or invalid. */
export function formatDateTime(value) {
  if (!value) return '--';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '--';
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * Compact relative time for job list rows; falls back to a short absolute date.
 */
export function formatRelativeDateTime(value) {
  if (!value) return '--';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '--';

  const diffMs = Date.now() - date.getTime();
  if (diffMs < 0) return formatDateTime(value);

  const diffMins = Math.floor(diffMs / (1000 * 60));
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return formatDateTime(value);
}
