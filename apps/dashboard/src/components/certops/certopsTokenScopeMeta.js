/**
 * Display metadata for CertOps API token scopes (ApiTokenModal + ApiTokenList).
 * Kept in sync with ALLOWED_SCOPES in apps/api/services/certops/apiTokens.js.
 */
export const CERTOPS_SCOPE_META = {
  'certops:read': {
    short: 'read',
    description: 'read certificates and jobs',
  },
  'certops:events:write': {
    short: 'events:write',
    description: 'report job lifecycle events',
  },
  'certops:jobs:read': {
    short: 'jobs:read',
    description: 'poll job status',
  },
  'certops:evidence:write': {
    short: 'evidence:write',
    description: 'attach evidence records',
  },
  'certops:observations:write': {
    short: 'observations:write',
    description:
      'report cert-manager controller observations for a bound cluster',
  },
  'certops:provision:execute': {
    short: 'provision:execute',
    description:
      'drive cert-manager controller provisioning intents for a bound cluster',
  },
};

/** Short label for a scope, falling back to the raw value with its prefix stripped. */
export function certOpsScopeShortLabel(scope) {
  return (
    CERTOPS_SCOPE_META[scope]?.short ||
    String(scope || '').replace(/^certops:/, '')
  );
}

/**
 * Cluster-id syntax accepted by the server (RFC 1123 DNS label): lowercase
 * alphanumerics and hyphens, 1-63 characters, not starting or ending with a
 * hyphen. Mirrors RFC1123_LABEL_PATTERN in
 * apps/api/services/certops/apiTokens.js so the client rejects an invalid
 * id before the round trip.
 */
export const CONTROLLER_CLUSTER_ID_PATTERN = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
export const CONTROLLER_CLUSTER_ID_MAX_LENGTH = 63;

export function isValidControllerClusterId(value) {
  const trimmed = String(value || '').trim();
  return (
    trimmed.length > 0 &&
    trimmed.length <= CONTROLLER_CLUSTER_ID_MAX_LENGTH &&
    CONTROLLER_CLUSTER_ID_PATTERN.test(trimmed)
  );
}
