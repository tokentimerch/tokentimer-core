/**
 * Shared SSO dashboard helpers (ESM only).
 */

export function normalizeApiBase(apiBaseUrl) {
  return String(apiBaseUrl || '')
    .trim()
    .replace(/\/+$/, '');
}

/**
 * Public API origin for IdP callback/metadata URLs shown in the dashboard.
 * Uses configured API_URL when set; otherwise the browser origin (same-host ingress).
 */
export function resolvePublicApiBase(apiBaseUrl) {
  const configured = normalizeApiBase(apiBaseUrl);
  if (configured) return configured;
  if (
    typeof globalThis !== 'undefined' &&
    globalThis.window?.location?.origin
  ) {
    return normalizeApiBase(globalThis.window.location.origin);
  }
  return '';
}

export function computedCallbackUrl(apiBaseUrl, type, slug) {
  const base = resolvePublicApiBase(apiBaseUrl);
  return `${base}/auth/${type}/${encodeURIComponent(slug)}/callback`;
}

export function computedMetadataUrl(apiBaseUrl, slug) {
  const base = resolvePublicApiBase(apiBaseUrl);
  return `${base}/auth/saml/${encodeURIComponent(slug)}/metadata`;
}

/** Default SAML SP entity ID (Entra "Identifier", Okta "Audience URI"). */
export function defaultSamlSpEntityId(apiBaseUrl) {
  const base = resolvePublicApiBase(apiBaseUrl);
  return base ? `${base}/saml` : '/saml';
}

export function isFieldLocked(provider, dottedPath) {
  const locked = provider?.locked_fields || [];
  return Array.isArray(locked) && locked.includes(dottedPath);
}

export function lockedFieldHint(
  provider,
  dottedPath,
  deployMode = 'Helm or Compose'
) {
  if (!isFieldLocked(provider, dottedPath)) return null;
  return `Managed by ${deployMode}. Update the bootstrap manifest or env var and restart the API, or clear locks after removing the provider from GitOps.`;
}

export const SSO_SLUG_PATTERN = /^[a-z0-9][a-z0-9_-]{0,62}$/;

export function slugFromDisplayName(name) {
  return String(name || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63)
    .replace(/^([^a-z0-9])/, 'p$1');
}

/**
 * Client-side validation for wizard step "Provider details" (before IdP URL registration).
 * @returns {string[]} Human-readable errors (empty when valid).
 */
export function validateWizardConfigureStep({
  type,
  displayName,
  effectiveSlug,
  issuer,
  clientId,
  clientSecret,
  parsedSaml,
}) {
  const errors = [];
  if (!String(displayName || '').trim()) {
    errors.push('Display name is required');
  }
  if (!SSO_SLUG_PATTERN.test(String(effectiveSlug || ''))) {
    errors.push(
      'Slug must start with a letter or number and use only lowercase letters, numbers, hyphens, or underscores'
    );
  }
  if (type === 'oidc') {
    if (!String(issuer || '').trim()) errors.push('Issuer URL is required');
    if (!String(clientId || '').trim()) errors.push('Client ID is required');
    if (!String(clientSecret || '').trim())
      errors.push('Client secret is required');
  } else if (!parsedSaml?.entryPoint || !parsedSaml?.cert) {
    errors.push(
      'Paste IdP metadata XML or enter a metadata URL before continuing'
    );
  }
  return errors;
}

export const SSO_RELOAD_REASON_LABELS = {
  jwks_uri_missing: 'JWKS URI could not be resolved',
  not_configured: 'Required fields missing',
  config_build_failed: 'Could not build strategy config',
  secret_keyring_missing: 'SSO secrets keyring is not configured',
  provider_disabled: 'Provider is disabled',
  discovery_required_or_manual_endpoints_missing:
    'Discovery failed; set endpoints manually',
  saml_cache_provider_unavailable: 'SAML request cache unavailable',
  signing_key_missing:
    'SAML request signing is enabled but signing key is missing',
};

/**
 * Parse GET /api/auth/features for login buttons.
 * Expects multi-provider shape: { providers: { oidc: [], saml: [] } }.
 * Ignores legacy top-level { oidc: boolean, saml: boolean } responses.
 *
 * @param {unknown} data
 * @returns {Array<{ slug: string, type: 'oidc'|'saml', displayName?: string, signInReady?: boolean, loginUrl?: string, sortOrder?: number, sort_order?: number }>}
 */
export function parseAuthFeaturesProviders(data) {
  if (!data || typeof data !== 'object') return [];
  const root = /** @type {Record<string, unknown>} */ (data);
  if (!root.providers || typeof root.providers !== 'object') return [];

  const providers = /** @type {Record<string, unknown>} */ (root.providers);
  const oidc = Array.isArray(providers.oidc) ? providers.oidc : [];
  const saml = Array.isArray(providers.saml) ? providers.saml : [];

  return [
    ...oidc.map(p => ({ ...p, type: p.type || 'oidc' })),
    ...saml.map(p => ({ ...p, type: p.type || 'saml' })),
  ].filter(p => p && typeof p.slug === 'string' && p.slug.length > 0);
}

/**
 * @param {{ slug: string, type: string, loginUrl?: string }} provider
 * @param {string|null|undefined} nextPath
 * @returns {string}
 */
export function buildSsoLoginUrl(provider, nextPath, apiBaseUrl) {
  const apiBase = resolvePublicApiBase(apiBaseUrl);
  let base =
    provider.loginUrl ||
    `/auth/${provider.type}/${encodeURIComponent(provider.slug)}`;
  if (base.startsWith('/') && apiBase) {
    base = `${apiBase}${base}`;
  }
  if (!nextPath) return base;
  return `${base}?next=${encodeURIComponent(nextPath)}`;
}
