"use strict";

/**
 * Per-provider SAML/OIDC callback and metadata URLs.
 * Derived from API_URL; manual overrides live in provider.config.callback_url.
 */

function normalizeBaseUrl(url) {
  if (!url || typeof url !== "string") return "";
  return url.trim().replace(/\/+$/, "");
}

function apiBase() {
  return (
    normalizeBaseUrl(process.env.API_URL) ||
    normalizeBaseUrl(process.env.APP_URL) ||
    "http://localhost:4000"
  );
}

function getOidcCallbackUrl(providerSlug) {
  return `${apiBase()}/auth/oidc/${encodeURIComponent(providerSlug)}/callback`;
}

function getSamlCallbackUrl(providerSlug) {
  return `${apiBase()}/auth/saml/${encodeURIComponent(providerSlug)}/callback`;
}

function getSamlMetadataUrl(providerSlug) {
  return `${apiBase()}/auth/saml/${encodeURIComponent(providerSlug)}/metadata`;
}

module.exports = {
  getOidcCallbackUrl,
  getSamlCallbackUrl,
  getSamlMetadataUrl,
  normalizeBaseUrl,
  apiBase,
};
