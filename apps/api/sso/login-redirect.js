"use strict";

const { apiBase, normalizeBaseUrl } = require("./callback-urls.js");

/**
 * Absolute URL for browser navigation to an SSO route on the API host.
 */
function absoluteAuthRouteUrl(path) {
  const base = apiBase();
  const p = String(path || "").startsWith("/") ? path : `/${path || ""}`;
  return `${base}${p}`;
}

/**
 * Map internal OIDC failure reasons to login page ?error= codes.
 */
function publicOidcLoginErrorCode(reason) {
  switch (reason) {
    case "provider_disabled":
      return "provider_disabled";
    case "state_mismatch":
      return "state_mismatch";
    case "provider_mismatch":
      return "oidc_failed";
    case "pkce_verifier_missing":
      return "oidc_failed";
    case "issuer_mismatch":
      return "oidc_failed";
    case "session_login_error":
      return "oidc_failed";
    case "auto_link_disabled":
    case "local_account_exists_auto_link_disabled":
      return "oidc_auto_link_disabled";
    case "email_not_verified_for_link":
      return "oidc_email_not_verified";
    case "missing_email":
    case "missing_subject":
      return "oidc_missing_claims";
    case "sso_account_exists_subject_mismatch":
    case "cross_provider_auto_link_disabled":
      return "oidc_account_mismatch";
    case "no_group_mapping_matched":
      return "oidc_no_group_mapping";
    default:
      return "oidc_failed";
  }
}

function buildLoginFailureRedirect(appUrl, { error, provider, reason }) {
  const base = normalizeBaseUrl(appUrl) || "http://localhost:5173";
  const params = new URLSearchParams();
  params.set("error", error || "oidc_failed");
  if (provider) params.set("provider", provider);
  if (reason) params.set("reason", reason);
  return `${base}/login?${params.toString()}`;
}

module.exports = {
  absoluteAuthRouteUrl,
  publicOidcLoginErrorCode,
  buildLoginFailureRedirect,
};
