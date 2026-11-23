"use strict";

const ENTRA_GUEST_UPN = /#EXT#@/i;

const ENTRA_GIVEN_NAME_PATHS =
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname,givenName,firstName";
const ENTRA_SURNAME_PATHS =
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname,surname,lastName";

function isEntraGuestUpn(value) {
  return ENTRA_GUEST_UPN.test(String(value || ""));
}

/**
 * Decode Entra B2B guest UPNs like user_domain.tld#EXT#@tenant.onmicrosoft.com
 * back to user@domain.tld.
 *
 * @param {string} value
 * @returns {string|null}
 */
function decodeEntraGuestUpn(value) {
  const raw = String(value || "").trim();
  if (!raw || !isEntraGuestUpn(raw)) return null;
  const prefix = raw.split("#EXT#")[0];
  const sep = prefix.lastIndexOf("_");
  if (sep <= 0) return null;
  const local = prefix.slice(0, sep).trim();
  const domain = prefix.slice(sep + 1).trim();
  if (!local || !domain || !domain.includes(".")) return null;
  return `${local}@${domain}`.toLowerCase();
}

function looksLikeEmail(value) {
  const raw = String(value || "").trim();
  return raw.includes("@") && !isEntraGuestUpn(raw);
}

/**
 * Normalize email/display name extracted from Entra SAML/OIDC assertions.
 *
 * @param {{ email?: string|null, displayName?: string|null, givenName?: string|null, surname?: string|null, subjectId?: string|null }} input
 * @returns {{ email: string, displayName: string }}
 */
function normalizeEntraIdentityClaims({
  email,
  displayName,
  givenName,
  surname,
  subjectId,
}) {
  let resolvedEmail = String(email || "").trim();
  let resolvedDisplay = String(displayName || "").trim();

  if (!looksLikeEmail(resolvedEmail)) {
    const decoded =
      decodeEntraGuestUpn(resolvedEmail) ||
      decodeEntraGuestUpn(subjectId) ||
      decodeEntraGuestUpn(resolvedDisplay);
    if (decoded) resolvedEmail = decoded;
  }

  const given = String(givenName || "").trim();
  const sur = String(surname || "").trim();
  const composedName = `${given} ${sur}`.trim();

  if (
    !resolvedDisplay ||
    isEntraGuestUpn(resolvedDisplay) ||
    resolvedDisplay === String(email || "").trim()
  ) {
    resolvedDisplay = composedName;
  }

  if (!resolvedDisplay && looksLikeEmail(resolvedEmail)) {
    resolvedDisplay = resolvedEmail.split("@")[0];
  }

  return {
    email: resolvedEmail,
    displayName: resolvedDisplay,
  };
}

module.exports = {
  ENTRA_GIVEN_NAME_PATHS,
  ENTRA_SURNAME_PATHS,
  isEntraGuestUpn,
  decodeEntraGuestUpn,
  looksLikeEmail,
  normalizeEntraIdentityClaims,
};
