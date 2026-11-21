/**
 * ESM helpers for SSO Providers OIDC wizard (dashboard bundle).
 */

import {
  suggestJwksUriFromIssuer,
  discoveryDocumentUrlFromIssuer,
} from './oidc-endpoint-defaults.js';
import {
  OIDC_PROVIDER_HINTS,
  matchIssuerProviderHint,
  OVERRIDE_FIELD_HELP,
  applyProviderEndpointTemplates,
} from './oidc-provider-hints.js';

export {
  suggestJwksUriFromIssuer,
  discoveryDocumentUrlFromIssuer,
  OIDC_PROVIDER_HINTS,
  matchIssuerProviderHint,
  OVERRIDE_FIELD_HELP,
  applyProviderEndpointTemplates,
};

/** Wizard template metadata (display only). */
export const OIDC_WIZARD_TEMPLATES = [
  { id: 'entra', name: 'Microsoft Entra ID' },
  { id: 'keycloak', name: 'Keycloak' },
  { id: 'okta', name: 'Okta' },
  { id: 'auth0', name: 'Auth0' },
  { id: 'google', name: 'Google Workspace' },
  { id: 'generic', name: 'Generic OIDC' },
];

export const SAML_WIZARD_TEMPLATES = [
  { id: 'entra', name: 'Microsoft Entra ID' },
  { id: 'keycloak', name: 'Keycloak' },
  { id: 'okta', name: 'Okta' },
  { id: 'generic', name: 'Generic SAML' },
];

/**
 * Suggest default claim_mapping for a template (OIDC).
 *
 * @param {string} templateId
 * @returns {object}
 */
export function defaultOidcClaimMapping(templateId) {
  const base =
    templateId === 'entra' || templateId === 'google'
      ? {
          email: 'email',
          display_name: 'name',
          groups: 'groups,roles',
          subject: 'sub',
        }
      : {
          email: 'email',
          display_name: 'name,preferred_username',
          groups: 'groups,roles',
          subject: 'sub',
        };
  return { oidc: base };
}

/**
 * Default SAML claim paths per wizard template.
 * Entra defaults match Attributes & Claims URIs out of the box:
 * emailaddress, givenname, name, surname (givenname/surname read in saml.js).
 *
 * @param {string} templateId
 * @returns {object}
 */
export function defaultSamlClaimMapping(templateId) {
  if (templateId === 'entra') {
    return {
      saml: {
        email:
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        display_name:
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
        groups:
          'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups,http://schemas.microsoft.com/ws/2008/06/identity/claims/role',
        subject: 'nameID',
      },
    };
  }
  return {
    saml: {
      email: 'email,nameID',
      display_name: 'displayName',
      groups: 'groups,memberOf',
      subject: 'nameID',
    },
  };
}
