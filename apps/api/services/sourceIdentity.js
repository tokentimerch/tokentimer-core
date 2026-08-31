"use strict";

/**
 * Single source of truth for "which credential/account/vault/project did
 * this token come from" across every provider. Both the manual-import
 * routes and the auto-sync worker call this resolver so a token's
 * provenance is computed identically regardless of which code path
 * triggered the scan -- no route-specific or worker-specific divergence.
 *
 * `ownerKey` is always an immutable principal id (a numeric user/org/repo
 * id, an account id, a project id, a tenant id, a vault URL) -- never a
 * mutable display name -- because obsolete-token cleanup matches on it.
 * `ownerDisplay` carries a human-readable label for the UI only and must
 * never be used in a matching predicate.
 *
 * @typedef {Object} SourceIdentity
 * @property {string} instance - Host/account/project/vault/tenant identifying this connection.
 * @property {string} ownerKey - Immutable principal id scoping ownership within the instance.
 * @property {string|null} ownerDisplay - Mutable human-readable label (UI only).
 * @property {Object} dimensions - Provider-specific per-token narrowing (mount+path for Vault, region+service for AWS, source kind for Azure/Azure AD, ...). Distinct from a scan's coarser sub-scope filter (e.g. a requested path *prefix*), which callers build separately when finalizing a scan.
 */

function requireString(value, field, provider) {
  if (value === null || value === undefined || String(value).trim() === "") {
    throw new Error(
      `resolveSourceIdentity(${provider}): missing required "${field}"`,
    );
  }
  return String(value);
}

/**
 * @param {string} provider - One of: github, gitlab, vault, aws, azure, azure-ad, gcp.
 * @param {Object} context - Provider-specific identity inputs (see cases below).
 * @returns {SourceIdentity}
 */
function resolveSourceIdentity(provider, context = {}) {
  switch (provider) {
    case "github":
    case "gitlab": {
      // instance = host/baseUrl so two self-hosted (or GHE) instances with
      // colliding numeric owner/repo ids never share a cleanup scope.
      // ownerKey is whichever numeric id actually owns/scopes this token's
      // object: the authenticated user for user-owned objects (PATs, SSH
      // keys), or the repo/project/group's own numeric id for repo- or
      // group-scoped objects (deploy keys, repo secrets, project/group
      // access tokens) -- callers pass the correct one per item.
      const instance = requireString(context.host, "host", provider);
      const ownerKey = requireString(context.ownerKey, "ownerKey", provider);
      return {
        instance,
        ownerKey,
        ownerDisplay: context.ownerDisplay ? String(context.ownerDisplay) : null,
        dimensions: {},
      };
    }

    case "vault": {
      // Vault has no separate per-object ownership concept beyond "which
      // server (and, for Enterprise namespaces, which namespace)": ownerKey
      // mirrors instance. dimensions describe *this token's own* narrowing
      // (which mount, which exact path, which category) -- kvOrPki is
      // deliberately omitted here since that distinction is already carried
      // by the token's source_kind field, not duplicated into dimensions.
      // Scan-level sub-scope filters (e.g. a requested path *prefix*) are a
      // separate, coarser concept built by the caller when finalizing the
      // scan, not by this per-token resolver.
      const address = requireString(context.address, "address", provider);
      const instance = context.namespace
        ? `${address}::${String(context.namespace)}`
        : address;
      return {
        instance,
        ownerKey: instance,
        ownerDisplay: instance,
        dimensions: {
          mount: context.mount ?? null,
          path: context.path ?? null,
          category: context.category ?? null,
        },
      };
    }

    case "aws": {
      // instance/ownerKey = STS account id (the only thing that reliably
      // identifies "which AWS account" regardless of which IAM principal
      // within it made the call).
      const accountId = requireString(context.accountId, "accountId", provider);
      return {
        instance: accountId,
        ownerKey: accountId,
        ownerDisplay: accountId,
        dimensions: {
          region: context.region ?? null,
          service: context.service ?? null,
        },
      };
    }

    case "azure": {
      // Azure Key Vault: the vault itself is both the instance and the
      // owner -- there is no further per-object ownership within a vault.
      const vaultUrl = requireString(context.vaultUrl, "vaultUrl", provider);
      return {
        instance: vaultUrl,
        ownerKey: vaultUrl,
        ownerDisplay: vaultUrl,
        dimensions: {
          sourceKind: context.sourceKind ?? null,
        },
      };
    }

    case "azure-ad": {
      // Azure AD (Microsoft Graph): tenant id scopes both instance and
      // ownership. Applications/ServicePrincipals are tracked as an
      // independent completeness dimension (see azureADIntegration.js).
      const tenantId = requireString(context.tenantId, "tenantId", provider);
      return {
        instance: tenantId,
        ownerKey: tenantId,
        ownerDisplay: tenantId,
        dimensions: {
          sourceKind: context.sourceKind ?? null,
        },
      };
    }

    case "gcp": {
      // GCP Secret Manager is already project-scoped; no further narrowing.
      const projectId = requireString(context.projectId, "projectId", provider);
      return {
        instance: projectId,
        ownerKey: projectId,
        ownerDisplay: projectId,
        dimensions: {},
      };
    }

    default:
      throw new Error(`resolveSourceIdentity: unknown provider "${provider}"`);
  }
}

module.exports = { resolveSourceIdentity };
