"use strict";

const { resolveSsoBindings } = require("./group-resolver.js");
const { getProviderRow } = require("./provider-registry.js");
const { SLUG_RE } = require("./mapping-validation.js");

const ROLE_LABELS = {
  admin: "System Admin",
  workspace_manager: "Workspace Manager",
  viewer: "Viewer",
};

function parseBootstrapAdminGroups(config) {
  const raw =
    config?.bootstrap_admin_groups || config?.admin_groups || "";
  return String(raw || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Dry-run SSO group mapping resolution (never persists).
 *
 * @param {import('pg').Pool} pool
 * @param {{ providerSlug: string, groups: string[], strictSyncPreview?: boolean }} opts
 */
async function runMappingSimulation(pool, opts) {
  const providerSlug = typeof opts?.providerSlug === "string"
    ? opts.providerSlug.trim().toLowerCase()
    : "";
  const groups = opts?.groups ?? [];
  if (!providerSlug) {
    return { error: "provider_slug is required" };
  }
  if (!SLUG_RE.test(providerSlug)) {
    return { error: "Invalid provider_slug" };
  }
  if (!Array.isArray(groups) ||
      groups.some((group) => typeof group !== "string" || group.includes("\0"))) {
    return { error: "groups must contain valid group names" };
  }

  const provider = await getProviderRow(pool, providerSlug);
  if (!provider) {
    return { error: `unknown provider_slug: ${providerSlug}` };
  }

  const bootstrapAdminGroups = parseBootstrapAdminGroups(provider.config || {});

  const resolution = await resolveSsoBindings({
    pool,
    providerSlug,
    idpGroups: groups,
    bootstrapAdminGroups,
  });

  const workspaceIds = resolution.workspaceGrants.map((g) => g.workspace_id);
  const nameById = new Map();
  if (workspaceIds.length > 0) {
    const { rows } = await pool.query(
      "SELECT id, name FROM workspaces WHERE id = ANY($1::uuid[])",
      [workspaceIds],
    );
    for (const row of rows) {
      nameById.set(row.id, row.name);
    }
  }

  const grants = [];
  if (resolution.isAdmin) {
    grants.push({ role: "admin", workspace: "system-wide" });
  }
  for (const g of resolution.workspaceGrants) {
    grants.push({
      role: g.role,
      workspace_id: g.workspace_id,
      workspace: nameById.get(g.workspace_id) || g.workspace_id,
    });
  }

  const adminNote =
    "System admin grants persist until an administrator removes them.";
  const strictSyncNote = opts?.strictSyncPreview === true
    ? `Strict sync can revoke this provider's SSO-managed workspace memberships at sign-in. A group-only preview has no membership history. ${adminNote}`
    : adminNote;

  return {
    provider_slug: providerSlug,
    matched_groups: resolution.matchedGroups,
    matched_groups_count: resolution.matchedGroups.length,
    is_admin: resolution.isAdmin,
    grants,
    workspace_grants: resolution.workspaceGrants,
    revoked_preview: [],
    strict_sync_note: strictSyncNote,
    users_who_would_no_longer_match_admin_mapping: resolution.isAdmin
      ? 0
      : "N/A (no admin mapping matched)",
    roles: resolution.workspaceGrants.map((g) => ({
      label: ROLE_LABELS[g.role] || g.role,
      role: g.role,
      workspace_id: g.workspace_id,
      workspace: nameById.get(g.workspace_id) || g.workspace_id,
    })),
  };
}

module.exports = {
  runMappingSimulation,
  parseBootstrapAdminGroups,
};
