/**
 * Validator for SSO group->role mapping payloads (provider_slug scoped).
 */

"use strict";

const SSO_MAPPING_ROLES = ["admin", "workspace_manager", "viewer"];
const SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,62}$/;
const UUID_RE = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i;
const PRIORITY_MIN = 1;
const PRIORITY_MAX = 1000;
const PRIORITY_DEFAULT = 100;

function validateMappingPayload(body) {
  const providerSlug = typeof body?.provider_slug === "string"
    ? body.provider_slug.trim().toLowerCase()
    : "";
  const role = typeof body?.role === "string" ? body.role.trim().toLowerCase() : "";
  const idpGroup = typeof body?.idp_group === "string" ? body.idp_group.trim() : "";
  const workspaceId = typeof body?.workspace_id === "string"
    ? body.workspace_id.trim()
    : null;
  const priorityRaw = body?.priority;

  if (!SLUG_RE.test(providerSlug)) {
    return {
      error:
        "provider_slug must match ^[a-z0-9][a-z0-9_-]{0,62}$ (use an SSO provider slug)",
    };
  }
  if (!idpGroup || idpGroup.includes("\0")) {
    return { error: "idp_group must be a non-empty group name" };
  }
  if (!SSO_MAPPING_ROLES.includes(role)) {
    return {
      error: `role must be one of ${SSO_MAPPING_ROLES.join(", ")}`,
    };
  }
  if (role === "admin" && workspaceId) {
    return {
      error: "admin role is system-wide and cannot target a workspace",
    };
  }
  if (body?.workspace_id != null && body.workspace_id !== "" &&
      !UUID_RE.test(workspaceId || "")) {
    return { error: "workspace_id must be a UUID or null" };
  }

  let priority = PRIORITY_DEFAULT;
  if (priorityRaw !== undefined && priorityRaw !== null && priorityRaw !== "") {
    if (typeof priorityRaw !== "number" && typeof priorityRaw !== "string") {
      return { error: "priority must be a finite number" };
    }
    const n = Number(priorityRaw);
    if (!Number.isFinite(n)) {
      return { error: "priority must be a finite number" };
    }
    const truncated = Math.trunc(n);
    if (truncated < PRIORITY_MIN || truncated > PRIORITY_MAX) {
      return {
        error: `priority must be between ${PRIORITY_MIN} and ${PRIORITY_MAX}`,
      };
    }
    priority = truncated;
  }

  return {
    value: {
      provider_slug: providerSlug,
      idp_group: idpGroup.toLowerCase(),
      role,
      workspace_id: workspaceId || null,
      priority,
    },
  };
}

module.exports = {
  validateMappingPayload,
  SSO_MAPPING_ROLES,
  SLUG_RE,
  UUID_RE,
  PRIORITY_MIN,
  PRIORITY_MAX,
  PRIORITY_DEFAULT,
};
