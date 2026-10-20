"use strict";

// Operator-safe projections (ADR-0015 section 4). Every function here builds
// its result from a fixed list of named fields. Nothing is produced by
// deleting fields from a richer record, so a field added to an internal record
// later cannot reach a connection by accident. Outputs are validated against
// packages/contracts/mcp/mcp-read-tools.schema.json in the unit tests.

const MAX_UNTRUSTED_TEXT = 512;

function isoOrNull(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

// Text that came from a certificate, asset, agent or operator is data, not
// instructions. The wrapper makes that explicit to any client.
function untrustedText(value) {
  if (value === undefined || value === null) return null;
  const text = String(value);
  if (text === "") return null;
  const truncated = text.length > MAX_UNTRUSTED_TEXT;
  return {
    value: truncated ? text.slice(0, MAX_UNTRUSTED_TEXT) : text,
    untrusted: true,
    truncated,
  };
}

function snakeCodeOrNull(value) {
  return typeof value === "string" && /^[a-z][a-z0-9_]{1,63}$/.test(value) ? value : null;
}

function projectWhoami({ operator, workspace, certops }) {
  return {
    contractVersion: 1,
    workspace: { id: String(workspace.id), name: untrustedText(workspace.name) || untrustedText("(unnamed)") },
    role: {
      current: operator.currentRole,
      ceiling: operator.roleCeiling,
      effective: operator.role,
    },
    connection: {
      id: operator.connectionId,
      scopes: [...operator.scopes],
      expiresAt: isoOrNull(operator.expiresAt),
    },
    certops: {
      enabled: certops.enabled === true,
      paused: certops.paused === true,
      approvalRequiredAlways: certops.approvalRequiredAlways === true,
      // True only when the instance flag and this workspace's setting are both
      // on. The scope is a third gate and is reported separately in the scopes.
      mcpWritesEnabled: certops.mcpWritesEnabled === true,
    },
  };
}

module.exports = {
  MAX_UNTRUSTED_TEXT,
  isoOrNull,
  projectWhoami,
  snakeCodeOrNull,
  untrustedText,
};
