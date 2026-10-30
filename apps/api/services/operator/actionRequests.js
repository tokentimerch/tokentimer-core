"use strict";

// Renew requests from an operator connection (ADR-0015).
//
// Every function here runs on a caller-owned transaction client. The order of
// checks is deliberate and is the point of the module:
//   1. re-read the connection's authority with its row locked, so a revocation
//      that commits first is always seen and one that comes after must wait;
//   2. the three write gates (instance flag, workspace setting, scope);
//   3. only then touch certificates, plans or jobs.
// A request becomes an ordinary CertOps job under workspace approval policy,
// so the existing approval, dispatch and audit paths do the
// rest and nothing about execution is reimplemented here.

const crypto = require("node:crypto");
const connections = require("./connections");
const reads = require("./reads");
const { PLAN_TTL_MS, APPROVAL_TTL_MS, hashPlan, renewEffect } = require("./planEffects");
const { hasAtLeastRole } = require("../rbac");
const { lockWorkspaceForCertOpsSideEffect } = require("../certops/workspaceKillSwitch");
const {
  loadManagedCertificateForRenewal,
  manualRenewalJobCreator,
  preflightManualRenewalJob,
} = require("../certops/jobs");

const WRITE_SCOPE = "mcp:renew:request";
const MAX_PENDING_PER_CONNECTION = 10;

const CODES = Object.freeze({
  WRITES_DISABLED: "OPERATOR_WRITES_DISABLED",
  SCOPE_DENIED: "OPERATOR_CONNECTION_SCOPE_DENIED",
  UNAUTHORIZED: "OPERATOR_CONNECTION_UNAUTHORIZED",
  NOT_FOUND: "NOT_FOUND",
  NOT_MANAGED: "OPERATOR_CERTIFICATE_NOT_MANAGED",
  RETIRED: "OPERATOR_CERTIFICATE_RETIRED",
  NOT_POSSIBLE: "OPERATOR_RENEWAL_NOT_POSSIBLE",
  PLAN_EXPIRED: "OPERATOR_PLAN_EXPIRED",
  PLAN_USED: "OPERATOR_PLAN_USED",
  PLAN_MISMATCH: "OPERATOR_PLAN_MISMATCH",
  INTENT_STALE: "OPERATOR_INTENT_STALE",
  CONFLICT: "OPERATOR_IDEMPOTENCY_CONFLICT",
  PENDING_LIMIT: "OPERATOR_PENDING_LIMIT",
  NOT_CANCELLABLE: "OPERATOR_REQUEST_NOT_CANCELLABLE",
});

function fail(code, message, extra = {}) {
  const error = new Error(message);
  error.code = code;
  Object.assign(error, extra);
  return error;
}

// The three gates. The scope check uses the authority just read under the
// lock, not whatever the route read earlier.
async function assertWriteAllowed({ client, authority, workspaceId, requireGates = true }) {
  if (!authority.scopes.includes(WRITE_SCOPE) || !hasAtLeastRole(authority.effectiveRole, "workspace_manager")) {
    throw fail(CODES.SCOPE_DENIED, "Operator connection scope denied");
  }
  if (!requireGates) return;
  const instance = String(process.env.MCP_OPERATOR_WRITES_ENABLED || "").trim().toLowerCase() === "true";
  // Serialize admission with the admin's write-disable and cancellation sweep.
  // Hold this lock until the preview/request transaction commits or rolls back.
  const row = await client.query("SELECT operator_writes_enabled FROM workspaces WHERE id = $1 FOR SHARE", [workspaceId]);
  if (!instance || row.rows[0]?.operator_writes_enabled !== true) {
    throw fail(CODES.WRITES_DISABLED, "Write requests are not enabled here");
  }
}

async function authorize({ client, operator, requireGates = true }) {
  const locked = await connections.lockConnectionAuthority({ client, connectionId: operator.connectionId });
  if (!locked.valid) throw fail(CODES.UNAUTHORIZED, "Operator connection authentication required");
  await assertWriteAllowed({ client, authority: locked.authority, workspaceId: operator.workspaceId, requireGates });
  return locked;
}

function snake(value) {
  const text = String(value || "").toLowerCase();
  return /^[a-z][a-z0-9_]{1,63}$/.test(text) ? text : "unspecified";
}

module.exports = {
  APPROVAL_TTL_MS,
  CODES,
  MAX_PENDING_PER_CONNECTION,
  PLAN_TTL_MS,
  WRITE_SCOPE,
  authorize,
  fail,
  snake,
  _deps: { crypto, reads, hashPlan, renewEffect, lockWorkspaceForCertOpsSideEffect, loadManagedCertificateForRenewal, manualRenewalJobCreator, preflightManualRenewalJob },
};
