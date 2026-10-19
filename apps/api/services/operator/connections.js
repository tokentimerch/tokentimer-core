"use strict";

// Operator connections (ADR-0015). A connection is a delegated principal: one
// user, one workspace, a fixed scope list and a fixed role ceiling. This
// module owns creation, validation, rotation, revocation and the per-request
// authority calculation. It never reads req/res.

const { pool } = require("../../db/database");
const {
  defineCredentialFamily,
  safeCompareSha256Hex,
  sha256Hex,
} = require("../credentials/primitives");
const { effectiveWorkspaceRole, hasAtLeastRole } = require("../rbac");
const { containsPrivateKeyMaterial } = require("../../utils/secretMaterial");

const CONNECTION_CREDENTIAL = defineCredentialFamily({ prefix: "ttopc_" });

const CONNECTION_INVALID = "OPERATOR_CONNECTION_INVALID";
const CONNECTION_NAME_INVALID = "OPERATOR_CONNECTION_NAME_INVALID";
const CONNECTION_SCOPE_INVALID = "OPERATOR_CONNECTION_SCOPE_INVALID";
const CONNECTION_SCOPE_DENIED = "OPERATOR_CONNECTION_SCOPE_DENIED";
const CONNECTION_ROLE_CEILING_INVALID = "OPERATOR_CONNECTION_ROLE_CEILING_INVALID";
const CONNECTION_EXPIRY_INVALID = "OPERATOR_CONNECTION_EXPIRY_INVALID";
const CONNECTION_FORBIDDEN = "OPERATOR_CONNECTION_FORBIDDEN";
const CONNECTION_UNAUTHORIZED = "OPERATOR_CONNECTION_UNAUTHORIZED";
const PRIVATE_KEY_MATERIAL_REJECTED = "PRIVATE_KEY_MATERIAL_REJECTED";

const DAY_MS = 24 * 60 * 60 * 1000;
const DEFAULT_LIFETIME_MS = 30 * DAY_MS;
const MAX_LIFETIME_MS = 90 * DAY_MS;
const MAX_SCOPES = 16;
const MAX_LAST_USED_WRITE_INTERVAL = "5 minutes";

// Scope name -> least workspace role that can ever use it. This mirrors
// packages/contracts/mcp/mcp-tool-catalog.json; a unit test keeps the two in
// step. Scopes that are not listed here do not exist.
const SCOPE_MIN_ROLE = Object.freeze({
  "mcp:identity:read": "viewer",
  "mcp:certs:read": "viewer",
  "mcp:agents:read": "workspace_manager",
  "mcp:jobs:read": "viewer",
  "mcp:assets:read": "viewer",
  "mcp:renewals:read": "viewer",
  "mcp:evidence:read": "viewer",
  "mcp:logs:read": "workspace_manager",
  "mcp:audit:read": "viewer",
  "mcp:requests:read": "viewer",
  "mcp:ops:request": "workspace_manager",
  "mcp:lifecycle:request": "workspace_manager",
  "mcp:config:request": "admin",
  "mcp:ca-revoke": "admin",
});
const ALLOWED_SCOPES = Object.freeze(Object.keys(SCOPE_MIN_ROLE));
const ALLOWED_SCOPE_SET = new Set(ALLOWED_SCOPES);
const ROLE_CEILINGS = Object.freeze(["viewer", "workspace_manager", "admin"]);

// Scopes that no connection may hold until the stage that implements them
// ships. Keeps a premature grant from becoming live authority later. The
// extended read set stays closed until the qualification gate passes.
const RESERVED_SCOPES = Object.freeze(
  new Set([
    "mcp:assets:read",
    "mcp:renewals:read",
    "mcp:evidence:read",
    "mcp:logs:read",
    "mcp:audit:read",
    "mcp:ops:request",
    "mcp:lifecycle:request",
    "mcp:config:request",
    "mcp:ca-revoke",
    "mcp:requests:read",
  ]),
);

const SAFE_SELECT_FIELDS = `
  id, workspace_id, user_id, name, scopes, role_ceiling, credential_prefix,
  credential_rotated_at, status, expires_at, last_used_at, revoked_at,
  revoked_by, created_by, created_at, updated_at
`;

function serviceError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function dateToIso(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function normalizeName(value) {
  if (typeof value !== "string") {
    throw serviceError("Connection name is required", CONNECTION_NAME_INVALID);
  }
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 128) {
    throw serviceError("Connection name is invalid", CONNECTION_NAME_INVALID);
  }
  if (containsPrivateKeyMaterial(trimmed)) {
    throw serviceError(
      "Private key material is not accepted in connection metadata",
      PRIVATE_KEY_MATERIAL_REJECTED,
    );
  }
  if (CONNECTION_CREDENTIAL.containsEmbedded(trimmed)) {
    throw serviceError("Connection name is invalid", CONNECTION_NAME_INVALID);
  }
  return trimmed;
}

function normalizeScopes(scopes) {
  if (!Array.isArray(scopes) || scopes.length === 0 || scopes.length > MAX_SCOPES) {
    throw serviceError("Connection scopes are invalid", CONNECTION_SCOPE_INVALID);
  }
  const normalized = [];
  for (const scope of scopes) {
    const trimmed = typeof scope === "string" ? scope.trim() : "";
    if (!ALLOWED_SCOPE_SET.has(trimmed)) {
      throw serviceError("Connection scope is not allowed", CONNECTION_SCOPE_INVALID);
    }
    if (RESERVED_SCOPES.has(trimmed)) {
      throw serviceError(
        "Connection scope is not available in this release",
        CONNECTION_SCOPE_INVALID,
      );
    }
    if (!normalized.includes(trimmed)) normalized.push(trimmed);
  }
  return normalized;
}

function normalizeRoleCeiling(value) {
  if (!ROLE_CEILINGS.includes(value)) {
    throw serviceError("Role ceiling is invalid", CONNECTION_ROLE_CEILING_INVALID);
  }
  return value;
}

function resolveExpiry(value, now = new Date()) {
  if (value === undefined || value === null || value === "") {
    return new Date(now.getTime() + DEFAULT_LIFETIME_MS);
  }
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime()) || date.getTime() <= now.getTime()) {
    throw serviceError("Connection expiry is invalid", CONNECTION_EXPIRY_INVALID);
  }
  if (date.getTime() > now.getTime() + MAX_LIFETIME_MS) {
    throw serviceError(
      "Connection lifetime exceeds the 90 day maximum",
      CONNECTION_EXPIRY_INVALID,
    );
  }
  return date;
}

function connectionStatusFromRow(row, now = new Date()) {
  if (row?.status !== "active") return row?.status || null;
  const expiresAt = row.expires_at ? new Date(row.expires_at) : null;
  if (expiresAt && expiresAt.getTime() <= now.getTime()) return "expired";
  return "active";
}

function connectionFromRow(row, now = new Date()) {
  if (!row) return null;
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    userId: row.user_id,
    name: row.name,
    scopes: Array.isArray(row.scopes) ? [...row.scopes] : [],
    roleCeiling: row.role_ceiling,
    credentialPrefix: row.credential_prefix,
    credentialRotatedAt: dateToIso(row.credential_rotated_at),
    status: connectionStatusFromRow(row, now),
    expiresAt: dateToIso(row.expires_at),
    lastUsedAt: dateToIso(row.last_used_at),
    revokedAt: dateToIso(row.revoked_at),
    revokedBy: row.revoked_by ?? null,
    createdBy: row.created_by ?? null,
    createdAt: dateToIso(row.created_at),
    updatedAt: dateToIso(row.updated_at),
  };
}

// The role a user holds in a workspace right now. The decision itself (a
// membership row wins, then the implicit workspace-owner rule) is shared with
// session authorization in rbac.js; only the queries live here so they can run
// on a caller-supplied transaction client.
async function resolveCurrentWorkspaceRole(db, { userId, workspaceId }) {
  const membership = await db.query(
    "SELECT role FROM workspace_memberships WHERE user_id = $1 AND workspace_id = $2",
    [userId, workspaceId],
  );
  const owner = membership.rows[0]?.role
    ? { rows: [] }
    : await db.query("SELECT created_by FROM workspaces WHERE id = $1", [workspaceId]);
  return effectiveWorkspaceRole({
    membershipRole: membership.rows[0]?.role || null,
    workspaceCreatedBy: owner.rows[0]?.created_by,
    userId,
  });
}

function minRole(a, b) {
  if (!a || !b) return null;
  return hasAtLeastRole(a, b) ? b : a;
}

// What a connection may do right now. The effective role is the lower of the
// ceiling fixed at creation and the user's current role, so a demotion applies
// on the next request and a promotion never widens the connection.
function computeAuthority({ connection, currentRole }) {
  const effectiveRole = minRole(currentRole, connection.roleCeiling);
  const grantedScopes = effectiveRole
    ? connection.scopes.filter((scope) =>
        hasAtLeastRole(effectiveRole, SCOPE_MIN_ROLE[scope] || "admin"),
      )
    : [];
  return { currentRole, ceiling: connection.roleCeiling, effectiveRole, scopes: grantedScopes };
}

// The checks every connection request goes through, whether it is created
// directly or by redeeming an enrollment grant: normalized name, scopes and
// ceiling, and proof that the user really holds the authority being delegated.
// Redemption runs this again at redemption time, so authority lost between
// issuing a grant and spending it is caught.
async function validateConnectionRequest(options) {
  const db = options.client || pool;
  const workspaceId = typeof options.workspaceId === "string" ? options.workspaceId.trim() : "";
  if (!workspaceId) {
    throw serviceError("Workspace is required", CONNECTION_INVALID);
  }
  if (!Number.isInteger(options.userId)) {
    throw serviceError("User is required", CONNECTION_INVALID);
  }
  const name = normalizeName(options.name);
  const scopes = normalizeScopes(options.scopes);
  const roleCeiling = normalizeRoleCeiling(options.roleCeiling);

  // A connection can only be created with authority its user actually holds.
  const currentRole = await resolveCurrentWorkspaceRole(db, {
    userId: options.userId,
    workspaceId,
  });
  if (!currentRole) {
    throw serviceError("User has no access to this workspace", CONNECTION_FORBIDDEN);
  }
  if (!hasAtLeastRole(currentRole, roleCeiling)) {
    throw serviceError(
      "Role ceiling exceeds the user's current role",
      CONNECTION_FORBIDDEN,
    );
  }
  for (const scope of scopes) {
    if (!hasAtLeastRole(roleCeiling, SCOPE_MIN_ROLE[scope])) {
      throw serviceError(
        "A scope requires a higher role ceiling",
        CONNECTION_SCOPE_DENIED,
      );
    }
  }
  return { workspaceId, userId: options.userId, name, scopes, roleCeiling };
}

async function createConnection(options) {
  const db = options.client || pool;
  const expiresAt = resolveExpiry(options.expiresAt, options.now);
  const { workspaceId, name, scopes, roleCeiling } = await validateConnectionRequest(options);

  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const plaintextCredential = CONNECTION_CREDENTIAL.generate();
    const parsed = CONNECTION_CREDENTIAL.parse(plaintextCredential);
    try {
      const result = await db.query(
        `INSERT INTO operator_connections (
           workspace_id, user_id, name, scopes, role_ceiling,
           credential_prefix, credential_hash, expires_at, created_by
         )
         VALUES ($1, $2, $3, $4::text[], $5, $6, $7, $8, $9)
         RETURNING ${SAFE_SELECT_FIELDS}`,
        [
          workspaceId,
          options.userId,
          name,
          scopes,
          roleCeiling,
          parsed.lookupPrefix,
          sha256Hex(plaintextCredential),
          expiresAt,
          options.createdBy ?? options.userId,
        ],
      );
      return { connection: connectionFromRow(result.rows[0]), plaintextCredential };
    } catch (error) {
      const collision =
        error?.code === "23505" &&
        /operator_connections_credential|uq_operator_connections_credential/.test(
          String(error.constraint || ""),
        );
      if (collision && attempt < 3) continue;
      throw error;
    }
  }
  throw serviceError("Unable to create connection", CONNECTION_INVALID);
}

async function getConnection({ client, workspaceId, connectionId }) {
  const result = await (client || pool).query(
    `SELECT ${SAFE_SELECT_FIELDS} FROM operator_connections
      WHERE workspace_id = $1 AND id = $2 LIMIT 1`,
    [workspaceId, connectionId],
  );
  return connectionFromRow(result.rows[0] || null);
}

async function listConnections({ client, workspaceId, userId = null }) {
  const params = [workspaceId];
  let userClause = "";
  if (userId !== null) {
    params.push(userId);
    userClause = " AND user_id = $2";
  }
  const result = await (client || pool).query(
    `SELECT ${SAFE_SELECT_FIELDS} FROM operator_connections
      WHERE workspace_id = $1${userClause}
      ORDER BY created_at DESC, id ASC`,
    params,
  );
  return result.rows.map((row) => connectionFromRow(row));
}

// Revocation is idempotent. The row lock taken here is the same lock that
// authentication takes before authorizing a request, so once this commits no
// later request can authenticate (ADR-0015 section 8).
async function revokeConnection({ client, workspaceId, connectionId, revokedBy = null }) {
  const db = client || pool;
  const result = await db.query(
    `UPDATE operator_connections
        SET status = 'revoked', revoked_at = NOW(), revoked_by = $3, updated_at = NOW()
      WHERE workspace_id = $1 AND id = $2 AND status = 'active'
      RETURNING ${SAFE_SELECT_FIELDS}`,
    [workspaceId, connectionId, revokedBy],
  );
  if (result.rows[0]) {
    return { connection: connectionFromRow(result.rows[0]), revokedNow: true };
  }
  return {
    connection: await getConnection({ client: db, workspaceId, connectionId }),
    revokedNow: false,
  };
}

// Replaces the secret and nothing else: same connection id, owner, scopes,
// ceiling and expiry. A revoked or expired connection cannot be rotated.
async function rotateCredential({ client, workspaceId, connectionId }) {
  const db = client || pool;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const plaintextCredential = CONNECTION_CREDENTIAL.generate();
    const parsed = CONNECTION_CREDENTIAL.parse(plaintextCredential);
    try {
      const result = await db.query(
        `UPDATE operator_connections
            SET credential_prefix = $3, credential_hash = $4,
                credential_rotated_at = NOW(), updated_at = NOW()
          WHERE workspace_id = $1 AND id = $2
            AND status = 'active' AND expires_at > NOW()
          RETURNING ${SAFE_SELECT_FIELDS}`,
        [workspaceId, connectionId, parsed.lookupPrefix, sha256Hex(plaintextCredential)],
      );
      if (!result.rows[0]) return null;
      return { connection: connectionFromRow(result.rows[0]), plaintextCredential };
    } catch (error) {
      const collision =
        error?.code === "23505" &&
        /credential/.test(String(error.constraint || ""));
      if (collision && attempt < 3) continue;
      throw error;
    }
  }
  return null;
}

function invalid(code = CONNECTION_UNAUTHORIZED) {
  return { valid: false, code };
}

// Authenticates a presented credential and computes the authority it carries
// at this moment. The connection row is locked FOR SHARE inside the caller's
// transaction when one is supplied, which is what serializes a concurrent
// revocation against authorization.
async function authenticateCredential({ client, rawCredential, now = new Date() }) {
  const parsed = CONNECTION_CREDENTIAL.parse(rawCredential);
  if (!parsed) return invalid();
  const db = client || pool;

  const found = await db.query(
    `SELECT ${SAFE_SELECT_FIELDS}, credential_hash
       FROM operator_connections
      WHERE credential_prefix = $1
      LIMIT 1${client ? " FOR SHARE" : ""}`,
    [parsed.lookupPrefix],
  );
  const row = found.rows[0];
  if (!row) return invalid();
  if (!safeCompareSha256Hex(sha256Hex(rawCredential), row.credential_hash)) {
    return invalid();
  }
  const connection = connectionFromRow(row, now);
  if (connection.status !== "active") return invalid();

  const currentRole = await resolveCurrentWorkspaceRole(db, {
    userId: row.user_id,
    workspaceId: row.workspace_id,
  });
  const authority = computeAuthority({ connection, currentRole });
  if (!authority.effectiveRole) return invalid();

  return { valid: true, connection, authority };
}

// Usage timestamps are advisory, written at most every few minutes, and a
// failure here must never fail a request.
async function recordUse({ client, connectionId }) {
  try {
    await (client || pool).query(
      `UPDATE operator_connections
          SET last_used_at = NOW()
        WHERE id = $1
          AND (last_used_at IS NULL
               OR last_used_at <= NOW() - INTERVAL '${MAX_LAST_USED_WRITE_INTERVAL}')`,
      [connectionId],
    );
  } catch (_error) {
    /* advisory only */
  }
}

module.exports = {
  ALLOWED_SCOPES,
  CONNECTION_CREDENTIAL,
  CONNECTION_EXPIRY_INVALID,
  CONNECTION_FORBIDDEN,
  CONNECTION_INVALID,
  CONNECTION_NAME_INVALID,
  CONNECTION_ROLE_CEILING_INVALID,
  CONNECTION_SCOPE_DENIED,
  CONNECTION_SCOPE_INVALID,
  CONNECTION_UNAUTHORIZED,
  DEFAULT_LIFETIME_MS,
  MAX_LIFETIME_MS,
  PRIVATE_KEY_MATERIAL_REJECTED,
  RESERVED_SCOPES,
  ROLE_CEILINGS,
  SCOPE_MIN_ROLE,
  authenticateCredential,
  computeAuthority,
  connectionFromRow,
  createConnection,
  getConnection,
  listConnections,
  recordUse,
  resolveCurrentWorkspaceRole,
  revokeConnection,
  rotateCredential,
  validateConnectionRequest,
  _test: { resolveExpiry, normalizeName, normalizeScopes, connectionStatusFromRow },
};
