"use strict";

// Operator enrollment grants (ADR-0015 section 12).
//
// A signed-in person creates a short-lived, single-use grant that fixes the
// user, workspace, scopes, role ceiling, connection name and connection
// lifetime. Redeeming it creates the connection and hands back the runtime
// credential exactly once. Nothing about the credential is kept: if the
// response is lost, the connection is revoked and a new grant is issued.
//
// Redemption never trusts what the grant said at creation. It re-checks the
// authorizing user's current role inside the same transaction that consumes
// the grant, so authority lost in between is caught, and the grant row is
// locked so only one of several concurrent redemptions can win.

const { pool } = require("../../db/database");
const {
  defineCredentialFamily,
  safeCompareSha256Hex,
  sha256Hex,
} = require("../credentials/primitives");
const connections = require("./connections");

const GRANT_CREDENTIAL = defineCredentialFamily({ prefix: "ttopg_" });

const ENROLLMENT_INVALID = "OPERATOR_ENROLLMENT_INVALID";
const ENROLLMENT_EXPIRED = "OPERATOR_ENROLLMENT_EXPIRED";
const ENROLLMENT_USED = "OPERATOR_ENROLLMENT_USED";
const ENROLLMENT_REVOKED = "OPERATOR_ENROLLMENT_REVOKED";
const ENROLLMENT_AUTHORITY_LOST = "OPERATOR_ENROLLMENT_AUTHORITY_LOST";
const ENROLLMENT_LIFETIME_INVALID = "OPERATOR_ENROLLMENT_LIFETIME_INVALID";
const ENROLLMENT_NOT_FOUND = "OPERATOR_ENROLLMENT_NOT_FOUND";

const MINUTE_MS = 60 * 1000;
const GRANT_TTL_MS = 10 * MINUTE_MS;
// The database caps a grant at 15 minutes; the service stays under it.
const MAX_GRANT_TTL_MS = 15 * MINUTE_MS;
const DEFAULT_CONNECTION_DAYS = 30;
const MAX_CONNECTION_DAYS = 90;
const DAY_MS = 24 * 60 * 60 * 1000;

const SAFE_SELECT_FIELDS = `
  id, workspace_id, user_id, name, scopes, role_ceiling,
  connection_lifetime_days, grant_prefix, status, expires_at, redeemed_at,
  redeemed_connection_id, revoked_at, revoked_by, created_by, created_at,
  updated_at
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

function grantStatusFromRow(row, now = new Date()) {
  if (row?.status !== "pending") return row?.status || null;
  const expiresAt = row.expires_at ? new Date(row.expires_at) : null;
  return expiresAt && expiresAt.getTime() <= now.getTime() ? "expired" : "pending";
}

function grantFromRow(row, now = new Date()) {
  if (!row) return null;
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    userId: row.user_id,
    name: row.name,
    scopes: Array.isArray(row.scopes) ? [...row.scopes] : [],
    roleCeiling: row.role_ceiling,
    connectionLifetimeDays: row.connection_lifetime_days,
    grantPrefix: row.grant_prefix,
    status: grantStatusFromRow(row, now),
    expiresAt: dateToIso(row.expires_at),
    redeemedAt: dateToIso(row.redeemed_at),
    redeemedConnectionId: row.redeemed_connection_id ?? null,
    revokedAt: dateToIso(row.revoked_at),
    revokedBy: row.revoked_by ?? null,
    createdBy: row.created_by ?? null,
    createdAt: dateToIso(row.created_at),
    updatedAt: dateToIso(row.updated_at),
  };
}

function normalizeConnectionDays(value) {
  if (value === undefined || value === null || value === "") return DEFAULT_CONNECTION_DAYS;
  const days = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(days) || days < 1 || days > MAX_CONNECTION_DAYS) {
    throw serviceError(
      "Connection lifetime must be a whole number of days from 1 to 90",
      ENROLLMENT_LIFETIME_INVALID,
    );
  }
  return days;
}

// The grant is validated as strictly as the connection it will become, so a
// request that could never be redeemed is refused now, not ten minutes later.
async function createGrant(options) {
  const db = options.client || pool;
  const now = options.now instanceof Date ? options.now : new Date();
  const days = normalizeConnectionDays(options.connectionLifetimeDays);
  const request = await connections.validateConnectionRequest({
    client: db,
    workspaceId: options.workspaceId,
    userId: options.userId,
    name: options.name,
    scopes: options.scopes,
    roleCeiling: options.roleCeiling,
  });

  const ttl = Math.min(options.ttlMs ?? GRANT_TTL_MS, MAX_GRANT_TTL_MS);
  const expiresAt = new Date(now.getTime() + ttl);

  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const plaintextGrant = GRANT_CREDENTIAL.generate();
    const parsed = GRANT_CREDENTIAL.parse(plaintextGrant);
    try {
      const result = await db.query(
        `INSERT INTO operator_enrollment_grants (
           workspace_id, user_id, name, scopes, role_ceiling,
           connection_lifetime_days, grant_prefix, grant_hash,
           expires_at, created_by, created_at, updated_at
         )
         VALUES ($1, $2, $3, $4::text[], $5, $6, $7, $8, $9, $10, $11, $11)
         RETURNING ${SAFE_SELECT_FIELDS}`,
        [
          request.workspaceId,
          request.userId,
          request.name,
          request.scopes,
          request.roleCeiling,
          days,
          parsed.lookupPrefix,
          sha256Hex(plaintextGrant),
          expiresAt,
          options.createdBy ?? request.userId,
          now,
        ],
      );
      return { grant: grantFromRow(result.rows[0], now), plaintextGrant };
    } catch (error) {
      const collision =
        error?.code === "23505" &&
        /operator_enrollment_grants_(prefix|hash)|uq_operator_enrollment_grants/.test(
          String(error.constraint || ""),
        );
      if (collision && attempt < 3) continue;
      throw error;
    }
  }
  throw serviceError("Unable to create enrollment", ENROLLMENT_INVALID);
}

async function getGrant({ client, workspaceId, grantId }) {
  const result = await (client || pool).query(
    `SELECT ${SAFE_SELECT_FIELDS} FROM operator_enrollment_grants
      WHERE workspace_id = $1 AND id = $2 LIMIT 1`,
    [workspaceId, grantId],
  );
  return grantFromRow(result.rows[0] || null);
}

async function listGrants({ client, workspaceId, userId = null }) {
  const params = [workspaceId];
  let userClause = "";
  if (userId !== null) {
    params.push(userId);
    userClause = " AND user_id = $2";
  }
  const result = await (client || pool).query(
    `SELECT ${SAFE_SELECT_FIELDS} FROM operator_enrollment_grants
      WHERE workspace_id = $1${userClause}
      ORDER BY created_at DESC, id ASC
      LIMIT 100`,
    params,
  );
  return result.rows.map((row) => grantFromRow(row));
}

// Idempotent: revoking a grant that is already revoked, spent or expired
// changes nothing and reports the row as it stands.
async function revokeGrant({ client, workspaceId, grantId, revokedBy = null }) {
  const db = client || pool;
  await db.query(
    `UPDATE operator_enrollment_grants
        SET status = 'revoked', revoked_at = NOW(), revoked_by = $3, updated_at = NOW()
      WHERE workspace_id = $1 AND id = $2 AND status = 'pending'`,
    [workspaceId, grantId, revokedBy],
  );
  return getGrant({ client: db, workspaceId, grantId });
}

// Redeem a grant. Must run on a transaction client: the row lock only means
// something inside one. Failures before the secret is proven are one uniform
// error, so nothing is revealed to someone who does not hold a real grant.
// After the secret is proven, the specific reason is returned, because the
// caller already holds the credential and needs to know what to do next.
async function redeemGrant({ client, rawGrant, now = new Date() }) {
  if (!client || typeof client.query !== "function") {
    throw serviceError("Redemption requires a transaction client", ENROLLMENT_INVALID);
  }
  const parsed = GRANT_CREDENTIAL.parse(rawGrant);
  if (!parsed) throw serviceError("Enrollment code is not valid", ENROLLMENT_INVALID);

  const locked = await client.query(
    `SELECT ${SAFE_SELECT_FIELDS}, grant_hash
       FROM operator_enrollment_grants
      WHERE grant_prefix = $1
      FOR UPDATE`,
    [parsed.lookupPrefix],
  );
  const row = locked.rows[0];
  // Compare even when no row matched, so a miss and a wrong secret cost the same.
  const stored = row?.grant_hash || "0".repeat(64);
  const matches = safeCompareSha256Hex(sha256Hex(parsed.raw), stored);
  if (!row || !matches) throw serviceError("Enrollment code is not valid", ENROLLMENT_INVALID);

  const grant = grantFromRow(row, now);
  if (grant.status === "redeemed") {
    throw serviceError("This enrollment code has already been used", ENROLLMENT_USED);
  }
  if (grant.status === "revoked") {
    throw serviceError("This enrollment code was revoked", ENROLLMENT_REVOKED);
  }
  if (grant.status === "expired") {
    throw serviceError("This enrollment code has expired", ENROLLMENT_EXPIRED);
  }

  // Authority is re-checked now, not trusted from when the grant was issued.
  // Everything a grant fixed is passed through unchanged: the redeemer chooses
  // nothing. A user who left the workspace or was demoted below the ceiling
  // cannot have a connection minted from an old grant.
  let created;
  // The database caps lifetime against its own clock; a margin keeps a
  // 90-day grant valid when this process's clock runs slightly ahead.
  const requestedExpiry = now.getTime() + grant.connectionLifetimeDays * DAY_MS;
  const latestExpiry = now.getTime() + connections.MAX_LIFETIME_MS - 5 * MINUTE_MS;
  try {
    created = await connections.createConnection({
      client,
      workspaceId: grant.workspaceId,
      userId: grant.userId,
      createdBy: grant.userId,
      name: grant.name,
      scopes: grant.scopes,
      roleCeiling: grant.roleCeiling,
      expiresAt: new Date(Math.min(requestedExpiry, latestExpiry)),
      now,
    });
  } catch (error) {
    if (
      error?.code === connections.CONNECTION_FORBIDDEN ||
      error?.code === connections.CONNECTION_SCOPE_DENIED
    ) {
      throw serviceError(
        "The person who issued this enrollment code no longer has the access it needs",
        ENROLLMENT_AUTHORITY_LOST,
      );
    }
    throw error;
  }

  const consumed = await client.query(
    `UPDATE operator_enrollment_grants
        SET status = 'redeemed', redeemed_at = $2, redeemed_connection_id = $3, updated_at = $2
      WHERE id = $1 AND status = 'pending'
      RETURNING ${SAFE_SELECT_FIELDS}`,
    [grant.id, now, created.connection.id],
  );
  if (!consumed.rows[0]) {
    // Unreachable while the row is locked; if it ever happens, abort rather
    // than hand out a credential for a grant that was not consumed.
    throw serviceError("Enrollment could not be completed", ENROLLMENT_INVALID);
  }

  return {
    connection: created.connection,
    plaintextCredential: created.plaintextCredential,
    grant: grantFromRow(consumed.rows[0], now),
  };
}

module.exports = {
  ENROLLMENT_AUTHORITY_LOST,
  ENROLLMENT_EXPIRED,
  ENROLLMENT_INVALID,
  ENROLLMENT_LIFETIME_INVALID,
  ENROLLMENT_NOT_FOUND,
  ENROLLMENT_REVOKED,
  ENROLLMENT_USED,
  GRANT_CREDENTIAL,
  GRANT_TTL_MS,
  MAX_GRANT_TTL_MS,
  createGrant,
  getGrant,
  grantFromRow,
  listGrants,
  redeemGrant,
  revokeGrant,
  _test: { grantStatusFromRow, normalizeConnectionDays },
};
