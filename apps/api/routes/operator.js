"use strict";

// Operator interface routes (ADR-0015).
//
// Two surfaces with deliberately different authentication:
//   /api/v1/workspaces/:id/operator/connections   session-only management of
//       connections. These sit under the workspace prefix, so the shared
//       requireAuth + loadWorkspace + requireWorkspaceMembership stack runs
//       first and operator credentials are rejected by the early guard.
//   /api/v1/operator/*                            the operator namespace. It
//       accepts only an operator connection credential; the workspace comes
//       from the connection, never from the path.

const router = require("express").Router();

const { pool } = require("../db/database");
const { logger } = require("../utils/logger");
const { getApiLimiter } = require("../middleware/rateLimit");
const { rejectKeyMaterial } = require("../middleware/reject-key-material");
const {
  requireOperatorInterfaceEnabled,
} = require("../middleware/require-operator-interface");
const {
  requireOperatorConnection,
} = require("../middleware/operator-connection-auth");
const { writeAudit } = require("../services/audit");
const { hasAtLeastRole } = require("../services/rbac");
const {
  getWorkspaceCertOpsPauseState,
} = require("../services/certops/workspaceKillSwitch");
const connections = require("../services/operator/connections");
const { projectWhoami } = require("../services/operator/projections");

const VALIDATION_CODES = new Set([
  connections.CONNECTION_EXPIRY_INVALID,
  connections.CONNECTION_INVALID,
  connections.CONNECTION_NAME_INVALID,
  connections.CONNECTION_ROLE_CEILING_INVALID,
  connections.CONNECTION_SCOPE_INVALID,
  connections.PRIVATE_KEY_MATERIAL_REJECTED,
]);
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function requireSessionUser(req, res, next) {
  if (req.isWorkerCall || !req.user?.id) {
    return res.status(403).json({
      error: "Forbidden: session user required",
      code: "INSUFFICIENT_ROLE",
    });
  }
  return next();
}

// What a management call returns about a connection. The credential hash and
// anything derived from it never leave the service.
function connectionView(connection) {
  return {
    id: connection.id,
    name: connection.name,
    userId: connection.userId,
    scopes: connection.scopes,
    roleCeiling: connection.roleCeiling,
    credentialPrefix: connection.credentialPrefix,
    credentialRotatedAt: connection.credentialRotatedAt,
    status: connection.status,
    expiresAt: connection.expiresAt,
    lastUsedAt: connection.lastUsedAt,
    revokedAt: connection.revokedAt,
    createdAt: connection.createdAt,
  };
}

function handleError(res, err, message) {
  if (VALIDATION_CODES.has(err?.code) || err?.code === connections.CONNECTION_SCOPE_DENIED) {
    const status = err.code === connections.PRIVATE_KEY_MATERIAL_REJECTED ? 422 : 400;
    return res.status(status).json({ error: err.message, code: err.code });
  }
  if (err?.code === connections.CONNECTION_FORBIDDEN) {
    return res.status(403).json({ error: err.message, code: err.code });
  }
  logger.error(message, { error: err?.message, code: err?.code || null });
  return res.status(500).json({ error: message, code: "INTERNAL_ERROR" });
}

async function withTransaction(callback) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await callback(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

function auditConnection({ client, req, action, connection }) {
  return writeAudit({
    client,
    actorUserId: req.user.id,
    subjectUserId: connection.userId,
    action,
    targetType: "operator_connection",
    targetId: null,
    workspaceId: req.workspace.id,
    metadata: {
      connection_id: connection.id,
      name: connection.name,
      scopes: connection.scopes,
      role_ceiling: connection.roleCeiling,
      credential_prefix: connection.credentialPrefix,
      status: connection.status,
      expires_at: connection.expiresAt,
    },
  });
}

// A member manages their own connections. A workspace admin can see and revoke
// everyone's, but never rotates another user's credential, because rotation
// hands the new secret to the caller.
function canSeeConnection(req, connection) {
  return (
    String(connection.userId) === String(req.user.id) ||
    hasAtLeastRole(req.authz?.workspaceRole, "admin")
  );
}

router.get(
  "/api/v1/workspaces/:id/operator/connections",
  getApiLimiter(),
  requireOperatorInterfaceEnabled,
  requireSessionUser,
  async (req, res) => {
    try {
      const isAdmin = hasAtLeastRole(req.authz?.workspaceRole, "admin");
      const items = await connections.listConnections({
        workspaceId: req.workspace.id,
        userId: isAdmin ? null : req.user.id,
      });
      return res.json({ items: items.map(connectionView) });
    } catch (err) {
      return handleError(res, err, "Failed to list operator connections");
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/operator/connections",
  getApiLimiter(),
  rejectKeyMaterial,
  requireOperatorInterfaceEnabled,
  requireSessionUser,
  async (req, res) => {
    try {
      const created = await withTransaction(async (client) => {
        const result = await connections.createConnection({
          client,
          workspaceId: req.workspace.id,
          userId: req.user.id,
          createdBy: req.user.id,
          name: req.body?.name,
          scopes: req.body?.scopes,
          roleCeiling: req.body?.roleCeiling,
          expiresAt: req.body?.expiresAt,
        });
        await auditConnection({
          client,
          req,
          action: "OPERATOR_CONNECTION_CREATED",
          connection: result.connection,
        });
        return result;
      });
      // The credential is returned once and is not recoverable afterwards.
      res.set("Cache-Control", "no-store");
      return res.status(201).json({
        connection: connectionView(created.connection),
        credential: created.plaintextCredential,
      });
    } catch (err) {
      return handleError(res, err, "Failed to create operator connection");
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/operator/connections/:connectionId/revoke",
  getApiLimiter(),
  rejectKeyMaterial,
  requireOperatorInterfaceEnabled,
  requireSessionUser,
  async (req, res) => {
    try {
      if (!UUID_PATTERN.test(String(req.params.connectionId || ""))) {
        return res.status(404).json({ error: "Connection not found", code: "NOT_FOUND" });
      }
      const outcome = await withTransaction(async (client) => {
        const existing = await connections.getConnection({
          client,
          workspaceId: req.workspace.id,
          connectionId: req.params.connectionId,
        });
        if (!existing || !canSeeConnection(req, existing)) return null;
        const result = await connections.revokeConnection({
          client,
          workspaceId: req.workspace.id,
          connectionId: req.params.connectionId,
          revokedBy: req.user.id,
        });
        if (result.revokedNow) {
          await auditConnection({
            client,
            req,
            action: "OPERATOR_CONNECTION_REVOKED",
            connection: result.connection,
          });
        }
        return result;
      });
      if (!outcome) {
        return res.status(404).json({ error: "Connection not found", code: "NOT_FOUND" });
      }
      return res.json({ connection: connectionView(outcome.connection) });
    } catch (err) {
      return handleError(res, err, "Failed to revoke operator connection");
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/operator/connections/:connectionId/rotate",
  getApiLimiter(),
  rejectKeyMaterial,
  requireOperatorInterfaceEnabled,
  requireSessionUser,
  async (req, res) => {
    try {
      if (!UUID_PATTERN.test(String(req.params.connectionId || ""))) {
        return res.status(404).json({ error: "Connection not found", code: "NOT_FOUND" });
      }
      const rotated = await withTransaction(async (client) => {
        const existing = await connections.getConnection({
          client,
          workspaceId: req.workspace.id,
          connectionId: req.params.connectionId,
        });
        // Only the owner rotates: the new secret is returned to the caller.
        if (!existing || String(existing.userId) !== String(req.user.id)) return null;
        const result = await connections.rotateCredential({
          client,
          workspaceId: req.workspace.id,
          connectionId: req.params.connectionId,
        });
        if (!result) return { gone: true };
        await auditConnection({
          client,
          req,
          action: "OPERATOR_CONNECTION_CREDENTIAL_ROTATED",
          connection: result.connection,
        });
        return result;
      });
      if (!rotated) {
        return res.status(404).json({ error: "Connection not found", code: "NOT_FOUND" });
      }
      if (rotated.gone) {
        return res.status(409).json({
          error: "Connection is revoked or expired",
          code: connections.CONNECTION_UNAUTHORIZED,
        });
      }
      res.set("Cache-Control", "no-store");
      return res.json({
        connection: connectionView(rotated.connection),
        credential: rotated.plaintextCredential,
      });
    } catch (err) {
      return handleError(res, err, "Failed to rotate operator credential");
    }
  },
);

router.get(
  "/api/v1/operator/whoami",
  getApiLimiter(),
  requireOperatorInterfaceEnabled,
  requireOperatorConnection({ scope: "mcp:identity:read" }),
  async (req, res) => {
    try {
      const workspaceRow = await pool.query(
        "SELECT id, name FROM workspaces WHERE id = $1",
        [req.operator.workspaceId],
      );
      if (!workspaceRow.rows[0]) {
        return res.status(404).json({ error: "Not found", code: "NOT_FOUND" });
      }
      const state = await getWorkspaceCertOpsPauseState({
        workspaceId: req.operator.workspaceId,
      });
      return res.json(
        projectWhoami({
          operator: req.operator,
          workspace: workspaceRow.rows[0],
          certops: {
            enabled: state.certOpsEnabled,
            paused: state.certOpsPaused,
            approvalRequiredAlways: state.certOpsRequireApprovalAlways,
          },
        }),
      );
    } catch (err) {
      logger.error("Operator whoami failed", { error: err.message });
      return res.status(500).json({
        error: "Failed to read operator identity",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

module.exports = router;
