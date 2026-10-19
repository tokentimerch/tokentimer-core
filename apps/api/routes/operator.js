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
const { getApiLimiter, getOperatorEnrollmentLimiter } = require("../middleware/rateLimit");
const { rejectKeyMaterial } = require("../middleware/reject-key-material");
const { requireCertOpsEnabled } = require("../middleware/require-certops-enabled");
const {
  requireOperatorInterfaceEnabled,
} = require("../middleware/require-operator-interface");
const {
  bearerFromRequest,
  hasSessionIdentity,
  requireOperatorConnection,
} = require("../middleware/operator-connection-auth");
const { writeAudit } = require("../services/audit");
const { hasAtLeastRole } = require("../services/rbac");
const {
  getWorkspaceCertOpsPauseState,
} = require("../services/certops/workspaceKillSwitch");
const connections = require("../services/operator/connections");
const enrollments = require("../services/operator/enrollments");
const { projectWhoami } = require("../services/operator/projections");
const reads = require("../services/operator/reads");
const queries = require("../services/operator/queryParsers");
const { CURSOR_INVALID, isUuid } = require("../services/operator/readProjections");

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

// ---------------------------------------------------------------------------
// Read routes. Every one is GET, behind the rollout gate and a connection
// guard that names its scope. The workspace is the connection's, never the
// path's. A missing record and a record in another workspace both answer 404,
// so a caller cannot tell the two apart.

function operatorRead(scope, { minRole } = {}) {
  return [
    getApiLimiter(),
    requireOperatorInterfaceEnabled,
    requireOperatorConnection({ scope, minRole }),
    // Same rollout switch the session routes honor: with CertOps off, none of
    // this data is served to anyone.
    requireCertOpsEnabled,
  ];
}

function notFound(res) {
  return res.status(404).json({ error: "Not found", code: "NOT_FOUND" });
}

function readError(res, err, message) {
  if (err?.code === "OPERATOR_VALIDATION_ERROR" || err?.code === CURSOR_INVALID) {
    return res.status(400).json({ error: err.message, code: "OPERATOR_VALIDATION_ERROR" });
  }
  logger.error(message, { error: err?.message, code: err?.code || null });
  return res.status(500).json({ error: message, code: "INTERNAL_ERROR" });
}

function identityParam(req, res) {
  const id = String(req.params.identityId || "");
  if (!isUuid(id)) {
    notFound(res);
    return null;
  }
  return id;
}

router.get("/api/v1/operator/certificates", ...operatorRead("mcp:certs:read"), async (req, res) => {
  try {
    const parsed = queries.parseCertificates(req.query);
    const body = await reads.listCertificates({
      workspaceId: req.operator.workspaceId,
      limit: 25,
      offset: 0,
      ...parsed,
    });
    return res.json(body);
  } catch (err) {
    return readError(res, err, "Failed to list certificates");
  }
});

router.get("/api/v1/operator/certificates/:identityId", ...operatorRead("mcp:certs:read"), async (req, res) => {
  try {
    const identityId = identityParam(req, res);
    if (!identityId) return null;
    queries.parseQuery(req.query, {});
    const body = await reads.getCertificate({ workspaceId: req.operator.workspaceId, identityId });
    return body ? res.json(body) : notFound(res);
  } catch (err) {
    return readError(res, err, "Failed to read certificate");
  }
});

router.get(
  "/api/v1/operator/certificates/:identityId/observations",
  ...operatorRead("mcp:certs:read"),
  async (req, res) => {
    try {
      const identityId = identityParam(req, res);
      if (!identityId) return null;
      const parsed = queries.parsePaged(req.query);
      const body = await reads.getObservations({
        workspaceId: req.operator.workspaceId,
        identityId,
        limit: 25,
        offset: 0,
        ...parsed,
      });
      return body ? res.json(body) : notFound(res);
    } catch (err) {
      return readError(res, err, "Failed to read observations");
    }
  },
);

router.get(
  "/api/v1/operator/certificates/:identityId/explain",
  ...operatorRead("mcp:certs:read"),
  async (req, res) => {
    try {
      const identityId = identityParam(req, res);
      if (!identityId) return null;
      queries.parseQuery(req.query, {});
      const body = await reads.explainCertificate({ workspaceId: req.operator.workspaceId, identityId });
      return body ? res.json(body) : notFound(res);
    } catch (err) {
      return readError(res, err, "Failed to explain certificate state");
    }
  },
);

router.get(
  "/api/v1/operator/agents",
  ...operatorRead("mcp:agents:read", { minRole: "workspace_manager" }),
  async (req, res) => {
    try {
      const parsed = queries.parsePaged(req.query);
      const body = await reads.listAgentHealth({
        workspaceId: req.operator.workspaceId,
        limit: 25,
        offset: 0,
        ...parsed,
      });
      return res.json(body);
    } catch (err) {
      return readError(res, err, "Failed to list agents");
    }
  },
);

router.get("/api/v1/operator/jobs", ...operatorRead("mcp:jobs:read"), async (req, res) => {
  try {
    const parsed = queries.parseJobs(req.query);
    const body = await reads.listJobs({
      workspaceId: req.operator.workspaceId,
      limit: 25,
      offset: 0,
      ...parsed,
    });
    return res.json(body);
  } catch (err) {
    return readError(res, err, "Failed to list jobs");
  }
});

router.get("/api/v1/operator/jobs/:jobId", ...operatorRead("mcp:jobs:read"), async (req, res) => {
  try {
    const jobId = String(req.params.jobId || "");
    if (!isUuid(jobId)) return notFound(res);
    queries.parseQuery(req.query, {});
    const body = await reads.getJob({ workspaceId: req.operator.workspaceId, jobId });
    return body ? res.json(body) : notFound(res);
  } catch (err) {
    return readError(res, err, "Failed to read job");
  }
});

// ---------------------------------------------------------------------------
// Enrollment. A signed-in person creates a short-lived, single-use grant; a
// local setup command redeems it for the runtime credential. Grants are
// managed under the workspace prefix (session only). Redemption is the one
// operator-namespace route that takes no connection credential: it takes the
// grant, once.

const ENROLLMENT_VALIDATION_CODES = new Set([
  enrollments.ENROLLMENT_LIFETIME_INVALID,
]);

function enrollmentView(grant) {
  return {
    id: grant.id,
    name: grant.name,
    userId: grant.userId,
    scopes: grant.scopes,
    roleCeiling: grant.roleCeiling,
    connectionLifetimeDays: grant.connectionLifetimeDays,
    status: grant.status,
    expiresAt: grant.expiresAt,
    redeemedAt: grant.redeemedAt,
    redeemedConnectionId: grant.redeemedConnectionId,
    revokedAt: grant.revokedAt,
    createdAt: grant.createdAt,
  };
}

function handleEnrollmentError(res, err, message) {
  if (ENROLLMENT_VALIDATION_CODES.has(err?.code)) {
    return res.status(400).json({ error: err.message, code: err.code });
  }
  return handleError(res, err, message);
}

function auditEnrollment({ client, actorUserId, grant, action, connection = null }) {
  return writeAudit({
    client,
    actorUserId,
    subjectUserId: grant.userId,
    action,
    targetType: "operator_enrollment",
    targetId: null,
    workspaceId: grant.workspaceId,
    metadata: {
      enrollment_id: grant.id,
      name: grant.name,
      scopes: grant.scopes,
      role_ceiling: grant.roleCeiling,
      connection_lifetime_days: grant.connectionLifetimeDays,
      status: grant.status,
      expires_at: grant.expiresAt,
      connection_id: connection ? connection.id : grant.redeemedConnectionId,
    },
  });
}

router.post(
  "/api/v1/workspaces/:id/operator/enrollments",
  getApiLimiter(),
  rejectKeyMaterial,
  requireOperatorInterfaceEnabled,
  requireSessionUser,
  async (req, res) => {
    try {
      const created = await withTransaction(async (client) => {
        const result = await enrollments.createGrant({
          client,
          workspaceId: req.workspace.id,
          userId: req.user.id,
          createdBy: req.user.id,
          name: req.body?.name,
          scopes: req.body?.scopes,
          roleCeiling: req.body?.roleCeiling,
          connectionLifetimeDays: req.body?.connectionLifetimeDays,
        });
        await auditEnrollment({
          client,
          actorUserId: req.user.id,
          grant: result.grant,
          action: "OPERATOR_ENROLLMENT_CREATED",
        });
        return result;
      });
      // The grant is shown once, here, and is not recoverable afterwards.
      res.set("Cache-Control", "no-store");
      return res.status(201).json({
        enrollment: enrollmentView(created.grant),
        grant: created.plaintextGrant,
      });
    } catch (err) {
      return handleEnrollmentError(res, err, "Failed to create operator enrollment");
    }
  },
);

router.get(
  "/api/v1/workspaces/:id/operator/enrollments",
  getApiLimiter(),
  requireOperatorInterfaceEnabled,
  requireSessionUser,
  async (req, res) => {
    try {
      const isAdmin = hasAtLeastRole(req.authz?.workspaceRole, "admin");
      const items = await enrollments.listGrants({
        workspaceId: req.workspace.id,
        userId: isAdmin ? null : req.user.id,
      });
      return res.json({ items: items.map(enrollmentView) });
    } catch (err) {
      return handleEnrollmentError(res, err, "Failed to list operator enrollments");
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/operator/enrollments/:enrollmentId/revoke",
  getApiLimiter(),
  rejectKeyMaterial,
  requireOperatorInterfaceEnabled,
  requireSessionUser,
  async (req, res) => {
    try {
      if (!UUID_PATTERN.test(String(req.params.enrollmentId || ""))) {
        return res.status(404).json({ error: "Enrollment not found", code: "NOT_FOUND" });
      }
      const outcome = await withTransaction(async (client) => {
        const existing = await enrollments.getGrant({
          client,
          workspaceId: req.workspace.id,
          grantId: req.params.enrollmentId,
        });
        const allowed =
          existing &&
          (String(existing.userId) === String(req.user.id) ||
            hasAtLeastRole(req.authz?.workspaceRole, "admin"));
        if (!allowed) return null;
        const after = await enrollments.revokeGrant({
          client,
          workspaceId: req.workspace.id,
          grantId: req.params.enrollmentId,
          revokedBy: req.user.id,
        });
        if (existing.status === "pending" && after.status === "revoked") {
          await auditEnrollment({
            client,
            actorUserId: req.user.id,
            grant: after,
            action: "OPERATOR_ENROLLMENT_REVOKED",
          });
        }
        return after;
      });
      if (!outcome) {
        return res.status(404).json({ error: "Enrollment not found", code: "NOT_FOUND" });
      }
      return res.json({ enrollment: enrollmentView(outcome) });
    } catch (err) {
      return handleEnrollmentError(res, err, "Failed to revoke operator enrollment");
    }
  },
);

const REDEEM_ERROR_STATUS = Object.freeze({
  [enrollments.ENROLLMENT_INVALID]: 401,
  [enrollments.ENROLLMENT_USED]: 409,
  [enrollments.ENROLLMENT_REVOKED]: 410,
  [enrollments.ENROLLMENT_EXPIRED]: 410,
  [enrollments.ENROLLMENT_AUTHORITY_LOST]: 403,
});

router.post(
  "/api/v1/operator/enroll/redeem",
  getOperatorEnrollmentLimiter(),
  requireOperatorInterfaceEnabled,
  async (req, res) => {
    // Only the grant, alone. A cookie or session next to it is ambiguous.
    if (hasSessionIdentity(req)) {
      return res.status(401).json({
        error: "Session identity is not allowed when redeeming an enrollment code",
        code: enrollments.ENROLLMENT_INVALID,
      });
    }
    const bearer = bearerFromRequest(req);
    try {
      const redeemed = await withTransaction(async (client) => {
        const result = await enrollments.redeemGrant({ client, rawGrant: bearer.raw });
        // Nobody is signed in here, so no actor is recorded. The grant holder
        // acts for the user who issued it; that user is the subject.
        await auditEnrollment({
          client,
          actorUserId: null,
          grant: result.grant,
          action: "OPERATOR_ENROLLMENT_REDEEMED",
          connection: result.connection,
        });
        return result;
      });
      res.set("Cache-Control", "no-store");
      return res.status(201).json({
        connection: connectionView(redeemed.connection),
        credential: redeemed.plaintextCredential,
      });
    } catch (err) {
      const status = REDEEM_ERROR_STATUS[err?.code];
      if (status) {
        return res.status(status).json({ error: err.message, code: err.code });
      }
      logger.error("Operator enrollment redemption failed", { error: err?.message, code: err?.code || null });
      return res.status(500).json({ error: "Failed to redeem enrollment code", code: "INTERNAL_ERROR" });
    }
  },
);

module.exports = router;
