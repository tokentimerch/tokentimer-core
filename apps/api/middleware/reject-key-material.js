"use strict";

const {
  containsPrivateKeyMaterial,
} = require("../utils/secretMaterial");
const { writeAudit } = require("../services/audit");
const { logger } = require("../utils/logger");

const PRIVATE_KEY_MATERIAL_REJECTED = "PRIVATE_KEY_MATERIAL_REJECTED";
const CERTOPS_KEY_MATERIAL_REJECTED = "CERTOPS_KEY_MATERIAL_REJECTED";
const CERTOPS_SECURITY_AUDIT_UNAVAILABLE =
  "CERTOPS_SECURITY_AUDIT_UNAVAILABLE";

const REJECTION_RESPONSE = Object.freeze({
  error: "Private key material is not accepted in CertOps requests",
  code: PRIVATE_KEY_MATERIAL_REJECTED,
});

const AUDIT_UNAVAILABLE_RESPONSE = Object.freeze({
  error: "Security audit unavailable",
  code: CERTOPS_SECURITY_AUDIT_UNAVAILABLE,
});

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function requestBodyType(value) {
  if (Buffer.isBuffer(value)) return "buffer";
  if (Array.isArray(value)) return "array";
  if (value === null) return "null";
  return typeof value;
}

function workspaceIdFromRequest(req) {
  const workspaceId = req.workspace?.id || req.params?.id || null;
  if (typeof workspaceId !== "string") return null;
  return UUID_PATTERN.test(workspaceId) ? workspaceId : null;
}

function safeRequestPath(req) {
  return req.route?.path || req.path || null;
}

function buildAuditEvent(req) {
  const actorUserId = req.user?.id || null;
  return {
    actorUserId,
    subjectUserId: actorUserId,
    action: CERTOPS_KEY_MATERIAL_REJECTED,
    targetType: "certops_request",
    targetId: null,
    workspaceId: workspaceIdFromRequest(req),
    metadata: {
      code: PRIVATE_KEY_MATERIAL_REJECTED,
      method: req.method || null,
      path: safeRequestPath(req),
      body_type: requestBodyType(req.body),
    },
  };
}

async function recordKeyMaterialRejection(req, auditWriter = writeAudit) {
  await auditWriter(buildAuditEvent(req));
}

function createRejectKeyMaterialMiddleware({ auditWriter = writeAudit } = {}) {
  return async function rejectKeyMaterial(req, res, next) {
    if (!containsPrivateKeyMaterial(req.body)) {
      return next();
    }

    try {
      await recordKeyMaterialRejection(req, auditWriter);
    } catch (err) {
      logger.warn("Failed to record CertOps key-material rejection audit", {
        code: err.code || null,
        error_name: err.name || null,
        path: safeRequestPath(req),
        method: req.method || null,
      });
      return res.status(503).json(AUDIT_UNAVAILABLE_RESPONSE);
    }

    return res.status(422).json(REJECTION_RESPONSE);
  };
}

const rejectKeyMaterial = createRejectKeyMaterialMiddleware();

module.exports = {
  PRIVATE_KEY_MATERIAL_REJECTED,
  CERTOPS_KEY_MATERIAL_REJECTED,
  CERTOPS_SECURITY_AUDIT_UNAVAILABLE,
  buildAuditEvent,
  createRejectKeyMaterialMiddleware,
  recordKeyMaterialRejection,
  rejectKeyMaterial,
};
