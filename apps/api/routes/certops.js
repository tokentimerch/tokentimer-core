"use strict";

const router = require("express").Router();

const { getApiLimiter } = require("../middleware/rateLimit");
const {
  PRIVATE_KEY_MATERIAL_REJECTED,
  rejectKeyMaterial,
} = require("../middleware/reject-key-material");
const {
  requireCertOpsEnabled,
} = require("../middleware/require-certops-enabled");
const { hasAtLeastRole } = require("../services/rbac");
const {
  CERTOPS_CERTIFICATE_PARSE_FAILED,
  CERTOPS_KEY_REFERENCE_INVALID,
  getManagedCertificate,
  importPublicCertificates,
  listManagedCertificates,
} = require("../services/certops/inventory");
const { writeAudit } = require("../services/audit");
const { logger } = require("../utils/logger");

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function requireCertOpsWriteRole(req, res, next) {
  if (req.isWorkerCall) return next();

  if (!hasAtLeastRole(req.authz?.workspaceRole, "workspace_manager")) {
    return res.status(403).json({
      error: "Forbidden: insufficient role",
      code: "INSUFFICIENT_ROLE",
    });
  }

  return next();
}

function certificatePemFromBody(body) {
  if (typeof body === "string") return body;
  if (!body || typeof body !== "object") return null;

  for (const field of ["certificatePem", "pem", "certificate", "chainPem"]) {
    if (typeof body[field] === "string") return body[field];
  }

  if (
    Array.isArray(body.certificates) &&
    body.certificates.every((item) => typeof item === "string")
  ) {
    return body.certificates.join("\n");
  }

  return null;
}

function optionalTrimmedString(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function writeOptionsFromRequest(req, source) {
  return {
    workspaceId: req.workspace.id,
    certificatePem: certificatePemFromBody(req.body),
    source,
    sourceRef: optionalTrimmedString(req.body?.sourceRef),
    name: optionalTrimmedString(req.body?.name),
    keyMode: optionalTrimmedString(req.body?.keyMode),
    keyReference: optionalTrimmedString(req.body?.keyReference),
    createdBy: req.user?.id || null,
  };
}

function handleCertOpsError(res, err) {
  if (err?.code === PRIVATE_KEY_MATERIAL_REJECTED) {
    return res.status(422).json({
      error: "Private key material is not accepted in CertOps requests",
      code: PRIVATE_KEY_MATERIAL_REJECTED,
    });
  }

  if (err?.code === CERTOPS_CERTIFICATE_PARSE_FAILED) {
    return res.status(400).json({
      error: "Certificate input could not be parsed",
      code: CERTOPS_CERTIFICATE_PARSE_FAILED,
    });
  }

  if (err?.code === CERTOPS_KEY_REFERENCE_INVALID) {
    return res.status(400).json({
      error: "keyReference must be a non-secret reference",
      code: CERTOPS_KEY_REFERENCE_INVALID,
    });
  }

  return null;
}

async function recordInventoryAudit(req, source, certificates) {
  const actorUserId = req.user?.id || null;
  await writeAudit({
    actorUserId,
    subjectUserId: actorUserId,
    action:
      source === "api"
        ? "CERTOPS_CERTIFICATE_REGISTERED"
        : "CERTOPS_CERTIFICATE_IMPORTED",
    targetType: "managed_certificate",
    targetId: null,
    workspaceId: req.workspace.id,
    metadata: {
      source,
      count: certificates.length,
      certificate_ids: certificates.map((certificate) => certificate.id),
      fingerprints_sha256: certificates.map(
        (certificate) => certificate.fingerprintSha256,
      ),
    },
  });
}

async function importCertificatesHandler(req, res, source, statusCode) {
  try {
    const options = writeOptionsFromRequest(req, source);
    if (!options.certificatePem) {
      return res.status(400).json({
        error: "certificatePem is required",
        code: "CERTOPS_CERTIFICATE_PEM_REQUIRED",
      });
    }

    const certificates = await importPublicCertificates(options);
    await recordInventoryAudit(req, source, certificates);
    return res.status(statusCode).json({
      items: certificates,
      count: certificates.length,
    });
  } catch (err) {
    const handled = handleCertOpsError(res, err);
    if (handled) return handled;

    logger.error("CertOps certificate import failed", {
      error: err.message,
      code: err.code || null,
      workspaceId: req.workspace?.id,
      userId: req.user?.id,
    });
    return res.status(500).json({
      error: "Failed to import certificate",
      code: "INTERNAL_ERROR",
    });
  }
}

router.get(
  "/api/v1/workspaces/:id/certops/certificates",
  getApiLimiter(),
  requireCertOpsEnabled,
  async (req, res) => {
    try {
      const result = await listManagedCertificates({
        workspaceId: req.workspace.id,
        limit: req.query.limit,
        offset: req.query.offset,
      });
      return res.json(result);
    } catch (err) {
      logger.error("CertOps certificate list failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to list certificates",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/certificates",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  requireCertOpsWriteRole,
  (req, res) => importCertificatesHandler(req, res, "api", 201),
);

router.get(
  "/api/v1/workspaces/:id/certops/certificates/:certId",
  getApiLimiter(),
  requireCertOpsEnabled,
  async (req, res) => {
    if (!UUID_PATTERN.test(String(req.params.certId || ""))) {
      return res.status(404).json({
        error: "Certificate not found",
        code: "CERTOPS_CERTIFICATE_NOT_FOUND",
      });
    }

    try {
      const certificate = await getManagedCertificate({
        workspaceId: req.workspace.id,
        certId: req.params.certId,
      });

      if (!certificate) {
        return res.status(404).json({
          error: "Certificate not found",
          code: "CERTOPS_CERTIFICATE_NOT_FOUND",
        });
      }

      return res.json({ certificate });
    } catch (err) {
      logger.error("CertOps certificate detail failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        certId: req.params?.certId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to load certificate",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/imports",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  requireCertOpsWriteRole,
  (req, res) => importCertificatesHandler(req, res, "import", 202),
);

module.exports = router;
