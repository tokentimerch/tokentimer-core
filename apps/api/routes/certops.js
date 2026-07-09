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
  CERTOPS_CERTIFICATE_NOT_FOUND,
  CERTOPS_CERTIFICATE_PARSE_FAILED,
  CERTOPS_CERTIFICATE_RETIRE_REASON_INVALID,
  CERTOPS_CERTIFICATE_RETIRE_STATUS_INVALID,
  CERTOPS_KEY_MODE_INVALID,
  CERTOPS_KEY_REFERENCE_INVALID,
  getManagedCertificate,
  importPublicCertificates,
  listCertificateInstances,
  listManagedCertificates,
  retireManagedCertificate,
} = require("../services/certops/inventory");
const {
  CERTOPS_API_TOKEN_INVALID,
  CERTOPS_API_TOKEN_NAME_INVALID,
  CERTOPS_API_TOKEN_SCOPE_INVALID,
  createApiToken,
  listApiTokens,
  revokeApiToken,
} = require("../services/certops/apiTokens");
const {
  CERTOPS_JOB_INVALID,
  CERTOPS_JOB_LOG_EVENT_TYPE_INVALID,
  CERTOPS_JOB_NOT_FOUND,
  CERTOPS_JOB_OPERATION_INVALID,
  CERTOPS_JOB_SOURCE_INVALID,
  CERTOPS_JOB_STATUS_INVALID,
  getCertificateJobById,
  listCertificateJobLog,
  listCertificateJobs,
} = require("../services/certops/jobs");
const {
  CERTOPS_EVIDENCE_INVALID,
  CERTOPS_EVIDENCE_TYPE_INVALID,
  listCertificateEvidence,
} = require("../services/certops/evidence");
const { writeAudit } = require("../services/audit");
const { logger } = require("../utils/logger");

const CERTOPS_API_TOKEN_NOT_FOUND = "CERTOPS_API_TOKEN_NOT_FOUND";

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

  if (err?.code === CERTOPS_CERTIFICATE_NOT_FOUND) {
    return res.status(404).json({
      error: "Certificate not found",
      code: CERTOPS_CERTIFICATE_NOT_FOUND,
    });
  }

  if (err?.code === CERTOPS_CERTIFICATE_RETIRE_STATUS_INVALID) {
    return res.status(400).json({
      error: "Invalid certificate retire status",
      code: CERTOPS_CERTIFICATE_RETIRE_STATUS_INVALID,
    });
  }

  if (err?.code === CERTOPS_CERTIFICATE_RETIRE_REASON_INVALID) {
    return res.status(400).json({
      error: "Invalid certificate retire reason",
      code: CERTOPS_CERTIFICATE_RETIRE_REASON_INVALID,
    });
  }

  if (err?.code === CERTOPS_KEY_MODE_INVALID) {
    return res.status(400).json({
      error: "Invalid CertOps key mode",
      code: CERTOPS_KEY_MODE_INVALID,
    });
  }

  if (err?.code === CERTOPS_KEY_REFERENCE_INVALID) {
    return res.status(400).json({
      error: "keyReference must be a non-secret reference",
      code: CERTOPS_KEY_REFERENCE_INVALID,
    });
  }

  if (err?.code === CERTOPS_API_TOKEN_NOT_FOUND) {
    return res.status(404).json({
      error: "CertOps API token not found",
      code: CERTOPS_API_TOKEN_NOT_FOUND,
    });
  }

  if (
    err?.code === CERTOPS_API_TOKEN_INVALID ||
    err?.code === CERTOPS_API_TOKEN_NAME_INVALID ||
    err?.code === CERTOPS_API_TOKEN_SCOPE_INVALID
  ) {
    return res.status(400).json({
      error: "CertOps API token request is invalid",
      code: err.code,
    });
  }

  if (err?.code === CERTOPS_JOB_NOT_FOUND) {
    return res.status(404).json({
      error: "Certificate job not found",
      code: CERTOPS_JOB_NOT_FOUND,
    });
  }

  const certOpsJobBadRequestCodes = new Set([
    CERTOPS_JOB_INVALID,
    CERTOPS_JOB_OPERATION_INVALID,
    CERTOPS_JOB_SOURCE_INVALID,
    CERTOPS_JOB_STATUS_INVALID,
    CERTOPS_JOB_LOG_EVENT_TYPE_INVALID,
    CERTOPS_EVIDENCE_INVALID,
    CERTOPS_EVIDENCE_TYPE_INVALID,
  ]);
  if (certOpsJobBadRequestCodes.has(err?.code)) {
    return res.status(400).json({
      error: "CertOps job request is invalid",
      code: err.code,
    });
  }

  return null;
}

function jobIdFromParams(req, res) {
  const jobId = String(req.params.jobId || "");
  if (!UUID_PATTERN.test(jobId)) {
    res.status(400).json({
      error: "CertOps job identifier is invalid",
      code: CERTOPS_JOB_INVALID,
    });
    return null;
  }
  return jobId;
}

function tokenIdFromParams(req, res) {
  const tokenId = String(req.params.tokenId || "");
  if (!UUID_PATTERN.test(tokenId)) {
    res.status(400).json({
      error: "CertOps API token identifier is invalid",
      code: CERTOPS_API_TOKEN_INVALID,
    });
    return null;
  }
  return tokenId;
}

function jobListOptionsFromRequest(req) {
  return {
    workspaceId: req.workspace.id,
    limit: req.query.limit,
    offset: req.query.offset,
    status: req.query.status,
    subjectType: req.query.subjectType,
    subjectId: req.query.subjectId,
    operation: req.query.operation,
    source: req.query.source,
  };
}

function jobSummary(job) {
  return {
    id: job.id,
    workspaceId: job.workspaceId,
    operation: job.operation,
    status: job.status,
    source: job.source,
    subjectType: job.subjectType,
    subjectId: job.subjectId,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    queuedAt: job.queuedAt,
    startedAt: job.startedAt,
    completedAt: job.completedAt,
    cancelledAt: job.cancelledAt,
    requestedByUserId: job.requestedByUserId,
    requestedByApiTokenId: job.requestedByApiTokenId,
  };
}

function jobDetail(job) {
  return {
    ...jobSummary(job),
    payload: job.payload || {},
    resultMetadata: job.resultMetadata || {},
    errorCode: job.errorCode,
    errorMessage: job.errorMessage,
  };
}

function jobLogEntry(entry) {
  return {
    id: entry.id,
    workspaceId: entry.workspaceId,
    jobId: entry.jobId,
    eventType: entry.eventType,
    status: entry.status,
    message: entry.message,
    metadata: entry.metadata || {},
    createdByUserId: entry.createdByUserId,
    createdByApiTokenId: entry.createdByApiTokenId,
    createdAt: entry.createdAt,
  };
}

function evidenceItem(item) {
  return {
    id: item.id,
    workspaceId: item.workspaceId,
    jobId: item.jobId,
    evidenceType: item.evidenceType,
    subjectType: item.subjectType,
    subjectId: item.subjectId,
    metadata: item.metadata || {},
    observedAt: item.observedAt,
    createdByUserId: item.createdByUserId,
    createdByApiTokenId: item.createdByApiTokenId,
    createdAt: item.createdAt,
  };
}

function apiTokenMetadata(token) {
  return {
    id: token.id,
    workspaceId: token.workspaceId,
    name: token.name,
    tokenPrefix: token.tokenPrefix,
    scopes: Array.isArray(token.scopes) ? [...token.scopes] : [],
    status: token.status,
    expiresAt: token.expiresAt,
    lastUsedAt: token.lastUsedAt,
    revokedAt: token.revokedAt,
    revokedByUserId: token.revokedBy ?? null,
    createdByUserId: token.createdBy ?? null,
    createdAt: token.createdAt,
    updatedAt: token.updatedAt,
  };
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

router.get(
  "/api/v1/workspaces/:id/certops/tokens",
  getApiLimiter(),
  requireCertOpsEnabled,
  async (req, res) => {
    try {
      const tokens = await listApiTokens({
        workspaceId: req.workspace.id,
      });
      return res.json({ items: tokens.map(apiTokenMetadata) });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps API token list failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to list CertOps API tokens",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/tokens",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  requireCertOpsWriteRole,
  async (req, res) => {
    try {
      const created = await createApiToken({
        workspaceId: req.workspace.id,
        name: req.body?.name,
        scopes: req.body?.scopes,
        expiresAt: req.body?.expiresAt,
        createdBy: req.user?.id || null,
      });

      return res.status(201).json({
        token: apiTokenMetadata(created.token),
        plaintextToken: created.plaintextToken,
      });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps API token create failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to create CertOps API token",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/tokens/:tokenId/revoke",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  requireCertOpsWriteRole,
  async (req, res) => {
    const tokenId = tokenIdFromParams(req, res);
    if (!tokenId) return null;

    try {
      const revoked = await revokeApiToken({
        workspaceId: req.workspace.id,
        tokenId,
        revokedBy: req.user?.id || null,
      });

      if (!revoked) {
        return res.status(404).json({
          error: "CertOps API token not found",
          code: CERTOPS_API_TOKEN_NOT_FOUND,
        });
      }

      return res.json({ token: apiTokenMetadata(revoked) });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps API token revoke failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        tokenId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to revoke CertOps API token",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.get(
  "/api/v1/workspaces/:id/certops/jobs",
  getApiLimiter(),
  requireCertOpsEnabled,
  async (req, res) => {
    try {
      const result = await listCertificateJobs(jobListOptionsFromRequest(req));
      return res.json({
        items: result.items.map(jobSummary),
        pagination: result.pagination,
      });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps job list failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to list CertOps jobs",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.get(
  "/api/v1/workspaces/:id/certops/jobs/:jobId/log",
  getApiLimiter(),
  requireCertOpsEnabled,
  async (req, res) => {
    const jobId = jobIdFromParams(req, res);
    if (!jobId) return null;

    try {
      const result = await listCertificateJobLog({
        workspaceId: req.workspace.id,
        jobId,
        limit: req.query.limit,
        offset: req.query.offset,
      });
      return res.json({
        items: result.items.map(jobLogEntry),
        pagination: result.pagination,
      });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps job log list failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        jobId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to list CertOps job log",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.get(
  "/api/v1/workspaces/:id/certops/jobs/:jobId/evidence",
  getApiLimiter(),
  requireCertOpsEnabled,
  async (req, res) => {
    const jobId = jobIdFromParams(req, res);
    if (!jobId) return null;

    try {
      const result = await listCertificateEvidence({
        workspaceId: req.workspace.id,
        jobId,
        limit: req.query.limit,
        offset: req.query.offset,
      });
      return res.json({
        items: result.items.map(evidenceItem),
        pagination: result.pagination,
      });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps job evidence list failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        jobId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to list CertOps job evidence",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.get(
  "/api/v1/workspaces/:id/certops/jobs/:jobId",
  getApiLimiter(),
  requireCertOpsEnabled,
  async (req, res) => {
    const jobId = jobIdFromParams(req, res);
    if (!jobId) return null;

    try {
      const job = await getCertificateJobById({
        workspaceId: req.workspace.id,
        jobId,
      });

      if (!job) {
        return res.status(404).json({
          error: "Certificate job not found",
          code: CERTOPS_JOB_NOT_FOUND,
        });
      }

      return res.json({ job: jobDetail(job) });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps job detail failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        jobId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to load CertOps job",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

async function retireCertificateHandler(req, res) {
  if (!UUID_PATTERN.test(String(req.params.certId || ""))) {
    return res.status(404).json({
      error: "Certificate not found",
      code: CERTOPS_CERTIFICATE_NOT_FOUND,
    });
  }

  try {
    const certificate = await retireManagedCertificate({
      workspaceId: req.workspace.id,
      certificateId: req.params.certId,
      status: req.body?.status,
      reason: req.body?.reason,
      actorUserId: req.user?.id || null,
      createdBy: req.user?.id || null,
    });

    return res.json({ certificate });
  } catch (err) {
    const handled = handleCertOpsError(res, err);
    if (handled) return handled;

    logger.error("CertOps certificate retire failed", {
      error: err.message,
      code: err.code || null,
      workspaceId: req.workspace?.id,
      certId: req.params?.certId,
      userId: req.user?.id,
    });
    return res.status(500).json({
      error: "Failed to retire certificate",
      code: "INTERNAL_ERROR",
    });
  }
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
  "/api/v1/workspaces/:id/certops/certificates/:certId/instances",
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
      const result = await listCertificateInstances({
        workspaceId: req.workspace.id,
        certId: req.params.certId,
        limit: req.query.limit,
        offset: req.query.offset,
      });

      if (!result) {
        return res.status(404).json({
          error: "Certificate not found",
          code: "CERTOPS_CERTIFICATE_NOT_FOUND",
        });
      }

      return res.json(result);
    } catch (err) {
      logger.error("CertOps certificate instances list failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        certId: req.params?.certId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to list certificate instances",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/certificates/:certId/retire",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  requireCertOpsWriteRole,
  retireCertificateHandler,
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
