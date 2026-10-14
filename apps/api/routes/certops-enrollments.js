"use strict";

const router = require("express").Router();
const { getApiLimiter } = require("../middleware/rateLimit");
const { requireCertOpsEnabled } = require("../middleware/require-certops-enabled");
const { authorize } = require("../services/rbac");
const {
  abandonEnrollment,
  cancelEnrollment,
  confirmIssuerKey,
  countInstalledEnrollments,
  createEnrollment,
  createIssuer,
  discardUnconfiguredIssuer,
  dispatchPreflight,
  listEnrollments,
  listIssuers,
  proposeReconcileRequestId,
} = require("../services/certops/certificateEnrollments");

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function fail(res, err) {
  const code = err?.code || "INTERNAL_ERROR";
  if (
    code === "CERTOPS_ISSUER_NOT_FOUND" ||
    code === "CERTOPS_ENROLLMENT_NOT_FOUND" ||
    code === "CERTOPS_PROFILE_NOT_FOUND"
  ) {
    return res.status(404).json({ error: err.message, code });
  }
  if (code === "CERTOPS_PREFLIGHT_RATE_LIMITED") {
    return res.status(429).json({ error: err.message, code });
  }
  if (String(code).startsWith("CERTOPS_")) {
    return res.status(400).json({ error: err.message, code });
  }
  return res.status(500).json({ error: "CertOps enrollment request failed", code: "INTERNAL_ERROR" });
}

router.get(
  "/api/v1/workspaces/:id/certops/issuers",
  getApiLimiter(),
  requireCertOpsEnabled,
  authorize("certops.issuer.manage"),
  async (req, res) => {
    try {
      const page = await listIssuers({
        workspaceId: req.workspace.id,
        limit: req.query.limit,
        offset: req.query.offset,
        includeUnconfigured: req.query.includeUnconfigured === "true",
      });
      return res.json(page);
    } catch (err) {
      return fail(res, err);
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/issuers",
  getApiLimiter(),
  requireCertOpsEnabled,
  authorize("certops.issuer.manage"),
  async (req, res) => {
    try {
      const issuer = await createIssuer({
        workspaceId: req.workspace.id,
        kind: req.body?.kind,
        name: req.body?.name,
        actorUserId: req.user?.id || null,
      });
      return res.status(201).json({ issuer });
    } catch (err) {
      return fail(res, err);
    }
  },
);

router.delete(
  "/api/v1/workspaces/:id/certops/issuers/:issuerId",
  getApiLimiter(),
  requireCertOpsEnabled,
  authorize("certops.issuer.manage"),
  async (req, res) => {
    try {
      if (!UUID.test(String(req.params.issuerId || ""))) {
        return res.status(404).json({ error: "issuer not found", code: "CERTOPS_ISSUER_NOT_FOUND" });
      }
      await discardUnconfiguredIssuer({
        workspaceId: req.workspace.id,
        issuerId: req.params.issuerId,
      });
      return res.status(204).send();
    } catch (err) {
      return fail(res, err);
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/issuers/:issuerId/preflight",
  getApiLimiter(),
  requireCertOpsEnabled,
  authorize("certops.issuer.manage"),
  async (req, res) => {
    try {
      if (!UUID.test(String(req.params.issuerId || ""))) {
        return res.status(400).json({ error: "issuer id is invalid", code: "CERTOPS_ISSUER_NOT_FOUND" });
      }
      const job = await dispatchPreflight({
        workspaceId: req.workspace.id,
        issuerId: req.params.issuerId,
        agentId: req.body?.agentId,
        caConfig: req.body?.caConfig,
        template: req.body?.template,
        actorUserId: req.user?.id || null,
      });
      return res.status(201).json({ job });
    } catch (err) {
      return fail(res, err);
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/issuers/:issuerId/confirm",
  getApiLimiter(),
  requireCertOpsEnabled,
  authorize("certops.issuer.manage"),
  async (req, res) => {
    try {
      const confirmed = await confirmIssuerKey({
        workspaceId: req.workspace.id,
        issuerId: req.params.issuerId,
        caKeySha256: req.body?.caKeySha256,
        caConfig: req.body?.caConfig,
        template: req.body?.template,
        actorUserId: req.user?.id || null,
      });
      return res.json(confirmed);
    } catch (err) {
      return fail(res, err);
    }
  },
);

router.get(
  "/api/v1/workspaces/:id/certops/enrollments",
  getApiLimiter(),
  requireCertOpsEnabled,
  authorize("certops.issuer.manage"),
  async (req, res) => {
    try {
      const page = await listEnrollments({
        workspaceId: req.workspace.id,
        limit: req.query.limit,
        offset: req.query.offset,
      });
      return res.json(page);
    } catch (err) {
      return fail(res, err);
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/enrollments",
  getApiLimiter(),
  requireCertOpsEnabled,
  authorize("certops.issuer.manage"),
  async (req, res) => {
    try {
      const created = await createEnrollment({
        workspaceId: req.workspace.id,
        issuerId: req.body?.issuerId,
        certificateId: req.body?.certificateId,
        agentId: req.body?.agentId,
        target: req.body?.target,
        authorizedDnsNames: req.body?.authorizedDnsNames,
        keyAlgorithm: req.body?.keyAlgorithm,
        keySize: req.body?.keySize,
        profileId: req.body?.profileId,
        actorUserId: req.user?.id || null,
      });
      return res.status(201).json(created);
    } catch (err) {
      return fail(res, err);
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/enrollments/:enrollmentId/reconcile",
  getApiLimiter(),
  requireCertOpsEnabled,
  authorize("certops.issuer.manage"),
  async (req, res) => {
    try {
      await proposeReconcileRequestId({
        workspaceId: req.workspace.id,
        enrollmentId: req.params.enrollmentId,
        requestId: req.body?.requestId,
        actorUserId: req.user?.id || null,
      });
      return res.status(204).end();
    } catch (err) {
      return fail(res, err);
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/enrollments/:enrollmentId/cancel",
  getApiLimiter(),
  requireCertOpsEnabled,
  authorize("certops.issuer.manage"),
  async (req, res) => {
    try {
      await cancelEnrollment({
        workspaceId: req.workspace.id,
        enrollmentId: req.params.enrollmentId,
        actorUserId: req.user?.id || null,
      });
      return res.status(204).end();
    } catch (err) {
      return fail(res, err);
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/enrollments/:enrollmentId/abandon",
  getApiLimiter(),
  requireCertOpsEnabled,
  authorize("certops.issuer.manage"),
  async (req, res) => {
    try {
      await abandonEnrollment({
        workspaceId: req.workspace.id,
        enrollmentId: req.params.enrollmentId,
        actorUserId: req.user?.id || null,
      });
      return res.status(204).end();
    } catch (err) {
      return fail(res, err);
    }
  },
);

router.get(
  "/api/v1/workspaces/:id/certops/enrollments/meter",
  getApiLimiter(),
  requireCertOpsEnabled,
  authorize("certops.issuer.manage"),
  async (req, res) => {
    try {
      const meter = await countInstalledEnrollments({ workspaceId: req.workspace.id });
      return res.json(meter);
    } catch (err) {
      return fail(res, err);
    }
  },
);

module.exports = router;
