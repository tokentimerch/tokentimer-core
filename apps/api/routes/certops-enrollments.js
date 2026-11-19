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
  retryEnrollmentInstallation,
  recoverOrphanedEnrollment,
} = require("../services/certops/certificateEnrollments");

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function requireRecoverySessionUser(req,res,next) {
  if (req.isWorkerCall || !req.user?.id) return res.status(403).json({error:"Session user required for recovery",code:"INSUFFICIENT_ROLE"});
  return next();
}

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
  if (code === "CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED" || code === "CERTOPS_ENROLLMENT_OPEN") {
    return res.status(409).json({ error: err.message, code });
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
        pollInterval: req.body?.pollInterval,
        pendingTimeout: req.body?.pendingTimeout,
        minimumRemainingValidity: req.body?.minimumRemainingValidity,
        requireLaterNotAfter: req.body?.requireLaterNotAfter,
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
  "/api/v1/workspaces/:id/certops/enrollments/:enrollmentId/retry-installation",
  getApiLimiter(),
  requireCertOpsEnabled,
  requireRecoverySessionUser,
  authorize("certops.issuer.manage"),
  async (req, res) => {
    try {
      if (!UUID.test(req.params.enrollmentId) ||
          req.body === null || typeof req.body !== "object" || Array.isArray(req.body) ||
          Object.keys(req.body || {}).length) {
        return res.status(400).json({ error: "Retry accepts an enrollment identifier and an empty body", code: "CERTOPS_SNAPSHOT_INVALID" });
      }
      const result = await retryEnrollmentInstallation({ workspaceId: req.workspace.id,
        enrollmentId: req.params.enrollmentId, actorUserId: req.user?.id || null });
      return res.status(result.created ? 201 : 200).json(result);
    } catch (err) { return fail(res, err); }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/enrollments/:enrollmentId/recover-installation-proof",
  getApiLimiter(), requireCertOpsEnabled, requireRecoverySessionUser, authorize("certops.issuer.manage"),
  async (req, res) => {
    const body = req.body;
    if (!UUID.test(String(req.params.enrollmentId || "")) || !body || typeof body !== "object" || Array.isArray(body) ||
        Object.keys(body).some(key => !["orphanedJobId", "reason"].includes(key)) || !UUID.test(String(body.orphanedJobId || ""))) {
      return res.status(400).json({ error: "Proof recovery accepts the orphaned job identifier and reason", code: "CERTOPS_SNAPSHOT_INVALID" });
    }
    const client = await require("../db/database").pool.connect();
    try {
      await client.query("BEGIN");
      // Agent dispatch takes this lock before the workspace lock.
      await client.query(`SELECT a.id FROM certops_agents a JOIN certificate_enrollments e
        ON e.workspace_id=a.workspace_id AND e.agent_id=a.id
        WHERE e.workspace_id=$1 AND e.id=$2::uuid FOR SHARE OF a`, [req.workspace.id, req.params.enrollmentId]);
      await require("../services/certops/workspaceKillSwitch").lockWorkspaceForCertOpsSideEffect({ client, workspaceId: req.workspace.id, env: process.env });
      const recovery = require("../services/certops/adcsProofRecovery");
      const intent = await recovery.prepareAdcsProofRecoveryTx({ client, workspaceId: req.workspace.id,
        enrollmentId: req.params.enrollmentId, originalJobId: body.orphanedJobId, reason: body.reason, actorUserId: req.user.id });
      let queued = null;
      if (intent.intentId) {
        try { queued = await recovery.queueAdcsProofRecoveryTx({ client, workspaceId: req.workspace.id, intentId: intent.intentId, actorUserId: req.user.id }); }
        catch (error) { if (error.code !== "CERTOPS_ADCS_PROOF_AGENT_UNAVAILABLE") throw error; }
      }
      await client.query("COMMIT");
      return res.status(queued?.created ? 201 : 200).json({ ...intent, ...(queued ? { state: "queued", job: queued.job } : {}) });
    } catch (error) {
      await client.query("ROLLBACK");
      return fail(res, error);
    } finally { client.release(); }
  },
);

router.get(
  "/api/v1/workspaces/:id/certops/acme-store-enrollments/by-job/:jobId",
  getApiLimiter(), requireCertOpsEnabled, requireRecoverySessionUser, authorize("certops.issuer.manage"),
  async (req, res) => {
    if (!UUID.test(String(req.params.jobId || ""))) return res.status(404).json({ error: "Enrollment not found", code: "CERTOPS_ENROLLMENT_NOT_FOUND" });
    try {
      const result = await require("../db/database").pool.query(`SELECT e.id,e.state,e.current_job_id,e.original_job_id,
          j.status,j.needs_operator_reconciliation
        FROM certops_acme_store_enrollments e JOIN certificate_jobs j
          ON j.workspace_id=e.workspace_id AND j.id=$2::uuid
        WHERE e.workspace_id=$1::uuid AND (e.current_job_id=j.id OR e.original_job_id=j.id)`,
      [req.workspace.id, req.params.jobId]);
      const row = result.rows[0];
      if (!row) return res.status(404).json({ error: "Enrollment not found", code: "CERTOPS_ENROLLMENT_NOT_FOUND" });
      return res.json({ enrollmentId: String(row.id), state: row.state,
        outcomeUncertain: row.status === "orphaned_unknown_effect" && row.needs_operator_reconciliation === true,
        recoveryAvailable: String(row.current_job_id) === req.params.jobId &&
          row.status === "orphaned_unknown_effect" && row.needs_operator_reconciliation === true });
    } catch (error) { return fail(res, error); }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/acme-store-enrollments/:enrollmentId/recover",
  getApiLimiter(), requireCertOpsEnabled, requireRecoverySessionUser, authorize("certops.issuer.manage"),
  async (req, res) => {
    const body = req.body;
    if (!UUID.test(String(req.params.enrollmentId || "")) || !body || typeof body !== "object" || Array.isArray(body) ||
        Object.keys(body).some(key => !["orphanedJobId", "acknowledgeUnknownEffect", "reason"].includes(key)) ||
        !UUID.test(String(body.orphanedJobId || "")) || body.acknowledgeUnknownEffect !== true) {
      return res.status(400).json({ error: "Recovery requires the orphaned job identifier, explicit acknowledgement and reason", code: "CERTOPS_SNAPSHOT_INVALID" });
    }
    let client;
    try {
      client = await require("../db/database").pool.connect();
      await client.query("BEGIN");
      // Match dispatch lock ordering; the primitive rechecks the binding under lock.
      await client.query(`SELECT a.id FROM certops_agents a JOIN certops_acme_store_enrollments e
        ON e.workspace_id=a.workspace_id AND e.agent_id=a.id
        WHERE e.workspace_id=$1 AND e.id=$2::uuid FOR SHARE OF a`, [req.workspace.id, req.params.enrollmentId]);
      await require("../services/certops/workspaceKillSwitch").lockWorkspaceForCertOpsSideEffect({ client, workspaceId: req.workspace.id, env: process.env });
      const result = await require("../services/certops/acmeStorePersistence").continueAcmeStoreEnrollmentTx({ client,
        workspaceId: req.workspace.id, enrollmentId: req.params.enrollmentId, orphanedJobId: body.orphanedJobId,
        acknowledgeUnknownEffect: body.acknowledgeUnknownEffect, reason: body.reason, actorUserId: req.user.id });
      await client.query("COMMIT");
      return res.status(result.created ? 201 : 200).json(result);
    } catch (error) {
      if (client) await client.query("ROLLBACK");
      return fail(res, error);
    } finally { if (client) client.release(); }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/enrollments/:enrollmentId/recover",
  getApiLimiter(),
  requireCertOpsEnabled,
  requireRecoverySessionUser,
  authorize("certops.issuer.manage"),
  async(req,res)=>{
    try{
      const body=req.body;
      if (!UUID.test(req.params.enrollmentId) || !body || typeof body!=="object" || Array.isArray(body) ||
          Object.keys(body).some(key=>!["orphanedJobId","acknowledgeUnknownEffect","reason"].includes(key)) || !UUID.test(String(body.orphanedJobId || ""))) {
        return res.status(400).json({error:"Recovery accepts only the orphaned job identifier, acknowledgement and reason",code:"CERTOPS_SNAPSHOT_INVALID"});
      }
      const result=await recoverOrphanedEnrollment({workspaceId:req.workspace.id,enrollmentId:req.params.enrollmentId,
        orphanedJobId:body.orphanedJobId,acknowledgeUnknownEffect:body.acknowledgeUnknownEffect,reason:body.reason,actorUserId:req.user.id});
      return res.status(result.created?201:200).json(result);
    }catch(error){return fail(res,error);}
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
