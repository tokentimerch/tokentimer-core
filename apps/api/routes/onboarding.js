"use strict";

const express = require("express");
const { pool } = require("../db/database");
const { logger } = require("../utils/logger");
const { writeAudit } = require("../services/audit");
const { getApiLimiter } = require("../middleware/rateLimit");
const { requireAuth } = require("../middleware/auth");
const { loadWorkspace, requireWorkspaceMembership } = require("../services/rbac");
const { isSmtpConfigured } = require("../services/systemSettings");
const { isCertOpsEnabled } = require("../services/certops/settings");
const {
  OnboardingValidationError,
  assertFlow,
  validateSessionWrite,
} = require("../services/onboarding/sessionSchema");
const {
  RevisionConflictError,
  getSession,
  writeSession,
  resetSession,
} = require("../services/onboarding/sessionStore");
const { evaluateCapabilities, getDocsBaseUrl, UNKNOWN } = require("../services/onboarding/capabilities");
const { buildSummary, hasSummaryProviders } = require("../services/onboarding/summary");
const { loadCertopsReality } = require("../services/onboarding/certopsReality");

const router = express.Router({ mergeParams: true });
const BASE = "/api/v1/workspaces/:id/onboarding";

const guards = [getApiLimiter(), requireAuth, loadWorkspace, requireWorkspaceMembership];

async function settle(fn, fallback = UNKNOWN) {
  try {
    return await fn();
  } catch (e) {
    logger.warn("Onboarding signal unavailable", { error: e.message });
    return fallback;
  }
}

// Mirrors the admin guard: trust a hydrated flag, otherwise ask the database.
async function resolveIsSystemAdmin(req) {
  if (req.user?.is_admin === true) return true;
  return settle(async () => {
    const { rows } = await pool.query(
      "SELECT is_admin FROM users WHERE id = $1 LIMIT 1",
      [req.user.id],
    );
    return rows[0]?.is_admin === true;
  }, false);
}
async function readSignals() {
  const [smtpConfigured, certopsEnabled] = await Promise.all([
    settle(() => isSmtpConfigured(pool)),
    settle(() => isCertOpsEnabled({ dbPool: pool })),
  ]);
  return { smtpConfigured, certopsEnabled };
}

function audit(req, action, metadata = {}) {
  return writeAudit({
    actorUserId: req.user.id,
    subjectUserId: req.user.id,
    action,
    targetType: "onboarding",
    workspaceId: req.workspace.id,
    metadata,
  }).catch((e) =>
    logger.warn("Onboarding audit failed", { action, error: e.message }),
  );
}

function handleError(res, e, label) {
  if (e instanceof OnboardingValidationError) {
    return res.status(400).json({ error: e.message, code: e.code });
  }
  if (e instanceof RevisionConflictError) {
    return res.status(409).json({
      error: "Onboarding was updated from another tab or device",
      code: "REVISION_CONFLICT",
      current: e.current,
    });
  }
  logger.error(`Onboarding ${label} error`, { error: e.message });
  return res
    .status(500)
    .json({ error: "Onboarding request failed", code: "INTERNAL_ERROR" });
}

router.get(`${BASE}/capabilities`, ...guards, async (req, res) => {
  try {
    const signals = await readSignals();
    const isSystemAdmin = await resolveIsSystemAdmin(req);
    const items = evaluateCapabilities({
      workspaceRole: req.authz?.workspaceRole,
      isSystemAdmin,
      ...signals,
    });
    res.set("Cache-Control", "no-store");
    res.json({
      items,
      docsBaseUrl: getDocsBaseUrl(),
      viewer: {
        workspaceRole: req.authz?.workspaceRole || null,
        isSystemAdmin,
      },
    });
  } catch (e) {
    handleError(res, e, "capabilities");
  }
});

router.get(`${BASE}/:flow/summary`, ...guards, async (req, res) => {
  try {
    const flow = assertFlow(req.params.flow);
    const session = await getSession(pool, {
      userId: req.user.id,
      workspaceId: req.workspace.id,
      flow,
    });
    const smtpConfigured = await settle(() => isSmtpConfigured(pool));
    const certopsEnabled = await settle(() => isCertOpsEnabled({ dbPool: pool }));
    // Null (unknown) when CertOps is off, the caller is a viewer, or the read fails.
    const certops = await settle(
      () =>
        loadCertopsReality(pool, {
          workspaceId: req.workspace.id,
          role: req.authz?.workspaceRole,
          enabled: certopsEnabled,
          since: session.createdAt,
          dryRunJobId: session.progress?.certops?.dryRunJobId,
          issueJobId: session.progress?.certops?.issueJobId,
        }),
      null,
    );
    // Only identifies the caller to edition providers; no extra query unless
    // an edition registered one.
    const user = hasSummaryProviders()
      ? {
          id: req.user.id,
          isSystemAdmin: await resolveIsSystemAdmin(req),
          workspaceRole: req.authz?.workspaceRole || null,
        }
      : null;
    const summary = await buildSummary(pool, {
      workspaceId: req.workspace.id,
      refs: session.operationRefs,
      smtpConfigured,
      certops,
      user,
    });
    res.set("Cache-Control", "no-store");
    res.json({ summary });
  } catch (e) {
    handleError(res, e, "summary");
  }
});

router.get(`${BASE}/:flow`, ...guards, async (req, res) => {
  try {
    const flow = assertFlow(req.params.flow);
    const session = await getSession(pool, {
      userId: req.user.id,
      workspaceId: req.workspace.id,
      flow,
    });
    res.set("Cache-Control", "no-store");
    res.json({ session });
  } catch (e) {
    handleError(res, e, "get");
  }
});

router.put(`${BASE}/:flow`, ...guards, async (req, res) => {
  try {
    const flow = assertFlow(req.params.flow);
    const { expectedRevision, patch } = validateSessionWrite(req.body);
    const session = await writeSession(pool, {
      userId: req.user.id,
      workspaceId: req.workspace.id,
      flow,
      expectedRevision,
      patch,
    });
    if (expectedRevision === 0) await audit(req, "ONBOARDING_STARTED", { flow });
    if (patch.status === "completed") {
      await audit(req, "ONBOARDING_COMPLETED", { flow });
    }
    res.json({ session });
  } catch (e) {
    handleError(res, e, "put");
  }
});

router.post(`${BASE}/:flow/reset`, ...guards, async (req, res) => {
  try {
    const flow = assertFlow(req.params.flow);
    const removed = await resetSession(pool, {
      userId: req.user.id,
      workspaceId: req.workspace.id,
      flow,
    });
    if (removed) await audit(req, "ONBOARDING_RESET", { flow });
    res.json({ reset: removed });
  } catch (e) {
    handleError(res, e, "reset");
  }
});

module.exports = router;
