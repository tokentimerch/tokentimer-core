"use strict";

const { writeAudit } = require("../audit");
const { redactGenericSecrets } = require("../../utils/secretMaterial");
const { CERTOPS_DISABLED, isCertOpsEnabled } = require("./settings");
const { createCertificateJob } = require("./jobs");
const { windowsIisTargetAuditFields } = require("./renewalProfile");

const CERTOPS_WORKSPACE_PAUSED = "CERTOPS_WORKSPACE_PAUSED";
const CERTOPS_WORKSPACE_NOT_FOUND = "CERTOPS_WORKSPACE_NOT_FOUND";
const CERTOPS_WORKSPACE_PAUSE_REASON_INVALID =
  "CERTOPS_WORKSPACE_PAUSE_REASON_INVALID";
const CERTOPS_WORKSPACE_PAUSE_STATE_INVALID =
  "CERTOPS_WORKSPACE_PAUSE_STATE_INVALID";
const CERTOPS_WORKSPACE_APPROVAL_POLICY_STATE_INVALID =
  "CERTOPS_WORKSPACE_APPROVAL_POLICY_STATE_INVALID";
const MAX_CERTOPS_PAUSE_REASON_LENGTH = 500;

class CertOpsWorkspaceKillSwitchError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "CertOpsWorkspaceKillSwitchError";
    this.code = code;
  }
}

function defaultPool() {
  return require("../../db/database").pool;
}

function workspaceKillSwitchError(message, code) {
  return new CertOpsWorkspaceKillSwitchError(message, code);
}

function normalizePaused(value) {
  if (typeof value !== "boolean") {
    throw workspaceKillSwitchError(
      "certOpsPaused must be a boolean",
      CERTOPS_WORKSPACE_PAUSE_STATE_INVALID,
    );
  }
  return value;
}

function normalizeRequireApprovalAlways(value) {
  if (typeof value !== "boolean") {
    throw workspaceKillSwitchError(
      "requireApprovalAlways must be a boolean",
      CERTOPS_WORKSPACE_APPROVAL_POLICY_STATE_INVALID,
    );
  }
  return value;
}

function normalizeReason(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    throw workspaceKillSwitchError(
      "reason must be a string",
      CERTOPS_WORKSPACE_PAUSE_REASON_INVALID,
    );
  }

  const reason = value.trim();
  if (reason.length === 0) return null;
  if (reason.length > MAX_CERTOPS_PAUSE_REASON_LENGTH) {
    throw workspaceKillSwitchError(
      `reason must not exceed ${MAX_CERTOPS_PAUSE_REASON_LENGTH} characters`,
      CERTOPS_WORKSPACE_PAUSE_REASON_INVALID,
    );
  }
  if (/[\u0000-\u001F\u007F]/.test(reason)) {
    throw workspaceKillSwitchError(
      "reason contains control characters",
      CERTOPS_WORKSPACE_PAUSE_REASON_INVALID,
    );
  }

  // Audit metadata must never become a backdoor for generic secrets. The
  // shared redactor also fail-closes on private-key material for direct
  // service consumers; the HTTP boundary rejects it earlier with the
  // canonical 422 response.
  return redactGenericSecrets(reason);
}

function stateFromRow({
  workspaceId,
  certOpsPaused,
  certOpsEnabled,
  certOpsRequireApprovalAlways,
}) {
  const paused = certOpsPaused === true;
  const enabled = certOpsEnabled === true;
  return {
    workspaceId: String(workspaceId),
    certOpsPaused: paused,
    certOpsEnabled: enabled,
    certOpsActive: enabled && !paused,
    certOpsRequireApprovalAlways: certOpsRequireApprovalAlways === true,
  };
}

async function loadWorkspacePauseState(dbPool, workspaceId, { lock = null } = {}) {
  const lockClause =
    lock === "update" ? " FOR UPDATE" : lock === "share" ? " FOR SHARE" : "";
  const result = await dbPool.query(
    `SELECT id, certops_paused, certops_require_approval_always
       FROM workspaces
      WHERE id = $1${lockClause}`,
    [workspaceId],
  );
  const row = result.rows[0];
  if (!row) {
    throw workspaceKillSwitchError(
      "Workspace not found",
      CERTOPS_WORKSPACE_NOT_FOUND,
    );
  }
  return row;
}

/**
 * Return both the stored workspace state and the effective ability to start a
 * CertOps side effect. The global rollout flag remains independently owned by
 * settings.js; this service only composes with it.
 */
async function getWorkspaceCertOpsPauseState({
  workspaceId,
  dbPool = defaultPool(),
  certOpsEnabledResolver = isCertOpsEnabled,
  env = process.env,
} = {}) {
  if (!workspaceId) {
    throw workspaceKillSwitchError(
      "workspaceId is required",
      CERTOPS_WORKSPACE_NOT_FOUND,
    );
  }

  const workspace = await loadWorkspacePauseState(dbPool, workspaceId);
  const certOpsEnabled = await certOpsEnabledResolver({ dbPool, env });
  return stateFromRow({
    workspaceId: workspace.id,
    certOpsPaused: workspace.certops_paused,
    certOpsEnabled,
    certOpsRequireApprovalAlways: workspace.certops_require_approval_always,
  });
}

/**
 * Advisory snapshot for UI and preflight callers. An unlocked activity check
 * is not authoritative protection for a later side effect: a pause can commit
 * after this read. Every authoritative side effect must recheck the pause
 * state under a transactional workspace lock shared with its write and audit.
 */
async function getWorkspaceCertOpsActivitySnapshot(options = {}) {
  const state = await getWorkspaceCertOpsPauseState(options);
  if (!state.certOpsEnabled) {
    const error = workspaceKillSwitchError(
      "CertOps is disabled for this deployment",
      CERTOPS_DISABLED,
    );
    error.state = state;
    throw error;
  }
  if (state.certOpsPaused) {
    const error = workspaceKillSwitchError(
      "CertOps is paused for this workspace",
      CERTOPS_WORKSPACE_PAUSED,
    );
    error.state = state;
    throw error;
  }
  return state;
}

/**
 * Backwards-compatible alias for the advisory snapshot helper. Do not use this
 * unlocked assertion to authorize a later write; use
 * lockWorkspaceForCertOpsSideEffect inside the write transaction instead.
 */
function assertWorkspaceCertOpsActive(options = {}) {
  return getWorkspaceCertOpsActivitySnapshot(options);
}

/**
 * Acquire the workspace lock required before any authoritative CertOps side
 * effect. The caller must supply its already transaction-bound PostgreSQL
 * client and retain this lock until the side effect and synchronous audit have
 * committed or rolled back. After acquiring the workspace lock, this helper
 * rechecks both the global rollout and local pause gates inside that same
 * transaction. FOR SHARE conflicts with the kill switch's FOR UPDATE
 * transition lock.
 */
async function lockWorkspaceForCertOpsSideEffect({
  client,
  workspaceId,
  certOpsEnabledResolver = isCertOpsEnabled,
  env = process.env,
} = {}) {
  if (!client || typeof client.query !== "function") {
    throw workspaceKillSwitchError(
      "A transaction-bound database client is required",
      CERTOPS_WORKSPACE_NOT_FOUND,
    );
  }
  if (!workspaceId) {
    throw workspaceKillSwitchError(
      "workspaceId is required",
      CERTOPS_WORKSPACE_NOT_FOUND,
    );
  }

  const workspace = await loadWorkspacePauseState(client, workspaceId, {
    lock: "share",
  });
  const certOpsEnabled = await certOpsEnabledResolver({ dbPool: client, env });
  const state = stateFromRow({
    workspaceId: workspace.id,
    certOpsPaused: workspace.certops_paused,
    certOpsEnabled,
    certOpsRequireApprovalAlways: workspace.certops_require_approval_always,
  });

  if (!state.certOpsEnabled) {
    const error = workspaceKillSwitchError(
      "CertOps is disabled for this deployment",
      CERTOPS_DISABLED,
    );
    error.state = state;
    throw error;
  }
  if (state.certOpsPaused) {
    const error = workspaceKillSwitchError(
      "CertOps is paused for this workspace",
      CERTOPS_WORKSPACE_PAUSED,
    );
    error.state = state;
    throw error;
  }
  return workspace;
}

/**
 * Change the workspace-local pause state and its audit event atomically. A
 * failed audit write rolls the row update back; an idempotent request commits
 * no row change and emits no duplicate transition audit.
 */
async function setWorkspaceCertOpsPauseState({
  workspaceId,
  certOpsPaused,
  reason,
  actorUserId = null,
  subjectUserId = actorUserId,
  dbPool = defaultPool(),
  auditWriter = writeAudit,
  certOpsEnabledResolver = isCertOpsEnabled,
  env = process.env,
} = {}) {
  if (!workspaceId) {
    throw workspaceKillSwitchError(
      "workspaceId is required",
      CERTOPS_WORKSPACE_NOT_FOUND,
    );
  }

  const paused = normalizePaused(certOpsPaused);
  const safeReason = normalizeReason(reason);
  const client = await dbPool.connect();
  let transactionStarted = false;

  try {
    await client.query("BEGIN");
    transactionStarted = true;

    const workspace = await loadWorkspacePauseState(client, workspaceId, {
      lock: "update",
    });
    const previousCertOpsPaused = workspace.certops_paused === true;
    const certOpsEnabled = await certOpsEnabledResolver({ dbPool: client, env });

    if (previousCertOpsPaused === paused) {
      await client.query("COMMIT");
      transactionStarted = false;
      return {
        ...stateFromRow({
          workspaceId: workspace.id,
          certOpsPaused: paused,
          certOpsEnabled,
        }),
        changed: false,
      };
    }

    await client.query(
      `UPDATE workspaces
          SET certops_paused = $1,
              updated_at = NOW()
        WHERE id = $2`,
      [paused, workspace.id],
    );

    const state = stateFromRow({
      workspaceId: workspace.id,
      certOpsPaused: paused,
      certOpsEnabled,
    });
    await auditWriter({
      client,
      actorUserId,
      subjectUserId,
      action: paused ? "CERTOPS_WORKSPACE_PAUSED" : "CERTOPS_WORKSPACE_RESUMED",
      targetType: "workspace",
      targetId: workspace.id,
      workspaceId: workspace.id,
      metadata: {
        workspaceId: workspace.id,
        previousCertOpsPaused,
        certOpsPaused: paused,
        certOpsEnabled: state.certOpsEnabled,
        certOpsActive: state.certOpsActive,
        reason: safeReason,
      },
    });

    await client.query("COMMIT");
    transactionStarted = false;
    return { ...state, changed: true };
  } catch (error) {
    if (transactionStarted) {
      try {
        await client.query("ROLLBACK");
      } catch (_) {
        // Preserve the primary write/audit failure for the caller.
      }
    }
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Change the workspace-wide "always require approval" policy and its audit
 * event atomically, mirroring setWorkspaceCertOpsPauseState. A failed audit
 * write rolls the row update back; an idempotent request commits no row
 * change and emits no duplicate transition audit.
 */
async function setWorkspaceCertOpsRequireApprovalAlways({
  workspaceId,
  requireApprovalAlways,
  actorUserId = null,
  subjectUserId = actorUserId,
  dbPool = defaultPool(),
  auditWriter = writeAudit,
  certOpsEnabledResolver = isCertOpsEnabled,
  env = process.env,
} = {}) {
  if (!workspaceId) {
    throw workspaceKillSwitchError(
      "workspaceId is required",
      CERTOPS_WORKSPACE_NOT_FOUND,
    );
  }

  const requireApproval = normalizeRequireApprovalAlways(requireApprovalAlways);
  const client = await dbPool.connect();
  let transactionStarted = false;

  try {
    await client.query("BEGIN");
    transactionStarted = true;

    const workspace = await loadWorkspacePauseState(client, workspaceId, {
      lock: "update",
    });
    const previousRequireApprovalAlways =
      workspace.certops_require_approval_always === true;
    const certOpsEnabled = await certOpsEnabledResolver({ dbPool: client, env });

    if (previousRequireApprovalAlways === requireApproval) {
      await client.query("COMMIT");
      transactionStarted = false;
      return {
        ...stateFromRow({
          workspaceId: workspace.id,
          certOpsPaused: workspace.certops_paused,
          certOpsEnabled,
          certOpsRequireApprovalAlways: requireApproval,
        }),
        changed: false,
      };
    }

    await client.query(
      `UPDATE workspaces
          SET certops_require_approval_always = $1,
              updated_at = NOW()
        WHERE id = $2`,
      [requireApproval, workspace.id],
    );

    const state = stateFromRow({
      workspaceId: workspace.id,
      certOpsPaused: workspace.certops_paused,
      certOpsEnabled,
      certOpsRequireApprovalAlways: requireApproval,
    });
    await auditWriter({
      client,
      actorUserId,
      subjectUserId,
      action: requireApproval
        ? "CERTOPS_WORKSPACE_APPROVAL_POLICY_ENABLED"
        : "CERTOPS_WORKSPACE_APPROVAL_POLICY_DISABLED",
      targetType: "workspace",
      targetId: workspace.id,
      workspaceId: workspace.id,
      metadata: {
        workspaceId: workspace.id,
        previousRequireApprovalAlways,
        certOpsRequireApprovalAlways: requireApproval,
      },
    });

    await client.query("COMMIT");
    transactionStarted = false;
    return { ...state, changed: true };
  } catch (error) {
    if (transactionStarted) {
      try {
        await client.query("ROLLBACK");
      } catch (_) {
        // Preserve the primary write/audit failure for the caller.
      }
    }
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Create a manual job and its creation audit as one workspace-serialized
 * transaction. The shared row lock conflicts with the kill switch's update
 * lock, so a pause that commits first is always observed before this job is
 * inserted. Idempotent replays return the stored job without another audit.
 */
async function createManualCertificateJob({
  workspaceId,
  actorUserId = null,
  subjectUserId = actorUserId,
  dbPool = defaultPool(),
  jobCreator = createCertificateJob,
  auditWriter = writeAudit,
  certOpsEnabledResolver = isCertOpsEnabled,
  env = process.env,
  ...jobOptions
} = {}) {
  if (!workspaceId) {
    throw workspaceKillSwitchError(
      "workspaceId is required",
      CERTOPS_WORKSPACE_NOT_FOUND,
    );
  }

  const client = await dbPool.connect();
  let transactionStarted = false;

  try {
    await client.query("BEGIN");
    transactionStarted = true;

    const workspace = await lockWorkspaceForCertOpsSideEffect({
      client,
      workspaceId,
      certOpsEnabledResolver,
      env,
    });

    const outcome = await jobCreator({
      ...jobOptions,
      workspaceId: workspace.id,
      source: "api",
      client,
      workspaceRequiresApprovalAlways:
        workspace.certops_require_approval_always === true,
      returnOutcome: true,
    });
    const job = outcome?.job || outcome;
    const created = outcome?.created === true;
    // A revoke-trust call can legitimately create no job (see
    // trustAnchors.js's runCreateTrustJob): releasing one owner's reference
    // while another's is still live must not touch the OS. Callers need
    // skippedOsMutation/installation to tell that apart from a failure.
    const skippedOsMutation = outcome?.skippedOsMutation === true;
    const installation = outcome?.installation;

    if (created) {
      await auditWriter({
        client,
        actorUserId,
        subjectUserId,
        action: "CERTOPS_JOB_CREATED_MANUAL",
        targetType: "certificate_job",
        targetId: job.id,
        workspaceId: workspace.id,
        metadata: {
          jobId: job.id,
          operation: job.operation,
          subjectType: job.subjectType,
          subjectId: job.subjectId,
          source: job.source,
          ...windowsIisTargetAuditFields(job.payload?.target),
        },
      });
    }

    await client.query("COMMIT");
    transactionStarted = false;
    return { job, created, skippedOsMutation, installation };
  } catch (error) {
    if (transactionStarted) {
      try {
        await client.query("ROLLBACK");
      } catch (_) {
        // Preserve the primary job or audit failure for the caller.
      }
    }
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Change the workspace-local pause state and/or the always-require-approval
 * policy as one transaction. A request naming both fields must not be able
 * to commit one and fail the other: this locks the row once, writes both
 * changed columns in a single UPDATE, and emits a transition audit per
 * field that actually changed. A failure at any point (including an audit
 * write) rolls back every column this call would have touched, so the
 * caller's error response always matches a workspace that changed nothing.
 */
async function setWorkspaceCertOpsSettings({
  workspaceId,
  certOpsPaused,
  requireApprovalAlways,
  reason,
  actorUserId = null,
  subjectUserId = actorUserId,
  dbPool = defaultPool(),
  auditWriter = writeAudit,
  certOpsEnabledResolver = isCertOpsEnabled,
  env = process.env,
} = {}) {
  if (!workspaceId) {
    throw workspaceKillSwitchError(
      "workspaceId is required",
      CERTOPS_WORKSPACE_NOT_FOUND,
    );
  }

  const hasPauseField = certOpsPaused !== undefined;
  const hasApprovalField = requireApprovalAlways !== undefined;
  const paused = hasPauseField ? normalizePaused(certOpsPaused) : undefined;
  const requireApproval = hasApprovalField
    ? normalizeRequireApprovalAlways(requireApprovalAlways)
    : undefined;
  const safeReason = normalizeReason(reason);

  const client = await dbPool.connect();
  let transactionStarted = false;

  try {
    await client.query("BEGIN");
    transactionStarted = true;

    const workspace = await loadWorkspacePauseState(client, workspaceId, {
      lock: "update",
    });
    const previousCertOpsPaused = workspace.certops_paused === true;
    const previousRequireApprovalAlways =
      workspace.certops_require_approval_always === true;
    const certOpsEnabled = await certOpsEnabledResolver({ dbPool: client, env });

    const nextPaused = hasPauseField ? paused : previousCertOpsPaused;
    const nextRequireApproval = hasApprovalField
      ? requireApproval
      : previousRequireApprovalAlways;
    const pauseChanged = hasPauseField && previousCertOpsPaused !== paused;
    const approvalChanged =
      hasApprovalField && previousRequireApprovalAlways !== requireApproval;

    if (pauseChanged || approvalChanged) {
      await client.query(
        `UPDATE workspaces
            SET certops_paused = $1,
                certops_require_approval_always = $2,
                updated_at = NOW()
          WHERE id = $3`,
        [nextPaused, nextRequireApproval, workspace.id],
      );

      if (pauseChanged) {
        await auditWriter({
          client,
          actorUserId,
          subjectUserId,
          action: nextPaused
            ? "CERTOPS_WORKSPACE_PAUSED"
            : "CERTOPS_WORKSPACE_RESUMED",
          targetType: "workspace",
          targetId: workspace.id,
          workspaceId: workspace.id,
          metadata: {
            workspaceId: workspace.id,
            previousCertOpsPaused,
            certOpsPaused: nextPaused,
            certOpsEnabled,
            certOpsActive: certOpsEnabled && !nextPaused,
            reason: safeReason,
          },
        });
      }
      if (approvalChanged) {
        await auditWriter({
          client,
          actorUserId,
          subjectUserId,
          action: nextRequireApproval
            ? "CERTOPS_WORKSPACE_APPROVAL_POLICY_ENABLED"
            : "CERTOPS_WORKSPACE_APPROVAL_POLICY_DISABLED",
          targetType: "workspace",
          targetId: workspace.id,
          workspaceId: workspace.id,
          metadata: {
            workspaceId: workspace.id,
            previousRequireApprovalAlways,
            certOpsRequireApprovalAlways: nextRequireApproval,
          },
        });
      }
    }

    const state = stateFromRow({
      workspaceId: workspace.id,
      certOpsPaused: nextPaused,
      certOpsEnabled,
      certOpsRequireApprovalAlways: nextRequireApproval,
    });
    await client.query("COMMIT");
    transactionStarted = false;
    return { ...state, changed: pauseChanged || approvalChanged };
  } catch (error) {
    if (transactionStarted) {
      try {
        await client.query("ROLLBACK");
      } catch (_) {
        // Preserve the primary write/audit failure for the caller.
      }
    }
    throw error;
  } finally {
    client.release();
  }
}

module.exports = {
  CERTOPS_WORKSPACE_PAUSED,
  CERTOPS_WORKSPACE_NOT_FOUND,
  CERTOPS_WORKSPACE_PAUSE_REASON_INVALID,
  CERTOPS_WORKSPACE_PAUSE_STATE_INVALID,
  CERTOPS_WORKSPACE_APPROVAL_POLICY_STATE_INVALID,
  MAX_CERTOPS_PAUSE_REASON_LENGTH,
  CertOpsWorkspaceKillSwitchError,
  assertWorkspaceCertOpsActive,
  createManualCertificateJob,
  getWorkspaceCertOpsActivitySnapshot,
  getWorkspaceCertOpsPauseState,
  lockWorkspaceForCertOpsSideEffect,
  normalizePaused,
  normalizeReason,
  normalizeRequireApprovalAlways,
  setWorkspaceCertOpsPauseState,
  setWorkspaceCertOpsRequireApprovalAlways,
  setWorkspaceCertOpsSettings,
};
