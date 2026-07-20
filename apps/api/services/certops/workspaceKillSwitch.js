"use strict";

const { writeAudit } = require("../audit");
const { redactGenericSecrets } = require("../../utils/secretMaterial");
const { isCertOpsEnabled } = require("./settings");
const { createCertificateJob } = require("./jobs");

const CERTOPS_WORKSPACE_PAUSED = "CERTOPS_WORKSPACE_PAUSED";
const CERTOPS_WORKSPACE_NOT_FOUND = "CERTOPS_WORKSPACE_NOT_FOUND";
const CERTOPS_WORKSPACE_PAUSE_REASON_INVALID =
  "CERTOPS_WORKSPACE_PAUSE_REASON_INVALID";
const CERTOPS_WORKSPACE_PAUSE_STATE_INVALID =
  "CERTOPS_WORKSPACE_PAUSE_STATE_INVALID";
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

function stateFromRow({ workspaceId, certOpsPaused, certOpsEnabled }) {
  const paused = certOpsPaused === true;
  const enabled = certOpsEnabled === true;
  return {
    workspaceId: String(workspaceId),
    certOpsPaused: paused,
    certOpsEnabled: enabled,
    certOpsActive: enabled && !paused,
  };
}

async function loadWorkspacePauseState(dbPool, workspaceId, { lock = null } = {}) {
  const lockClause =
    lock === "update" ? " FOR UPDATE" : lock === "share" ? " FOR SHARE" : "";
  const result = await dbPool.query(
    `SELECT id, certops_paused
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
  });
}

/**
 * Guard for non-HTTP side-effect callers (future intent, dispatch, and
 * controller mutation paths). HTTP routes retain require-certops-enabled.js
 * as the primary rollout middleware and use the dedicated pause middleware.
 */
async function assertWorkspaceCertOpsActive(options = {}) {
  const state = await getWorkspaceCertOpsPauseState(options);
  if (!state.certOpsEnabled) {
    const error = workspaceKillSwitchError(
      "CertOps is disabled for this deployment",
      "CERTOPS_DISABLED",
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

    // FOR SHARE conflicts with the pause transition's FOR UPDATE lock.
    const workspace = await loadWorkspacePauseState(client, workspaceId, {
      lock: "share",
    });
    if (workspace.certops_paused === true) {
      const error = workspaceKillSwitchError(
        "CertOps is paused for this workspace",
        CERTOPS_WORKSPACE_PAUSED,
      );
      error.state = stateFromRow({
        workspaceId: workspace.id,
        certOpsPaused: true,
        certOpsEnabled: true,
      });
      throw error;
    }

    const outcome = await jobCreator({
      ...jobOptions,
      workspaceId: workspace.id,
      source: "api",
      client,
      returnOutcome: true,
    });
    const job = outcome?.job || outcome;
    const created = outcome?.created === true;

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
          operation: job.operation,
          subjectType: job.subjectType,
          subjectId: job.subjectId,
          source: job.source,
        },
      });
    }

    await client.query("COMMIT");
    transactionStarted = false;
    return { job, created };
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

module.exports = {
  CERTOPS_WORKSPACE_PAUSED,
  CERTOPS_WORKSPACE_NOT_FOUND,
  CERTOPS_WORKSPACE_PAUSE_REASON_INVALID,
  CERTOPS_WORKSPACE_PAUSE_STATE_INVALID,
  MAX_CERTOPS_PAUSE_REASON_LENGTH,
  CertOpsWorkspaceKillSwitchError,
  assertWorkspaceCertOpsActive,
  createManualCertificateJob,
  getWorkspaceCertOpsPauseState,
  normalizePaused,
  normalizeReason,
  setWorkspaceCertOpsPauseState,
};
