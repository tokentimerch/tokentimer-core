"use strict";

/**
 * Diagnostic-agent bootstrap service (ADR-0012 decision 7).
 *
 * POST /api/v1/workspaces/:id/certops/agents/diagnostic-bootstrap is
 * session-authenticated (an operator, not a machine credential) and behind
 * the certops.agents.diagnose permission. This module is the one
 * transaction the route calls into: consume the single-use bootstrap
 * request row, create the diagnostic agent, and create its protocol_smoke
 * job, all three or none. There is no interval in which the agent row
 * exists with no job, and no interval in which a second call with the same
 * requestId can observe (or create) a half-finished bootstrap.
 */

const crypto = require("node:crypto");

const { pool } = require("../../db/database");
const { generateAgentCredential } = require("./agentCredentials");
const { ensureActiveSigningKey } = require("./jobSigning");
const { createCertificateJob } = require("./jobs");
const { writeAudit } = require("../audit");

const CERTOPS_DIAGNOSTIC_BOOTSTRAP_ALREADY_CONSUMED =
  "diagnostic_bootstrap_already_consumed";
const CERTOPS_DIAGNOSTIC_BOOTSTRAP_REQUEST_ID_INVALID =
  "CERTOPS_DIAGNOSTIC_BOOTSTRAP_REQUEST_ID_INVALID";

// 15-minute single-use bootstrap window (ADR-0012 decision 7). This is a
// documented request window and a future janitor-cleanup boundary for the
// audit trail, not a re-arm mechanism: a consumed row is never deleted or
// reset, so the UNIQUE(workspace_id, request_id) index (migration
// certops_diagnostic_bootstrap_requests) makes single-use permanent
// regardless of this TTL.
const DEFAULT_DIAGNOSTIC_BOOTSTRAP_TTL_MS = 15 * 60 * 1000;

// Placeholder wire identity for a diagnostic reference client. It is not an
// agent build, so there is no real agentVersion/protocolVersion to report;
// these satisfy the certops_agents CHECK constraints (protocol_version must
// be x.y.z; agent_version 1-32 chars) without claiming compatibility with
// any real agent release.
const DIAGNOSTIC_AGENT_VERSION = "diagnostic-client";
const DIAGNOSTIC_PROTOCOL_VERSION = "1.0.0";

function serviceError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function diagnosticBootstrapTtlMs(env = process.env) {
  const raw = Number.parseInt(env.CERTOPS_DIAGNOSTIC_BOOTSTRAP_TTL_MS, 10);
  if (Number.isSafeInteger(raw) && raw > 0) return raw;
  return DEFAULT_DIAGNOSTIC_BOOTSTRAP_TTL_MS;
}

function normalizeWorkspaceId(value) {
  const workspaceId = typeof value === "string" ? value.trim() : "";
  if (!workspaceId) {
    throw serviceError(
      "Workspace id is required",
      "CERTOPS_AGENT_WORKSPACE_REQUIRED",
    );
  }
  return workspaceId;
}

function normalizeRequestId(value) {
  const requestId = typeof value === "string" ? value.trim() : "";
  if (!requestId || requestId.length > 128) {
    throw serviceError(
      "requestId is required and must be at most 128 characters",
      CERTOPS_DIAGNOSTIC_BOOTSTRAP_REQUEST_ID_INVALID,
    );
  }
  return requestId;
}

function generateDiagnosticAgentId() {
  // "diag-" + a UUID satisfies certops_agents.agent_id's
  // ^[A-Za-z0-9_.:-]{1,128}$ CHECK and is unmistakable in the fleet list.
  return `diag-${crypto.randomUUID()}`;
}

async function withTransaction(dbPool, fn) {
  const client = await dbPool.connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (_rollbackError) {
      // The original error is more useful to the caller.
    }
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Runs the whole diagnostic bootstrap in one transaction:
 *   1. Insert the single-use request row (workspace_id, request_id). A
 *      unique-violation on this insert means a prior call already consumed
 *      this exact requestId, so the transaction is rolled back and the
 *      caller sees diagnostic_bootstrap_already_consumed rather than a
 *      replayed {agentId, credential, job}.
 *   2. Create the certops_agents row with agent_kind = 'diagnostic'.
 *   3. Create its protocol_smoke job (mode: dry_run) via the same
 *      createCertificateJob used everywhere else, passing
 *      allowDiagnosticOperation so the operation-name guard in jobs.js
 *      lets it through.
 *   4. Stamp the request row with the new agent/job ids (for audit and
 *      for the orphan-retirement sweep to find this agent's job).
 */
async function createDiagnosticBootstrap({
  dbPool = pool,
  workspaceId,
  requestId,
  requestedByUserId = null,
  env = process.env,
  deps = {},
} = {}) {
  const ensureKey = deps.ensureActiveSigningKey || ensureActiveSigningKey;
  const generateCredential =
    deps.generateAgentCredential || generateAgentCredential;
  const createJob = deps.createCertificateJob || createCertificateJob;
  const auditWriter = deps.writeAudit || writeAudit;

  const normalizedWorkspaceId = normalizeWorkspaceId(workspaceId);
  const normalizedRequestId = normalizeRequestId(requestId);
  const ttlMs = diagnosticBootstrapTtlMs(env);

  return await withTransaction(dbPool, async (client) => {
    let requestRow;
    try {
      const inserted = await client.query(
        `INSERT INTO certops_diagnostic_bootstrap_requests (
           workspace_id, request_id, requested_by_user_id, expires_at
         )
         VALUES ($1, $2, $3, NOW() + make_interval(secs => $4))
         RETURNING id`,
        [
          normalizedWorkspaceId,
          normalizedRequestId,
          requestedByUserId,
          Math.floor(ttlMs / 1000),
        ],
      );
      requestRow = inserted.rows[0];
    } catch (error) {
      if (
        error?.code === "23505" &&
        String(error.constraint || "").includes(
          "uq_certops_diagnostic_bootstrap_workspace_request",
        )
      ) {
        throw serviceError(
          "This diagnostic bootstrap request was already consumed",
          CERTOPS_DIAGNOSTIC_BOOTSTRAP_ALREADY_CONSUMED,
        );
      }
      throw error;
    }

    const signingKey = await ensureKey({ client });
    const credential = generateCredential();
    const agentId = generateDiagnosticAgentId();

    const insertedAgent = await client.query(
      `INSERT INTO certops_agents (
         workspace_id,
         agent_id,
         name,
         agent_version,
         protocol_version,
         credential_prefix,
         credential_hash,
         agent_kind,
         status,
         last_sequence,
         capabilities_updated_at
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'diagnostic', 'active', 0, NOW())
       RETURNING id, agent_id, protocol_version`,
      [
        normalizedWorkspaceId,
        agentId,
        "Diagnostic bootstrap client",
        DIAGNOSTIC_AGENT_VERSION,
        DIAGNOSTIC_PROTOCOL_VERSION,
        credential.credentialPrefix,
        credential.credentialHash,
      ],
    );
    const agentRow = insertedAgent.rows[0];

    // assignedAgentId pins the smoke job to this exact diagnostic agent so
    // it can never be claimed by a different diagnostic agent in the same
    // workspace; the agent_kind gate in agentDispatch.js claimJobs is the
    // real security boundary, this is just correct routing on top of it.
    const job = await createJob({
      client,
      workspaceId: normalizedWorkspaceId,
      operation: "protocol_smoke",
      mode: "dry_run",
      source: "api",
      status: "pending",
      executorKind: "agent",
      assignedAgentId: agentRow.id,
      requestedByUserId,
      allowDiagnosticOperation: true,
    });

    await client.query(
      `UPDATE certops_diagnostic_bootstrap_requests
          SET agent_row_id = $2,
              job_id = $3
        WHERE id = $1`,
      [requestRow.id, agentRow.id, job.id],
    );

    // The bootstrap is the moment a diagnostic client gains the right to
    // authenticate against this workspace's agent protocol (a low-privilege
    // right, but a real one: it can occupy the fleet list and the
    // per-workspace rate limit), and it is the only record of who requested
    // it. Written inside this transaction, so the agent cannot exist
    // unaudited.
    await auditWriter({
      client,
      actorUserId: requestedByUserId,
      subjectUserId: null,
      action: "CERTOPS_DIAGNOSTIC_AGENT_BOOTSTRAPPED",
      targetType: "certops_agent",
      targetId: null,
      workspaceId: normalizedWorkspaceId,
      metadata: {
        agentId: agentRow.agent_id,
        requestId: normalizedRequestId,
        jobId: String(job.id),
        credentialPrefix: credential.credentialPrefix,
        signingKeyId: signingKey?.signingKeyId ?? null,
      },
    });

    return {
      agentId: agentRow.agent_id,
      credential: credential.plaintextCredential,
      protocolVersion: agentRow.protocol_version,
      signingKeyId: signingKey?.signingKeyId ?? null,
      signingPublicKeyPem: signingKey?.publicKeyPem ?? null,
      job: {
        id: String(job.id),
        operation: job.operation,
        mode: job.mode,
        status: job.status,
      },
    };
  });
}

module.exports = {
  CERTOPS_DIAGNOSTIC_BOOTSTRAP_ALREADY_CONSUMED,
  CERTOPS_DIAGNOSTIC_BOOTSTRAP_REQUEST_ID_INVALID,
  DEFAULT_DIAGNOSTIC_BOOTSTRAP_TTL_MS,
  createDiagnosticBootstrap,
  diagnosticBootstrapTtlMs,
  _test: {
    generateDiagnosticAgentId,
    normalizeRequestId,
    normalizeWorkspaceId,
  },
};
