"use strict";

/**
 * Agent control-plane dispatch service: registration, heartbeat, claim
 * and result ingestion transaction logic for the four
 * /api/v1/certops/agent/* machine routes (ADR-0002/0003).
 *
 * All SQL lives here so apps/api/routes/certops-agent.js stays a thin
 * middleware-composition layer. Every transactional entry point accepts an
 * injectable client/pool plus injectable collaborator functions so unit
 * tests can run against a mocked pool without a database.
 */

const { pool } = require("../../db/database");
const {
  consumeBootstrapToken,
  generateAgentCredential,
} = require("./agentCredentials");
const {
  CERTOPS_NONCE_REPLAYED,
  ensureActiveSigningKey,
  getActiveSigningKeyPublicInfo,
  signJobForDispatch,
  consumeNonce,
} = require("./jobSigning");
const {
  lockWorkspaceForCertOpsSideEffect,
} = require("./workspaceKillSwitch");
const {
  computeJobPayloadApprovalHash,
  invalidateApprovalForClaim,
} = require("./jobApprovals");
const { queueCertRenewalFailedAlert } = require("./renewalFailureAlerts");
const { logger } = require("../../utils/logger");

// --- Frozen error codes ---
const CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED =
  "CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED";
const CERTOPS_AGENT_REGISTRATION_CONFLICT =
  "CERTOPS_AGENT_REGISTRATION_CONFLICT";
const CERTOPS_AGENT_RETIRED = "CERTOPS_AGENT_RETIRED";
const CERTOPS_AGENT_MESSAGE_INVALID = "CERTOPS_AGENT_MESSAGE_INVALID";
const CERTOPS_AGENT_JOB_NOT_FOUND = "CERTOPS_AGENT_JOB_NOT_FOUND";
const CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH =
  "CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH";
const CERTOPS_AGENT_RESULT_NONCE_REJECTED =
  "CERTOPS_AGENT_RESULT_NONCE_REJECTED";
const CERTOPS_AGENT_RESULT_STATUS_INVALID =
  "CERTOPS_AGENT_RESULT_STATUS_INVALID";

const DEFAULT_JOB_LEASE_SECONDS = 900;

// result body status -> certificate_jobs terminal status. "rejected" and
// "blocked" from the agent-protocol resultBody map to the jobs.js statuses
// of the same name; the transitions map allows all of these from
// claimed/running.
const RESULT_STATUS_TO_JOB_STATUS = Object.freeze({
  succeeded: "succeeded",
  failed: "failed",
  rejected: "rejected",
  blocked: "blocked",
});

function serviceError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function jobLeaseSeconds(env = process.env) {
  const raw = Number.parseInt(env.CERTOPS_JOB_LEASE_SECONDS, 10);
  if (Number.isInteger(raw) && raw > 0) return raw;
  return DEFAULT_JOB_LEASE_SECONDS;
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

function dateToIso(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}

// --- Registration (7.2) ---

/**
 * Runs the whole registration side effect in one transaction:
 * consume bootstrap token (single-use, atomic; null means a lost race and
 * the caller must answer a generic 401), ensure the active signing key,
 * mint the per-agent credential, insert the certops_agents row.
 *
 * Returns the exact shape the packages/agent register client parses:
 * { agentId, credential, protocolVersion, signingKeyId, signingPublicKeyPem }.
 */
async function registerAgent({
  dbPool = pool,
  bootstrapToken,
  envelope,
  body,
  deps = {},
} = {}) {
  const consume = deps.consumeBootstrapToken || consumeBootstrapToken;
  const ensureKey = deps.ensureActiveSigningKey || ensureActiveSigningKey;
  const generateCredential =
    deps.generateAgentCredential || generateAgentCredential;

  return await withTransaction(dbPool, async (client) => {
    // Signing key and credential are prepared before the insert so a
    // constraint failure cannot leave a half-registered agent.
    const signingKey = await ensureKey({ client });
    const credential = generateCredential();

    const inserted = await client.query(
      `INSERT INTO certops_agents (
         workspace_id,
         agent_id,
         name,
         hostname,
         platform,
         node_version,
         agent_version,
         protocol_version,
         credential_prefix,
         credential_hash,
         declared_target_selectors,
         declared_command_profile_names,
         status,
         bootstrap_token_id
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12::jsonb, 'active', $13)
       ON CONFLICT (agent_id) DO NOTHING
       RETURNING id, agent_id, protocol_version`,
      [
        bootstrapToken.workspaceId,
        envelope.agentId,
        typeof body.name === "string" && body.name.trim()
          ? body.name.trim().slice(0, 128)
          : null,
        body.hostname ?? null,
        body.platform ?? null,
        body.nodeVersion ?? null,
        body.agentVersion,
        envelope.protocolVersion,
        credential.credentialPrefix,
        credential.credentialHash,
        JSON.stringify(body.declaredTargetSelectors || []),
        JSON.stringify(body.declaredCommandProfileNames || []),
        bootstrapToken.id,
      ],
    );

    const row = inserted.rows[0];
    if (!row) {
      throw serviceError(
        "An agent with this agentId already exists",
        CERTOPS_AGENT_REGISTRATION_CONFLICT,
      );
    }

    // Consume last so the token row update can reference the new agent row.
    const consumed = await consume({
      client,
      tokenId: bootstrapToken.id,
      agentRowId: row.id,
    });
    if (!consumed) {
      // Lost the single-use race (or the token expired between auth and
      // consumption): the transaction rolls back and the route answers a
      // generic 401.
      throw serviceError(
        "Bootstrap token could not be consumed",
        CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED,
      );
    }

    return {
      agentId: row.agent_id,
      credential: credential.plaintextCredential,
      protocolVersion: row.protocol_version,
      signingKeyId: signingKey?.signingKeyId ?? null,
      signingPublicKeyPem: signingKey?.publicKeyPem ?? null,
    };
  });
}

// --- Heartbeat (7.2/7.6) ---

/**
 * Steady-state heartbeat write. The route has already rejected retired
 * agents (410, no last_seen_at update). An 'offline' agent that calls in is
 * alive again, so status flips back to 'active'.
 */
async function recordHeartbeat({
  dbPool = pool,
  agent,
  envelope,
  body,
  deps = {},
} = {}) {
  const getSigningKey =
    deps.getActiveSigningKeyPublicInfo || getActiveSigningKeyPublicInfo;

  const clockOffsetMs = Number.isInteger(envelope.clockOffsetMs)
    ? envelope.clockOffsetMs
    : null;
  const ntpSynced = typeof body.ntpSynced === "boolean" ? body.ntpSynced : null;
  const uptimeSeconds =
    Number.isInteger(body.uptimeSeconds) && body.uptimeSeconds >= 0
      ? body.uptimeSeconds
      : null;
  const pinnedSigningKeyId =
    typeof body.pinnedSigningKeyId === "string" && body.pinnedSigningKeyId
      ? body.pinnedSigningKeyId
      : null;

  const result = await dbPool.query(
    `UPDATE certops_agents
        SET last_seen_at = NOW(),
            clock_offset_ms = $2,
            ntp_synced = $3,
            uptime_seconds = $4,
            pinned_signing_key_id = COALESCE($5, pinned_signing_key_id),
            agent_version = $6,
            status = CASE WHEN status = 'offline' THEN 'active' ELSE status END,
            updated_at = NOW()
      WHERE id = $1
        AND status <> 'retired'
      RETURNING id, status, last_seen_at`,
    [
      agent.id,
      clockOffsetMs,
      ntpSynced,
      uptimeSeconds,
      pinnedSigningKeyId,
      body.agentVersion || agent.agentVersion,
    ],
  );

  const row = result.rows[0];
  if (!row) {
    // Retired between auth and write: freeze, same as the route-level rule.
    throw serviceError("Agent is retired", CERTOPS_AGENT_RETIRED);
  }

  const signingKey = await getSigningKey({ client: dbPool });
  return {
    ok: true,
    status: row.status,
    lastSeenAt: dateToIso(row.last_seen_at),
    signingKeyId: signingKey?.signingKeyId ?? null,
    signingPublicKeyPem: signingKey?.publicKeyPem ?? null,
  };
}

// --- Claim (7.3) ---

/**
 * Claims up to maxJobs pending jobs for the agent inside one transaction on
 * one client: workspace kill-switch lock first (dispatch is blocked while
 * paused/disabled; results never are), then FOR UPDATE SKIP LOCKED job
 * selection, per-job lease fields, and signed dispatch payloads.
 */
async function claimJobs({
  dbPool = pool,
  agent,
  body = {},
  env = process.env,
  deps = {},
} = {}) {
  const lockWorkspace =
    deps.lockWorkspaceForCertOpsSideEffect || lockWorkspaceForCertOpsSideEffect;
  const signJob = deps.signJobForDispatch || signJobForDispatch;
  const invalidateApproval =
    deps.invalidateApprovalForClaim || invalidateApprovalForClaim;

  const maxJobs =
    Number.isInteger(body.maxJobs) && body.maxJobs >= 1 && body.maxJobs <= 16
      ? body.maxJobs
      : 1;
  const supportedActions = Array.isArray(body.supportedActions)
    ? body.supportedActions.filter((action) => typeof action === "string")
    : [];
  const leaseSeconds = jobLeaseSeconds(env);

  return await withTransaction(dbPool, async (client) => {
    // Throws CERTOPS_WORKSPACE_PAUSED / CERTOPS_DISABLED; the route maps
    // these to 409 / 404 and no job is claimed.
    await lockWorkspace({ client, workspaceId: agent.workspaceId });

    if (supportedActions.length === 0) return { jobs: [] };

    const selected = await client.query(
      `SELECT id, workspace_id, operation, subject_type, subject_id, payload,
              approved_payload_hash
         FROM certificate_jobs
        WHERE workspace_id = $1
          AND status = 'pending'
          AND (scheduled_for IS NULL OR scheduled_for <= NOW())
          AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())
          AND operation = ANY($2::text[])
        ORDER BY created_at
        LIMIT $3
        FOR UPDATE SKIP LOCKED`,
      [agent.workspaceId, supportedActions, maxJobs],
    );

    const jobs = [];
    for (const row of selected.rows) {
      // Approval-gate re-verification: an approval is bound to a SHA256
      // hash of the canonical payload at approval time. If the payload was
      // edited afterwards, the approval is void: flip the job back to
      // pending_approval instead of dispatching it. Jobs with no stored
      // approval hash never required approval and pass through untouched.
      if (row.approved_payload_hash) {
        const rowPayload =
          row.payload && typeof row.payload === "object"
            ? row.payload
            : safeParseJson(row.payload);
        const currentHash = computeJobPayloadApprovalHash(rowPayload);
        if (currentHash !== row.approved_payload_hash) {
          await invalidateApproval({
            client,
            workspaceId: agent.workspaceId,
            jobId: row.id,
            staleHash: row.approved_payload_hash,
            currentHash,
          });
          continue;
        }
      }

      const claimed = await client.query(
        `UPDATE certificate_jobs
            SET status = 'claimed',
                claimed_by_agent_id = $2,
                claim_id = gen_random_uuid(),
                lease_expires_at = NOW() + make_interval(secs => $3),
                attempt_count = attempt_count + 1,
                queued_at = COALESCE(queued_at, NOW()),
                updated_at = NOW()
          WHERE id = $1
          RETURNING id, claim_id, lease_expires_at, attempt_count, operation,
                    subject_type, subject_id, payload`,
        [row.id, agent.id, leaseSeconds],
      );
      const job = claimed.rows[0];
      if (!job) continue;

      const payload =
        job.payload && typeof job.payload === "object"
          ? job.payload
          : safeParseJson(job.payload);

      // attemptId mirrors claim_id so a schema-minimal result report
      // (jobId/attemptId/status only) still re-proves claim ownership:
      // the results route falls back to attemptId when claimId is absent.
      const basePayload = {
        ...payload,
        jobId: String(job.id),
        workspaceId: agent.workspaceId,
        action: job.operation,
        claimId: job.claim_id,
        attemptId: job.claim_id,
        leaseExpiresAt: dateToIso(job.lease_expires_at),
        attemptCount: job.attempt_count,
      };

      const signedJob = await signJob({
        client,
        job: basePayload,
        agentId: agent.id,
        workspaceId: agent.workspaceId,
      });
      jobs.push(signedJob);
    }

    return { jobs };
  });
}

function safeParseJson(value) {
  if (typeof value !== "string") return {};
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

// --- Results (7.4/7.7) ---

/**
 * Ingests a terminal result message in one transaction: lock the job row,
 * re-prove claim ownership (agent + claimId), consume the dispatch nonce
 * (single-use replay ledger), transition status, persist error_code /
 * error_message for terminal failures, clear the lease.
 */
async function ingestResult({
  dbPool = pool,
  agent,
  body = {},
  deps = {},
} = {}) {
  const consume = deps.consumeNonce || consumeNonce;
  const queueRenewalFailedAlert =
    deps.queueCertRenewalFailedAlert || queueCertRenewalFailedAlert;
  const log = deps.logger || logger;

  const jobStatus = RESULT_STATUS_TO_JOB_STATUS[body.status];
  if (!jobStatus) {
    throw serviceError(
      "Result status is invalid",
      CERTOPS_AGENT_RESULT_STATUS_INVALID,
    );
  }

  return await withTransaction(dbPool, async (client) => {
    const locked = await client.query(
      `SELECT id, status, claimed_by_agent_id, claim_id, operation,
              subject_type, subject_id
         FROM certificate_jobs
        WHERE id = $1
          AND workspace_id = $2
        FOR UPDATE`,
      [body.jobId, agent.workspaceId],
    );
    const job = locked.rows[0];
    if (!job) {
      throw serviceError(
        "Certificate job not found",
        CERTOPS_AGENT_JOB_NOT_FOUND,
      );
    }

    // Ownership re-proof: the reporting agent must still hold this claim.
    if (
      String(job.claimed_by_agent_id || "") !== String(agent.id) ||
      String(job.claim_id || "") !== String(body.claimId || "")
    ) {
      throw serviceError(
        "Result does not match the current claim for this job",
        CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH,
      );
    }

    // Single-use nonce consumption (replay ledger).
    const nonceOutcome = await consume({
      client,
      nonce: body.nonce,
      jobId: body.jobId,
    });
    if (!nonceOutcome?.consumed) {
      const error = serviceError(
        "Result nonce was rejected",
        CERTOPS_AGENT_RESULT_NONCE_REJECTED,
      );
      error.nonceCode = nonceOutcome?.code || null;
      error.replayed = nonceOutcome?.code === CERTOPS_NONCE_REPLAYED;
      throw error;
    }

    if (job.status !== "claimed" && job.status !== "running") {
      throw serviceError(
        "Certificate job is not in a claimable-result state",
        CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH,
      );
    }

    const isFailure = jobStatus !== "succeeded";
    // Terminal renew failures must persist error_code for the alerts stage.
    const errorCode = isFailure
      ? body.rejectionReason || `AGENT_RESULT_${jobStatus.toUpperCase()}`
      : null;
    const errorMessage =
      isFailure && typeof body.errorMessage === "string"
        ? body.errorMessage.slice(0, 1024)
        : null;

    const updated = await client.query(
      `UPDATE certificate_jobs
          SET status = $2,
              error_code = $3,
              error_message = $4,
              completed_at = COALESCE(completed_at, NOW()),
              lease_expires_at = NULL,
              updated_at = NOW()
        WHERE id = $1
        RETURNING id, status, error_code, completed_at`,
      [job.id, jobStatus, errorCode, errorMessage],
    );

    const row = updated.rows[0];

    // Terminal renew failures queue a cert_renewal_failed alert inside
    // the same transaction. Alert failures must never fail result
    // ingestion, so this is best-effort (endpoint-check-worker pattern).
    if (isFailure && jobStatus === "failed" && job.operation === "renew") {
      // Savepoint so a failed alert insert cannot abort the surrounding
      // ingestion transaction.
      try {
        await client.query("SAVEPOINT certops_renewal_alert");
        const alertOutcome = await queueRenewalFailedAlert({
          client,
          job: {
            id: job.id,
            workspace_id: agent.workspaceId,
            operation: job.operation,
            subject_type: job.subject_type,
            subject_id: job.subject_id,
          },
          workspaceId: agent.workspaceId,
          errorCode,
        });
        await client.query("RELEASE SAVEPOINT certops_renewal_alert");
        if (!alertOutcome?.queued && log?.warn) {
          log.warn("certops-renewal-failed-alert-skipped", {
            jobId: String(job.id),
            reason: alertOutcome?.reason || "unknown",
          });
        }
      } catch (alertErr) {
        try {
          await client.query("ROLLBACK TO SAVEPOINT certops_renewal_alert");
        } catch (_rollbackErr) {
          // Savepoint may not exist if the SAVEPOINT statement itself failed.
        }
        if (log?.warn) {
          log.warn("certops-renewal-failed-alert-error", {
            jobId: String(job.id),
            error: alertErr.message,
          });
        }
      }
    }

    return {
      ok: true,
      jobId: String(row.id),
      status: row.status,
      errorCode: row.error_code || null,
      completedAt: dateToIso(row.completed_at),
    };
  });
}

module.exports = {
  CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH,
  CERTOPS_AGENT_JOB_NOT_FOUND,
  CERTOPS_AGENT_MESSAGE_INVALID,
  CERTOPS_AGENT_REGISTRATION_CONFLICT,
  CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED,
  CERTOPS_AGENT_RESULT_NONCE_REJECTED,
  CERTOPS_AGENT_RESULT_STATUS_INVALID,
  CERTOPS_AGENT_RETIRED,
  DEFAULT_JOB_LEASE_SECONDS,
  claimJobs,
  ingestResult,
  jobLeaseSeconds,
  recordHeartbeat,
  registerAgent,
  _test: {
    RESULT_STATUS_TO_JOB_STATUS,
    dateToIso,
    safeParseJson,
    serviceError,
    withTransaction,
  },
};
