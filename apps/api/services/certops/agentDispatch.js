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
  acknowledgeSigningKey,
  ensureActiveSigningKey,
  getActiveSigningKeyPublicInfo,
  getSigningKeyRotationNotice,
  signJobForDispatch,
  consumeNonce,
} = require("./jobSigning");
const {
  lockWorkspaceForCertOpsSideEffect,
} = require("./workspaceKillSwitch");
const {
  computeCanonicalIntentHash,
  computeJobPayloadApprovalHash,
  invalidateApprovalForClaim,
} = require("./jobApprovals");
const { queueCertRenewalFailedAlert } = require("./renewalFailureAlerts");
const {
  redactGenericSecrets,
  redactPrivateKeyMaterial,
} = require("../../utils/secretMaterial");
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
const CERTOPS_AGENT_SEQUENCE_REGRESSION = "CERTOPS_AGENT_SEQUENCE_REGRESSION";

const DEFAULT_JOB_LEASE_SECONDS = 900;
// The dispatch nonce must stay consumable for the whole window the agent is
// allowed to work and report: lease + clock-drift tolerance + bounded
// result-delivery grace. A nonce that expires before the lease would reject
// legitimate results from long-running (but in-lease) jobs.
const NONCE_TTL_GRACE_SECONDS = 300;

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

// --- Per-agent monotonic sequence enforcement (defense in depth) ---

/**
 * Extracts a usable sequence value from an envelope. Envelopes without a
 * `sequence` field are legacy traffic: they are tolerated only for agents
 * that have never sent a sequenced message (last_sequence = 0). See the
 * no-bypass rule in enforceAgentSequence.
 */
function envelopeSequence(envelope) {
  const sequence = envelope?.sequence;
  return Number.isInteger(sequence) && sequence >= 1 ? sequence : null;
}

/**
 * Atomic compare-and-swap of certops_agents.last_sequence: a single UPDATE
 * only matches when the incoming sequence strictly exceeds the stored one,
 * so two concurrent messages can never both pass with the same value (the
 * row lock serializes them and the loser sees last_sequence >= its own).
 *
 * Runs after credential auth (the agent row is known to exist) and after
 * any nonce replay check, per the agent-route check ordering, and always on
 * the caller's transaction client so a message that later fails rolls the
 * counter back with everything else. A no-match is a sequence regression
 * within the current registered generation and rejects the message with a
 * 409-shaped error; the message must not be processed.
 *
 * No-bypass rule: an envelope WITHOUT a sequence is accepted only while the
 * agent has never sent one (last_sequence = 0, pre-sequencing agent
 * builds). Once any sequenced message has been accepted, unsequenced
 * traffic is rejected outright; otherwise dropping the field would defeat
 * the whole regression check (a replayed captured message could simply
 * omit it).
 *
 * @param {object} params
 * @param {object} [params.client] pg client or pool (injectable; defaults
 *   to the shared pool)
 * @param {string} params.agentRowId certops_agents.id (NOT the public
 *   agent_id string)
 * @param {object} params.envelope validated message envelope
 */
async function enforceAgentSequence({ client = pool, agentRowId, envelope }) {
  const sequence = envelopeSequence(envelope);
  if (sequence === null) {
    const existing = await client.query(
      `SELECT last_sequence FROM certops_agents WHERE id = $1 FOR UPDATE`,
      [agentRowId],
    );
    const lastSequence = Number(existing.rows[0]?.last_sequence ?? 0);
    if (lastSequence > 0) {
      throw serviceError(
        "Message carries no sequence but this agent already sends sequenced messages",
        CERTOPS_AGENT_SEQUENCE_REGRESSION,
      );
    }
    return;
  }

  const result = await client.query(
    `UPDATE certops_agents
        SET last_sequence = $2
      WHERE id = $1
        AND last_sequence < $2
      RETURNING id`,
    [agentRowId, sequence],
  );
  if (result.rows.length === 0) {
    throw serviceError(
      "Message sequence is not greater than the last accepted sequence for this agent",
      CERTOPS_AGENT_SEQUENCE_REGRESSION,
    );
  }
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
         bootstrap_token_id,
         last_sequence
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12::jsonb, 'active', $13, $14)
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
        // Registration begins a new sequence generation: last_sequence is
        // seeded from the register envelope's own sequence (or 0 when the
        // agent does not send one), so an agent whose non-persisted counter
        // restarted low is only ever compared against its new generation,
        // never against a previous registration's high-water mark.
        envelopeSequence(envelope) ?? 0,
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
 *
 * Runs in one transaction so the sequence bump and the heartbeat write
 * commit or roll back together (a failed write must not burn the sequence).
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
  const getRotationNotice =
    deps.getSigningKeyRotationNotice || getSigningKeyRotationNotice;
  const ackSigningKey = deps.acknowledgeSigningKey || acknowledgeSigningKey;
  const enforceSequence = deps.enforceAgentSequence || enforceAgentSequence;

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

  return await withTransaction(dbPool, async (client) => {
    // Sequence enforcement runs after auth (route middleware) and before
    // the heartbeat write; a regression rejects the message with no
    // last_seen_at (or any other) update.
    await enforceSequence({ client, agentRowId: agent.id, envelope });

    const result = await client.query(
      `UPDATE certops_agents
          SET last_seen_at = NOW(),
              clock_offset_ms = $2,
              ntp_synced = $3,
              uptime_seconds = $4,
              pinned_signing_key_id = COALESCE($5, pinned_signing_key_id),
              agent_version = $6,
              protocol_version = COALESCE($7, protocol_version),
              status = CASE WHEN status = 'offline' THEN 'active' ELSE status END,
              updated_at = NOW()
        WHERE id = $1
          AND status <> 'retired'
        RETURNING id, status, last_seen_at, pinned_signing_key_id`,
      [
        agent.id,
        clockOffsetMs,
        ntpSynced,
        uptimeSeconds,
        pinnedSigningKeyId,
        body.agentVersion || agent.agentVersion,
        envelope.protocolVersion || null,
      ],
    );

    const row = result.rows[0];
    if (!row) {
      // Retired between auth and write: freeze, same as the route-level rule.
      throw serviceError("Agent is retired", CERTOPS_AGENT_RETIRED);
    }

    if (pinnedSigningKeyId) {
      await ackSigningKey({
        client,
        workspaceId: agent.workspaceId,
        agentRowId: agent.id,
        signingKeyId: pinnedSigningKeyId,
      });
    }

    const signingKey = await getSigningKey({ client });
    const signingKeyRotation = await getRotationNotice({
      client,
      pinnedSigningKeyId:
        pinnedSigningKeyId || row.pinned_signing_key_id || null,
    });
    return {
      ok: true,
      status: row.status,
      lastSeenAt: dateToIso(row.last_seen_at),
      signingKeyId: signingKey?.signingKeyId ?? null,
      signingPublicKeyPem: signingKey?.publicKeyPem ?? null,
      // H3: agents that have not yet pinned the replacement key receive this
      // notice. Agent-side consumption is owned by another engineer; see
      // COORDINATION-H3.md for the exact field contract.
      signingKeyRotation,
    };
  });
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
  envelope = {},
  body = {},
  env = process.env,
  deps = {},
} = {}) {
  const lockWorkspace =
    deps.lockWorkspaceForCertOpsSideEffect || lockWorkspaceForCertOpsSideEffect;
  const signJob = deps.signJobForDispatch || signJobForDispatch;
  const invalidateApproval =
    deps.invalidateApprovalForClaim || invalidateApprovalForClaim;
  const enforceSequence = deps.enforceAgentSequence || enforceAgentSequence;

  const maxJobs =
    Number.isInteger(body.maxJobs) && body.maxJobs >= 1 && body.maxJobs <= 16
      ? body.maxJobs
      : 1;
  const supportedActions = Array.isArray(body.supportedActions)
    ? body.supportedActions.filter((action) => typeof action === "string")
    : [];
  const leaseSeconds = jobLeaseSeconds(env);

  return await withTransaction(dbPool, async (client) => {
    // Sequence enforcement first (post-auth, pre-dispatch): a regression
    // rejects the poll before any workspace lock or job selection. Inside
    // the transaction, so a claim that later fails rolls the counter back
    // with everything else.
    await enforceSequence({ client, agentRowId: agent.id, envelope });

    // Throws CERTOPS_WORKSPACE_PAUSED / CERTOPS_DISABLED; the route maps
    // these to 409 / 404 and no job is claimed.
    await lockWorkspace({ client, workspaceId: agent.workspaceId });

    // Claiming is a liveness signal: an agent polling for jobs is alive, so
    // last_seen_at advances and an 'offline' agent flips back to 'active'.
    // Without this, a stale-swept agent could keep receiving jobs while
    // being displayed as offline.
    await client.query(
      `UPDATE certops_agents
          SET last_seen_at = NOW(),
              status = CASE WHEN status = 'offline' THEN 'active' ELSE status END,
              updated_at = NOW()
        WHERE id = $1
          AND status <> 'retired'`,
      [agent.id],
    );

    if (supportedActions.length === 0) return { jobs: [] };

    const selected = await client.query(
      `SELECT id, workspace_id, operation, subject_type, subject_id, payload,
              approved_payload_hash,
              approved_canonical_intent_hash,
              operation,
              subject_type,
              subject_id
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
      // hash of the canonical payload and canonical execution intent at
      // approval time. If either drifts, the approval is void.
      if (row.approved_payload_hash) {
        const rowPayload =
          row.payload && typeof row.payload === "object"
            ? row.payload
            : safeParseJson(row.payload);
        const currentHash = computeJobPayloadApprovalHash(rowPayload);
        const currentIntentHash = computeCanonicalIntentHash({
          operation: row.operation,
          subjectType: row.subject_type,
          subjectId: row.subject_id,
          payload: rowPayload,
        });
        const intentMismatch =
          row.approved_canonical_intent_hash &&
          currentIntentHash !== row.approved_canonical_intent_hash;
        if (currentHash !== row.approved_payload_hash || intentMismatch) {
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
        // Nonce validity covers the full lease plus grace so a legitimate
        // in-lease result can always consume its nonce (see
        // NONCE_TTL_GRACE_SECONDS).
        nonceTtlSeconds: leaseSeconds + NONCE_TTL_GRACE_SECONDS,
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
  envelope = {},
  body = {},
  deps = {},
} = {}) {
  const consume = deps.consumeNonce || consumeNonce;
  const enforceSequence = deps.enforceAgentSequence || enforceAgentSequence;
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
              subject_type, subject_id, error_code, completed_at
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

    // Single-use nonce consumption (replay ledger), bound to the workspace
    // and the agent the nonce was issued to.
    const nonceOutcome = await consume({
      client,
      nonce: body.nonce,
      jobId: body.jobId,
      workspaceId: agent.workspaceId,
      agentRowId: agent.id,
    });
    if (!nonceOutcome?.consumed) {
      // Idempotent duplicate delivery: the same owner re-sending the exact
      // terminal outcome it already reported (e.g. a retry after a lost
      // response) is acknowledged instead of erroring. Anything else stays
      // a hard rejection.
      if (
        nonceOutcome?.code === CERTOPS_NONCE_REPLAYED &&
        job.status === jobStatus &&
        job.completed_at
      ) {
        return {
          ok: true,
          jobId: String(job.id),
          status: job.status,
          errorCode: job.error_code || null,
          completedAt: dateToIso(job.completed_at),
          duplicate: true,
        };
      }
      const error = serviceError(
        "Result nonce was rejected",
        CERTOPS_AGENT_RESULT_NONCE_REJECTED,
      );
      error.nonceCode = nonceOutcome?.code || null;
      error.replayed = nonceOutcome?.code === CERTOPS_NONCE_REPLAYED;
      throw error;
    }

    // Sequence enforcement after the nonce replay ledger (route-family
    // check ordering: auth, nonce replay, sequence) and before the status
    // transition. A regression aborts the transaction, so the nonce
    // consumption above rolls back with it and the message is not
    // processed.
    await enforceSequence({ client, agentRowId: agent.id, envelope });

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
    // Agent-provided error text is untrusted: scrub private-key material
    // and generic secrets before it is stored, logged, audited or alerted.
    const errorMessage =
      isFailure && typeof body.errorMessage === "string"
        ? redactGenericSecrets(
            redactPrivateKeyMaterial(body.errorMessage),
          ).slice(0, 1024)
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

// --- Evidence ownership (7.4) ---

/**
 * Evidence appends are workspace-scoped writes coming from a machine
 * credential, so they must be bound to a claim: the reporting agent must be
 * the agent that claimed the job (claimed_by_agent_id survives completion,
 * so post-result evidence from the same agent stays valid). Throws
 * CERTOPS_AGENT_JOB_NOT_FOUND / CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH.
 */
async function assertEvidenceClaimOwnership({
  dbPool = pool,
  agent,
  jobId,
} = {}) {
  const result = await dbPool.query(
    `SELECT claimed_by_agent_id
       FROM certificate_jobs
      WHERE id = $1
        AND workspace_id = $2
      FOR UPDATE
      LIMIT 1`,
    [jobId, agent.workspaceId],
  );
  const row = result.rows[0];
  if (!row) {
    throw serviceError(
      "Certificate job not found",
      CERTOPS_AGENT_JOB_NOT_FOUND,
    );
  }
  if (String(row.claimed_by_agent_id || "") !== String(agent.id)) {
    throw serviceError(
      "Evidence does not match the claim for this job",
      CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH,
    );
  }
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
  CERTOPS_AGENT_SEQUENCE_REGRESSION,
  DEFAULT_JOB_LEASE_SECONDS,
  assertEvidenceClaimOwnership,
  claimJobs,
  enforceAgentSequence,
  ingestResult,
  jobLeaseSeconds,
  recordHeartbeat,
  registerAgent,
  _test: {
    NONCE_TTL_GRACE_SECONDS,
    RESULT_STATUS_TO_JOB_STATUS,
    dateToIso,
    envelopeSequence,
    safeParseJson,
    serviceError,
    withTransaction,
  },
};
