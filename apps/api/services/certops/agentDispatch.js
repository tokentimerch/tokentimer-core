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
const crypto = require("node:crypto");
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
  extendJobNonceExpiry,
} = require("./jobSigning");
const {
  CERTOPS_REGISTRATION_CREDENTIAL_UNAVAILABLE,
  CERTOPS_REGISTRATION_ENCRYPTION_KEY_MISSING,
  ENCRYPTION_VERSION: REGISTRATION_CREDENTIAL_ENCRYPTION_VERSION,
  decryptRegistrationCredential,
  encryptRegistrationCredential,
} = require("./registrationCredentialCrypto");
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
  dispatchNonceTtlSeconds,
  jobLeaseSeconds,
} = require("./leaseTiming");
const {
  redactGenericSecrets,
  redactPrivateKeyMaterial,
  assertNoPrivateKeyMaterial,
} = require("../../utils/secretMaterial");
const { logger } = require("../../utils/logger");
const {
  computeAgentCompatibility,
} = require("./agentRegistry");

// --- Frozen error codes ---
const CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED =
  "CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED";
const CERTOPS_AGENT_REGISTRATION_CONFLICT =
  "CERTOPS_AGENT_REGISTRATION_CONFLICT";
const CERTOPS_AGENT_COMPATIBILITY_BLOCKED =
  "CERTOPS_AGENT_COMPATIBILITY_BLOCKED";
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
const CERTOPS_AGENT_LEASE_INVALID = "CERTOPS_AGENT_LEASE_INVALID";
const CERTOPS_AGENT_DEPLOY_CERT_UNAVAILABLE =
  "CERTOPS_AGENT_DEPLOY_CERT_UNAVAILABLE";

// RegistrationId → credential replay window (H1). Short crash-retry window;
// override via CERTOPS_REGISTRATION_REPLAY_TTL_MS (milliseconds).
const DEFAULT_REGISTRATION_REPLAY_TTL_MS = 15 * 60 * 1000;

function registrationReplayTtlMs(env = process.env) {
  const raw = Number.parseInt(env.CERTOPS_REGISTRATION_REPLAY_TTL_MS, 10);
  if (Number.isSafeInteger(raw) && raw > 0) return raw;
  return DEFAULT_REGISTRATION_REPLAY_TTL_MS;
}

// Back-compat alias for callers/tests that read the constant default.
const REGISTRATION_REPLAY_TTL_MS = DEFAULT_REGISTRATION_REPLAY_TTL_MS;

const RESULT_STATUS_TO_JOB_STATUS = Object.freeze({
  succeeded: "succeeded",
  failed: "failed",
  rejected: "rejected",
  blocked: "blocked",
  // B4: dry-run terminal. Agent engineers must report this (never
  // "succeeded") when the claimed job's mode is "dry_run".
  dry_run_complete: "dry_run_complete",
  // Agent self-reported: side effects may have occurred and rollback is
  // uncertain. Requires operator reconciliation (distinct from failed).
  orphaned_unknown_effect: "orphaned_unknown_effect",
});

// Agent runtime embeds reconciliation markers in free-form errorMessage, e.g.
// `...; needsOperatorReconciliation=true; reconciliationReason=<slug>)`.
const NEEDS_OPERATOR_RECONCILIATION_RE = /needsOperatorReconciliation=true/;
const RECONCILIATION_REASON_RE = /reconciliationReason=([a-z0-9_]+)/;
const RECONCILIATION_REASON_MAX_LENGTH = 1024;
const FALLBACK_ORPHANED_RECONCILIATION_REASON =
  "agent_reported_orphaned_unknown_effect";

/**
 * Extract operator-reconciliation markers from an agent result errorMessage.
 * Returns a bounded reason slug when present; never throws.
 */
function parseReconciliationFromErrorMessage(errorMessage) {
  if (typeof errorMessage !== "string" || errorMessage.length === 0) {
    return {
      needsOperatorReconciliation: false,
      reconciliationReason: null,
    };
  }
  const needsOperatorReconciliation =
    NEEDS_OPERATOR_RECONCILIATION_RE.test(errorMessage);
  const match = errorMessage.match(RECONCILIATION_REASON_RE);
  const reconciliationReason = match ? match[1] : null;
  return { needsOperatorReconciliation, reconciliationReason };
}

function boundReconciliationReason(reason) {
  if (typeof reason !== "string" || reason.length === 0) return null;
  return reason.slice(0, RECONCILIATION_REASON_MAX_LENGTH);
}

// Re-export shared lease default for existing callers/tests.
const { DEFAULT_JOB_LEASE_SECONDS } = require("./leaseTiming");

function serviceError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
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
function registrationReplayResponse(row) {
  const credential = decryptRegistrationCredential(
    row.credential_ciphertext,
    row.encryption_version,
  );
  return {
    agentId: row.agent_id,
    credential,
    protocolVersion: row.protocol_version,
    signingKeyId: row.signing_key_id ?? null,
    signingPublicKeyPem: row.signing_public_key_pem ?? null,
  };
}

async function findRegistrationReplay(client, bootstrapTokenId, registrationId) {
  const result = await client.query(
    `SELECT agent_id,
            credential_ciphertext,
            encryption_version,
            protocol_version,
            signing_key_id,
            signing_public_key_pem
       FROM certops_agent_registration_replays
      WHERE bootstrap_token_id = $1
        AND registration_id = $2
        AND expires_at > NOW()
      LIMIT 1`,
    [bootstrapTokenId, registrationId],
  );
  return result.rows[0] || null;
}

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
  const registrationId = body.registrationId;

  return await withTransaction(dbPool, async (client) => {
    // Serialize concurrent registrations against the same bootstrap token so
    // a lost-response retry and a first-time register cannot both mint.
    const lockedToken = await client.query(
      `SELECT id, status, workspace_id
         FROM certops_agent_bootstrap_tokens
        WHERE id = $1
        FOR UPDATE`,
      [bootstrapToken.id],
    );
    const tokenRow = lockedToken.rows[0];
    if (!tokenRow) {
      throw serviceError(
        "Bootstrap token could not be consumed",
        CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED,
      );
    }

    const existingReplay = await findRegistrationReplay(
      client,
      bootstrapToken.id,
      registrationId,
    );
    if (existingReplay) {
      try {
        return registrationReplayResponse(existingReplay);
      } catch (error) {
        // Corrupt/unreadable envelope: treat as replay-not-available so a
        // still-active token can mint fresh, and a spent token hard-rejects.
        if (
          error?.code !== CERTOPS_REGISTRATION_CREDENTIAL_UNAVAILABLE &&
          error?.code !== CERTOPS_REGISTRATION_ENCRYPTION_KEY_MISSING
        ) {
          throw error;
        }
      }
    }

    // Spent token + unknown registrationId remains a hard rejection (H1).
    if (tokenRow.status === "used") {
      throw serviceError(
        "Bootstrap token could not be consumed",
        CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED,
      );
    }

    // Signing key and credential are prepared before the insert so a
    // constraint failure cannot leave a half-registered agent.
    const signingKey = await ensureKey({ client });
    const credential = generateCredential();
    // Fail closed BEFORE persisting: never store plaintext credentials.
    const credentialCiphertext = encryptRegistrationCredential(
      credential.plaintextCredential,
    );

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
       ON CONFLICT (workspace_id, agent_id) DO NOTHING
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
      // Lost the single-use race (or the token expired between lock and
      // consumption): the transaction rolls back and the route answers a
      // generic 401. Concurrent same-registrationId retries are handled
      // above via the row lock + replay lookup.
      throw serviceError(
        "Bootstrap token could not be consumed",
        CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED,
      );
    }

    const response = {
      agentId: row.agent_id,
      credential: credential.plaintextCredential,
      protocolVersion: row.protocol_version,
      signingKeyId: signingKey?.signingKeyId ?? null,
      signingPublicKeyPem: signingKey?.publicKeyPem ?? null,
    };

    await client.query(
      `INSERT INTO certops_agent_registration_replays (
         workspace_id,
         bootstrap_token_id,
         registration_id,
         agent_id,
         credential_ciphertext,
         encryption_version,
         protocol_version,
         signing_key_id,
         signing_public_key_pem,
         expires_at
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW() + make_interval(secs => $10))
       ON CONFLICT (bootstrap_token_id, registration_id) DO NOTHING`,
      [
        bootstrapToken.workspaceId,
        bootstrapToken.id,
        registrationId,
        response.agentId,
        credentialCiphertext,
        REGISTRATION_CREDENTIAL_ENCRYPTION_VERSION,
        response.protocolVersion,
        response.signingKeyId,
        response.signingPublicKeyPem,
        Math.floor(registrationReplayTtlMs() / 1000),
      ],
    );

    return response;
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
  const supportedOperations = normalizeStringList(body.supportedOperations, 16);
  const supportedDnsProviders = normalizeStringList(
    body.supportedDnsProviders,
    64,
  );
  const declaredTargetSelectors = normalizeStringList(
    body.declaredTargetSelectors,
    64,
  );
  const declaredCommandProfileNames = normalizeStringList(
    body.declaredCommandProfileNames,
    64,
  );

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
              supported_operations = CASE
                WHEN $7::jsonb = '[]'::jsonb THEN supported_operations
                ELSE $7::jsonb
              END,
              supported_dns_providers = CASE
                WHEN $8::jsonb = '[]'::jsonb THEN supported_dns_providers
                ELSE $8::jsonb
              END,
              declared_target_selectors = CASE
                WHEN $9::jsonb = '[]'::jsonb THEN declared_target_selectors
                ELSE $9::jsonb
              END,
              declared_command_profile_names = CASE
                WHEN $10::jsonb = '[]'::jsonb THEN declared_command_profile_names
                ELSE $10::jsonb
              END,
              protocol_version = COALESCE($11, protocol_version),
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
        JSON.stringify(supportedOperations),
        JSON.stringify(supportedDnsProviders),
        JSON.stringify(declaredTargetSelectors),
        JSON.stringify(declaredCommandProfileNames),
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

function normalizeStringList(value, maxItems) {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item) => typeof item === "string" && item.length > 0)
    .slice(0, maxItems);
}

function jsonbTextArray(value) {
  if (!Array.isArray(value)) return [];
  return value.filter((item) => typeof item === "string");
}

/**
 * Resolve the public leaf(+chain) PEM for a standalone deploy job from
 * managed certificate inventory. PEM is attached only at signed dispatch
 * time (never persisted in certificate_jobs.payload).
 */
async function resolveDeployPublicCertificate({
  client,
  workspaceId,
  job,
  payload,
}) {
  const managedCertificateId =
    (job.subject_type === "managed_certificate" && job.subject_id) ||
    payload.certificateId ||
    payload.target?.managedCertificateId ||
    null;
  if (!managedCertificateId) {
    throw serviceError(
      "Deploy job has no managed certificate to resolve a public certificate from",
      CERTOPS_AGENT_DEPLOY_CERT_UNAVAILABLE,
    );
  }
  const result = await client.query(
    `SELECT certificate_pem, fingerprint_sha256
       FROM managed_certificates
      WHERE workspace_id = $1
        AND id = $2
      LIMIT 1`,
    [workspaceId, managedCertificateId],
  );
  const row = result.rows[0];
  const certificatePem =
    typeof row?.certificate_pem === "string" ? row.certificate_pem.trim() : "";
  if (!certificatePem || !certificatePem.startsWith("-----BEGIN CERTIFICATE-----")) {
    throw serviceError(
      "Public certificate material is unavailable for this deploy job",
      CERTOPS_AGENT_DEPLOY_CERT_UNAVAILABLE,
    );
  }
  assertNoPrivateKeyMaterial(certificatePem);
  const certificatePemSha256 = crypto
    .createHash("sha256")
    .update(certificatePem, "utf8")
    .digest("hex");
  return {
    certificatePem,
    certificatePemSha256,
    fingerprintSha256: row.fingerprint_sha256 || null,
  };
}

/**
 * Claims up to maxJobs pending agent-lane jobs for the agent inside one
 * transaction on one client: workspace kill-switch lock first (dispatch is
 * blocked while paused/disabled; results never are), then FOR UPDATE SKIP
 * LOCKED job selection matched on executor_kind + capabilities + selectors,
 * per-job lease fields, and signed dispatch payloads.
 *
 * Controller-lane jobs (executor_kind='controller') are never selectable
 * here (B2). Capability/target matching is B5. Deploy jobs receive the
 * public certificate PEM (+ content hash) at this point (B15).
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
  const resolveDeployCert =
    deps.resolveDeployPublicCertificate || resolveDeployPublicCertificate;

  const maxJobs =
    Number.isInteger(body.maxJobs) && body.maxJobs >= 1 && body.maxJobs <= 16
      ? body.maxJobs
      : 1;
  const supportedActions = Array.isArray(body.supportedActions)
    ? body.supportedActions.filter((action) => typeof action === "string")
    : [];
  const supportedDnsProviders = normalizeStringList(
    body.supportedDnsProviders,
    64,
  );
  const leaseSeconds = jobLeaseSeconds(env);
  const nonceTtlSeconds = dispatchNonceTtlSeconds(env);

  return await withTransaction(dbPool, async (client) => {
    // Sequence enforcement first (post-auth, pre-dispatch): a regression
    // rejects the poll before any workspace lock or job selection. Inside
    // the transaction, so a claim that later fails rolls the counter back
    // with everything else.
    await enforceSequence({ client, agentRowId: agent.id, envelope });

    // H8 hard floor: blocked agents must not claim or execute jobs.
    // "outdated" remains advisory and does not reject claims.
    const compatibility = (deps.computeAgentCompatibility ||
      computeAgentCompatibility)(agent, env);
    if (compatibility.compatibilityState === "blocked") {
      const cfg = compatibility.compatibilityConfig || {};
      throw serviceError(
        "Agent is blocked by CertOps compatibility policy " +
          `(protocol ${cfg.minProtocolVersion || "?"}–${cfg.maxProtocolVersion || "?"}, ` +
          `agent ${cfg.minAgentVersion || "?"}–${cfg.maxAgentVersion || "?"})`,
        CERTOPS_AGENT_COMPATIBILITY_BLOCKED,
      );
    }

    // Throws CERTOPS_WORKSPACE_PAUSED / CERTOPS_DISABLED; the route maps
    // these to 409 / 404 and no job is claimed.
    await lockWorkspace({ client, workspaceId: agent.workspaceId });

    // Claiming is a liveness signal: an agent polling for jobs is alive, so
    // last_seen_at advances and an 'offline' agent flips back to 'active'.
    // Without this, a stale-swept agent could keep receiving jobs while
    // being displayed as offline. Also refresh capability columns from the
    // claim body so the matcher stays current even between heartbeats.
    await client.query(
      `UPDATE certops_agents
          SET last_seen_at = NOW(),
              status = CASE WHEN status = 'offline' THEN 'active' ELSE status END,
              supported_operations = CASE
                WHEN $2::jsonb = '[]'::jsonb THEN supported_operations
                ELSE $2::jsonb
              END,
              supported_dns_providers = CASE
                WHEN $3::jsonb = '[]'::jsonb THEN supported_dns_providers
                ELSE $3::jsonb
              END,
              updated_at = NOW()
        WHERE id = $1
          AND status <> 'retired'`,
      [
        agent.id,
        JSON.stringify(supportedActions),
        JSON.stringify(supportedDnsProviders),
      ],
    );

    if (supportedActions.length === 0) return { jobs: [] };

    // Load the agent's persisted selectors for the claim matcher. The claim
    // body can override DNS providers for this poll; targets/profiles come
    // from registration/heartbeat.
    const agentCaps = await client.query(
      `SELECT declared_target_selectors,
              declared_command_profile_names,
              supported_dns_providers
         FROM certops_agents
        WHERE id = $1
        FOR UPDATE`,
      [agent.id],
    );
    const caps = agentCaps.rows[0] || {};
    const targetSelectors = jsonbTextArray(caps.declared_target_selectors);
    const commandProfiles = jsonbTextArray(caps.declared_command_profile_names);
    const dnsProviders =
      supportedDnsProviders.length > 0
        ? supportedDnsProviders
        : jsonbTextArray(caps.supported_dns_providers);

    // B2/B5: agent lane only; match assigned agent, target selector, DNS
    // provider, and command profile when the job requires them.
    const selected = await client.query(
      `SELECT id, workspace_id, operation, subject_type, subject_id, payload,
              approved_payload_hash, approved_canonical_intent_hash,
              mode, executor_kind,
              assigned_agent_id, required_target_selector,
              required_dns_provider, required_command_profile
         FROM certificate_jobs
        WHERE workspace_id = $1
          AND status = 'pending'
          AND executor_kind = 'agent'
          AND (scheduled_for IS NULL OR scheduled_for <= NOW())
          AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())
          AND operation = ANY($2::text[])
          AND (assigned_agent_id IS NULL OR assigned_agent_id = $3::uuid)
          AND (
            required_target_selector IS NULL
            OR required_target_selector = ANY($4::text[])
          )
          AND (
            required_dns_provider IS NULL
            OR required_dns_provider = ANY($5::text[])
          )
          AND (
            required_command_profile IS NULL
            OR required_command_profile = ANY($6::text[])
          )
        ORDER BY created_at
        LIMIT $7
        FOR UPDATE SKIP LOCKED`,
      [
        agent.workspaceId,
        supportedActions,
        agent.id,
        targetSelectors,
        dnsProviders,
        commandProfiles,
        maxJobs,
      ],
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

      // B15: resolve public cert before claiming so a missing inventory
      // row blocks only this job instead of aborting the whole claim batch.
      let deployPublicCert = null;
      if (row.operation === "deploy") {
        const rowPayload =
          row.payload && typeof row.payload === "object"
            ? row.payload
            : safeParseJson(row.payload);
        try {
          deployPublicCert = await resolveDeployCert({
            client,
            workspaceId: agent.workspaceId,
            job: row,
            payload: rowPayload,
          });
        } catch (error) {
          if (error?.code !== CERTOPS_AGENT_DEPLOY_CERT_UNAVAILABLE) throw error;
          await client.query(
            `UPDATE certificate_jobs
                SET status = 'blocked',
                    error_code = $2,
                    error_message = $3,
                    completed_at = COALESCE(completed_at, NOW()),
                    updated_at = NOW()
              WHERE id = $1`,
            [
              row.id,
              CERTOPS_AGENT_DEPLOY_CERT_UNAVAILABLE,
              "Public certificate material is unavailable for this deploy job",
            ],
          );
          continue;
        }
      }

      const claimed = await client.query(
        `UPDATE certificate_jobs
            SET status = 'claimed',
                claimed_by_agent_id = $2,
                claim_id = gen_random_uuid(),
                lease_expires_at = NOW() + make_interval(secs => $3),
                lease_renewed_at = NULL,
                attempt_count = attempt_count + 1,
                queued_at = COALESCE(queued_at, NOW()),
                updated_at = NOW()
          WHERE id = $1
          RETURNING id, claim_id, lease_expires_at, attempt_count, operation,
                    subject_type, subject_id, payload, mode`,
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
      // mode is a first-class immutable job attribute (B4); always include
      // it on the signed dispatch payload even if the stored payload lacks
      // it (pre-migration rows default to "real").
      const basePayload = {
        ...payload,
        jobId: String(job.id),
        workspaceId: agent.workspaceId,
        action: job.operation,
        mode: job.mode || payload.mode || "real",
        claimId: job.claim_id,
        attemptId: job.claim_id,
        leaseExpiresAt: dateToIso(job.lease_expires_at),
        attemptCount: job.attempt_count,
      };

      if (deployPublicCert) {
        basePayload.certificatePem = deployPublicCert.certificatePem;
        basePayload.certificatePemSha256 =
          deployPublicCert.certificatePemSha256;
        if (
          !basePayload.target ||
          typeof basePayload.target !== "object" ||
          Array.isArray(basePayload.target)
        ) {
          basePayload.target = {};
        }
        if (
          deployPublicCert.fingerprintSha256 &&
          !basePayload.target.fingerprintSha256
        ) {
          basePayload.target = {
            ...basePayload.target,
            fingerprintSha256: deployPublicCert.fingerprintSha256,
          };
        }
      }

      const signedJob = await signJob({
        client,
        job: basePayload,
        agentId: agent.id,
        workspaceId: agent.workspaceId,
        // Nonce validity covers lease + reaper hard grace + delivery grace
        // (leaseTiming.dispatchNonceTtlSeconds) and is extended on renew.
        nonceTtlSeconds,
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

// --- Lease renew (B6/B7) ---
//
// Contract for the agent runtime (see COORDINATION-B6.md at worktree root):
//   POST /api/v1/certops/agent/jobs/:jobId/lease
//   Auth: agent credential bearer
//   Body: { claimId: <uuid from signed dispatch>, sequence?: <int>=1 }
//   200: {
//     ok: true,
//     jobId, status: "running", claimId,
//     leaseExpiresAt, nonceExpiresAt
//   }
// Call this to transition claimed→running on first renew, and again before
// each external side effect (ACME/DNS/deploy/reload) so the reaper can tell
// "never renewed / safe to requeue" from "effects unknown".

/**
 * Re-proves claim ownership (agent_id + claim_id), transitions claimed→running
 * on first call, extends lease_expires_at, stamps lease_renewed_at, and
 * extends the still-open dispatch nonce so late results remain reportable
 * for the full renewable lease + hard-grace window.
 */
async function renewJobLease({
  dbPool = pool,
  agent,
  jobId,
  claimId,
  envelope = {},
  env = process.env,
  deps = {},
} = {}) {
  const enforceSequence = deps.enforceAgentSequence || enforceAgentSequence;
  const extendNonce = deps.extendJobNonceExpiry || extendJobNonceExpiry;
  const leaseSeconds = jobLeaseSeconds(env);
  const nonceTtlSeconds = dispatchNonceTtlSeconds(env);

  if (typeof jobId !== "string" || jobId.length === 0) {
    throw serviceError("jobId is required", CERTOPS_AGENT_LEASE_INVALID);
  }
  if (typeof claimId !== "string" || claimId.length === 0) {
    throw serviceError("claimId is required", CERTOPS_AGENT_LEASE_INVALID);
  }

  return await withTransaction(dbPool, async (client) => {
    await enforceSequence({ client, agentRowId: agent.id, envelope });

    const locked = await client.query(
      `SELECT id, status, claimed_by_agent_id, claim_id, lease_expires_at
         FROM certificate_jobs
        WHERE id = $1
          AND workspace_id = $2
          AND executor_kind = 'agent'
        FOR UPDATE`,
      [jobId, agent.workspaceId],
    );
    const job = locked.rows[0];
    if (!job) {
      throw serviceError(
        "Certificate job not found",
        CERTOPS_AGENT_JOB_NOT_FOUND,
      );
    }
    if (
      String(job.claimed_by_agent_id || "") !== String(agent.id) ||
      String(job.claim_id || "") !== String(claimId)
    ) {
      throw serviceError(
        "Lease renew does not match the current claim for this job",
        CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH,
      );
    }
    if (job.status !== "claimed" && job.status !== "running") {
      throw serviceError(
        "Certificate job is not in a renewable lease state",
        CERTOPS_AGENT_LEASE_INVALID,
      );
    }

    const updated = await client.query(
      `UPDATE certificate_jobs
          SET status = 'running',
              started_at = COALESCE(started_at, NOW()),
              lease_expires_at = NOW() + make_interval(secs => $2),
              lease_renewed_at = NOW(),
              updated_at = NOW()
        WHERE id = $1
        RETURNING id, status, claim_id, lease_expires_at, lease_renewed_at`,
      [job.id, leaseSeconds],
    );
    const row = updated.rows[0];

    const nonceOutcome = await extendNonce({
      client,
      jobId: String(job.id),
      workspaceId: agent.workspaceId,
      agentRowId: agent.id,
      nonceTtlSeconds,
    });

    return {
      ok: true,
      jobId: String(row.id),
      status: row.status,
      claimId: row.claim_id,
      leaseExpiresAt: dateToIso(row.lease_expires_at),
      leaseRenewedAt: dateToIso(row.lease_renewed_at),
      nonceExpiresAt: nonceOutcome.expiresAt,
    };
  });
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
    // Lock the agent row before the job row. claimJobs/renewJobLease both
    // lock the agent row (inside enforceAgentSequence) before any job row;
    // ingestResult used to lock the job row first and the agent row only
    // later (inside enforceSequence below), an inverted order that could
    // deadlock against a concurrent claim/lease-renew for the same agent.
    // Postgres would resolve that by aborting one transaction rather than
    // hanging, but acquiring the lock in the same order here removes the
    // possibility entirely; enforceSequence's own lock on this row later
    // in the transaction is then a no-op re-entrant lock.
    await client.query(
      `SELECT id FROM certops_agents WHERE id = $1 FOR UPDATE`,
      [agent.id],
    );

    const locked = await client.query(
      `SELECT id, status, claimed_by_agent_id, claim_id, operation,
              subject_type, subject_id, error_code, completed_at, mode
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

    // B4: dry_run jobs must never terminate as succeeded; real jobs must
    // never terminate as dry_run_complete. Dry-run jobs also cannot report
    // orphaned_unknown_effect (they never mutate real-world state).
    const jobMode = job.mode || "real";
    if (jobMode === "dry_run" && jobStatus === "succeeded") {
      throw serviceError(
        "dry_run jobs must report dry_run_complete, never succeeded",
        CERTOPS_AGENT_RESULT_STATUS_INVALID,
      );
    }
    if (jobMode === "real" && jobStatus === "dry_run_complete") {
      throw serviceError(
        "dry_run_complete is only valid for dry_run jobs",
        CERTOPS_AGENT_RESULT_STATUS_INVALID,
      );
    }
    if (jobMode === "dry_run" && jobStatus === "orphaned_unknown_effect") {
      throw serviceError(
        "orphaned_unknown_effect is only valid for real jobs",
        CERTOPS_AGENT_RESULT_STATUS_INVALID,
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

    const isFailure =
      jobStatus !== "succeeded" && jobStatus !== "dry_run_complete";
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

    // Only ever SET needs_operator_reconciliation to true here — never clear
    // an existing true from fencing (clearing is an explicit operator action).
    let setNeedsReconciliation = false;
    let reconciliationReason = null;
    if (jobStatus === "orphaned_unknown_effect") {
      setNeedsReconciliation = true;
      const parsed = parseReconciliationFromErrorMessage(body.errorMessage);
      reconciliationReason = boundReconciliationReason(
        parsed.reconciliationReason || FALLBACK_ORPHANED_RECONCILIATION_REASON,
      );
    }

    const updated = await client.query(
      `UPDATE certificate_jobs
          SET status = $2,
              error_code = $3,
              error_message = $4,
              completed_at = COALESCE(completed_at, NOW()),
              lease_expires_at = NULL,
              needs_operator_reconciliation = CASE
                WHEN $5::boolean THEN TRUE
                ELSE needs_operator_reconciliation
              END,
              reconciliation_reason = CASE
                WHEN $5::boolean THEN $6
                ELSE reconciliation_reason
              END,
              updated_at = NOW()
        WHERE id = $1
        RETURNING id, status, error_code, completed_at,
                  needs_operator_reconciliation, reconciliation_reason`,
      [
        job.id,
        jobStatus,
        errorCode,
        errorMessage,
        setNeedsReconciliation,
        reconciliationReason,
      ],
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
  CERTOPS_AGENT_COMPATIBILITY_BLOCKED,
  CERTOPS_AGENT_DEPLOY_CERT_UNAVAILABLE,
  CERTOPS_AGENT_JOB_NOT_FOUND,
  CERTOPS_AGENT_LEASE_INVALID,
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
  renewJobLease,
  resolveDeployPublicCertificate,
  _test: {
    DEFAULT_REGISTRATION_REPLAY_TTL_MS,
    FALLBACK_ORPHANED_RECONCILIATION_REASON,
    REGISTRATION_REPLAY_TTL_MS,
    RESULT_STATUS_TO_JOB_STATUS,
    boundReconciliationReason,
    dateToIso,
    envelopeSequence,
    findRegistrationReplay,
    normalizeStringList,
    parseReconciliationFromErrorMessage,
    registrationReplayResponse,
    registrationReplayTtlMs,
    safeParseJson,
    serviceError,
    withTransaction,
  },
};
