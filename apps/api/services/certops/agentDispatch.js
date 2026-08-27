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
  ENVELOPE_VERSION_1,
  ENVELOPE_VERSION_2,
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
const {
  RENEWAL_ALERTING_OPERATIONS,
  TRANSITION_ORIGINS,
  classifyTerminalTransition,
} = require("./renewalAlertPolicy");
const {
  OUTBOX_EVENT_TYPES,
  enqueueOutboxEvent,
} = require("./outbox");
const {
  linkReconciledCertificateToken,
} = require("./inventory");
const {
  DERIVATION_REASON_ALREADY_LINKED,
  ensureDerivedRenewalProfile,
} = require("./renewalProfileDerivation");
const {
  dispatchNonceTtlSeconds,
  jobLeaseSeconds,
} = require("./leaseTiming");
const {
  redactGenericSecrets,
  redactPrivateKeyMaterial,
  assertNoPrivateKeyMaterial,
} = require("../../utils/secretMaterial");
const { writeAudit } = require("../audit");
const { logger } = require("../../utils/logger");
const {
  computeAgentCompatibility,
} = require("./agentRegistry");
const {
  EVIDENCE_CLAIM_BINDING_CAPABILITY,
  TRUST_ANCHOR_DEPLOY_CAPABILITY,
  evaluateAgentJobEligibility,
  hasFreshCapability,
  wireActionForOperation,
} = require("./agentJobEligibility");
const { isTrustAnchorOperation } = require("./jobs");
const {
  revalidateTrustJobForDispatch,
  ingestTrustJobResult,
  onTrustJobTerminalTransition,
  TRUST_JOB_TERMINAL_NEGATIVE_STATUSES,
} = require("./trustAnchors");

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

/**
 * Windows-iis-specific audit fields for a job payload's `target`, shared
 * across every audit event that reports on a windows-iis issuance or
 * renewal (CERTOPS_CERTIFICATE_ISSUED, the two _UNRECONCILED events,
 * CERTOPS_JOB_FAILED, CERTOPS_RENEWAL_PROFILE_DERIVED). Without this, those
 * events carried only `deployedCertPath`/`certPath`, which is always null
 * for a windows-iis target (ADR-0012 decisions 1 and 10: the destination is
 * a machine certificate store + IIS binding, not a file), leaving an
 * operator no way to tell from the audit log alone which store/site/port a
 * Windows deployment actually touched.
 *
 * Takes the *whole* job payload, not payload.target directly, and
 * normalizes it the same defensive way the claim path already does
 * (job.payload is jsonb and normally arrives pre-parsed, but is read here
 * defensively in case it ever arrives as a raw JSON string) — calling
 * safeParseJson on an already-parsed object would silently discard it, since
 * safeParseJson only ever parses strings. Returns `{ targetType: null }` for
 * a missing or malformed target rather than throwing, since every call site
 * here is inside an audit-metadata object literal, where a thrown error
 * would abort the write of the event itself.
 */
function windowsIisAuditFields(jobPayload) {
  const payload =
    jobPayload && typeof jobPayload === "object"
      ? jobPayload
      : safeParseJson(jobPayload);
  const target = payload?.target;
  const targetType =
    target && typeof target === "object" && typeof target.type === "string"
      ? target.type
      : null;
  if (targetType !== "windows-iis") {
    return { targetType };
  }
  const binding =
    target.binding && typeof target.binding === "object"
      ? target.binding
      : null;
  return {
    targetType,
    windowsStore: typeof target.store === "string" ? target.store : null,
    windowsBindingSite:
      binding && typeof binding.site === "string" ? binding.site : null,
    windowsBindingPort:
      binding && Number.isSafeInteger(binding.port) ? binding.port : null,
    windowsBindingSniHost:
      binding && typeof binding.sniHost === "string" ? binding.sniHost : null,
  };
}



// Reconciliation of a provisioning certificate only trusts verify evidence that
// is bound to the current claim, which an agent must explicitly support. Gating
// claimability on the declared capability keeps an older agent from running an
// issuance that could never be reconciled, leaving the certificate stuck in
// 'provisioning' with a succeeded job and no way forward.
// ADR-0012 decision 1: an agent that declares this capability at
// registration/heartbeat receives the v2 "exact-byte" signed envelope
// ({ envelopeVersion: 2, payloadB64, signatureB64, signingKeyId }) instead of
// the legacy v1 canonical-JSON-signed job object. Dual-format dispatch is
// per-agent, decided fresh on every claim from the agent's current declared
// capabilities (not sticky), so an agent upgrade takes effect on its very
// next poll with no separate migration step.
const SIGNED_PAYLOAD_B64_CAPABILITY = "signed-payload-b64-v1";

// ADR-0012 decision 17: a declared capability is only trusted for gated
// selection while its assertion is fresh. `capabilities_updated_at` is set
// at registration and on every heartbeat write that touches
// declared_capabilities (including a no-op replace); it is NEVER backfilled
// for pre-existing rows (migration adds the column NULL, on purpose - see
// the migration's own comment). NULL therefore means "never asserted since
// this column existed" and must fail the freshness check, not pass it.
//
// The freshness bound itself (CERTOPS_CAPABILITY_FRESHNESS_MS) lives in
// agentRegistry.js, reusing that file's existing CERTOPS_AGENT_OFFLINE_AFTER_MS
// value/reasoning as its own independently named constant: an agent whose
// last capability assertion is older than the point at which it would
// already be considered liveness-stale has no business being offered a
// capability-gated job. This is NOT "3x the 30s heartbeat interval" - that
// reasoning was considered and explicitly rejected (ADR-0012 decision 17).

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
  const auditWriter = deps.writeAudit || writeAudit;
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
         declared_capabilities,
         status,
         bootstrap_token_id,
         last_sequence,
         capabilities_updated_at,
         downtime_alerts_enabled,
         contact_group_id
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12::jsonb,
               $15::jsonb, 'active', $13, $14, NOW(), $16, $17)
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
        JSON.stringify(normalizeStringList(body.declaredCapabilities, 64)),
        // Legacy bootstrap tokens (created before migration 45) carry
        // downtimeAlertsEnabled: null; NULL here means "unset", not "off",
        // so it must resolve to the column's own TRUE default rather than
        // to false. A bootstrap token that explicitly opted out (=== false)
        // is the only way this agent starts with alerting disabled.
        bootstrapToken.downtimeAlertsEnabled === false ? false : true,
        bootstrapToken.contactGroupId || null,
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

    // Enrollment is the moment a new machine principal gains the right to run
    // commands on hosts in this workspace, and it is the only record of a
    // bootstrap token being spent (a consumed token is marked 'used', which
    // produces no revocation event). Written after the replay row, inside the
    // registration transaction, so an enrollment cannot commit unaudited.
    //
    // A replayed registration returns earlier and is deliberately not audited
    // again: the same enrollment reported twice would read as two agents.
    await auditWriter({
      client,
      actorUserId: null,
      subjectUserId: null,
      action: "CERTOPS_AGENT_REGISTERED",
      targetType: "certops_agent",
      targetId: null,
      workspaceId: bootstrapToken.workspaceId,
      metadata: {
        agentId: response.agentId,
        hostname: body.hostname ?? null,
        platform: body.platform ?? null,
        agentVersion: body.agentVersion ?? null,
        protocolVersion: response.protocolVersion,
        credentialPrefix: credential.credentialPrefix,
        bootstrapTokenId: String(bootstrapToken.id),
        signingKeyId: response.signingKeyId,
        declaredTargetSelectors: body.declaredTargetSelectors || [],
        declaredCommandProfileNames: body.declaredCommandProfileNames || [],
        declaredCapabilities: normalizeStringList(body.declaredCapabilities, 64),
      },
    });

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
  const auditWriter = deps.writeAudit || writeAudit;

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
  // Capability declaration is three-valued, unlike the legacy list fields
  // above: omitted preserves the stored set, an explicitly-sent empty array
  // clears it, and a non-empty array replaces it. Collapsing "absent" and
  // "empty" into one preserve-only rule would make capability *removal*
  // impossible, so an agent downgraded to a build that no longer supports a
  // capability would stay eligible for jobs it can no longer execute. NULL
  // is the wire representation of "omitted" for the UPDATE below.
  const declaredCapabilitiesList = Array.isArray(body.declaredCapabilities)
    ? normalizeStringList(body.declaredCapabilities, 64)
    : null;
  const declaredCapabilities = declaredCapabilitiesList
    ? JSON.stringify(declaredCapabilitiesList)
    : null;

  return await withTransaction(dbPool, async (client) => {
    // Sequence enforcement runs after auth (route middleware) and before
    // the heartbeat write; a regression rejects the message with no
    // last_seen_at (or any other) update.
    await enforceSequence({ client, agentRowId: agent.id, envelope });

    // ADR-0012 decision 17 requires an audit event on a capability SET
    // CHANGE, not on every heartbeat that merely re-sends the field. The
    // agent re-declares declaredCapabilities on every heartbeat by design
    // (an in-place binary upgrade needs to pick up a new capability without
    // re-enrollment), so most heartbeats send the exact same non-empty
    // constant list the agent always sends. Auditing on "field present on
    // the wire" rather than "value differs from what's stored" fires this
    // event on essentially every heartbeat, forever, for every agent - the
    // pre-write read below exists specifically so the two can be told apart.
    let previousCapabilities = null;
    if (declaredCapabilities !== null) {
      const previous = await client.query(
        `SELECT declared_capabilities FROM certops_agents WHERE id = $1`,
        [agent.id],
      );
      previousCapabilities = jsonbTextArray(
        previous.rows[0]?.declared_capabilities,
      );
    }

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
              declared_capabilities = CASE
                WHEN $12::jsonb IS NULL THEN declared_capabilities
                ELSE $12::jsonb
              END,
              -- Epoch for the freshness check ADR-0012 decision 17 adds at
              -- claim time. Mirrors the value CASE exactly: absent (NULL)
              -- preserves the existing timestamp untouched, and BOTH an
              -- explicit [] and a non-empty array stamp NOW(), because both
              -- are real assertions of "this is my current capability set as
              -- of right now" even when the set does not change.
              capabilities_updated_at = CASE
                WHEN $12::jsonb IS NULL THEN capabilities_updated_at
                ELSE NOW()
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
        declaredCapabilities,
      ],
    );

    const row = result.rows[0];
    if (!row) {
      // Retired between auth and write: freeze, same as the route-level rule.
      throw serviceError("Agent is retired", CERTOPS_AGENT_RETIRED);
    }

    // Mirrors CERTOPS_AGENT_REGISTERED's audit shape (registration is the
    // only other place declared_capabilities is written). Fired only when
    // the set actually differs from what was stored - never on the
    // absent-preserves no-op path, and never on a heartbeat that re-sends
    // the same set it sent last time - so a real downgrade (or any real
    // capability change) is reconstructable after the fact without burying
    // it under one audit row per heartbeat for every agent. Order-insensitive
    // by design: this is a set, not a sequence, so a capability list that
    // comes back in a different order is not itself a change worth an event.
    const capabilitiesActuallyChanged =
      declaredCapabilities !== null &&
      !sameStringSet(previousCapabilities, declaredCapabilitiesList);
    if (capabilitiesActuallyChanged) {
      await auditWriter({
        client,
        actorUserId: null,
        subjectUserId: null,
        action: "CERTOPS_AGENT_CAPABILITIES_CHANGED",
        targetType: "certops_agent",
        targetId: null,
        workspaceId: agent.workspaceId,
        metadata: {
          agentId: agent.agentId,
          previousCapabilities,
          declaredCapabilities: declaredCapabilitiesList,
        },
      });
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
 * Order-insensitive equality for two string arrays, treating both as sets.
 * Used to decide whether a heartbeat's re-declared declaredCapabilities is
 * an actual change worth auditing (ADR-0012 decision 17) versus the agent
 * simply re-sending the same constant list it sends on every heartbeat.
 */
function sameStringSet(a, b) {
  const listA = Array.isArray(a) ? [...a].sort() : [];
  const listB = Array.isArray(b) ? [...b].sort() : [];
  if (listA.length !== listB.length) return false;
  return listA.every((item, index) => item === listB[index]);
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
              supported_dns_providers,
              declared_capabilities,
              capabilities_updated_at,
              agent_kind
         FROM certops_agents
        WHERE id = $1
        FOR UPDATE`,
      [agent.id],
    );
    const caps = agentCaps.rows[0] || {};
    // ADR-0012 decision 7: agent_kind is server-assigned at registration and
    // never updated afterward, unlike declared_capabilities/supportedActions
    // (both client-supplied on every call). The protocol_smoke gate below is
    // keyed on this column alone, so a normal agent cannot make itself
    // eligible for a diagnostic job (or vice versa) by declaring, or
    // withholding, any capability.
    const agentKind = caps.agent_kind === "diagnostic" ? "diagnostic" : "normal";
    const targetSelectors = jsonbTextArray(caps.declared_target_selectors);
    const commandProfiles = jsonbTextArray(caps.declared_command_profile_names);
    const dnsProviders =
      supportedDnsProviders.length > 0
        ? supportedDnsProviders
        : jsonbTextArray(caps.supported_dns_providers);
    // ADR-0012 decision 17: capability-restricted claim selection is gated
    // on freshness, not just presence in the (possibly stale) declared
    // array. A capability whose last assertion is older than
    // CERTOPS_CAPABILITY_FRESHNESS_MS - or that was never asserted at all
    // (capabilities_updated_at IS NULL, e.g. a pre-existing row that has not
    // yet heartbeated since this column was added) - is treated as absent
    // for gating purposes, even though the array itself may still list it.
    const canBindEvidenceToClaim = hasFreshCapability({
      declaredCapabilities: caps.declared_capabilities,
      capabilitiesUpdatedAt: caps.capabilities_updated_at,
      capability: EVIDENCE_CLAIM_BINDING_CAPABILITY,
      env,
    });
    // ADR-0012 decisions 17/20i: mirrors canBindEvidenceToClaim, gating
    // trust-anchor job candidacy on a fresh trust-anchor-deploy-v1
    // declaration. Lock-efficient SQL prefilter only; evaluateAgentJobEligibility
    // below is still the authoritative recheck.
    const canBindTrustAnchorDeploy = hasFreshCapability({
      declaredCapabilities: caps.declared_capabilities,
      capabilitiesUpdatedAt: caps.capabilities_updated_at,
      capability: TRUST_ANCHOR_DEPLOY_CAPABILITY,
      env,
    });
    const useV2Envelope = hasFreshCapability({
      declaredCapabilities: caps.declared_capabilities,
      capabilitiesUpdatedAt: caps.capabilities_updated_at,
      capability: SIGNED_PAYLOAD_B64_CAPABILITY,
      env,
    });

    // B2/B5: agent lane only; match assigned agent, target selector, DNS
    // provider, and command profile when the job requires them.
    //
    // The operation filter compares against the agent's wire actions
    // (supportedActions), not the control-plane operation column directly:
    // "issue" is dispatched to agents as "renew" (see
    // agentJobEligibility.wireActionForOperation) and no agent ever declares
    // "issue" as a supported action, so
    // without this translation issue jobs would sit at 'pending' forever.
    // The shared pure predicate below authoritatively rechecks this prefilter.
    //
    // The capability gate covers BOTH ways a job can need claim-bound evidence.
    // Gating operation = 'issue' alone is insufficient: a failed issuance is
    // retried as an ordinary renew against the still-'provisioning' certificate
    // (ADR-0008), and that retry has to reconcile too. So the gate is
    // "operation is issue OR the subject is still provisioning". An agent
    // without the capability keeps claiming ordinary renewals of active
    // certificates exactly as before.
    const selected = await client.query(
      `SELECT id, workspace_id, operation, subject_type, subject_id, payload,
              approved_payload_hash, approved_canonical_intent_hash,
              mode, executor_kind,
              assigned_agent_id, required_target_selector,
              required_dns_provider, required_command_profile,
              EXISTS (
                SELECT 1
                  FROM managed_certificates mc
                 WHERE mc.workspace_id = cj.workspace_id
                   AND cj.subject_type = 'managed_certificate'
                   AND cj.subject_id IS NOT NULL
                   AND mc.id = cj.subject_id::uuid
                   AND mc.status = 'provisioning'
              ) AS subject_is_provisioning
         FROM certificate_jobs cj
        WHERE workspace_id = $1
          AND status = 'pending'
          AND executor_kind = 'agent'
          AND (scheduled_for IS NULL OR scheduled_for <= NOW())
          AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())
          AND (CASE operation WHEN 'issue' THEN 'renew' ELSE operation END) = ANY($2::text[])
          AND (assigned_agent_id IS NULL OR assigned_agent_id = $3::uuid)
          AND (
            $8::boolean
            OR (
              operation <> 'issue'
              AND NOT EXISTS (
                SELECT 1
                  FROM managed_certificates mc
                 WHERE mc.workspace_id = cj.workspace_id
                   AND cj.subject_type = 'managed_certificate'
                   AND cj.subject_id IS NOT NULL
                   AND mc.id = cj.subject_id::uuid
                   AND mc.status = 'provisioning'
              )
            )
          )
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
          AND (
            ($9::text = 'diagnostic' AND operation = 'protocol_smoke')
            OR ($9::text <> 'diagnostic' AND operation <> 'protocol_smoke')
          )
          -- ADR-0012 decisions 17/20i: excludes a distribute-trust/revoke-trust
          -- candidate from this batch unless the polling agent's
          -- trust-anchor-deploy-v1 declaration is fresh (prefilter only;
          -- evaluateAgentJobEligibility below is the authoritative recheck).
          AND (
            operation NOT IN ('distribute-trust', 'revoke-trust')
            OR $10::boolean
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
        canBindEvidenceToClaim,
        agentKind,
        canBindTrustAnchorDeploy,
      ],
    );

    const eligibilityAgent = {
      ...agent,
      supportedOperations: supportedActions,
      targetSelectors,
      dnsProviders,
      commandProfiles,
      declaredCapabilities: caps.declared_capabilities,
      capabilitiesUpdatedAt: caps.capabilities_updated_at,
      agentKind,
    };
    const jobs = [];
    for (const row of selected.rows) {
      // SQL above is a lock-efficient prefilter. This shared pure predicate
      // is authoritative and is also used by renewal-path health, preventing
      // the UI from calling a path healthy that dispatch would reject.
      const eligibility = evaluateAgentJobEligibility({
        agent: eligibilityAgent,
        job: {
          operation: row.operation,
          executorKind: row.executor_kind,
          assignedAgentId: row.assigned_agent_id,
          requiredTargetSelector: row.required_target_selector,
          requiredDnsProvider: row.required_dns_provider,
          requiredCommandProfile: row.required_command_profile,
          subjectIsProvisioning: row.subject_is_provisioning === true,
        },
        compatibility,
        env,
      });
      if (!eligibility.eligible) continue;

      // ADR-0012 decision 20i: re-verify the anchor's current status and
      // that the signed intent still matches the anchor row, defense-in-depth
      // against a retirement landing between approval and this claim. A
      // distribute-trust job whose anchor was retired in that window is
      // unwound here (pending_install deleted) instead of claimed; the job
      // itself is left for the normal terminal-status path to close out.
      // pem is read back fresh (never persisted on certificate_jobs.payload)
      // and attached to basePayload once the job is actually claimed.
      let trustAnchorPem;
      let trustTransitionGeneration;
      if (isTrustAnchorOperation(row.operation)) {
        const revalidation = await revalidateTrustJobForDispatch({
          client,
          job: row,
        });
        if (!revalidation.allow) {
          await client.query(
            `UPDATE certificate_jobs
                SET status = 'rejected',
                    error_code = 'CERTOPS_TRUST_ANCHOR_DISPATCH_REVALIDATION_FAILED',
                    error_message = $2,
                    completed_at = COALESCE(completed_at, NOW()),
                    updated_at = NOW()
              WHERE id = $1
                AND status = 'pending'`,
            [row.id, `Trust job dispatch revalidation failed: ${revalidation.reason}`],
          );
          continue;
        }
        trustAnchorPem = revalidation.pem;
        trustTransitionGeneration = revalidation.transitionGeneration;
      }


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
                    subject_type, subject_id, payload, mode, created_at`,
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
        // ADR-0012 decision 3: binds this dispatch to one agent identity so
        // a captured envelope cannot be replayed against a different agent.
        // This is the wire-format agentId (agent.agentId), not the
        // certops_agents row id passed to signJob below for the nonce
        // ledger; the two are different identifiers for the same agent.
        agentId: agent.agentId,
        action: wireActionForOperation(job.operation),
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

      if (trustAnchorPem) {
        // Only distribute-trust sets trustAnchorPem (revoke-trust gets
        // undefined); trust-job-payload.schema.json's allOf forbids "pem"
        // on a revoke-trust payload, so this can never violate it.
        basePayload.pem = trustAnchorPem;
      }

      if (trustTransitionGeneration !== undefined) {
        // Resolved from the installation row at dispatch time, not stored
        // on the job payload (which is hashed for idempotency).
        basePayload.transitionGeneration = trustTransitionGeneration;
      }

      if (!basePayload.requestedAt) {
        // trust-job-payload.schema.json requires requestedAt, but the
        // stored payload omits it (fingerprinted into creation_request_hash,
        // so a per-call timestamp would break idempotent replay). The job
        // row's created_at is stable across every re-dispatch.
        basePayload.requestedAt = dateToIso(job.created_at);
      }

      const signedJob = await signJob({
        client,
        job: basePayload,
        agentId: agent.id,
        workspaceId: agent.workspaceId,
        // Nonce validity covers lease + reaper hard grace + delivery grace
        // (leaseTiming.dispatchNonceTtlSeconds) and is extended on renew.
        nonceTtlSeconds,
        envelopeVersion: useV2Envelope
          ? ENVELOPE_VERSION_2
          : ENVELOPE_VERSION_1,
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
 * Promote a freshly issued certificate from 'provisioning' to 'active',
 * backfilling the real x509 facts from the job's own verify-step evidence.
 *
 * The trigger is the SUBJECT's status, not the job's operation. That is
 * deliberate: after a failed issuance the operator retries with an ordinary
 * renew job against the now-known subjectId, and that retry has to reconcile
 * too. Keying on 'provisioning' makes both paths converge with no special
 * casing, and makes this a no-op for every already-active certificate.
 *
 * Three constraints make the promotion trustworthy rather than optimistic:
 *
 * 1. Only VERIFY-step evidence counts. The agent emits validation.passed twice
 *    per run, once when ACME returns and once when the deployed file has been
 *    read back and fingerprinted. Only the second describes what is actually on
 *    the host. Accepting the first would let the control plane record the
 *    certificate it asked for rather than the one that exists.
 * 2. Only evidence bound to THIS claim counts. A job can be attempted more than
 *    once, and evidence from a previous attempt outlives it, so an unbound
 *    lookup could promote attempt 2 using attempt 1's fingerprint.
 * 3. Fingerprint and expiry are mandatory. A certificate with no expiry cannot
 *    be renewed on schedule or alerted on, so activating without one produces a
 *    row that looks healthy and is silently unmanaged.
 *
 * When any of those fails the row stays 'provisioning' with a recorded
 * reconciliation_reason, which is a state an operator can see and act on.
 *
 * On a successful promotion this also derives the certificate's renewal profile
 * from the payload that just succeeded, because without one the renewal
 * scheduler will never pick the certificate up and it would silently expire.
 *
 * Runs inside the result-ingestion transaction. Returns
 * { certificateId, promoted, reason, profileId } or null when there was nothing
 * to do.
 */
async function reconcileProvisionedCertificate({
  client,
  workspaceId,
  job,
  agent = null,
  log = null,
  linkToken = linkReconciledCertificateToken,
  ensureRenewalProfile = ensureDerivedRenewalProfile,
  auditWriter = writeAudit,
}) {
  if (job.subject_type !== "managed_certificate" || !job.subject_id) return null;

  const locked = await client.query(
    `SELECT id, source, common_name, deployed_cert_path, deployed_agent_id, token_id
       FROM managed_certificates
      WHERE workspace_id = $1
        AND id = $2::uuid
        AND status = 'provisioning'
      FOR UPDATE`,
    [workspaceId, job.subject_id],
  );
  const certificate = locked.rows[0];
  if (!certificate) return null;

  const evidence = await client.query(
    `SELECT metadata
       FROM certificate_evidence
      WHERE workspace_id = $1
        AND job_id = $2
        AND evidence_type = 'validation.passed'
        AND claim_id = $3::uuid
        AND metadata->>'step' = 'verify'
      ORDER BY created_at DESC
      LIMIT 1`,
    [workspaceId, job.id, job.claim_id],
  );
  const metadata = evidence.rows[0]?.metadata || null;

  const text = (value) =>
    typeof value === "string" && value.trim() !== "" ? value.trim() : null;
  const timestamp = (value) => {
    const parsed = text(value) ? Date.parse(value) : Number.NaN;
    return Number.isNaN(parsed) ? null : new Date(parsed).toISOString();
  };

  const fingerprint = metadata ? text(metadata.fingerprintSha256) : null;
  const notAfter = metadata ? timestamp(metadata.validTo) : null;

  if (!metadata || !fingerprint || !notAfter) {
    const reason = !metadata
      ? "no_claim_bound_verify_evidence"
      : !fingerprint
        ? "verify_evidence_missing_fingerprint"
        : "verify_evidence_missing_expiry";
    await client.query(
      `UPDATE managed_certificates
          SET reconciliation_reason = $3,
              updated_at = NOW()
        WHERE workspace_id = $1
          AND id = $2::uuid`,
      [workspaceId, job.subject_id, reason],
    );
    // A succeeded job whose certificate could not be promoted is the most
    // misleading state CertOps can produce: the job history says the work
    // completed while the certificate is not usable and will not renew. The
    // reason lives on the row, but the row only ever shows its latest value, so
    // without an event there is no record that this happened at all, nor when.
    await auditWriter({
      client,
      actorUserId: null,
      subjectUserId: null,
      action: "CERTOPS_CERTIFICATE_ISSUANCE_UNRECONCILED",
      targetType: "managed_certificate",
      targetId: null,
      workspaceId,
      metadata: {
        managedCertificateId: String(job.subject_id),
        commonName: text(certificate.common_name),
        jobId: String(job.id),
        operation: job.operation || null,
        claimId: job.claim_id ? String(job.claim_id) : null,
        agentId: agent?.agentId || null,
        reconciliationReason: reason,
        ...windowsIisAuditFields(job.payload),
      },
    });
    return { certificateId: String(job.subject_id), promoted: false, reason };
  }

  const sans = text(metadata.subjectAltNames);

  await client.query(
    `UPDATE managed_certificates
        SET status = 'active',
            fingerprint_sha256 = $3,
            serial_number = COALESCE($4, serial_number),
            subject = COALESCE($5, subject),
            issuer = COALESCE($6, issuer),
            not_before = COALESCE($7::timestamptz, not_before),
            not_after = $8::timestamptz,
            subject_alt_names = CASE
              WHEN $9::text IS NULL THEN subject_alt_names
              ELSE (
                SELECT ARRAY(
                  SELECT DISTINCT BTRIM(name)
                    FROM regexp_split_to_table($9::text, '\\s*,\\s*') AS name
                   WHERE BTRIM(name) <> ''
                )
              )
            END,
            reconciliation_reason = NULL,
            updated_at = NOW()
      WHERE workspace_id = $1
        AND id = $2::uuid`,
    [
      workspaceId,
      job.subject_id,
      fingerprint,
      text(metadata.serialNumber),
      text(metadata.subject),
      text(metadata.issuer),
      timestamp(metadata.validFrom),
      notAfter,
      sans,
    ],
  );

  // Token linking waits until here on purpose. tokens.expiration is DATE NOT
  // NULL, so a certificate that does not exist yet cannot have a legitimate
  // token row: any earlier attempt would have to invent an expiry. Now that a
  // verified notAfter is known, the certificate can join the token-centric
  // inventory that expiry tracking, dashboards and alert routing all key off.
  await linkToken({
    client,
    workspaceId,
    certificateId: String(job.subject_id),
    certificate: {
      // The agent's verify evidence never carries a parsed "commonName" field
      // (only the raw X.509 "subject" DN string), so this has to come from
      // the row itself: it was set authoritatively from the issue request's
      // target.reference when the provisioning row was created.
      commonName: text(certificate.common_name),
      subject: text(metadata.subject),
      subjectAltNames: sans
        ? sans.split(",").map((name) => name.trim()).filter(Boolean)
        : [],
      issuer: text(metadata.issuer),
      serialNumber: text(metadata.serialNumber),
      fingerprintSha256: fingerprint,
      notAfter,
    },
    existingTokenId: certificate.token_id || null,
  });

  // A certificate with no renewal profile is never picked up by the renewal
  // scheduler: it refuses to dispatch a renewal it cannot fully specify. Since
  // nothing else in the product writes certificate_profiles, an issued
  // certificate would sit at 'active' with a real expiry and silently never
  // renew. Derive the profile here, where the payload that just succeeded is
  // known to work, rather than asking the operator to retype it and risk
  // disagreeing with what actually ran.
  const derivation = await ensureRenewalProfile({
    client,
    workspaceId,
    certificateId: String(job.subject_id),
    payload: job.payload || {},
    operation: job.operation || null,
    certificate: {
      commonName: text(certificate.common_name),
      subjectAltNames: sans
        ? sans.split(",").map((name) => name.trim()).filter(Boolean)
        : [],
    },
    logger: log || null,
  });

  // A declined derivation used to be visible only as profileId: null buried in
  // the CERTOPS_CERTIFICATE_ISSUED metadata, and the logger was not even passed,
  // so the log line the derivation writes for exactly this case was unreachable.
  // The operator-visible consequence is the worst kind: the certificate is
  // active, its expiry is real, the job says succeeded, and it will never renew,
  // with nothing anywhere saying why. Record it the same way an unreconciled
  // issuance is recorded, on the row and as an event, so the certificate carries
  // an actionable reason. `already_linked` is the normal path (the certificate
  // has a profile) and is not a decline.
  const derivationDeclined =
    !derivation?.profileId &&
    derivation?.reason !== DERIVATION_REASON_ALREADY_LINKED;
  if (derivationDeclined) {
    const derivationReason = `renewal_profile_${derivation?.reason || "derivation_failed"}`;
    await client.query(
      `UPDATE managed_certificates
          SET reconciliation_reason = $3,
              updated_at = NOW()
        WHERE workspace_id = $1
          AND id = $2::uuid`,
      [workspaceId, job.subject_id, derivationReason],
    );
    await auditWriter({
      client,
      actorUserId: null,
      subjectUserId: null,
      action: "CERTOPS_RENEWAL_PROFILE_DERIVATION_DECLINED",
      targetType: "managed_certificate",
      targetId: null,
      workspaceId,
      metadata: {
        managedCertificateId: String(job.subject_id),
        commonName: text(certificate.common_name),
        jobId: String(job.id),
        operation: job.operation || null,
        agentId: agent?.agentId || null,
        derivationReason: derivation?.reason || null,
        reconciliationReason: derivationReason,
        // The decline detail explains which payload field was missing or
        // malformed. It names fields, never their values, so it cannot become a
        // topology disclosure the way the DERIVED event's metadata can.
        detail: derivation?.error || null,
        // Not the full windowsIisAuditFields() set deliberately: a declined
        // derivation means the store/binding fields could not be trusted (that
        // is very often *why* it declined), so only the type discriminator is
        // safe to record here. Requesting the fuller set from a payload that
        // failed exactly this validation would surface fields the derivation
        // itself refused to certify as complete.
        targetType: text(job.payload?.target?.type),
      },
    });
  }

  // The moment the certificate exists. Everything above this line is the only
  // point in the product where a certificate comes into being without a human
  // request immediately preceding it: a scheduled renewal reaches here with no
  // operator in the loop at all. Written in the reconciliation transaction, so a
  // certificate cannot become active unaudited.
  //
  // No actor: the agent is a machine principal and audit_events.actor_user_id
  // is a users FK. The acting agent is identified in metadata instead.
  await auditWriter({
    client,
    actorUserId: null,
    subjectUserId: null,
    action: "CERTOPS_CERTIFICATE_ISSUED",
    targetType: "managed_certificate",
    targetId: null,
    workspaceId,
    metadata: {
      managedCertificateId: String(job.subject_id),
      commonName: text(certificate.common_name),
      jobId: String(job.id),
      // 'issue' is a first issuance; 'renew' here means a retry against a
      // certificate that never reconciled, which is worth telling apart.
      operation: job.operation || null,
      source: certificate.source || null,
      agentId: agent?.agentId || null,
      fingerprintSha256: fingerprint,
      serialNumber: text(metadata.serialNumber),
      issuer: text(metadata.issuer),
      notAfter,
      subjectAltNames: sans,
      deployedCertPath: text(certificate.deployed_cert_path),
      // deployedCertPath above is always null for a windows-iis target (its
      // destination is a certificate store + IIS binding, not a file); these
      // fields are the substitute, see windowsIisAuditFields.
      ...windowsIisAuditFields(job.payload),
      profileId: derivation?.profileId || null,
      // Why there is no profile, when there is none. Without this the ISSUED
      // event recorded the absence but never the cause, so an operator seeing
      // profileId: null had no way to tell an operator-owned name collision
      // from a payload that could not be derived from.
      profileDerivationReason: derivation?.profileId
        ? null
        : derivation?.reason || null,
    },
  });

  return {
    certificateId: String(job.subject_id),
    promoted: true,
    reason: null,
    profileId: derivation?.profileId || null,
  };
}

/**
 * A successful 'renew' against a certificate that is already 'active' never
 * reaches reconcileProvisionedCertificate's UPDATE: that function only locks
 * rows WHERE status = 'provisioning' and returns null for anything else, by
 * design (it exists to promote a first issuance, not to touch a certificate
 * that already went through that promotion). Without a second write path,
 * fingerprint_sha256/not_after would freeze at whatever the FIRST successful
 * reconciliation set and never advance again -- silently, since the job
 * itself still reports 'succeeded' and carries a perfectly good verify
 * evidence row. Two compounding effects follow: the dashboard shows a
 * permanently stale expiry past the first renewal, and the renewal
 * scheduler's idempotency key (certificate id + not_after, see
 * renewalIdempotencyKey in renewalScheduler.js) keeps colliding with the
 * already-succeeded job on every later sweep -- so a certificate would only
 * ever be renewed automatically once, not on every cycle, which defeats the
 * entire point of the scheduler. This function is the missing refresh: same
 * evidence source as reconcileProvisionedCertificate, and now the same
 * completeness contract too -- incomplete verify evidence is a durable,
 * audited reconciliation_reason rather than a silent no-op, and a successful
 * refresh mirrors the new facts onto the linked token in the same
 * transaction (deliberately still narrower than first reconciliation: no
 * status transition, no profile derivation -- those already happened once
 * and are not re-run on every renewal).
 */
async function refreshRenewedCertificateEvidence({
  client,
  workspaceId,
  job,
  agent = null,
  linkToken = linkReconciledCertificateToken,
  auditWriter = writeAudit,
}) {
  if (job.subject_type !== "managed_certificate" || !job.subject_id) return null;

  const locked = await client.query(
    `SELECT id, common_name, token_id
       FROM managed_certificates
      WHERE workspace_id = $1
        AND id = $2::uuid
        AND status = 'active'
      FOR UPDATE`,
    [workspaceId, job.subject_id],
  );
  const certificate = locked.rows[0];
  if (!certificate) return null;

  const evidence = await client.query(
    `SELECT metadata
       FROM certificate_evidence
      WHERE workspace_id = $1
        AND job_id = $2
        AND evidence_type = 'validation.passed'
        AND claim_id = $3::uuid
        AND metadata->>'step' = 'verify'
      ORDER BY created_at DESC
      LIMIT 1`,
    [workspaceId, job.id, job.claim_id],
  );
  const metadata = evidence.rows[0]?.metadata || null;

  const text = (value) =>
    typeof value === "string" && value.trim() !== "" ? value.trim() : null;
  const timestamp = (value) => {
    const parsed = text(value) ? Date.parse(value) : Number.NaN;
    return Number.isNaN(parsed) ? null : new Date(parsed).toISOString();
  };

  const fingerprint = metadata ? text(metadata.fingerprintSha256) : null;
  const notAfter = metadata ? timestamp(metadata.validTo) : null;

  // Same completeness bar as first reconciliation: a renewal that cannot
  // prove what it deployed must not silently overwrite a known-good row with
  // half of a new one.
  //
  // Unlike reconcileProvisionedCertificate's identical gate, an incomplete
  // result here used to just `return null`. That silence was more than a
  // missing log line: not_after never advances, and the renewal scheduler's
  // idempotency key is certificate id + not_after (renewalIdempotencyKey in
  // renewalScheduler.js), so the *next* sweep derives the exact same key,
  // collides with this already-'succeeded' job on the unique index, and is
  // recorded as a replay rather than a fresh attempt. A certificate can
  // therefore stay genuinely due for renewal indefinitely while every sweep
  // reports nothing wrong. Setting reconciliation_reason and auditing here
  // does not change that replay outcome by itself, but it turns an
  // indefinite silent loop into a durable, visible, alertable failure an
  // operator (or a future scheduler check keyed on reconciliation_reason) can
  // act on, matching the provisioning path's own contract.
  if (!fingerprint || !notAfter) {
    const reason = !metadata
      ? "no_claim_bound_verify_evidence"
      : !fingerprint
        ? "verify_evidence_missing_fingerprint"
        : "verify_evidence_missing_expiry";
    await client.query(
      `UPDATE managed_certificates
          SET reconciliation_reason = $3,
              updated_at = NOW()
        WHERE workspace_id = $1
          AND id = $2::uuid
          AND status = 'active'`,
      [workspaceId, job.subject_id, reason],
    );
    await auditWriter({
      client,
      actorUserId: null,
      subjectUserId: null,
      action: "CERTOPS_CERTIFICATE_RENEWAL_UNRECONCILED",
      targetType: "managed_certificate",
      targetId: null,
      workspaceId,
      metadata: {
        managedCertificateId: String(job.subject_id),
        commonName: text(certificate.common_name),
        jobId: String(job.id),
        operation: job.operation || null,
        claimId: job.claim_id ? String(job.claim_id) : null,
        agentId: agent?.agentId || null,
        reconciliationReason: reason,
        ...windowsIisAuditFields(job.payload),
      },
    });
    return { certificateId: String(job.subject_id), refreshed: false, reason };
  }

  const sans = text(metadata.subjectAltNames);

  await client.query(
    `UPDATE managed_certificates
        SET fingerprint_sha256 = $3,
            serial_number = COALESCE($4, serial_number),
            subject = COALESCE($5, subject),
            issuer = COALESCE($6, issuer),
            not_before = COALESCE($7::timestamptz, not_before),
            not_after = $8::timestamptz,
            subject_alt_names = CASE
              WHEN $9::text IS NULL THEN subject_alt_names
              ELSE (
                SELECT ARRAY(
                  SELECT DISTINCT BTRIM(name)
                    FROM regexp_split_to_table($9::text, '\\s*,\\s*') AS name
                   WHERE BTRIM(name) <> ''
                )
              )
            END,
            reconciliation_reason = NULL,
            updated_at = NOW()
      WHERE workspace_id = $1
        AND id = $2::uuid
        AND status = 'active'`,
    [
      workspaceId,
      job.subject_id,
      fingerprint,
      text(metadata.serialNumber),
      text(metadata.subject),
      text(metadata.issuer),
      timestamp(metadata.validFrom),
      notAfter,
      sans,
    ],
  );

  // Mirror the same facts to the linked token in the same transaction as the
  // certificate row. Without this, a renewal advances managed_certificates'
  // not_after while tokens.expiration (what the token-centric dashboard,
  // token_expiry alerts, and every other consumer of "when does this expire"
  // actually reads) stays frozen at the pre-renewal date, so the fleet looks
  // like it is silently approaching an expiry that already moved.
  if (certificate.token_id) {
    await linkToken({
      client,
      workspaceId,
      certificateId: String(job.subject_id),
      certificate: {
        commonName: text(certificate.common_name),
        subject: text(metadata.subject),
        subjectAltNames: sans
          ? sans.split(",").map((name) => name.trim()).filter(Boolean)
          : [],
        issuer: text(metadata.issuer),
        serialNumber: text(metadata.serialNumber),
        fingerprintSha256: fingerprint,
        notAfter,
      },
      existingTokenId: certificate.token_id,
    });
  }

  return {
    certificateId: String(job.subject_id),
    refreshed: true,
    fingerprintSha256: fingerprint,
    notAfter,
  };
}

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
  const recordOutboxEvent = deps.enqueueOutboxEvent || enqueueOutboxEvent;
  const auditWriter = deps.writeAudit || writeAudit;
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
              subject_type, subject_id, error_code, completed_at, mode,
              source, payload, assigned_agent_id
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

    // Every real agent-reported outcome used to leave result_metadata at its
    // insert-time default ({}): this UPDATE set status/error columns but
    // never result_metadata, so 100% of distribute-trust/revoke-trust/deploy
    // jobs carried no result evidence at all. body?.trustResult is already
    // schema-validated (trust-result-contract.schema.json) for every trust-
    // anchor job by the time this runs; rejectionReason/keyRotated are
    // schema-validated generic resultBody fields (agent-protocol.schema.json)
    // available for every job family. null-only entries below are always
    // legitimate: e.g. a very early failure before the agent even attempted
    // the OS mutation may not have an observedFingerprintBefore.
    const trustResult = body?.trustResult || null;
    const resultMetadata = {
      ...(body.rejectionReason != null
        ? { rejectionReason: body.rejectionReason }
        : {}),
      ...(body.keyRotated != null ? { keyRotated: body.keyRotated } : {}),
      ...(trustResult
        ? {
            outcome: trustResult.outcome ?? null,
            mutationAttempted: trustResult.mutationAttempted ?? null,
            mutationPerformed: trustResult.mutationPerformed ?? null,
            failureCategory: trustResult.failureCategory ?? null,
            observedFingerprintBefore:
              trustResult.observedFingerprintBefore ?? null,
            observedFingerprintAfter:
              trustResult.observedFingerprintAfter ?? null,
            store: trustResult.store ?? null,
            transitionGeneration: trustResult.transitionGeneration ?? null,
          }
        : {}),
    };

    const updated = await client.query(
      `UPDATE certificate_jobs
          SET status = $2,
              error_code = $3,
              error_message = $4,
              result_metadata = $7::jsonb,
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
        JSON.stringify(resultMetadata),
      ],
    );

    const row = updated.rows[0];

    // certificate_job_log's schema is designed to record job.completed/
    // job.failed/job.progress lifecycle events, but until now only the
    // lease-reaper sweep's synthetic terminalizations ever wrote there --
    // never this path, which is where every *real* agent-reported outcome
    // lands. Mirrors insertJobLog's plain-INSERT shape in
    // apps/worker/src/certops-worker.js so the two writers stay consistent;
    // this transaction already holds job.id row-locked, so no existence
    // recheck is needed here either.
    await client.query(
      `INSERT INTO certificate_job_log (
         workspace_id, job_id, event_type, status, message, metadata
       )
       VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
      [
        agent.workspaceId,
        job.id,
        isFailure ? "job.failed" : "job.completed",
        jobStatus,
        isFailure
          ? errorMessage || `Agent reported result: ${jobStatus}`
          : `Agent reported result: ${jobStatus}`,
        JSON.stringify({
          agentId: agent.agentId || null,
          errorCode: errorCode || null,
          ...resultMetadata,
        }),
      ],
    );

    // ADR-0012 decision 20b/20e: trust-anchor jobs advance/unwind the
    // certops_trust_anchor_installations row from inside this same
    // transaction, so the job's terminal status and the installation's
    // state can never be observed apart. A successful result is validated
    // against trust-result-contract.schema.json and cross-checked against
    // the persisted job/installation row before the row is touched;
    // ingestTrustJobResult throws (rolling back this whole transaction) on
    // any mismatch or stale generation. dry_run_complete and
    // orphaned_unknown_effect are left untouched: a dry run never mutated
    // anything, and an unknown-effect report must surface for operator
    // reconciliation rather than being silently resolved either way.
    if (isTrustAnchorOperation(job.operation)) {
      if (jobStatus === "succeeded") {
        // The typed result rides in its own envelope property; the rest of
        // `body` is the generic result shape every job family shares.
        const installation = await ingestTrustJobResult({
          client,
          job: { ...job, workspace_id: agent.workspaceId },
          result: body?.trustResult,
        });
        // ADR-0012 decision 15: fires only on this action's own terminal
        // succeeded transition. A terminal failure reuses the generic
        // CERTOPS_JOB_FAILED event below instead.
        await auditWriter({
          client,
          actorUserId: null,
          subjectUserId: null,
          action:
            job.operation === "distribute-trust"
              ? "CERTOPS_TRUST_ANCHOR_DISTRIBUTED"
              : "CERTOPS_TRUST_ANCHOR_REVOKED",
          targetType: "trust_anchor",
          targetId: installation.trustAnchorId,
          workspaceId: agent.workspaceId,
          metadata: {
            jobId: String(job.id),
            trustAnchorId: installation.trustAnchorId,
            installationId: installation.id,
            store: installation.store,
            host: installation.host,
            owner: installation.owner,
            transitionState: installation.transitionState,
            provenance: installation.provenance,
            agentId: agent.agentId || null,
            // Carried from the agent's own reported result (already
            // schema-validated by ingestTrustJobResult above), not just the
            // installation row, so the audit trail records what the agent
            // actually observed/did, not only where the row ended up.
            outcome: body?.trustResult?.outcome ?? null,
            mutationPerformed: body?.trustResult?.mutationPerformed ?? null,
            failureCategory: body?.trustResult?.failureCategory ?? null,
            observedFingerprintBefore:
              body?.trustResult?.observedFingerprintBefore ?? null,
            observedFingerprintAfter:
              body?.trustResult?.observedFingerprintAfter ?? null,
          },
        });
      } else if (TRUST_JOB_TERMINAL_NEGATIVE_STATUSES.has(jobStatus)) {
        await onTrustJobTerminalTransition({
          client,
          job: { ...job, status: jobStatus, workspace_id: agent.workspaceId },
        });
      }
    }

    // A successful result may be the moment a requested certificate first
    // really exists. Reconcile before the alert stage and inside this
    // transaction, so the job's terminal status and the certificate becoming
    // active are never observable apart.
    if (jobStatus === "succeeded") {
      const provisioned = await reconcileProvisionedCertificate({
        client,
        workspaceId: agent.workspaceId,
        job,
        agent,
        log,
        auditWriter,
      });
      // null means "not a still-provisioning certificate" (already active, or
      // not a managed_certificate subject at all): try the refresh path
      // instead so an ordinary renewal of an already-active certificate still
      // advances its stored fingerprint/not_after. See
      // refreshRenewedCertificateEvidence for why this is required, not
      // optional.
      if (!provisioned) {
        await refreshRenewedCertificateEvidence({
          client,
          workspaceId: agent.workspaceId,
          job,
          agent,
        });
      }
    }

    // Successes are not audited here: CERTOPS_CERTIFICATE_ISSUED already records
    // the outcome that matters, and a row per successful renewal per certificate
    // would bury the failures in the same log. Failures are audited because
    // certificate_jobs holds only the latest error, so a job that failed and was
    // then retried loses its own history, and orphaned_unknown_effect is the one
    // outcome where the real-world state is unknown and someone must intervene.
    if (isFailure) {
      // Symmetric with the success-path audit above: CERTOPS_JOB_FAILED used
      // to carry only the generic error code/message, dropping the same
      // trust-result fields (outcome/observedFingerprintBefore/After/
      // mutationPerformed/failureCategory/provenance) the success path
      // already includes. outcome/mutationPerformed/failureCategory/
      // fingerprints come from body.trustResult, already schema-validated
      // for every trust-anchor job; provenance is not part of that contract
      // (it is a server-derived installation-row field, same as on the
      // success path), so it is read from the installation row directly.
      // Fields the agent genuinely never reported (e.g. a failure before it
      // attempted the OS mutation) stay null rather than being invented.
      let trustResultAuditFields = {};
      if (isTrustAnchorOperation(job.operation)) {
        const installationLookup = await client.query(
          `SELECT provenance
             FROM certops_trust_anchor_installations
            WHERE workspace_id = $1 AND last_job_id = $2
            LIMIT 1`,
          [agent.workspaceId, job.id],
        );
        trustResultAuditFields = {
          outcome: body?.trustResult?.outcome ?? null,
          mutationPerformed: body?.trustResult?.mutationPerformed ?? null,
          failureCategory: body?.trustResult?.failureCategory ?? null,
          observedFingerprintBefore:
            body?.trustResult?.observedFingerprintBefore ?? null,
          observedFingerprintAfter:
            body?.trustResult?.observedFingerprintAfter ?? null,
          provenance: installationLookup.rows[0]?.provenance ?? null,
        };
      }
      await auditWriter({
        client,
        actorUserId: null,
        subjectUserId: null,
        action: "CERTOPS_JOB_FAILED",
        targetType: "certificate_job",
        targetId: null,
        workspaceId: agent.workspaceId,
        metadata: {
          jobId: String(job.id),
          operation: job.operation || null,
          jobStatus,
          source: job.source || null,
          mode: jobMode,
          agentId: agent.agentId || null,
          claimId: job.claim_id ? String(job.claim_id) : null,
          errorCode: errorCode || null,
          // Already scrubbed of key material and generic secrets above.
          errorMessage,
          subjectType: job.subject_type || null,
          subjectId: job.subject_id ? String(job.subject_id) : null,
          needsOperatorReconciliation: Boolean(
            row.needs_operator_reconciliation,
          ),
          reconciliationReason: row.reconciliation_reason || null,
          ...trustResultAuditFields,
          ...windowsIisAuditFields(job.payload),
        },
      });
    }

    // Terminal transitions that warrant a notification record the intent in the
    // outbox as part of this transaction. Contact resolution and the
    // alert_queue insert happen later in the maintenance worker's drain sweep,
    // so a slow or failing alert path cannot affect result ingestion, and an
    // ingestion that commits can never lose the intent to alert.
    const classification = classifyTerminalTransition({
      operation: job.operation,
      status: jobStatus,
      origin: TRANSITION_ORIGINS.AGENT_RESULT,
    });
    if (classification.alertWorthy) {
      await recordOutboxEvent({
        client,
        workspaceId: agent.workspaceId,
        eventType: OUTBOX_EVENT_TYPES.RENEWAL_ALERT_REQUESTED,
        dedupeKey: String(job.id),
        payload: {
          jobId: String(job.id),
          operation: job.operation,
          jobStatus,
          origin: TRANSITION_ORIGINS.AGENT_RESULT,
          classificationReason: classification.reason,
          priority: classification.priority || null,
          errorCode: errorCode || null,
          subjectType: job.subject_type || null,
          subjectId: job.subject_id ? String(job.subject_id) : null,
        },
      });
    } else if (log?.debug) {
      log.debug("certops-renewal-alert-not-queued", {
        jobId: String(job.id),
        reason: classification.reason,
      });
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
 * so post-result evidence from the same agent stays valid).
 *
 * Agent ownership alone is not enough for evidence that reconciliation will
 * trust. The same agent can legitimately hold the same job across more than one
 * attempt, so it must also prove WHICH attempt the evidence describes, or
 * evidence from a superseded attempt could be used to promote a certificate.
 * claimId is that proof: issued at dispatch, already carried in the protocol.
 * The server records the validated claim id together with its own attempt_count
 * rather than trusting any agent-supplied counter.
 *
 * Returns { claimId, attemptCount } for persistence. Throws
 * CERTOPS_AGENT_JOB_NOT_FOUND / CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH.
 */
async function assertEvidenceClaimOwnership({
  dbPool = pool,
  agent,
  jobId,
  claimId = null,
} = {}) {
  const result = await dbPool.query(
    `SELECT claimed_by_agent_id, claim_id, attempt_count
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
  if (claimId != null && String(claimId) !== String(row.claim_id || "")) {
    throw serviceError(
      "Evidence claim does not match the current claim for this job",
      CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH,
    );
  }
  return {
    claimId: row.claim_id || null,
    attemptCount: Number.isSafeInteger(row.attempt_count)
      ? row.attempt_count
      : null,
  };
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
    RENEWAL_ALERTING_OPERATIONS,
    boundReconciliationReason,
    dateToIso,
    envelopeSequence,
    evaluateAgentJobEligibility,
    findRegistrationReplay,
    normalizeStringList,
    parseReconciliationFromErrorMessage,
    reconcileProvisionedCertificate,
    refreshRenewedCertificateEvidence,
    registrationReplayResponse,
    registrationReplayTtlMs,
    safeParseJson,
    serviceError,
    wireActionForOperation,
    EVIDENCE_CLAIM_BINDING_CAPABILITY,
    TRUST_ANCHOR_DEPLOY_CAPABILITY,
    SIGNED_PAYLOAD_B64_CAPABILITY,
    hasFreshCapability,
    withTransaction,
  },
};
