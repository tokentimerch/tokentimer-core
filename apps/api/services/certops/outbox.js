"use strict";

/**
 * CertOps transactional outbox.
 *
 * Intents are recorded by the transaction that decides them and executed later
 * by the certops maintenance worker. Two properties matter:
 *
 * 1. The enqueue is a plain local INSERT inside the caller's transaction, so
 *    "the job reached its terminal status" and "the side effect was decided"
 *    commit together or not at all. There is no savepoint and no best-effort
 *    swallow: if the enqueue fails the caller's transaction fails, which is
 *    correct, because the alternative is losing the intent silently.
 * 2. Execution is retried with backoff under an owner-scoped lease, so a slow
 *    or failing downstream (contact resolution, alert_queue) never blocks or
 *    corrupts the deciding transaction.
 */

const { pool } = require("../../db/database");
const {
  containsPrivateKeyMaterial,
  containsGenericSecretMaterial,
} = require("../../utils/secretMaterial");

const OUTBOX_EVENT_TYPES = Object.freeze({
  RENEWAL_ALERT_REQUESTED: "renewal_alert_requested",
  PROFILE_DERIVATION_REQUESTED: "profile_derivation_requested",
});

const OUTBOX_EVENT_TYPE_VALUES = Object.freeze(
  new Set(Object.values(OUTBOX_EVENT_TYPES)),
);

const DEDUPE_KEY_MAX_LENGTH = 256;

// Per-event payload contracts. Ids and frozen codes only, so an outbox row can
// never become an exfiltration path for job payload contents. Unknown keys are
// rejected rather than dropped: a caller passing something unexpected is a bug
// worth surfacing, not data worth silently discarding.
const PAYLOAD_FIELDS_BY_EVENT_TYPE = Object.freeze({
  [OUTBOX_EVENT_TYPES.RENEWAL_ALERT_REQUESTED]: Object.freeze(
    new Set([
      "jobId",
      "operation",
      "jobStatus",
      "origin",
      "classificationReason",
      "priority",
      "errorCode",
      "subjectType",
      "subjectId",
    ]),
  ),
  [OUTBOX_EVENT_TYPES.PROFILE_DERIVATION_REQUESTED]: Object.freeze(
    new Set(["jobId", "certificateId", "operation"]),
  ),
});

const PAYLOAD_VALUE_MAX_LENGTH = 512;

function outboxError(message, code) {
  const err = new Error(message);
  err.code = code || "CERTOPS_OUTBOX_INVALID";
  err.statusCode = 422;
  return err;
}

function assertValidPayload(eventType, payload) {
  const allowed = PAYLOAD_FIELDS_BY_EVENT_TYPE[eventType];
  if (!allowed) {
    throw outboxError(
      `Unknown certops outbox event type: ${eventType}`,
      "CERTOPS_OUTBOX_UNKNOWN_EVENT_TYPE",
    );
  }
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    throw outboxError("Outbox payload must be an object");
  }
  for (const [key, value] of Object.entries(payload)) {
    if (!allowed.has(key)) {
      throw outboxError(
        `Outbox payload field not permitted for ${eventType}: ${key}`,
      );
    }
    if (value === null || value === undefined) continue;
    if (typeof value === "number" || typeof value === "boolean") continue;
    if (typeof value !== "string") {
      throw outboxError(`Outbox payload field ${key} must be a scalar`);
    }
    if (value.length > PAYLOAD_VALUE_MAX_LENGTH) {
      throw outboxError(`Outbox payload field ${key} is too long`);
    }
  }
  // Belt and braces: the field allowlist already excludes payload contents, but
  // these rows are operator-visible and cheap to scan.
  if (
    containsPrivateKeyMaterial(payload) ||
    containsGenericSecretMaterial(payload)
  ) {
    throw outboxError(
      "Outbox payload must not contain secret material",
      "CERTOPS_OUTBOX_SECRET_MATERIAL",
    );
  }
}

/**
 * Record an intent. Idempotent on (workspace_id, event_type, dedupe_key): a
 * retried caller transaction enqueues the same side effect once.
 *
 * Returns { enqueued: boolean, id: string | null }. enqueued is false when the
 * row already existed, which is a success, not an error.
 */
async function enqueueOutboxEvent({
  client,
  workspaceId,
  eventType,
  dedupeKey,
  payload = {},
  maxAttempts = null,
} = {}) {
  if (!client) {
    throw outboxError(
      "enqueueOutboxEvent requires the caller's transaction client",
      "CERTOPS_OUTBOX_NO_CLIENT",
    );
  }
  if (!workspaceId) throw outboxError("workspaceId is required");
  if (!OUTBOX_EVENT_TYPE_VALUES.has(eventType)) {
    throw outboxError(
      `Unknown certops outbox event type: ${eventType}`,
      "CERTOPS_OUTBOX_UNKNOWN_EVENT_TYPE",
    );
  }
  const key = typeof dedupeKey === "string" ? dedupeKey.trim() : "";
  if (key.length === 0 || key.length > DEDUPE_KEY_MAX_LENGTH) {
    throw outboxError("dedupeKey is required and must be bounded");
  }
  assertValidPayload(eventType, payload);

  const inserted = await client.query(
    `INSERT INTO certops_outbox
       (workspace_id, event_type, dedupe_key, payload, max_attempts)
     VALUES ($1, $2, $3, $4::jsonb, COALESCE($5, 5))
     ON CONFLICT (workspace_id, event_type, dedupe_key) DO NOTHING
     RETURNING id`,
    [workspaceId, eventType, key, JSON.stringify(payload), maxAttempts],
  );

  const row = inserted.rows[0] || null;
  return { enqueued: Boolean(row), id: row ? String(row.id) : null };
}

// Statuses a row can still be acted on from. 'pending' is waiting for the
// drain; 'failed' is parked but revivable through resetOutboxEventForRetry, so
// an invalidation that ignored it would leave a row an operator could bring
// back to life after the decision it contradicts.
const REVIVABLE_OUTBOX_STATUSES = Object.freeze(["pending", "failed"]);

const OUTBOX_OUTCOME_DETACHED = "detached";

/**
 * Invalidate a certificate's outstanding derivation intents.
 *
 * Takes the caller's transaction client so the invalidation and whatever
 * decided it (nulling profile_id) commit together. The rows are locked FOR
 * UPDATE before being written: the drain's handler locks the same row at the
 * start of its own derivation transaction, so whichever transaction commits
 * second observes the other's decision instead of overwriting it.
 *
 * Returns { invalidated: number, ids: string[] }.
 */
async function invalidateProfileDerivationIntents({
  client,
  workspaceId,
  certificateId,
  reason = OUTBOX_OUTCOME_DETACHED,
} = {}) {
  if (!client) {
    throw outboxError(
      "invalidateProfileDerivationIntents requires the caller's transaction client",
      "CERTOPS_OUTBOX_NO_CLIENT",
    );
  }
  if (!workspaceId) throw outboxError("workspaceId is required");
  if (!certificateId) throw outboxError("certificateId is required");

  const locked = await client.query(
    `SELECT id
       FROM certops_outbox
      WHERE workspace_id = $1
        AND event_type = $2
        AND payload->>'certificateId' = $3
        AND status = ANY($4::text[])
      FOR UPDATE`,
    [
      workspaceId,
      OUTBOX_EVENT_TYPES.PROFILE_DERIVATION_REQUESTED,
      String(certificateId),
      REVIVABLE_OUTBOX_STATUSES,
    ],
  );
  if (locked.rows.length === 0) return { invalidated: 0, ids: [] };

  const ids = locked.rows.map((row) => String(row.id));
  await client.query(
    `UPDATE certops_outbox
        SET status = 'skipped',
            outcome_reason = $2,
            claim_id = NULL,
            claimed_until = NULL,
            updated_at = NOW()
      WHERE id = ANY($1::uuid[])`,
    [ids, String(reason).slice(0, 256)],
  );

  return { invalidated: ids.length, ids };
}

/**
 * Put a parked row back in the drain's queue.
 *
 * Only a 'failed' row qualifies. A 'skipped' row is a recorded decision, not a
 * failure: reviving one would undo the very thing it records, which is exactly
 * what a detached intent must never allow.
 */
async function resetOutboxEventForRetry({
  client = pool,
  workspaceId,
  outboxId,
} = {}) {
  if (!workspaceId) throw outboxError("workspaceId is required");
  if (!outboxId) throw outboxError("outboxId is required");

  const existing = await client.query(
    `SELECT id, status, event_type
       FROM certops_outbox
      WHERE workspace_id = $1 AND id = $2::uuid`,
    [workspaceId, outboxId],
  );
  const row = existing.rows[0];
  if (!row) {
    throw outboxError(
      "Outbox event not found",
      "CERTOPS_OUTBOX_EVENT_NOT_FOUND",
    );
  }
  if (row.status !== "failed") {
    throw outboxError(
      `Only a failed outbox event can be retried; this one is ${row.status}`,
      "CERTOPS_OUTBOX_EVENT_NOT_RETRYABLE",
    );
  }

  const updated = await client.query(
    `UPDATE certops_outbox
        SET status = 'pending',
            attempt_count = 0,
            next_retry_at = NOW(),
            last_error = NULL,
            outcome_reason = NULL,
            claim_id = NULL,
            claimed_until = NULL,
            updated_at = NOW()
      WHERE workspace_id = $1
        AND id = $2::uuid
        AND status = 'failed'
      RETURNING id, event_type, status, attempt_count`,
    [workspaceId, outboxId],
  );
  const resetRow = updated.rows[0];
  if (!resetRow) {
    // Lost a race with a concurrent write that moved the row out of 'failed'.
    throw outboxError(
      "Outbox event is no longer retryable",
      "CERTOPS_OUTBOX_EVENT_NOT_RETRYABLE",
    );
  }
  return {
    id: String(resetRow.id),
    eventType: resetRow.event_type,
    status: resetRow.status,
    attemptCount: Number(resetRow.attempt_count),
  };
}

module.exports = {
  OUTBOX_EVENT_TYPES,
  OUTBOX_EVENT_TYPE_VALUES,
  OUTBOX_OUTCOME_DETACHED,
  PAYLOAD_FIELDS_BY_EVENT_TYPE,
  DEDUPE_KEY_MAX_LENGTH,
  REVIVABLE_OUTBOX_STATUSES,
  enqueueOutboxEvent,
  invalidateProfileDerivationIntents,
  resetOutboxEventForRetry,
  pool,
};
