"use strict";

/**
 * Adopting an existing certificate into automatic renewal.
 *
 * Automation is never armed as a side effect of a job succeeding. A renewal
 * profile is only ever derived for an already-active certificate when an
 * operator asked for it, and that request is recorded as a durable outbox
 * intent in the same transaction that creates the renew job. Without the intent
 * row, "active with profile_id IS NULL" is the state a detached certificate
 * sits in, so any rule that derived from that state alone would silently turn a
 * deliberate off switch back on at the operator's next manual renew.
 *
 * Zero-custody is unchanged: nothing here reads or writes key material.
 */

const { pool } = require("../../db/database");
const { writeAudit } = require("../audit");
const {
  OUTBOX_EVENT_TYPES,
  OUTBOX_OUTCOME_DETACHED,
  enqueueOutboxEvent,
  invalidateProfileDerivationIntents,
} = require("./outbox");

const CERTOPS_CERTIFICATE_NOT_FOUND = "CERTOPS_CERTIFICATE_NOT_FOUND";
const CERTOPS_CERTIFICATE_NOT_PROFILED = "CERTOPS_CERTIFICATE_NOT_PROFILED";

/**
 * Dedupe key for an adoption intent.
 *
 * Keyed on the job, not the certificate: the unique index is
 * (workspace_id, event_type, dedupe_key) and the enqueue is
 * ON CONFLICT DO NOTHING, so a replayed job creation (the manual-creation path
 * returns the existing job on an idempotency hit, producing the same job id)
 * enqueues nothing the second time instead of arming a second derivation.
 */
const ADOPTION_DEDUPE_KEY_PREFIX = "derive-profile:";

function adoptionIntentDedupeKey(jobId) {
  return `${ADOPTION_DEDUPE_KEY_PREFIX}${String(jobId)}`;
}

/**
 * Sources that describe a place the certificate is actually installed, as
 * opposed to a vantage point it was merely observed from. Only a deployment
 * location can be renewed into, so only these count towards the adoption block.
 */
const DEPLOYMENT_INSTANCE_SOURCES = Object.freeze([
  "agent_filesystem",
  "cert_manager",
]);

/**
 * Instance statuses that no longer describe a live location.
 */
const RETIRED_INSTANCE_STATUSES = Object.freeze(["decommissioned", "missing"]);

function adoptionError(message, code) {
  const error = new Error(message);
  error.code = code || CERTOPS_CERTIFICATE_NOT_FOUND;
  error.statusCode = code === CERTOPS_CERTIFICATE_NOT_FOUND ? 404 : 422;
  return error;
}

/**
 * Record the operator's intent to derive a renewal profile from a job.
 *
 * Takes the caller's transaction client so the intent and the job it depends on
 * commit together: an intent without its job would never terminate, and a job
 * without its intent would leave the operator watching a form that armed
 * nothing.
 */
async function enqueueRenewalAdoptionIntent({
  client,
  workspaceId,
  jobId,
  certificateId,
  operation = null,
} = {}) {
  return await enqueueOutboxEvent({
    client,
    workspaceId,
    eventType: OUTBOX_EVENT_TYPES.PROFILE_DERIVATION_REQUESTED,
    dedupeKey: adoptionIntentDedupeKey(jobId),
    payload: {
      jobId: String(jobId),
      certificateId: String(certificateId),
      operation: operation || null,
    },
  });
}

/**
 * How many live deployment locations a certificate has.
 *
 * COUNT(DISTINCT target_id), never COUNT(*). certificate_instances is unique on
 * (workspace_id, target_id, managed_certificate_id, observed_fingerprint_sha256)
 * and a new fingerprint at the same target appends a row as rotation history,
 * so COUNT(*) counts rotations: an ordinary single-location certificate that has
 * rotated three times would look like a three-location one. Superseded rotation
 * rows are never restatused either, so filtering on the live statuses does not
 * deduplicate them.
 */
async function countCertificateDeploymentLocations({
  db = pool,
  workspaceId,
  certificateId,
} = {}) {
  const result = await db.query(
    `SELECT COUNT(DISTINCT ci.target_id)::int AS locations
       FROM certificate_instances ci
      WHERE ci.workspace_id = $1
        AND ci.managed_certificate_id = $2::uuid
        AND ci.source = ANY($3::text[])
        AND NOT (ci.status = ANY($4::text[]))`,
    [
      workspaceId,
      certificateId,
      DEPLOYMENT_INSTANCE_SOURCES,
      RETIRED_INSTANCE_STATUSES,
    ],
  );
  return Number(result.rows[0]?.locations || 0);
}

/**
 * Detach a certificate from its renewal profile.
 *
 * One transaction does three things that must not be separable: nulling
 * profile_id, recording the audit event, and invalidating any outstanding
 * adoption intent. Skipping the third would let the drain re-attach a profile
 * minutes after the operator removed it, and the profile_id IS NULL guard in
 * derivation cannot catch that, because after a detach that is exactly the
 * state.
 *
 * The profile row itself is left alone. Profiles can cover several
 * certificates, so deleting one would silently change what runs for a sibling.
 */
async function detachRenewalProfile({
  dbPool = pool,
  workspaceId,
  certificateId,
  actorUserId = null,
  auditWriter = writeAudit,
} = {}) {
  const client = await dbPool.connect();
  let transactionStarted = false;
  try {
    await client.query("BEGIN");
    transactionStarted = true;

    const locked = await client.query(
      `SELECT mc.id, mc.common_name, mc.profile_id, cp.name AS profile_name
         FROM managed_certificates mc
         LEFT JOIN certificate_profiles cp
           ON cp.workspace_id = mc.workspace_id AND cp.id = mc.profile_id
        WHERE mc.workspace_id = $1 AND mc.id = $2::uuid
        FOR UPDATE OF mc`,
      [workspaceId, certificateId],
    );
    const row = locked.rows[0];
    if (!row) {
      throw adoptionError("Certificate not found", CERTOPS_CERTIFICATE_NOT_FOUND);
    }
    if (!row.profile_id) {
      throw adoptionError(
        "This certificate is not linked to a renewal profile",
        CERTOPS_CERTIFICATE_NOT_PROFILED,
      );
    }

    const detachedProfileId = String(row.profile_id);

    await client.query(
      `UPDATE managed_certificates
          SET profile_id = NULL,
              updated_at = NOW()
        WHERE workspace_id = $1 AND id = $2::uuid`,
      [workspaceId, certificateId],
    );

    const invalidated = await invalidateProfileDerivationIntents({
      client,
      workspaceId,
      certificateId,
      reason: OUTBOX_OUTCOME_DETACHED,
    });

    // Withdrawing standing authority to re-run a command on a host is as much
    // an authority change as granting it, so it gets the same durable record
    // the derivation grant does.
    await auditWriter({
      client,
      actorUserId,
      subjectUserId: actorUserId,
      action: "CERTOPS_RENEWAL_PROFILE_DETACHED",
      targetType: "managed_certificate",
      targetId: null,
      workspaceId,
      metadata: {
        managedCertificateId: String(certificateId),
        commonName: row.common_name || null,
        profileId: detachedProfileId,
        profileName: row.profile_name || null,
        invalidatedIntents: invalidated.invalidated,
      },
    });

    await client.query("COMMIT");
    transactionStarted = false;

    return {
      certificateId: String(certificateId),
      detachedProfileId,
      invalidatedIntents: invalidated.invalidated,
    };
  } catch (error) {
    if (transactionStarted) {
      try {
        await client.query("ROLLBACK");
      } catch (_) {
        // Preserve the primary failure for the caller.
      }
    }
    throw error;
  } finally {
    client.release();
  }
}

module.exports = {
  ADOPTION_DEDUPE_KEY_PREFIX,
  CERTOPS_CERTIFICATE_NOT_FOUND,
  CERTOPS_CERTIFICATE_NOT_PROFILED,
  DEPLOYMENT_INSTANCE_SOURCES,
  RETIRED_INSTANCE_STATUSES,
  adoptionIntentDedupeKey,
  countCertificateDeploymentLocations,
  detachRenewalProfile,
  enqueueRenewalAdoptionIntent,
};
