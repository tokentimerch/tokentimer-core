"use strict";

/**
 * CertOps renewal-profile administration.
 *
 * A renewal profile is not inert configuration. Every field on
 * public_metadata.renewalProfile is mapped onto agent job-payload execution
 * fields by renewalProfile.executionFieldsFromRenewalProfile, and the agent
 * acts on them with host privileges: certPath decides which file is
 * overwritten, owner/group/certMode decide who owns it, reloadService decides
 * which unit is restarted, and commandRef decides which ACME command runs.
 *
 * A profile edit is therefore a request to change what executes on a host, not
 * a settings change. That shapes this module:
 *
 *   1. Editing is allowlisted, not denylisted. EDITABLE_PROFILE_FIELDS is the
 *      complete set of things an operator may change through the API. Anything
 *      absent stays exactly as the issuance produced it. A denylist would fail
 *      open the next time the renewal-profile schema grows a field.
 *
 *   2. The host-affecting fields are deliberately NOT editable. They were
 *      derived from an issuance that provably worked (ADR-0010), so the stored
 *      values are known-good, and there is no operator workflow that needs to
 *      repoint a live certificate at a different path or unit badly enough to
 *      justify exposing that as an API primitive. Changing where a certificate
 *      deploys is a re-issuance, which already has its own audited route.
 *
 *   3. Every write goes through validateRenewalProfile, the same gate the
 *      scheduler admits on, so the API cannot persist a profile that would
 *      later be refused at renewal time.
 *
 * Zero-custody is unchanged: this module reads and writes public metadata only.
 */

const { pool } = require("../../db/database");
const { writeAudit } = require("../audit");
const {
  ACME_KINDS,
  CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
  CERTOPS_RENEWAL_PROFILE_INVALID,
  KEY_ALGORITHMS,
  SAN_POLICY_MODES,
  resolveRenewalProfileSnapshot,
  validateRenewalProfile,
} = require("./renewalProfile");
const {
  AUTO_RENEW_DISABLED_PROFILE_STATUSES,
  NON_RENEWABLE_CERTIFICATE_STATUSES,
} = require("./renewalScheduler");
const { isAgentDeployableKeyMode } = require("./jobs");

const CERTOPS_PROFILE_NOT_FOUND = "CERTOPS_PROFILE_NOT_FOUND";
const CERTOPS_PROFILE_INVALID = "CERTOPS_PROFILE_INVALID";
const CERTOPS_PROFILE_FIELD_IMMUTABLE = "CERTOPS_PROFILE_FIELD_IMMUTABLE";
const CERTOPS_PROFILE_NO_CHANGES = "CERTOPS_PROFILE_NO_CHANGES";

/**
 * Statuses an operator may set through the API.
 *
 * 'archived' is intentionally excluded even though the column and the scheduler
 * both accept it: it reads as a lifecycle end state, and offering two ways to
 * stop renewal would make the audit trail ambiguous about intent. Disabling is
 * the reversible operation this API exposes.
 */
const SETTABLE_PROFILE_STATUSES = Object.freeze(["active", "disabled"]);

/**
 * The complete set of renewalProfile paths an operator may change.
 *
 * Read this as the security boundary of the whole feature. Everything that
 * determines WHERE bytes land on a host or WHAT command produces them is
 * absent by design:
 *   - certPath, keyPath, chainPath and backupDir on target and every
 *     deploymentTargets entry
 *   - deploymentTargets owner, group, certMode, keyMode, chainMode
 *   - deploymentTargets reloadService
 *   - acme.commandRef, acme.kind
 *   - ca.endpoint, ca.accountRef, ca.eabRef
 *   - dns.provider, dns.zone
 *
 * KNOWN LIMITATION (2026-07-26, external review blocker 4). Edits made here are
 * not durable against re-derivation. ensureDerivedRenewalProfile upserts on
 * (workspace_id, LOWER(name)) where the name is `Derived: <commonName>`, and its
 * DO UPDATE replaces public_metadata wholesale. So issuing a second certificate
 * with the same common name overwrites every field below with freshly derived
 * values, and reports created:false, which reads as a benign idempotent replay.
 * The fix belongs to the derivation identity (it should key on something
 * certificate-scoped such as source_ref), not here: guarding the write on this
 * side would preserve an operator's edit on top of a profile whose deployment
 * details now describe a different host, which is worse. Until that lands, treat
 * a same-CN re-issuance as resetting these fields.
 */
const EDITABLE_PROFILE_FIELDS = Object.freeze([
  "sanPolicy",
  "keyAlgorithm",
  "keySize",
  "keyRotationPolicy",
  "verification",
  "preferredChain",
]);

/**
 * Immutable paths, listed only so a request that tries to set one gets a
 * specific 422 naming the field instead of a silent no-op. Silence would be
 * worse than refusal here: an operator who believes they moved certPath and
 * did not would discover it at renewal.
 */
const IMMUTABLE_PROFILE_FIELDS = Object.freeze([
  "acme",
  "ca",
  "dns",
  "deploymentTargets",
  "target",
  "schemaVersion",
  "profileId",
]);

function profileError(message, code = CERTOPS_PROFILE_INVALID, details = null) {
  const error = new Error(message);
  error.code = code;
  if (details) error.details = details;
  return error;
}

function normalizeLimit(value) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return 50;
  return Math.max(1, Math.min(100, parsed));
}

function normalizeOffset(value) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return 0;
  return Math.max(0, parsed);
}

function parseMetadata(value) {
  if (value == null) return {};
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return parsed && typeof parsed === "object" && !Array.isArray(parsed)
        ? parsed
        : {};
    } catch (_error) {
      return {};
    }
  }
  if (typeof value === "object" && !Array.isArray(value)) return value;
  return {};
}

/**
 * Public projection of a profile row.
 *
 * The renewalProfile is exposed in full because an operator needs to see where
 * a renewal will deploy in order to trust it, and every field is already
 * non-secret by the zero-custody rule (ADR-0001): paths, opaque account refs,
 * DNS provider and zone names. `editableFields` travels with the record so the
 * UI renders the same boundary the server enforces rather than duplicating it.
 */
function profileRecord(row) {
  const metadata = parseMetadata(row.public_metadata);
  const renewalProfile =
    metadata.renewalProfile && typeof metadata.renewalProfile === "object"
      ? metadata.renewalProfile
      : null;
  const derivedFrom =
    metadata.derivedFrom && typeof metadata.derivedFrom === "object"
      ? metadata.derivedFrom
      : null;

  return {
    id: String(row.id),
    name: row.name,
    description: row.description || null,
    status: row.status,
    source: row.source,
    autoRenewEnabled: !AUTO_RENEW_DISABLED_PROFILE_STATUSES.includes(
      String(row.status || "").toLowerCase(),
    ),
    renewBeforeDays:
      row.renew_before_days == null ? null : Number(row.renew_before_days),
    keyMode: row.key_mode || null,
    renewalProfile,
    // Machine-derived profiles are the norm now, so say so explicitly rather
    // than making an operator infer it from the name prefix.
    derived: Boolean(derivedFrom),
    derivedFrom,
    certificateCount: Number(row.certificate_count || 0),
    editableFields: [...EDITABLE_PROFILE_FIELDS],
    createdAt: row.created_at || null,
    updatedAt: row.updated_at || null,
  };
}

const PROFILE_SELECT = `
  SELECT cp.id,
         cp.name,
         cp.description,
         cp.status,
         cp.source,
         cp.renew_before_days,
         cp.key_mode,
         cp.public_metadata,
         cp.created_at,
         cp.updated_at,
         (
           SELECT COUNT(*)::int
             FROM managed_certificates mc
            WHERE mc.workspace_id = cp.workspace_id
              AND mc.profile_id = cp.id
         ) AS certificate_count
    FROM certificate_profiles cp
`;

async function listRenewalProfiles({
  db = pool,
  workspaceId,
  limit,
  offset,
} = {}) {
  const safeLimit = normalizeLimit(limit);
  const safeOffset = normalizeOffset(offset);

  const totalResult = await db.query(
    "SELECT COUNT(*)::int AS total FROM certificate_profiles WHERE workspace_id = $1",
    [workspaceId],
  );
  const result = await db.query(
    `${PROFILE_SELECT}
      WHERE cp.workspace_id = $1
      ORDER BY cp.name ASC
      LIMIT $2 OFFSET $3`,
    [workspaceId, safeLimit, safeOffset],
  );

  return {
    items: result.rows.map(profileRecord),
    total: Number(totalResult.rows[0]?.total || 0),
    limit: safeLimit,
    offset: safeOffset,
  };
}

async function getRenewalProfile({ db = pool, workspaceId, profileId } = {}) {
  const result = await db.query(
    `${PROFILE_SELECT} WHERE cp.workspace_id = $1 AND cp.id = $2::uuid`,
    [workspaceId, profileId],
  );
  if (result.rows.length === 0) {
    throw profileError("Renewal profile not found", CERTOPS_PROFILE_NOT_FOUND);
  }
  return profileRecord(result.rows[0]);
}

function requireBoolean(value, field) {
  if (typeof value !== "boolean") {
    throw profileError(`${field} must be a boolean`);
  }
  return value;
}

function normalizeRenewBeforeDays(value) {
  if (value === null) return null;
  // Number() rather than parseInt(): parseInt("30days") is 30 and
  // parseInt(1.5) is 1, so a malformed or fractional lead time would be
  // silently rounded into something the operator never asked for.
  const numeric = typeof value === "string" ? Number(value.trim()) : value;
  if (!Number.isSafeInteger(numeric) || numeric < 1 || numeric > 365) {
    throw profileError(
      "renewBeforeDays must be a whole number of days between 1 and 365, or null to use the deployment default",
    );
  }
  return numeric;
}

/**
 * Apply an operator patch to a stored renewalProfile.
 *
 * Immutable fields are refused loudly. Editable fields are merged onto the
 * stored profile and the RESULT is validated as a whole, so a patch cannot
 * produce a combination that individually-valid fields would allow but the
 * schema forbids (for example requireMatch true with no verification host).
 */
function applyRenewalProfilePatch(storedProfile, patch) {
  if (!storedProfile || typeof storedProfile !== "object") {
    throw profileError(
      "This profile has no renewal configuration to edit",
      CERTOPS_PROFILE_INVALID,
    );
  }
  if (!patch || typeof patch !== "object" || Array.isArray(patch)) {
    throw profileError("renewalProfile must be an object");
  }

  const rejected = Object.keys(patch).filter((key) =>
    IMMUTABLE_PROFILE_FIELDS.includes(key),
  );
  if (rejected.length > 0) {
    throw profileError(
      `These renewal-profile fields cannot be changed after issuance: ${rejected.join(", ")}. They determine where the certificate deploys and which command issues it, so changing them requires a new issuance.`,
      CERTOPS_PROFILE_FIELD_IMMUTABLE,
      { fields: rejected },
    );
  }

  const unknown = Object.keys(patch).filter(
    (key) => !EDITABLE_PROFILE_FIELDS.includes(key),
  );
  if (unknown.length > 0) {
    throw profileError(
      `Unknown renewal-profile fields: ${unknown.join(", ")}`,
      CERTOPS_PROFILE_INVALID,
      { fields: unknown },
    );
  }

  const merged = { ...storedProfile };
  for (const field of EDITABLE_PROFILE_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(patch, field)) {
      merged[field] = patch[field];
    }
  }

  // Whole-object validation through the scheduler's own gate.
  return validateRenewalProfile(merged);
}

/**
 * Update a profile's renewal configuration and its audit event atomically.
 *
 * The audit write shares the transaction with the update, matching
 * setWorkspaceCertOpsPauseState: a profile change that alters what runs on a
 * host must not be able to commit without its audit record.
 */
async function updateRenewalProfile({
  dbPool = pool,
  workspaceId,
  profileId,
  autoRenewEnabled,
  renewBeforeDays,
  renewalProfile,
  description,
  actorUserId = null,
  auditWriter = writeAudit,
} = {}) {
  const client = await dbPool.connect();
  let transactionStarted = false;
  try {
    await client.query("BEGIN");
    transactionStarted = true;

    const existing = await client.query(
      `SELECT id, name, status, renew_before_days, description, public_metadata
         FROM certificate_profiles
        WHERE workspace_id = $1 AND id = $2::uuid
        FOR UPDATE`,
      [workspaceId, profileId],
    );
    if (existing.rows.length === 0) {
      throw profileError("Renewal profile not found", CERTOPS_PROFILE_NOT_FOUND);
    }
    const row = existing.rows[0];
    const metadata = parseMetadata(row.public_metadata);

    const changes = {};
    let nextStatus = row.status;
    if (autoRenewEnabled !== undefined) {
      const enabled = requireBoolean(autoRenewEnabled, "autoRenewEnabled");
      // Only ever moves between the two statuses this API owns. A profile an
      // operator archived out of band is not silently resurrected into
      // 'active' by an unrelated toggle.
      const target = enabled ? "active" : "disabled";
      if (
        row.status !== target &&
        SETTABLE_PROFILE_STATUSES.includes(row.status)
      ) {
        nextStatus = target;
        changes.status = { from: row.status, to: target };
      } else if (!SETTABLE_PROFILE_STATUSES.includes(row.status)) {
        throw profileError(
          `This profile is ${row.status}, so automatic renewal cannot be toggled through this endpoint.`,
        );
      }
    }

    let nextRenewBeforeDays = row.renew_before_days;
    if (renewBeforeDays !== undefined) {
      nextRenewBeforeDays = normalizeRenewBeforeDays(renewBeforeDays);
      if (nextRenewBeforeDays !== row.renew_before_days) {
        changes.renewBeforeDays = {
          from: row.renew_before_days,
          to: nextRenewBeforeDays,
        };
      }
    }

    let nextMetadata = metadata;
    if (renewalProfile !== undefined) {
      const validated = applyRenewalProfilePatch(
        metadata.renewalProfile,
        renewalProfile,
      );
      nextMetadata = { ...metadata, renewalProfile: validated };
      changes.renewalProfileFields = Object.keys(renewalProfile);
    }

    let nextDescription = row.description;
    if (description !== undefined) {
      if (description !== null && typeof description !== "string") {
        throw profileError("description must be a string or null");
      }
      nextDescription =
        description === null ? null : description.trim().slice(0, 1024);
      if (nextDescription !== row.description) changes.description = true;
    }

    if (Object.keys(changes).length === 0) {
      throw profileError(
        "No supported changes were requested",
        CERTOPS_PROFILE_NO_CHANGES,
      );
    }

    const updated = await client.query(
      `UPDATE certificate_profiles
          SET status = $3,
              renew_before_days = $4,
              description = $5,
              public_metadata = $6::jsonb,
              updated_at = NOW()
        WHERE workspace_id = $1 AND id = $2::uuid
        RETURNING id`,
      [
        workspaceId,
        profileId,
        nextStatus,
        nextRenewBeforeDays,
        nextDescription,
        JSON.stringify(nextMetadata),
      ],
    );

    await auditWriter({
      client,
      actorUserId,
      subjectUserId: actorUserId,
      action: "CERTOPS_RENEWAL_PROFILE_UPDATED",
      targetType: "certificate_profile",
      targetId: String(updated.rows[0].id),
      workspaceId,
      metadata: {
        profileId: String(profileId),
        profileName: row.name,
        changes,
      },
    });

    await client.query("COMMIT");
    transactionStarted = false;

    return await getRenewalProfile({ db: dbPool, workspaceId, profileId });
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

/**
 * Why a certificate will not be renewed automatically, or null when it will.
 *
 * Resolved with resolveRenewalProfileSnapshot, the exact function the scheduler
 * admits on, so this view cannot claim a certificate is covered when the sweep
 * would refuse it. The two failure codes the resolver raises are collapsed into
 * operator-meaningful causes rather than surfaced raw.
 */
const RENEWAL_BLOCKED_NO_PROFILE = "no_profile";
const RENEWAL_BLOCKED_INCOMPLETE_PROFILE = "incomplete_profile";
const RENEWAL_BLOCKED_AUTO_RENEW_DISABLED = "auto_renew_disabled";
const RENEWAL_BLOCKED_UNKNOWN_EXPIRY = "unknown_expiry";
const RENEWAL_BLOCKED_NOT_AGENT_DEPLOYABLE = "not_agent_deployable";

/**
 * Classifies one row exactly as the sweep would.
 *
 * Order matters and encodes intent versus capability. A switched-off profile is
 * reported as switched off even if it is also incomplete, because that is the
 * state the operator chose and the one they can undo. Everything else is a
 * defect they need to fix.
 *
 * Key custody is checked through jobs.isAgentDeployableKeyMode rather than a
 * local key-mode list. The sweep does not filter on custody in SQL: it reaches
 * job creation, which throws CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE, and the
 * sweep counts that as skipped_not_agent_deployable. So a certificate with a
 * perfectly valid profile but no agent-manageable key never renews, and without
 * this check the schedule reported it as covered. That is the same class of
 * false all-clear this view exists to prevent, one layer further in.
 */
function classifyRenewalBlock(row) {
  if (
    AUTO_RENEW_DISABLED_PROFILE_STATUSES.includes(
      String(row.profile_status || "").toLowerCase(),
    )
  ) {
    return RENEWAL_BLOCKED_AUTO_RENEW_DISABLED;
  }
  if (row.not_after == null) return RENEWAL_BLOCKED_UNKNOWN_EXPIRY;
  if (!isAgentDeployableKeyMode(row)) {
    return RENEWAL_BLOCKED_NOT_AGENT_DEPLOYABLE;
  }
  if (!row.profile_id) return RENEWAL_BLOCKED_NO_PROFILE;
  try {
    resolveRenewalProfileSnapshot(row);
    return null;
  } catch (error) {
    if (
      error?.code === CERTOPS_RENEWAL_PROFILE_INCOMPLETE ||
      error?.code === CERTOPS_RENEWAL_PROFILE_INVALID
    ) {
      return RENEWAL_BLOCKED_INCOMPLETE_PROFILE;
    }
    throw error;
  }
}

/**
 * Certificates the renewal scheduler is expected to act on next.
 *
 * Reports every renewable certificate regardless of whether it is inside the
 * renewal window yet, so an operator can answer "what renews next, and is
 * anything not covered" from one place. The window start is computed exactly as
 * the scheduler scans (not_after minus the effective lead time).
 *
 * Deliberately a LEFT JOIN over the same status filter the sweep uses, and
 * deliberately not filtered on a resolvable profile. An inner join here was a
 * real defect: a certificate with no profile, or with a profile the scheduler
 * would refuse, is precisely the certificate that will silently expire, and
 * hiding it made this page answer "nothing scheduled to renew" for a workspace
 * where nothing renews at all. On a page whose only job is to expose
 * unattended-renewal risk, the reassuring answer has to be the one that is
 * hardest to produce by accident.
 *
 * The profile body is read to classify readiness but never returned: it carries
 * deployment topology, which is why these routes are manager-gated.
 */
async function listUpcomingRenewals({
  db = pool,
  workspaceId,
  limit,
  offset,
  thresholdDays,
} = {}) {
  const safeLimit = normalizeLimit(limit);
  const safeOffset = normalizeOffset(offset);
  const renewableStatusFilter = NON_RENEWABLE_CERTIFICATE_STATUSES.map(
    (status) => `'${status}'`,
  ).join(", ");

  const result = await db.query(
    `SELECT mc.id,
            mc.common_name,
            mc.subject_alt_names,
            mc.not_after,
            mc.status,
            mc.key_mode,
            mc.profile_id,
            cp.name AS profile_name,
            cp.status AS profile_status,
            cp.key_mode AS profile_key_mode,
            cp.public_metadata AS profile_public_metadata,
            cp.renew_before_days AS profile_renew_before_days,
            mc.not_after
              - (COALESCE(cp.renew_before_days, $2) || ' days')::interval
              AS renews_from,
            (
              SELECT cj.status
                FROM certificate_jobs cj
               WHERE cj.workspace_id = mc.workspace_id
                 AND cj.operation = 'renew'
                 AND cj.subject_type = 'managed_certificate'
                 AND cj.subject_id = mc.id::text
               ORDER BY cj.created_at DESC
               LIMIT 1
            ) AS last_renew_job_status
       FROM managed_certificates mc
       LEFT JOIN certificate_profiles cp
         ON cp.workspace_id = mc.workspace_id AND cp.id = mc.profile_id
      WHERE mc.workspace_id = $1
        AND mc.status NOT IN (${renewableStatusFilter})
      ORDER BY mc.not_after ASC NULLS LAST, mc.common_name ASC
      LIMIT $3 OFFSET $4`,
    [workspaceId, String(thresholdDays), safeLimit, safeOffset],
  );

  const totalResult = await db.query(
    `SELECT COUNT(*)::int AS total
       FROM managed_certificates mc
      WHERE mc.workspace_id = $1
        AND mc.status NOT IN (${renewableStatusFilter})`,
    [workspaceId],
  );

  return {
    items: result.rows.map((row) => {
      const blockedReason = classifyRenewalBlock(row);
      return {
        certificateId: String(row.id),
        commonName: row.common_name,
        certificateStatus: row.status,
        notAfter: row.not_after,
        renewsFrom: row.renews_from,
        profileId: row.profile_id ? String(row.profile_id) : null,
        profileName: row.profile_name || null,
        autoRenewEnabled: blockedReason == null,
        blockedReason,
        renewBeforeDays:
          row.profile_renew_before_days == null
            ? Number(thresholdDays)
            : Number(row.profile_renew_before_days),
        lastRenewJobStatus: row.last_renew_job_status || null,
      };
    }),
    total: Number(totalResult.rows[0]?.total || 0),
    limit: safeLimit,
    offset: safeOffset,
  };
}

module.exports = {
  ACME_KINDS,
  CERTOPS_PROFILE_FIELD_IMMUTABLE,
  CERTOPS_PROFILE_INVALID,
  CERTOPS_PROFILE_NOT_FOUND,
  CERTOPS_PROFILE_NO_CHANGES,
  EDITABLE_PROFILE_FIELDS,
  IMMUTABLE_PROFILE_FIELDS,
  KEY_ALGORITHMS,
  RENEWAL_BLOCKED_AUTO_RENEW_DISABLED,
  RENEWAL_BLOCKED_INCOMPLETE_PROFILE,
  RENEWAL_BLOCKED_NO_PROFILE,
  RENEWAL_BLOCKED_NOT_AGENT_DEPLOYABLE,
  RENEWAL_BLOCKED_UNKNOWN_EXPIRY,
  SAN_POLICY_MODES,
  SETTABLE_PROFILE_STATUSES,
  applyRenewalProfilePatch,
  classifyRenewalBlock,
  getRenewalProfile,
  listRenewalProfiles,
  listUpcomingRenewals,
  normalizeRenewBeforeDays,
  updateRenewalProfile,
};
