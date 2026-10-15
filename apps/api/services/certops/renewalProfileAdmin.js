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
  RENEWAL_JOB_TERMINAL_STATUSES,
  certificateCaBucket,
  countInFlightRenewalJobsByCaEndpoint,
} = require("./renewalScheduler");
const { resolveRenewalPerCaCap, caCapKey } = require("./renewalCapacity");
const { isAgentRenewableKeyMode } = require("./jobs");
const { OPERATOR_OWNED_METADATA_KEY } = require("./renewalProfileDerivation");
const { resolveListSort } = require("./listSorting");
const {
  ADCS_ECDSA_SIZES,
  ADCS_RSA_SIZES,
  ADCS_SITE_PATTERN,
  ADCS_STORE_PATTERN,
  CERTOPS_PROFILE_INVALID,
  CERTOPS_PROFILE_ISSUER_INCOMPATIBLE,
  adcsHost,
  adcsTargetComplete,
  profileError,
  validateAdcsRenewalPolicy,
  validateAdcsRenewalProfile,
} = require("./adcsRenewalRules");

const CERTOPS_PROFILE_NOT_FOUND = "CERTOPS_PROFILE_NOT_FOUND";
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
 * Edits made here are durable against re-derivation. The first successful edit
 * marks the profile operator-owned in public_metadata, and
 * ensureDerivedRenewalProfile refuses to overwrite a profile carrying that
 * marker. So a second issuance for the same common name no longer silently
 * reverts the fields below; the derivation reports its refusal instead.
 */
const EDITABLE_PROFILE_FIELDS = Object.freeze([
  "sanPolicy",
  "keyAlgorithm",
  "keySize",
  "keyRotationPolicy",
  "verification",
  "preferredChain",
]);

// The AD CS scheduler reads only these from a profile; the ACME-only fields
// would be saved and then ignored.
const ADCS_EDITABLE_PROFILE_FIELDS = Object.freeze([
  "sanPolicy",
  "keyAlgorithm",
  "keySize",
]);

// AD CS profiles have no schemaVersion, so the ACME validator would refuse them.
function isAdcsRenewalProfile(renewalProfile) {
  return (
    !!renewalProfile &&
    typeof renewalProfile === "object" &&
    renewalProfile.schemaVersion === undefined &&
    renewalProfile.target?.type === "windows-iis"
  );
}

// The issuer decides which rules apply: the scheduler renews through the
// issuer's path and ignores fields that path does not read. A profile that was
// ACME-shaped and then moved to an AD CS issuer keeps schemaVersion, so shape
// alone would apply the wrong rules. Shape is only the fallback when the issuer
// is not known.
function usesAdcsRules(renewalProfile, issuerKind) {
  if (issuerKind !== undefined) return issuerKind === "adcs";
  return isAdcsRenewalProfile(renewalProfile);
}

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

function certificateSummaries(value) {
  let rows = value;
  if (typeof value === "string") {
    try {
      rows = JSON.parse(value);
    } catch {
      rows = [];
    }
  }
  if (!Array.isArray(rows)) return [];
  return rows.flatMap((row) => {
    if (!row || typeof row.id !== "string" || row.id.length === 0) return [];
    const commonName =
      typeof row.commonName === "string" && row.commonName.trim()
        ? row.commonName.trim()
        : row.id;
    return [{ id: row.id, commonName }];
  });
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
    issuerId: row.issuer_id || null,
    renewalProfile,
    // Machine-derived profiles are the norm now, so say so explicitly rather
    // than making an operator infer it from the name prefix.
    derived: Boolean(derivedFrom),
    derivedFrom,
    certificateCount: Number(row.certificate_count || 0),
    certificates: certificateSummaries(row.certificate_names),
    editableFields: [
      ...(usesAdcsRules(renewalProfile, row.issuer_kind)
        ? ADCS_EDITABLE_PROFILE_FIELDS
        : EDITABLE_PROFILE_FIELDS),
    ],
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
         cp.issuer_id,
         (
           SELECT ci.kind
             FROM certificate_issuers ci
            WHERE ci.workspace_id = cp.workspace_id
              AND ci.id = cp.issuer_id
         ) AS issuer_kind,
         cp.public_metadata,
         cp.created_at,
         cp.updated_at,
         (
           SELECT COUNT(*)::int
             FROM managed_certificates mc
            WHERE mc.workspace_id = cp.workspace_id
              AND mc.profile_id = cp.id
         ) AS certificate_count,
         (
           SELECT COALESCE(jsonb_agg(jsonb_build_object(
                    'id', named.id,
                    'commonName', named.common_name
                  ) ORDER BY named.common_name), '[]'::jsonb)
             FROM (
               SELECT mc.id::text AS id,
                      COALESCE(NULLIF(TRIM(mc.common_name), ''), mc.id::text) AS common_name
                 FROM managed_certificates mc
                WHERE mc.workspace_id = cp.workspace_id
                  AND mc.profile_id = cp.id
                ORDER BY 2
                LIMIT 8
             ) named
         ) AS certificate_names
    FROM certificate_profiles cp
`;

const RENEWAL_PROFILE_SORTS = Object.freeze({
  profile: "cp.name",
  certificates: "certificate_count",
  autoRenew: `CASE
    WHEN LOWER(COALESCE(cp.status, '')) IN ('disabled', 'archived') THEN 0
    ELSE 1
  END`,
  leadTime: "cp.renew_before_days",
  key: `CASE
    WHEN NULLIF(cp.public_metadata->'renewalProfile'->>'keyAlgorithm', '') IS NULL
      THEN '--'
    ELSE CONCAT_WS(
      ' ',
      UPPER(cp.public_metadata->'renewalProfile'->>'keyAlgorithm'),
      NULLIF(cp.public_metadata->'renewalProfile'->>'keySize', '')
    )
  END`,
});

async function listRenewalProfiles({
  db = pool,
  workspaceId,
  limit,
  offset,
  sort,
  direction,
} = {}) {
  const safeLimit = normalizeLimit(limit);
  const safeOffset = normalizeOffset(offset);
  const orderBy = resolveListSort({
    sort,
    direction,
    allowlist: RENEWAL_PROFILE_SORTS,
    defaultOrderBy: "cp.name ASC, cp.id ASC",
    tieBreaker: "cp.id ASC",
  });

  const totalResult = await db.query(
    "SELECT COUNT(*)::int AS total FROM certificate_profiles WHERE workspace_id = $1",
    [workspaceId],
  );
  const result = await db.query(
    `${PROFILE_SELECT}
      WHERE cp.workspace_id = $1
      ORDER BY ${orderBy}
      LIMIT $2 OFFSET $3`,
    [workspaceId, safeLimit, safeOffset],
  );

  return {
    items: result.rows.map(profileRecord),
    total: Number(totalResult.rows[0]?.total || 0),
    limit: safeLimit,
    offset: safeOffset,
    // The flat fields above are read by shipped clients and stay until they
    // migrate; the nested object is the envelope every other CertOps list
    // returns, and new readers should take it from here.
    pagination: {
      limit: safeLimit,
      offset: safeOffset,
      total: Number(totalResult.rows[0]?.total || 0),
    },
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
function applyRenewalProfilePatch(storedProfile, patch, { issuerKind } = {}) {
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

  const adcs = usesAdcsRules(storedProfile, issuerKind);
  const editable = adcs ? ADCS_EDITABLE_PROFILE_FIELDS : EDITABLE_PROFILE_FIELDS;
  const unknown = Object.keys(patch).filter((key) => !editable.includes(key));
  if (unknown.length > 0) {
    throw profileError(
      `Unknown renewal-profile fields: ${unknown.join(", ")}`,
      CERTOPS_PROFILE_INVALID,
      { fields: unknown },
    );
  }

  const merged = { ...storedProfile };
  for (const field of editable) {
    if (Object.prototype.hasOwnProperty.call(patch, field)) {
      merged[field] = patch[field];
    }
  }

  // Whole-object validation through the scheduler's own gate.
  return adcs ? validateAdcsRenewalPolicy(merged) : validateRenewalProfile(merged);
}

/**
 * Update a profile's renewal configuration and its audit event atomically.
 *
 * The audit write shares the transaction with the update, matching
 * setWorkspaceCertOpsPauseState: a profile change that alters what runs on a
 * host must not be able to commit without its audit record.
 */
async function assertIssuerCompatibleWithProfile(client, { workspaceId, issuerId, renewalProfile }) {
  const result = await client.query(
    `SELECT i.kind, i.revalidation_required, v.ca_key_sha256
       FROM certificate_issuers i
       LEFT JOIN certificate_issuer_versions v
         ON v.workspace_id = i.workspace_id
        AND v.issuer_id = i.id
        AND v.version = i.current_version
      WHERE i.workspace_id = $1 AND i.id = $2::uuid
      FOR SHARE OF i`,
    [workspaceId, issuerId],
  );
  const issuer = result.rows[0];
  if (!issuer || issuer.kind !== "adcs") return;
  if (!adcsTargetComplete(renewalProfile?.target)) {
    throw profileError(
      "This profile has no complete Windows/IIS deployment target, so AD CS cannot renew it. Create an AD CS renewal profile instead.",
      CERTOPS_PROFILE_ISSUER_INCOMPATIBLE,
    );
  }
  // Switching an ACME-shaped profile onto AD CS must meet AD CS policy too,
  // not only the target shape above.
  try {
    validateAdcsRenewalPolicy(renewalProfile);
  } catch (error) {
    throw profileError(
      `This profile cannot be renewed through AD CS: ${error.message}`,
      CERTOPS_PROFILE_ISSUER_INCOMPATIBLE,
    );
  }
  if (issuer.revalidation_required === true || !issuer.ca_key_sha256) {
    throw profileError(
      "Confirm a CA certificate on this AD CS issuer before automatic renewal can use it.",
      CERTOPS_PROFILE_ISSUER_INCOMPATIBLE,
    );
  }
}

// Reverse of the check above. AD CS profiles never carry ca, acme, dns, or
// deploymentTargets, and this API cannot add them (they are immutable here),
// so clearing the issuer would leave a profile the scheduler refuses on its
// next due renewal.
function assertProfileRunsAcme(renewalProfile) {
  const runnable =
    typeof renewalProfile?.ca?.endpoint === "string" &&
    typeof renewalProfile?.acme?.commandRef === "string" &&
    typeof renewalProfile?.acme?.kind === "string" &&
    typeof renewalProfile?.dns?.provider === "string" &&
    typeof renewalProfile?.dns?.zone === "string" &&
    Array.isArray(renewalProfile?.deploymentTargets) &&
    renewalProfile.deploymentTargets.length > 0;
  if (!runnable) {
    throw profileError(
      "This profile has no ACME CA, command, or DNS settings, so it cannot switch to ACME. Create an ACME renewal profile instead.",
      CERTOPS_PROFILE_ISSUER_INCOMPATIBLE,
    );
  }
}

async function updateRenewalProfile({
  dbPool = pool,
  workspaceId,
  profileId,
  autoRenewEnabled,
  renewBeforeDays,
  renewalProfile,
  description,
  issuerId,
  actorUserId = null,
  auditWriter = writeAudit,
} = {}) {
  const client = await dbPool.connect();
  let transactionStarted = false;
  try {
    await client.query("BEGIN");
    transactionStarted = true;

    const existing = await client.query(
      `SELECT id, name, status, renew_before_days, description, public_metadata, issuer_id
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

    let nextDescription = row.description;
    if (description !== undefined) {
      if (description !== null && typeof description !== "string") {
        throw profileError("description must be a string or null");
      }
      nextDescription =
        description === null ? null : description.trim().slice(0, 1024);
      if (nextDescription !== row.description) changes.description = true;
    }

    let nextIssuerId = row.issuer_id || null;
    if (issuerId !== undefined) {
      if (issuerId === null) {
        nextIssuerId = null;
      } else if (
        typeof issuerId !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(issuerId)
      ) {
        throw profileError("issuerId must be a uuid or null");
      } else {
        const found = await client.query(
          `SELECT id FROM certificate_issuers WHERE workspace_id = $1 AND id = $2::uuid`,
          [workspaceId, issuerId],
        );
        if (found.rows.length === 0) {
          throw profileError(
            "Issuer was not found in this workspace",
            "CERTOPS_PROFILE_ISSUER_NOT_FOUND",
          );
        }
        nextIssuerId = issuerId;
      }
      if (nextIssuerId !== (row.issuer_id || null)) {
        changes.issuerId = { from: row.issuer_id || null, to: nextIssuerId };
      }
    }

    // The patch rules follow the issuer this profile will use, so it runs
    // after the issuer is resolved.
    let nextMetadata = metadata;
    if (renewalProfile !== undefined) {
      let issuerKind = null;
      if (nextIssuerId) {
        const kindResult = await client.query(
          `SELECT i.kind FROM certificate_issuers i
            WHERE i.workspace_id = $1 AND i.id = $2::uuid`,
          [workspaceId, nextIssuerId],
        );
        issuerKind = kindResult.rows[0]?.kind ?? null;
      }
      const validated = applyRenewalProfilePatch(
        metadata.renewalProfile,
        renewalProfile,
        { issuerKind },
      );
      nextMetadata = { ...metadata, renewalProfile: validated };
      changes.renewalProfileFields = Object.keys(renewalProfile);
    }

    if (Object.keys(changes).length === 0) {
      throw profileError(
        "No supported changes were requested",
        CERTOPS_PROFILE_NO_CHANGES,
      );
    }

    if (nextIssuerId && (changes.issuerId || changes.renewalProfileFields)) {
      await assertIssuerCompatibleWithProfile(client, {
        workspaceId,
        issuerId: nextIssuerId,
        renewalProfile: nextMetadata.renewalProfile,
      });
    }
    if (nextIssuerId === null && changes.issuerId) {
      assertProfileRunsAcme(nextMetadata.renewalProfile);
    }

    // The first successful edit takes ownership, which is what makes the edit
    // durable: derivation refuses to overwrite an owned profile, so a later
    // issuance for the same common name can no longer revert these fields.
    // Claimed only after the patch is known to be a real change, so a no-op
    // request cannot quietly take ownership, and written into the same metadata
    // the edit itself lands in, so the two commit together.
    if (nextMetadata[OPERATOR_OWNED_METADATA_KEY] !== true) {
      nextMetadata = { ...nextMetadata, [OPERATOR_OWNED_METADATA_KEY]: true };
      changes.operatorOwned = true;
    }

    const updated = await client.query(
      `UPDATE certificate_profiles
          SET status = $3,
              renew_before_days = $4,
              description = $5,
              public_metadata = $6::jsonb,
              issuer_id = $7,
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
        nextIssuerId,
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

function normalizeAdcsProfileInput(body) {
  const name = typeof body?.name === "string" ? body.name.trim() : "";
  if (!name || name.length > 128) {
    throw profileError("name must be 1 to 128 characters");
  }
  const description =
    body?.description == null || body.description === ""
      ? null
      : String(body.description).trim();
  if (description && description.length > 500) {
    throw profileError("description must be 500 characters or fewer");
  }
  const issuerId = String(body?.issuerId || "");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(issuerId)) {
    throw profileError("issuerId must be a confirmed AD CS issuer");
  }
  const target = body?.target;
  const binding = target?.binding;
  const reference = adcsHost(target?.reference, "certificate name");
  if (!target || target.type !== "windows-iis") {
    throw profileError("target must be a windows-iis binding");
  }
  if (typeof target.store !== "string" || !ADCS_STORE_PATTERN.test(target.store.trim())) {
    throw profileError("store must name a Windows certificate store, usually My");
  }
  if (
    !binding ||
    typeof binding.site !== "string" ||
    !ADCS_SITE_PATTERN.test(binding.site.trim())
  ) {
    throw profileError("IIS site name is invalid");
  }
  const port = Number(binding.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw profileError("IIS port must be an integer from 1 to 65535");
  }
  const sniHost =
    binding.sniHost == null || binding.sniHost === ""
      ? null
      : adcsHost(binding.sniHost, "SNI hostname");
  const extraNames = Array.isArray(body?.dnsNames) ? body.dnsNames : [];
  const dnsNames = [];
  for (const entry of [reference, ...extraNames]) {
    const host = adcsHost(entry, "DNS name");
    if (!dnsNames.includes(host)) dnsNames.push(host);
  }
  if (dnsNames.length > 16) {
    throw profileError("a renewal profile accepts at most 16 DNS names");
  }
  const keyAlgorithm = body?.keyAlgorithm;
  if (keyAlgorithm !== "rsa" && keyAlgorithm !== "ecdsa") {
    throw profileError("keyAlgorithm must be rsa or ecdsa");
  }
  const keySize = Number(body?.keySize);
  const allowed = keyAlgorithm === "rsa" ? ADCS_RSA_SIZES : ADCS_ECDSA_SIZES;
  if (!allowed.has(keySize)) {
    throw profileError(`keySize is invalid for ${keyAlgorithm}`);
  }
  return {
    name,
    description,
    issuerId,
    renewBeforeDays: normalizeRenewBeforeDays(body?.renewBeforeDays ?? 30),
    renewalProfile: {
      target: {
        type: "windows-iis",
        reference,
        store: target.store.trim(),
        binding: {
          site: binding.site.trim(),
          port,
          ...(sniHost ? { sniHost } : {}),
        },
      },
      sanPolicy: { sans: dnsNames },
      keyAlgorithm,
      keySize,
    },
  };
}

async function createAdcsRenewalProfile({
  dbPool = pool,
  workspaceId,
  body,
  actorUserId = null,
  auditWriter = writeAudit,
} = {}) {
  const input = normalizeAdcsProfileInput(body);
  const client = await dbPool.connect();
  let started = false;
  try {
    await client.query("BEGIN");
    started = true;
    const issuer = await client.query(
      `SELECT i.kind, i.revalidation_required, i.current_version, v.ca_key_sha256
         FROM certificate_issuers i
         LEFT JOIN certificate_issuer_versions v
           ON v.workspace_id = i.workspace_id
          AND v.issuer_id = i.id
          AND v.version = i.current_version
        WHERE i.workspace_id = $1 AND i.id = $2
        FOR UPDATE OF i`,
      [workspaceId, input.issuerId],
    );
    const row = issuer.rows[0];
    if (!row || row.kind !== "adcs") {
      throw profileError("issuerId must be a confirmed AD CS issuer", "CERTOPS_PROFILE_ISSUER_NOT_FOUND");
    }
    if (row.revalidation_required === true || !row.ca_key_sha256) {
      throw profileError(
        "Confirm a CA certificate on this issuer before creating a renewal profile",
      );
    }
    const inserted = await client.query(
      `INSERT INTO certificate_profiles (
         workspace_id, name, description, status, source, source_ref,
         issuer_id, renew_before_days, key_mode, public_metadata, created_by
       ) VALUES (
         $1, $2, $3, 'active', 'manual', $4, $5, $6, 'os-store-managed', $7::jsonb, $8
       )
       RETURNING id`,
      [
        workspaceId,
        input.name,
        input.description,
        `adcs-profile:${input.renewalProfile.target.reference}`,
        input.issuerId,
        input.renewBeforeDays,
        JSON.stringify({
          [OPERATOR_OWNED_METADATA_KEY]: true,
          renewalProfile: input.renewalProfile,
        }),
        Number.isInteger(actorUserId) ? actorUserId : null,
      ],
    );
    const profileId = inserted.rows[0].id;
    const agent = await client.query(
      `SELECT id
         FROM certops_agents
        WHERE workspace_id = $1
          AND status = 'active'
          AND declared_target_selectors @> jsonb_build_array($2::text)
        LIMIT 1`,
      [workspaceId, input.renewalProfile.target.reference],
    );
    await auditWriter({
      client,
      actorUserId,
      subjectUserId: actorUserId,
      action: "CERTOPS_RENEWAL_PROFILE_CREATED",
      targetType: "certificate_profile",
      targetId: String(profileId),
      workspaceId,
      metadata: {
        profileId: String(profileId),
        profileName: input.name,
        issuerId: input.issuerId,
        reference: input.renewalProfile.target.reference,
      },
    });
    await client.query("COMMIT");
    started = false;
    const profile = await getRenewalProfile({ db: dbPool, workspaceId, profileId });
    return {
      ...profile,
      agentDeclaresName: Boolean(agent.rows[0]),
    };
  } catch (error) {
    if (started) {
      try {
        await client.query("ROLLBACK");
      } catch (_rollbackError) {
        // Keep the original failure.
      }
    }
    if (error?.code === "23505") {
      throw profileError("A renewal profile with this name already exists");
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
 * Key custody is checked through jobs.isAgentRenewableKeyMode rather than a
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
  if (row.key_mode === "vault-managed" && !row.profile_id) return RENEWAL_BLOCKED_NO_PROFILE;
  if (!isAgentRenewableKeyMode(row)) {
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
 * Capacity deferral for one certificate, using the same guards as the sweep.
 *
 * Only a certificate the scheduler would otherwise act on this pass (no block,
 * due, and no active renew job) can be waiting on the per-CA in-flight cap.
 * A real block is never rewritten into a capacity wait.
 *
 * @returns {"ca_capacity"|null}
 */
function resolveDeferredRenewalReason(
  row,
  { workspaceId, inFlightByCa, perCaCap, now = Date.now() } = {},
) {
  if (classifyRenewalBlock(row) != null) return null;
  if (row?.renews_from == null) return null;
  const dueAt = new Date(row.renews_from).getTime();
  // NaN is not due. A future window is not due either.
  if (!(dueAt <= now) || row.has_active_renew_job) return null;
  const capKey = caCapKey(workspaceId, certificateCaBucket(row));
  const inFlight = inFlightByCa.get(capKey) || 0;
  return inFlight >= perCaCap ? "ca_capacity" : null;
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
 *
 * `deferredReason` is independent of `blockedReason`/`autoRenewEnabled`: a
 * covered certificate can still be `deferredReason: 'ca_capacity'` when the
 * scheduler would skip it this pass because its CA is already at the
 * per-CA in-flight cap. It clears itself once that CA has headroom again,
 * with no write path and no staleness to manage, because it is computed live
 * from the same in-flight count the sweep itself checks.
 */
async function listUpcomingRenewals({
  db = pool,
  workspaceId,
  limit,
  offset,
  thresholdDays,
  sort,
  direction,
} = {}) {
  const safeLimit = normalizeLimit(limit);
  const safeOffset = normalizeOffset(offset);
  const renewableStatusFilter = NON_RENEWABLE_CERTIFICATE_STATUSES.map(
    (status) => `'${status}'`,
  ).join(", ");
  const renewsFromExpression =
    "mc.not_after - (COALESCE(cp.renew_before_days, $2) || ' days')::interval";
  const orderBy = resolveListSort({
    sort,
    direction,
    allowlist: {
      certificate: "mc.common_name",
      expires: "mc.not_after",
      renewalWindow: renewsFromExpression,
      lastAttempt: "last_renew_job_status",
    },
    defaultOrderBy:
      "mc.not_after ASC NULLS LAST, mc.common_name ASC, mc.id ASC",
    tieBreaker: "mc.id ASC",
  });

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
            ) AS last_renew_job_status,
            -- Same "any non-terminal job exists" predicate
            -- findCertificatesDueForRenewal uses to skip a certificate: the
            -- latest job's status alone is not enough, because an older
            -- still-active job can coexist with a newer terminal one (e.g. a
            -- retried/superseded job).
            EXISTS (
              SELECT 1
                FROM certificate_jobs cj
               WHERE cj.workspace_id = mc.workspace_id
                 AND cj.operation = 'renew'
                 AND cj.subject_type = 'managed_certificate'
                 AND cj.subject_id = mc.id::text
                 AND NOT (cj.status = ANY($5::text[]))
            ) AS has_active_renew_job,
            NULLIF(BTRIM(mc.public_metadata->>'caEndpoint'), '')
              AS certificate_ca_endpoint,
            NULLIF(
              BTRIM(
                COALESCE(
                  cp.public_metadata->'renewalProfile'->'ca'->>'endpoint',
                  cp.public_metadata->>'caEndpoint'
                )
              ),
              ''
            ) AS profile_ca_endpoint,
            cp.issuer_id AS profile_issuer_id,
            ci.kind AS profile_issuer_kind
       FROM managed_certificates mc
       LEFT JOIN certificate_profiles cp
         ON cp.workspace_id = mc.workspace_id AND cp.id = mc.profile_id
       LEFT JOIN certificate_issuers ci
         ON ci.workspace_id = cp.workspace_id AND ci.id = cp.issuer_id
      WHERE mc.workspace_id = $1
        AND mc.status NOT IN (${renewableStatusFilter})
        AND NOT EXISTS (SELECT 1 FROM certops_certificate_identities identity
          WHERE identity.workspace_id = mc.workspace_id
            AND identity.fingerprint_sha256 = certops_normalize_fingerprint(mc.fingerprint_sha256)
            AND identity.lifecycle_status IN ('revoked', 'decommissioned'))
      ORDER BY ${orderBy}
      LIMIT $3 OFFSET $4`,
    [
      workspaceId,
      String(thresholdDays),
      safeLimit,
      safeOffset,
      RENEWAL_JOB_TERMINAL_STATUSES,
    ],
  );

  const totalResult = await db.query(
    `SELECT COUNT(*)::int AS total
       FROM managed_certificates mc
      WHERE mc.workspace_id = $1
        AND mc.status NOT IN (${renewableStatusFilter})
        AND NOT EXISTS (SELECT 1 FROM certops_certificate_identities identity
          WHERE identity.workspace_id = mc.workspace_id
            AND identity.fingerprint_sha256 = certops_normalize_fingerprint(mc.fingerprint_sha256)
            AND identity.lifecycle_status IN ('revoked', 'decommissioned'))`,
    [workspaceId],
  );

  // One page-wide in-flight lookup, not one query per row: the sweep's own
  // cap check reused verbatim, so this can never claim a certificate is
  // waiting on capacity the scheduler would not also see.
  const perCaCap = resolveRenewalPerCaCap();
  const inFlightByCa = await countInFlightRenewalJobsByCaEndpoint({
    db,
    terminalStatuses: RENEWAL_JOB_TERMINAL_STATUSES,
    workspaceId,
  });
  const now = Date.now();

  return {
    items: result.rows.map((row) => {
      const blockedReason = classifyRenewalBlock(row);
      const autoRenewEnabled = blockedReason == null;
      const deferredReason = resolveDeferredRenewalReason(row, {
        workspaceId,
        inFlightByCa,
        perCaCap,
        now,
      });

      return {
        certificateId: String(row.id),
        commonName: row.common_name,
        certificateStatus: row.status,
        notAfter: row.not_after,
        renewsFrom: row.renews_from,
        profileId: row.profile_id ? String(row.profile_id) : null,
        profileName: row.profile_name || null,
        autoRenewEnabled,
        blockedReason,
        deferredReason,
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
    // Flat fields retained for shipped clients; the nested object matches the
    // envelope the other CertOps lists return.
    pagination: {
      limit: safeLimit,
      offset: safeOffset,
      total: Number(totalResult.rows[0]?.total || 0),
    },
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
  OPERATOR_OWNED_METADATA_KEY,
  RENEWAL_BLOCKED_AUTO_RENEW_DISABLED,
  RENEWAL_BLOCKED_INCOMPLETE_PROFILE,
  RENEWAL_BLOCKED_NO_PROFILE,
  RENEWAL_BLOCKED_NOT_AGENT_DEPLOYABLE,
  RENEWAL_BLOCKED_UNKNOWN_EXPIRY,
  SAN_POLICY_MODES,
  SETTABLE_PROFILE_STATUSES,
  applyRenewalProfilePatch,
  classifyRenewalBlock,
  resolveDeferredRenewalReason,
  createAdcsRenewalProfile,
  getRenewalProfile,
  listRenewalProfiles,
  listUpcomingRenewals,
  normalizeRenewBeforeDays,
  updateRenewalProfile,
  validateAdcsRenewalProfile,
};
