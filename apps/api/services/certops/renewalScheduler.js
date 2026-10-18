"use strict";

/**
 * CertOps renewal scheduler.
 *
 * Scans managed_certificates approaching expiry and creates automation-source
 * renew jobs. Every job creation runs inside a transaction gated by
 * lockWorkspaceForCertOpsSideEffect, so paused workspaces and the global
 * rollout flag are respected (skipped, never errored). Reruns are idempotent:
 * the idempotency key is derived from the certificate id and its not_after
 * timestamp, and certificates that already have a non-terminal renew job for
 * the same subject are skipped before any insert is attempted.
 *
 * Before creating a job the scheduler resolves a complete, validated
 * renewal-profile snapshot (target, cert path, SANs, ACME command/profile,
 * DNS provider+zone, key/CA/verification settings) from
 * certificate_profiles.public_metadata.renewalProfile. Certificates lacking
 * a complete profile are refused (logged/alerted) and never produce a job
 * an agent cannot execute. The snapshot is bound into the job payload so
 * approval and dispatch hash an immutable contract.
 *
 * Zero-custody: this module only reads public inventory metadata and writes
 * public job payload fields. It never touches private key material.
 */

const { pool } = require("../../db/database");
const { logger } = require("../../utils/logger");
const {
  CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE,
  createCertificateJob,
  isTerminalJobStatus,
  isTrustAnchorOperation,
  JOB_STATUSES,
} = require("./jobs");
const {
  CERTOPS_WORKSPACE_PAUSED,
  lockWorkspaceForCertOpsSideEffect,
} = require("./workspaceKillSwitch");
const { CERTOPS_DISABLED } = require("./settings");
const {
  CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
  CERTOPS_RENEWAL_PROFILE_INVALID,
  AUTO_RENEW_DISABLED_PROFILE_STATUSES,
  buildRenewalJobPayload,
  windowsIisTargetAuditFields,
} = require("./renewalProfile");
const {
  CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED,
  DEFAULT_RENEWAL_PER_CA_CAP,
  IN_FLIGHT_BUCKET_SQL,
  RENEWAL_PER_CA_CAP_ENV,
  UNKNOWN_CA_BUCKET,
  adcsCaBucket,
  caCapKey,
  normalizeCaBucket,
  resolveRenewalPerCaCap,
} = require("./renewalCapacity");
const { writeAudit } = require("../audit");
const { createEnrollment } = require("./certificateEnrollments");
const { validateAdcsRenewalProfile } = require("./adcsRenewalRules");
const {
  loadCurrentAdcsIssuerVersion,
  loadQualifyingAdcsAgents,
} = require("./adcsPreflightGate");

const DEFAULT_RENEWAL_THRESHOLD_DAYS = 30;
const DEFAULT_BATCH_SIZE = 200;
const RENEWAL_THRESHOLD_ENV = "CERTOPS_RENEWAL_THRESHOLD_DAYS";
// An AD CS renewal waits here until an agent has a safe adcs-preflight for its CA.
const CERTOPS_ADCS_AGENT_NOT_PREPARED = "CERTOPS_ADCS_AGENT_NOT_PREPARED";

// Certificates without a resolvable caEndpoint share this bucket, so a flood
// of endpoint-less renewals is still capped instead of being unbounded.
// UNKNOWN_CA_BUCKET is imported from renewalCapacity (shared with jobs.js).

// Advisory lock key for the sweep (single-flight across workers). Any
// constant bigint works; this one is arbitrary but must stay stable.
const RENEWAL_SCHEDULER_ADVISORY_LOCK_KEY = 7_384_211_257_001n;

// "Still in flight" for renewal-capacity accounting. Derived from the full
// job status list (not a hand-maintained subset) so a new terminal status
// added to jobs.js is picked up automatically instead of silently missing
// here. Exported so any other read of in-flight renew jobs (e.g. the
// upcoming-renewals list) agrees with the sweep on what counts as done.
const RENEWAL_JOB_TERMINAL_STATUSES = JOB_STATUSES.filter(isTerminalJobStatus);

// Inventory statuses that never get automated renewal jobs.
const NON_RENEWABLE_CERTIFICATE_STATUSES = Object.freeze([
  "revoked",
  "decommissioned",
]);

// Profile statuses that switch automatic renewal off for every certificate
// linked to the profile. certificate_profiles.status has carried these values
// since the table was created, but the sweep never read the column, so setting
// a profile to 'disabled' silently did nothing. Since renewal profiles are now
// derived automatically at issuance (ADR-0010), this column is the operator's
// only per-certificate way to stop automatic renewal, so the sweep has to
// honour it.
//
// Filtered in SQL rather than skipped in JS: a disabled profile is not a
// candidate at all, so it must not consume a slot in the batch LIMIT and delay
// certificates that do renew.
//
// Canonical definition lives in renewalProfile.js (re-exported here for call
// sites in this file), since jobs.js's own defense-in-depth re-check at
// job-creation time needs the identical list.

function resolveRenewalThresholdDays(env = process.env) {
  const raw = env[RENEWAL_THRESHOLD_ENV];
  if (raw == null || String(raw).trim() === "") {
    return DEFAULT_RENEWAL_THRESHOLD_DAYS;
  }
  const parsed = Number.parseInt(String(raw).trim(), 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    return DEFAULT_RENEWAL_THRESHOLD_DAYS;
  }
  return parsed;
}

/**
 * Max renewal jobs that may be in flight per CA endpoint at sweep time.
 * resolveRenewalPerCaCap / normalizeCaBucket / caCapKey live in
 * renewalCapacity.js so createCertificateJob enforces the same rules.
 */

/**
 * True when a metadata caEndpoint value would pass the execution-field
 * validation in jobs.js (http/https URL, <= 512 chars). Invalid values are
 * still used for cap bucketing but never stamped onto job payloads.
 */
function isValidCaEndpointUrl(value) {
  if (typeof value !== "string" || value.length > 512) return false;
  let parsed;
  try {
    parsed = new URL(value);
  } catch (_error) {
    return false;
  }
  return parsed.protocol === "https:" || parsed.protocol === "http:";
}

/**
 * CA bucket for a due certificate: the caEndpoint recorded in the
 * certificate's public metadata, falling back to its profile's public
 * metadata / renewalProfile.ca.endpoint, else the shared unknown-CA bucket.
 * Normalized for bucketing.
 */
function certificateCaBucket(certificate) {
  if (certificate?.profile_issuer_kind === "adcs" && certificate.profile_issuer_id) {
    return adcsCaBucket(certificate.profile_issuer_id);
  }
  const candidates = [
    certificate?.certificate_ca_endpoint,
    certificate?.profile_ca_endpoint,
  ];
  for (const candidate of candidates) {
    if (typeof candidate === "string" && candidate.trim() !== "") {
      return normalizeCaBucket(candidate);
    }
  }
  return UNKNOWN_CA_BUCKET;
}

/**
 * Raw (un-normalized) caEndpoint candidate for stamping on job payloads.
 * Kept separate from certificateCaBucket so payloads carry the operator's
 * exact URL while cap accounting uses the canonical bucket.
 */
function certificateCaEndpointRaw(certificate) {
  const candidates = [
    certificate?.certificate_ca_endpoint,
    certificate?.profile_ca_endpoint,
  ];
  for (const candidate of candidates) {
    if (typeof candidate === "string" && candidate.trim() !== "") {
      return candidate.trim();
    }
  }
  return null;
}

/**
 * Point-in-time snapshot of in-flight renewal jobs keyed by
 * (workspace, normalized CA bucket). Jobs without a payload caEndpoint land
 * in the unknown-CA bucket. Normalization happens here in JS with the SAME
 * normalizeCaBucket used for due certificates, so both sides of the cap
 * comparison agree. The sweep itself is single-flight (advisory lock in
 * runRenewalSchedulerSweep) and locally increments this map for jobs it
 * creates, so the snapshot stays consistent for the duration of a sweep; a
 * concurrent manual job at worst delays a renewal by one sweep.
 *
 * The sweep always queries across every workspace; pass workspaceId to
 * scope the query to one, which is what a single per-workspace API request
 * needs instead of paying for a global scan.
 */
async function countInFlightRenewalJobsByCaEndpoint({
  db = pool,
  terminalStatuses,
  workspaceId = null,
} = {}) {
  const params = [terminalStatuses];
  let workspaceFilter = "";
  if (workspaceId != null) {
    params.push(workspaceId);
    workspaceFilter = ` AND cj.workspace_id = $${params.length}`;
  }
  const result = await db.query(
    `SELECT cj.workspace_id,
            ${IN_FLIGHT_BUCKET_SQL} AS ca_bucket,
            COUNT(*)::int AS in_flight
       FROM certificate_jobs cj
       LEFT JOIN certificate_enrollments e
         ON e.workspace_id = cj.workspace_id AND e.current_job_id = cj.id
      WHERE cj.operation = 'renew'
        AND NOT (cj.status = ANY($1::text[]))${workspaceFilter}
      GROUP BY 1, 2`,
    params,
  );
  const counts = new Map();
  for (const row of result.rows || []) {
    const bucket =
      row.ca_bucket == null
        ? UNKNOWN_CA_BUCKET
        : normalizeCaBucket(row.ca_bucket);
    const key = caCapKey(row.workspace_id, bucket);
    counts.set(key, (counts.get(key) || 0) + (Number(row.in_flight) || 0));
  }
  return counts;
}

/**
 * Stable idempotency key: cert id + not_after epoch. A renewed certificate
 * gets a new not_after, so the next expiry window produces a new key while
 * reruns within the same window replay the same job.
 */
function renewalIdempotencyKey(certificateId, notAfter) {
  const epoch = new Date(notAfter).getTime();
  return `certops-renewal:${certificateId}:${epoch}`;
}

/**
 * Certificates due for renewal: managed, expiring within the threshold, not
 * retired, linked to a profile that has not been switched off, and without an
 * existing non-terminal renew job for the same subject. terminalStatuses is
 * derived from jobs.js isTerminalJobStatus so the SQL dedupe stays aligned with
 * the service's terminal set.
 *
 * Also loads the linked certificate_profiles row (including
 * public_metadata.renewalProfile) needed to resolve an executable payload.
 */
async function findCertificatesDueForRenewal({
  db = pool,
  thresholdDays,
  batchSize = DEFAULT_BATCH_SIZE,
  terminalStatuses,
} = {}) {
  const result = await db.query(
    `SELECT mc.id,
            mc.workspace_id,
            mc.common_name,
            mc.subject_alt_names,
            mc.not_after,
            mc.key_mode,
            mc.profile_id,
            cp.name AS profile_name,
            cp.key_mode AS profile_key_mode,
            cp.public_metadata AS profile_public_metadata,
            cp.renew_before_days AS profile_renew_before_days,
            cp.issuer_id AS profile_issuer_id,
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
            ci.kind AS profile_issuer_kind
       FROM managed_certificates mc
       LEFT JOIN certificate_profiles cp
         ON cp.workspace_id = mc.workspace_id AND cp.id = mc.profile_id
       LEFT JOIN certificate_issuers ci
         ON ci.workspace_id = cp.workspace_id AND ci.id = cp.issuer_id
      WHERE mc.not_after IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM certops_certificate_identities identity
          WHERE identity.workspace_id = mc.workspace_id
            AND identity.fingerprint_sha256 = certops_normalize_fingerprint(mc.fingerprint_sha256)
            AND identity.lifecycle_status IN ('revoked', 'decommissioned'))
        AND EXISTS (SELECT 1 FROM certops_management_periods period
          WHERE period.workspace_id = mc.workspace_id
            AND period.managed_certificate_id = mc.id
            AND period.ended_at IS NULL AND period.automation_enabled = TRUE)
        AND mc.not_after <= NOW()
              + (COALESCE(cp.renew_before_days, $1) || ' days')::interval
        AND mc.status NOT IN (${NON_RENEWABLE_CERTIFICATE_STATUSES.map(
          (status) => `'${status}'`,
        ).join(", ")})
        -- Source status can lag behind an operator retirement when that cache
        -- row is held by another writer. Identity lifecycle is authoritative.
        AND NOT EXISTS (
          SELECT 1 FROM certops_certificate_identities identity
           WHERE identity.workspace_id = mc.workspace_id
             AND identity.fingerprint_sha256 = certops_normalize_fingerprint(mc.fingerprint_sha256)
             AND identity.lifecycle_status IN ('revoked', 'decommissioned')
        )
        -- cp.status IS NULL means the LEFT JOIN found no profile at all, which
        -- is a different (incomplete-profile) outcome resolved further down,
        -- not a disabled one. Without the explicit IS NULL test the ANY()
        -- comparison yields NULL for those rows and silently drops them.
        AND (cp.status IS NULL OR NOT (cp.status = ANY($4::text[])))
        AND NOT EXISTS (
          SELECT 1
            FROM certificate_jobs cj
           WHERE cj.workspace_id = mc.workspace_id
             AND cj.operation = 'renew'
             AND cj.subject_type = 'managed_certificate'
             AND cj.subject_id = mc.id::text
             AND NOT (cj.status = ANY($2::text[]))
        )
      ORDER BY mc.not_after ASC
      LIMIT $3`,
    [
      String(thresholdDays),
      terminalStatuses,
      batchSize,
      AUTO_RENEW_DISABLED_PROFILE_STATUSES,
    ],
  );
  return result.rows;
}

/**
 * Count certificates that WOULD be due but whose profile has automatic renewal
 * switched off.
 *
 * findCertificatesDueForRenewal excludes them in SQL, so without this they
 * would be invisible: `scanned` would not include them and no skip counter
 * would fire, making a workspace that has disabled everything look identical to
 * one with nothing due. An operator needs to be able to tell "nothing is
 * expiring" from "things are expiring and I told you not to renew them".
 *
 * Deliberately not gated on profile completeness or key custody: this counts
 * intent (renewal is switched off), not eligibility.
 */
async function countCertificatesWithAutoRenewDisabled({
  db = pool,
  thresholdDays,
  terminalStatuses,
} = {}) {
  const result = await db.query(
    `SELECT COUNT(*)::int AS disabled_count
       FROM managed_certificates mc
       JOIN certificate_profiles cp
         ON cp.workspace_id = mc.workspace_id AND cp.id = mc.profile_id
      WHERE mc.not_after IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM certops_certificate_identities identity
          WHERE identity.workspace_id = mc.workspace_id
            AND identity.fingerprint_sha256 = certops_normalize_fingerprint(mc.fingerprint_sha256)
            AND identity.lifecycle_status IN ('revoked', 'decommissioned'))
        AND EXISTS (SELECT 1 FROM certops_management_periods period
          WHERE period.workspace_id = mc.workspace_id
            AND period.managed_certificate_id = mc.id
            AND period.ended_at IS NULL AND period.automation_enabled = TRUE)
        AND mc.not_after <= NOW()
              + (COALESCE(cp.renew_before_days, $1) || ' days')::interval
        AND mc.status NOT IN (${NON_RENEWABLE_CERTIFICATE_STATUSES.map(
          (status) => `'${status}'`,
        ).join(", ")})
        -- Source status can lag behind an operator retirement when that cache
        -- row is held by another writer. Identity lifecycle is authoritative.
        AND NOT EXISTS (
          SELECT 1 FROM certops_certificate_identities identity
           WHERE identity.workspace_id = mc.workspace_id
             AND identity.fingerprint_sha256 = certops_normalize_fingerprint(mc.fingerprint_sha256)
             AND identity.lifecycle_status IN ('revoked', 'decommissioned')
        )
        AND cp.status = ANY($3::text[])
        AND NOT EXISTS (
          SELECT 1
            FROM certificate_jobs cj
           WHERE cj.workspace_id = mc.workspace_id
             AND cj.operation = 'renew'
             AND cj.subject_type = 'managed_certificate'
             AND cj.subject_id = mc.id::text
             AND NOT (cj.status = ANY($2::text[]))
        )`,
    [
      String(thresholdDays),
      terminalStatuses,
      AUTO_RENEW_DISABLED_PROFILE_STATUSES,
    ],
  );
  return Number(result.rows?.[0]?.disabled_count) || 0;
}

function incompleteRenewalProfile(message) {
  const error = new Error(message);
  error.code = CERTOPS_RENEWAL_PROFILE_INCOMPLETE;
  return error;
}

// Same rules the profile write path and renewal health apply.
function adcsFieldsFromProfile(certificate) {
  let profile;
  try {
    profile = validateAdcsRenewalProfile(certificate.profile_public_metadata?.renewalProfile);
  } catch (error) {
    throw incompleteRenewalProfile(error.message);
  }
  return {
    target: profile.target,
    authorizedDnsNames: profile.sanPolicy.sans,
    keyAlgorithm: profile.keyAlgorithm,
    keySize: profile.keySize,
  };
}

const OPEN_ENROLLMENT_STATES = [
  "requested",
  "prepared",
  "submitting",
  "pending_issuance",
  "submission_uncertain",
  "issued",
  "validation_deferred",
  "validated",
  "installing",
  "install_failed",
];

async function createAutomaticAdcsRenewal({
  dbPool,
  certificate,
  mode,
  env,
  auditWriter,
}) {
  const issuer = await dbPool.query(
    `SELECT kind FROM certificate_issuers WHERE workspace_id = $1 AND id = $2`,
    [certificate.workspace_id, certificate.profile_issuer_id],
  );
  if (issuer.rows[0]?.kind !== "adcs") return null;

  const fields = adcsFieldsFromProfile(certificate);
  // Evidence must describe the confirmed version (config, template, pinned key)
  // and come from a preflight job created after confirmation. Template ACLs can
  // change in AD without the name changing, so an older check does not qualify.
  const version = await loadCurrentAdcsIssuerVersion({
    db: dbPool,
    workspaceId: certificate.workspace_id,
    issuerId: certificate.profile_issuer_id,
  });
  // Declaring the target is not enough: the agent must hold a fresh, safe
  // adcs-preflight against this CA, so a renewal never goes to an agent that
  // cannot reach the CA. Renewal health applies the same check.
  const [agent] = await loadQualifyingAdcsAgents({
    db: dbPool,
    workspaceId: certificate.workspace_id,
    issuerId: certificate.profile_issuer_id,
    reference: fields.target.reference,
    version,
  });
  if (!agent) {
    const declared = await dbPool.query(
      `SELECT 1
         FROM certops_agents
        WHERE workspace_id = $1
          AND status = 'active'
          AND declared_target_selectors @> jsonb_build_array($2::text)
        LIMIT 1`,
      [certificate.workspace_id, fields.target.reference],
    );
    const error = new Error(
      declared.rows[0]
        ? "no agent has a safe adcs-preflight for this CA within the preflight freshness window; run the CA check from the agent"
        : "no active agent declares this AD CS renewal target",
    );
    error.code = declared.rows[0]
      ? CERTOPS_ADCS_AGENT_NOT_PREPARED
      : CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE;
    throw error;
  }
  const open = await dbPool.query(
    `SELECT id
       FROM certificate_enrollments
      WHERE workspace_id = $1
        AND certificate_id = $2
        AND state = ANY($3::text[])
      LIMIT 1`,
    [certificate.workspace_id, certificate.id, OPEN_ENROLLMENT_STATES],
  );
  if (open.rows[0]) return { job: { id: null, operation: "renew" }, created: false };

  const idempotencyKey = renewalIdempotencyKey(
    certificate.id,
    certificate.not_after,
  );
  const existingJob = await dbPool.query(
    `SELECT id
       FROM certificate_jobs
      WHERE workspace_id = $1
        AND idempotency_key = $2
      LIMIT 1`,
    [certificate.workspace_id, idempotencyKey],
  );
  if (existingJob.rows[0]) {
    return { job: { id: existingJob.rows[0].id, operation: "renew" }, created: false };
  }

  let created;
  try {
    created = await createEnrollment({
      client: dbPool,
      workspaceId: certificate.workspace_id,
      profileId: certificate.profile_id,
      certificateId: certificate.id,
      agentId: agent.id,
      source: "automation",
      mode,
      env,
      idempotencyKey,
      target: {
        type: "windows-iis",
        reference: fields.target.reference,
        store: fields.target.store,
        binding: {
          site: fields.target.binding.site,
          port: fields.target.binding.port,
          ...(fields.target.binding.sniHost
            ? { sniHost: fields.target.binding.sniHost }
            : {}),
        },
      },
      authorizedDnsNames: fields.authorizedDnsNames,
      keyAlgorithm: fields.keyAlgorithm,
      keySize: fields.keySize,
    });
  } catch (error) {
    if (error?.code === "CERTOPS_ENROLLMENT_REPLAY") {
      return { job: { id: null, operation: "renew" }, created: false };
    }
    throw error;
  }
  await auditWriter({
    client: dbPool,
    actorUserId: null,
    subjectUserId: null,
    action: "CERTOPS_JOB_CREATED_AUTOMATIC",
    targetType: "certificate_job",
    targetId: null,
    workspaceId: certificate.workspace_id,
    metadata: {
      jobId: String(created.jobId),
      enrollmentId: String(created.enrollmentId),
      operation: "renew",
      mode,
      subjectType: "managed_certificate",
      subjectId: String(certificate.id),
      commonName: certificate.common_name || null,
      issuerId: String(certificate.profile_issuer_id),
      source: "automation",
      trigger: "renewal_scheduler",
    },
  });
  return { job: { id: created.jobId, operation: "renew" }, created: true };
}

async function createRenewalJobForCertificate({
  dbPool,
  certificate,
  jobCreator,
  env,
  mode = "real",
  auditWriter = writeAudit,
}) {
  // By-construction exclusion (ADR-0012 decision 14): the renewal scheduler
  // creates exactly one operation, hardcoded below. isTrustAnchorOperation
  // can never be true for a literal "renew" and this assertion exists so
  // that stays true even if a future refactor parameterized the operation
  // instead of hardcoding it, at which point this throws in tests rather
  // than silently letting a trust job get picked up as a renewal.
  if (isTrustAnchorOperation("renew")) {
    throw new Error(
      "renewalScheduler: 'renew' must never be a trust-anchor operation",
    );
  }

  if (certificate.profile_issuer_id) {
    const adcsRenewal = await createAutomaticAdcsRenewal({
      dbPool,
      certificate,
      env,
      mode,
      auditWriter,
    });
    if (adcsRenewal) return adcsRenewal;
  }

  // Resolve the immutable execution contract BEFORE opening the insert
  // transaction. Incomplete profiles never create a job row.
  const payload = buildRenewalJobPayload({ certificate });

  const client = await dbPool.connect();
  let transactionStarted = false;
  try {
    await client.query("BEGIN");
    transactionStarted = true;

    // Kill-switch gate inside the same transaction as the insert. Paused or
    // globally disabled workspaces throw here; the caller converts that into
    // a skip, never an error.
    const workspace = await lockWorkspaceForCertOpsSideEffect({
      client,
      workspaceId: certificate.workspace_id,
      env,
    });

    const outcome = await jobCreator({
      client,
      workspaceId: certificate.workspace_id,
      operation: "renew",
      source: "automation",
      status: "pending",
      mode,
      subjectType: "managed_certificate",
      subjectId: String(certificate.id),
      idempotencyKey: renewalIdempotencyKey(
        certificate.id,
        certificate.not_after,
      ),
      payload,
      ...(payload.publication ? { assignedAgentId: (await client.query(
        "SELECT issuer_agent_id FROM certops_distribution_groups WHERE workspace_id=$1 AND id=$2 AND state='active'",
        [certificate.workspace_id, payload.publication.groupId])).rows[0]?.issuer_agent_id } : {}),
      env,
      workspaceRequiresApprovalAlways:
        workspace.certops_require_approval_always === true,
      returnOutcome: true,
    });

    const job = outcome?.job || outcome;
    const created = outcome?.created === true;

    // Mirrors CERTOPS_JOB_CREATED_MANUAL for the scheduler. Without it the
    // audit log contains only the jobs a human asked for, so unattended renewal
    // is precisely the activity it cannot account for. Only genuinely new jobs
    // are audited: an idempotent replay created nothing.
    if (created) {
      await auditWriter({
        client,
        actorUserId: null,
        subjectUserId: null,
        action: "CERTOPS_JOB_CREATED_AUTOMATIC",
        targetType: "certificate_job",
        targetId: null,
        workspaceId: certificate.workspace_id,
        metadata: {
          jobId: String(job.id),
          operation: job.operation,
          mode,
          subjectType: job.subjectType || "managed_certificate",
          subjectId: String(certificate.id),
          commonName: certificate.common_name || null,
          notAfter:
            certificate.not_after instanceof Date
              ? certificate.not_after.toISOString()
              : certificate.not_after || null,
          profileId: certificate.profile_id
            ? String(certificate.profile_id)
            : null,
          source: "automation",
          trigger: "renewal_scheduler",
          ...windowsIisTargetAuditFields(payload?.target),
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
        // Preserve the primary failure for the caller.
      }
    }
    throw error;
  } finally {
    client.release();
  }
}

/**
 * One renewal-planning pass. Returns a summary:
 * { thresholdDays, perCaCap, lockAcquired, scanned, created, replayed,
 *   skippedPaused, skippedByCaCap, skippedIncompleteProfile,
 *   skippedNotAgentDeployable, skippedAdcsAgentNotPrepared,
 *   skippedAutoRenewDisabled, errors }.
 *
 * Single-flight: the whole sweep runs under a session advisory lock
 * (pg_try_advisory_lock). A second worker starting a sweep while one is in
 * progress returns immediately with lockAcquired: false and does nothing;
 * without this, two concurrent sweeps would each take a point-in-time
 * in-flight snapshot and could jointly exceed every per-CA cap.
 *
 * Per-CA cap: before creating a job the sweep checks how many renew jobs
 * are already in flight for the certificate's (workspace, normalized CA)
 * bucket (snapshot taken once per sweep, incremented locally for jobs this
 * sweep creates). Capped certificates are skipped, counted in
 * skippedByCaCap, and picked up by a later sweep once the CA's in-flight
 * jobs drain.
 *
 * Incomplete profiles: certificates whose linked renewal profile cannot be
 * resolved into a complete executable snapshot are skipped (never insert a
 * job), counted in skippedIncompleteProfile, and logged/alerted.
 *
 * Switched off: certificates whose profile status is 'disabled'/'archived' are
 * excluded by the scan query and reported in skippedAutoRenewDisabled, so an
 * operator can distinguish "nothing due" from "renewal deliberately off".
 */
async function runRenewalSchedulerSweep({
  dbPool = pool,
  env = process.env,
  jobCreator = createCertificateJob,
  batchSize = DEFAULT_BATCH_SIZE,
  logger = null,
  mode = "real",
  auditWriter = writeAudit,
} = {}) {
  const thresholdDays = resolveRenewalThresholdDays(env);
  const perCaCap = resolveRenewalPerCaCap(env);
  const terminalStatuses = RENEWAL_JOB_TERMINAL_STATUSES;

  const summary = {
    thresholdDays,
    perCaCap,
    lockAcquired: false,
    scanned: 0,
    created: 0,
    replayed: 0,
    skippedPaused: 0,
    skippedRetired: 0,
    skippedByCaCap: 0,
    skippedIncompleteProfile: 0,
    skippedNotAgentDeployable: 0,
    skippedAdcsAgentNotPrepared: 0,
    skippedAutoRenewDisabled: 0,
    errors: [],
  };

  // Advisory locks are session-scoped: acquire and release on ONE dedicated
  // connection held for the whole sweep.
  const lockClient = await dbPool.connect();
  try {
    const lockResult = await lockClient.query(
      "SELECT pg_try_advisory_lock($1) AS acquired",
      [RENEWAL_SCHEDULER_ADVISORY_LOCK_KEY.toString()],
    );
    if (lockResult.rows?.[0]?.acquired !== true) {
      return summary;
    }
    summary.lockAcquired = true;

    const dueCertificates = await findCertificatesDueForRenewal({
      db: dbPool,
      thresholdDays,
      batchSize,
      terminalStatuses,
    });

    const inFlightByCa = await countInFlightRenewalJobsByCaEndpoint({
      db: dbPool,
      terminalStatuses,
    });

    // Observability only, and deliberately outside the loop below: these
    // certificates were excluded by the scan query, so nothing in the loop can
    // count them. A failure here must not abort a sweep that is otherwise able
    // to create renewals.
    try {
      summary.skippedAutoRenewDisabled =
        await countCertificatesWithAutoRenewDisabled({
          db: dbPool,
          thresholdDays,
          terminalStatuses,
        });
    } catch (error) {
      if (logger?.warn) {
        logger.warn("certops-renewal-scheduler-disabled-count-failed", {
          error: error?.message,
        });
      }
    }

    summary.scanned = dueCertificates.length;

    for (const certificate of dueCertificates) {
      const capKey = caCapKey(
        certificate.workspace_id,
        certificateCaBucket(certificate),
      );
      const inFlight = inFlightByCa.get(capKey) || 0;
      if (inFlight >= perCaCap) {
        summary.skippedByCaCap += 1;
        continue;
      }
      try {
        const { created } = await createRenewalJobForCertificate({
          dbPool,
          certificate,
          jobCreator,
          env,
          mode,
          auditWriter,
        });
        if (created) {
          summary.created += 1;
          inFlightByCa.set(capKey, inFlight + 1);
        } else {
          summary.replayed += 1;
        }
      } catch (error) {
        // Retirement may commit after the due-list snapshot. Job creation
        // rejects it; the sweep treats that operator decision as a skip.
        if (
          error?.code === CERTOPS_WORKSPACE_PAUSED ||
          error?.code === CERTOPS_DISABLED
        ) {
          summary.skippedPaused += 1;
          continue;
        }
        // Retirement may commit after the scan but before final transactional
        // admission. Only that exact policy refusal is a normal skip; unrelated
        // database or executor failures remain in errors below.
        if (["CERTOPS_CERTIFICATE_NOT_RENEWABLE", "CERTOPS_CERTIFICATE_RETIRED"].includes(error?.code)) {
          summary.skippedRetired += 1;
          continue;
        }
        if (error?.code === CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED) {
          summary.skippedByCaCap += 1;
          continue;
        }
        if (
          error?.code === CERTOPS_RENEWAL_PROFILE_INCOMPLETE ||
          error?.code === CERTOPS_RENEWAL_PROFILE_INVALID
        ) {
          summary.skippedIncompleteProfile += 1;
          if (logger?.warn || logger?.error) {
            const logFn = logger.warn || logger.error;
            logFn.call(logger, "certops-renewal-scheduler-incomplete-profile", {
              certificateId: String(certificate.id),
              workspaceId: certificate.workspace_id,
              profileId: certificate.profile_id
                ? String(certificate.profile_id)
                : null,
              error: error?.message,
              code: error?.code,
            });
          }
          continue;
        }
        // An observed-only certificate (endpoint or domain monitor, no agent
        // custody of the key) can never be renewed by an agent. That is an
        // expected steady state, not a failure, so counting it as an error would
        // make every sweep look broken and bury real failures.
        if (error?.code === CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE) {
          summary.skippedNotAgentDeployable += 1;
          continue;
        }
        // Expected until an agent runs the CA check: retried on the next sweep.
        if (error?.code === CERTOPS_ADCS_AGENT_NOT_PREPARED) {
          summary.skippedAdcsAgentNotPrepared += 1;
          continue;
        }
        summary.errors.push({
          certificateId: String(certificate.id),
          error: error?.message || String(error),
        });
        if (logger?.error) {
          logger.error("certops-renewal-scheduler-cert-failure", {
            certificateId: String(certificate.id),
            error: error?.message,
          });
        }
      }
    }

    return summary;
  } finally {
    if (summary.lockAcquired) {
      try {
        await lockClient.query("SELECT pg_advisory_unlock($1)", [
          RENEWAL_SCHEDULER_ADVISORY_LOCK_KEY.toString(),
        ]);
      } catch (_error) {
        // The session release below frees the lock regardless.
      }
    }
    lockClient.release();
  }
}

/**
 * Renewal inputs for the listed certificates, joined to their profile the
 * same way the scheduler joins it. Kept out of the inventory route module so
 * that file does not query the job table.
 */
async function loadCertificateRenewalRows({
  db = pool,
  workspaceId,
  certificateIds,
  env = process.env,
}) {
  const profileColumns = `SELECT mc.id,
            mc.status,
            mc.key_mode,
            mc.key_reference,
            mc.not_after,
            mc.common_name,
            mc.subject_alt_names,
            mc.profile_id,
            cp.name AS profile_name,
            cp.status AS profile_status,
            cp.key_mode AS profile_key_mode,
            cp.public_metadata AS profile_public_metadata,
            cp.renew_before_days AS profile_renew_before_days`;
  const scheduleColumns = `,
            mc.not_after
              - (COALESCE(cp.renew_before_days, $3) || ' days')::interval
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
            EXISTS (
              SELECT 1
                FROM certificate_jobs cj
               WHERE cj.workspace_id = mc.workspace_id
                 AND cj.operation = 'renew'
                 AND cj.subject_type = 'managed_certificate'
                 AND cj.subject_id = mc.id::text
                 AND NOT (cj.status = ANY($4::text[]))
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
            ci.kind AS profile_issuer_kind`;
  const fromClause = `
       FROM managed_certificates mc
       LEFT JOIN certificate_profiles cp
         ON cp.workspace_id = mc.workspace_id AND cp.id = mc.profile_id
       LEFT JOIN certificate_issuers ci
         ON ci.workspace_id = cp.workspace_id AND ci.id = cp.issuer_id
      WHERE mc.workspace_id = $1
        AND mc.id = ANY($2::uuid[])`;
  try {
    const result = await db.query(
      `${profileColumns}${scheduleColumns}${fromClause}`,
      [
        workspaceId,
        certificateIds,
        String(resolveRenewalThresholdDays(env)),
        RENEWAL_JOB_TERMINAL_STATUSES,
      ],
    );
    return { rows: result.rows, scheduleFacts: true };
  } catch (err) {
    logger.warn("CertOps renewal schedule enrichment failed", {
      error: err.message,
      workspaceId,
    });
    const result = await db.query(`${profileColumns}${fromClause}`, [
      workspaceId,
      certificateIds,
    ]);
    return { rows: result.rows, scheduleFacts: false };
  }
}

module.exports = {
  AUTO_RENEW_DISABLED_PROFILE_STATUSES,
  CERTOPS_ADCS_AGENT_NOT_PREPARED,
  DEFAULT_RENEWAL_PER_CA_CAP,
  DEFAULT_RENEWAL_THRESHOLD_DAYS,
  NON_RENEWABLE_CERTIFICATE_STATUSES,
  RENEWAL_JOB_TERMINAL_STATUSES,
  RENEWAL_PER_CA_CAP_ENV,
  RENEWAL_SCHEDULER_ADVISORY_LOCK_KEY,
  RENEWAL_THRESHOLD_ENV,
  UNKNOWN_CA_BUCKET,
  caCapKey,
  certificateCaBucket,
  certificateCaEndpointRaw,
  createAutomaticAdcsRenewal,
  countCertificatesWithAutoRenewDisabled,
  countInFlightRenewalJobsByCaEndpoint,
  loadCertificateRenewalRows,
  resolveRenewalThresholdDays,
  findCertificatesDueForRenewal,
  isValidCaEndpointUrl,
  normalizeCaBucket,
  renewalIdempotencyKey,
  resolveRenewalPerCaCap,
  resolveRenewalThresholdDays,
  runRenewalSchedulerSweep,
};
