"use strict";

const Ajv = require("ajv");
const { isDeepStrictEqual } = require("node:util");
const addFormats = require("ajv-formats");
const { pool } = require("../../db/database");
const enrollmentResultSchema = require("../../../../packages/contracts/certops/enrollment-result-contract.schema.json");
const preflightResultSchema = require("../../../../packages/contracts/certops/adcs-preflight-result-contract.schema.json");
const snapshotSchema = require("../../../../packages/contracts/certops/enrollment-snapshot.schema.json");

const ajv = new Ajv({ strict: false });
addFormats(ajv);
ajv.addSchema(snapshotSchema);
const validateEnrollmentResult = ajv.compile(enrollmentResultSchema);
const validatePreflightResult = ajv.compile(preflightResultSchema);

function assertSchema(validate, value, code) {
  if (validate(value)) return;
  throw serviceError("enrollment report does not match its contract", code);
}
const { writeAudit } = require("../audit");
const { logger } = require("../../utils/logger");
const { redactGenericSecrets } = require("../../utils/secretMaterial");
const { createCertificateJob } = require("./jobs");
const { adcsCaBucket } = require("./renewalCapacity");
const { lockWorkspaceForCertOpsSideEffect } = require("./workspaceKillSwitch");
const { iisSelectorKey } = require("./windowsRenewalOwnership");
const {
  loadRefreshJobs, refreshState, refreshIdempotencyKey,
  QUEUE_TIMEOUT_MS, issuerRefreshStates,
} = require("./adcsPreflightRefresh");
const {
  PREFLIGHT_PER_HOUR,
  UNREACHABLE_ERROR,
  assertDirectTransition,
  assertForwardTransition,
  assertIssuerKind,
  attachEnrollmentDispatch,
  confirmedKeyAllowed,
  decideContinuation,
  freezeSnapshot,
  nextPollAt,
  parseRequestId,
  serviceError,
  storedAdcsPayload,
} = require("./enrollmentLifecycle");

function dbOf(client) {
  return client || pool;
}

const CERTIFICATE_ID_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function validAdcsTarget(target) {
  if (!target || typeof target !== "object" || Array.isArray(target)) return false;
  if (target.type === "windows-iis") {
    if (!target.binding) return false;
    if (target.binding.address != null) {
      try { iisSelectorKey(target.binding); } catch (_) { return false; }
    }
    return true;
  }
  return target.type === "windows-cert-store" && target.store === "My" &&
    typeof target.reference === "string" &&
    target.reference.length <= 253 &&
    /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/.test(target.reference) &&
    Object.keys(target).every(key => ["type", "store", "reference"].includes(key));
}

// A job can be terminal while its CA enrollment remains in progress.
const OPEN_ENROLLMENT_STATES = Object.freeze([
  "requested", "prepared", "submitting", "pending_issuance", "submission_uncertain",
  "issued", "validation_deferred", "validated", "installing", "install_failed",
]);

async function findOpenEnrollment(db, workspaceId, certificateId) {
  const result = await db.query(
    `SELECT id FROM certificate_enrollments
      WHERE workspace_id = $1 AND certificate_id = $2 AND state = ANY($3::text[])
      LIMIT 1`,
    [workspaceId, certificateId, OPEN_ENROLLMENT_STATES],
  );
  return result.rows[0] || null;
}

// This refusal is emitted before the agent creates a key or submits to AD CS.
// Other failures may have unknown effects and must never use this retry path.
const LOCAL_DRY_RUN_REFUSAL = 'refusing mode:"real" job because local execution.dryRun is true; set execution.dryRun to false to perform real side effects, or ask the control plane for a mode:"dry_run" job';

// Only an initial, explicit local-policy rejection proves that AD CS was not
// contacted. A generic refused state can also follow an uncertain submission.
const SAFE_INITIAL_LOCAL_REFUSAL_SQL = `e.state = 'refused' AND e.last_error_code = 'ADCS_CA_CONFIG_UNSAFE'
  AND e.attempt <= 1 AND e.request_id IS NULL AND e.operator_request_id IS NULL
  AND e.pending_since IS NULL AND e.installed_at IS NULL
  AND EXISTS (SELECT 1 FROM certificate_jobs local_job
    WHERE local_job.workspace_id=e.workspace_id AND local_job.enrollment_id=e.id
      AND local_job.id=e.current_job_id AND local_job.source='automation'
      AND local_job.operation='renew' AND local_job.status='rejected'
      AND local_job.needs_operator_reconciliation IS FALSE
      AND local_job.error_code='issuer_not_allowlisted'
      AND local_job.error_message='ADCS_CA_CONFIG_UNSAFE: Local enrollment rule refused before key generation and CA submission. [tt-adcs-no-key-no-submit-v1]'
      AND local_job.result_metadata->>'rejectionReason'='issuer_not_allowlisted'
      AND local_job.result_metadata->'enrollmentResult'->>'state'='refused'
      AND local_job.result_metadata->'enrollmentResult'->>'errorCode'='ADCS_CA_CONFIG_UNSAFE')
  AND NOT EXISTS (SELECT 1 FROM certificate_jobs local_jobs
    WHERE local_jobs.workspace_id=e.workspace_id AND local_jobs.enrollment_id=e.id AND local_jobs.id<>e.current_job_id)`;

// A control-plane cancellation is safe only if no claim or nonce ever existed.
const SAFE_SUPERSEDED_BEFORE_CLAIM_SQL = `e.state='cancelled' AND e.attempt=0
  AND e.request_id IS NULL AND e.operator_request_id IS NULL AND e.pending_since IS NULL AND e.installed_at IS NULL
  AND EXISTS (SELECT 1 FROM certificate_jobs local_job
    WHERE local_job.workspace_id=e.workspace_id AND local_job.enrollment_id=e.id AND local_job.id=e.current_job_id
      AND local_job.source='automation' AND local_job.operation='renew' AND local_job.status='cancelled'
      AND local_job.error_code='CERTOPS_AUTOMATION_SUPERSEDED_BEFORE_CLAIM' AND local_job.completed_at IS NOT NULL
      AND local_job.attempt_count=0 AND local_job.claimed_by_agent_id IS NULL AND local_job.claim_id IS NULL
      AND local_job.lease_expires_at IS NULL AND local_job.lease_renewed_at IS NULL
      AND local_job.needs_operator_reconciliation IS FALSE
      AND NOT EXISTS (SELECT 1 FROM certops_consumed_nonces n WHERE n.workspace_id=e.workspace_id AND n.job_id=local_job.id))
  AND NOT EXISTS (SELECT 1 FROM certificate_jobs local_jobs
    WHERE local_jobs.workspace_id=e.workspace_id AND local_jobs.enrollment_id=e.id AND local_jobs.id<>e.current_job_id)`;

async function isSafeInitialLocalRefusal(db, workspaceId, jobId, { lock = false } = {}) {
  const result = await db.query(`SELECT j.updated_at FROM certificate_jobs j
    JOIN certificate_enrollments e ON e.workspace_id=j.workspace_id AND e.id=j.enrollment_id
    WHERE j.workspace_id=$1 AND j.id=$2 AND (${SAFE_INITIAL_LOCAL_REFUSAL_SQL})${lock ? " FOR UPDATE OF j,e" : ""}`, [workspaceId, jobId]);
  return result.rows[0] || null;
}

async function isSafeRetryableAutomaticEnrollment(db, workspaceId, jobId, { lock = false } = {}) {
  const result = await db.query(`SELECT j.updated_at, (${SAFE_SUPERSEDED_BEFORE_CLAIM_SQL}) AS superseded_before_claim FROM certificate_jobs j
    JOIN certificate_enrollments e ON e.workspace_id=j.workspace_id AND e.id=j.enrollment_id
    WHERE j.workspace_id=$1 AND j.id=$2 AND ((${SAFE_INITIAL_LOCAL_REFUSAL_SQL}) OR (${SAFE_SUPERSEDED_BEFORE_CLAIM_SQL}))${lock ? " FOR UPDATE OF j,e" : ""}`, [workspaceId, jobId]);
  return result.rows[0] || null;
}

function retryDryRunBlockedRenewal({ client, workspaceId, enrollmentId, eligibleAgentIds, env }) {
  if (!CERTIFICATE_ID_UUID.test(String(enrollmentId || ""))) return null;
  return withTransaction(dbOf(client), async (tx) => {
    const workspace = await lockWorkspaceForCertOpsSideEffect({ client: tx, workspaceId, env });
    const row = await loadEnrollment(tx, workspaceId, enrollmentId, { lock: true });
    if (!row || row.state !== "requested" || row.request_id != null ||
        row.operator_request_id != null || !eligibleAgentIds.includes(String(row.agent_id))) return null;
    const prior = await tx.query(`SELECT id, status, operation, source, mode, assigned_agent_id, error_code, error_message, updated_at
      FROM certificate_jobs WHERE workspace_id=$1 AND id=$2 AND enrollment_id=$3 FOR UPDATE`,
    [workspaceId, row.current_job_id, row.id]);
    const job = prior.rows[0];
    if (!job || job.status !== "blocked" || job.operation !== "renew" || job.source !== "automation" ||
        job.mode !== "real" || String(job.assigned_agent_id) !== String(row.agent_id) || job.error_code !== "AGENT_RESULT_BLOCKED" ||
        job.error_message !== LOCAL_DRY_RUN_REFUSAL ||
        Date.now() - new Date(job.updated_at).getTime() < 15 * 60 * 1000) return null;
    if (await identityRetired(tx, workspaceId, row.certificate_id) || !validAdcsTarget(row.deploy_target)) return null;
    const currentIssuer = await tx.query(`SELECT i.id FROM certificate_enrollments e
      JOIN managed_certificates mc ON mc.workspace_id=e.workspace_id AND mc.id=e.certificate_id
      JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id AND cp.issuer_id=e.issuer_id
      JOIN certificate_issuers i ON i.workspace_id=e.workspace_id AND i.id=e.issuer_id
      WHERE e.workspace_id=$1 AND e.id=$2 AND i.current_version=e.issuer_version
        AND i.revalidation_required=false
        AND cp.public_metadata->'renewalProfile'->'target'=e.deploy_target
        AND cp.public_metadata->'renewalProfile'->'sanPolicy'->'sans'=(convert_from(e.snapshot_bytes,'UTF8')::jsonb)->'authorizedDnsNames'
        AND cp.public_metadata->'renewalProfile'->'keyAlgorithm'=(convert_from(e.snapshot_bytes,'UTF8')::jsonb)->'keyAlgorithm'
        AND cp.public_metadata->'renewalProfile'->'keySize'=(convert_from(e.snapshot_bytes,'UTF8')::jsonb)->'keySize'
      FOR SHARE OF i, cp`, [workspaceId, row.id]);
    if (!currentIssuer.rows[0]) return null;
    const next = await createCertificateJob({ client: tx, workspaceId, operation: "renew", source: "automation",
      mode: "real", subjectType: "managed_certificate", subjectId: row.certificate_id,
      assignedAgentId: row.agent_id, payload: storedAdcsPayload({ certificateId: row.certificate_id, target: row.deploy_target }),
      enrollmentId: row.id, capacityBucket: adcsCaBucket(currentIssuer.rows[0].id), env,
      workspaceRequiresApprovalAlways: workspace.certops_require_approval_always === true });
    await tx.query(`UPDATE certificate_enrollments SET attempt=attempt+1, current_job_id=$3, updated_at=NOW()
      WHERE workspace_id=$1 AND id=$2`, [workspaceId, row.id, next.id]);
    await writeAudit({ client: tx, workspaceId, actorUserId: null, subjectUserId: null,
      action: "CERTOPS_JOB_CREATED_AUTOMATIC", targetType: "certificate_job", targetId: null,
      metadata: { jobId: String(next.id), enrollmentId: String(row.id), operation: "renew", reason: "retry_local_dry_run_refusal" } });
    return next;
  });
}

// Lock and compare the IIS destination, not the registration: a store copy
// and an IIS observation can both point to the same certificate and binding.
async function assertIisTargetAvailable(tx, { workspaceId, certificateId, agentId, target, source }) {
  if (!CERTIFICATE_ID_UUID.test(String(agentId || ""))) {
    throw serviceError("IIS enrollment requires a specific agent", "CERTOPS_SNAPSHOT_INVALID");
  }
  const port = String(target.binding.port || "");
  const sni = String(target.binding.sniHost || "").trim().toLowerCase();
  const address = !target.binding.address || target.binding.address === "*" ? "0.0.0.0" : target.binding.address;
  const selector = iisSelectorKey(target.binding);
  const key = JSON.stringify([String(workspaceId).toLowerCase(), String(agentId).toLowerCase(), selector]);
  await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))", [`certops-iis-enrollment:${key}`]);
  const result = await tx.query(
    `SELECT 1 FROM certificate_enrollments e
      WHERE e.workspace_id = $1 AND e.deploy_target->>'type' = 'windows-iis'
        AND (e.agent_id = $2::uuid OR e.agent_id IS NULL)
        AND e.deploy_target->'binding'->>'port' = $3
        AND lower(btrim(COALESCE(e.deploy_target->'binding'->>'sniHost', ''))) = $4
        AND ($4 <> '' OR COALESCE(NULLIF(e.deploy_target->'binding'->>'address', '*'), '0.0.0.0')::inet = $8::inet)
        AND (e.state = ANY($5::text[]) OR ($6 = 'automation'
          AND (e.state = 'installed' OR (e.state <> 'denied' AND NOT COALESCE(((${SAFE_INITIAL_LOCAL_REFUSAL_SQL}) OR (${SAFE_SUPERSEDED_BEFORE_CLAIM_SQL})), FALSE) AND EXISTS (SELECT 1 FROM certificate_jobs j
            WHERE j.workspace_id = e.workspace_id AND j.enrollment_id = e.id AND j.source = 'automation')))
          AND EXISTS (
          SELECT 1 FROM managed_certificates current_cert
          JOIN certops_certificate_identities identity
            ON identity.workspace_id = current_cert.workspace_id
           AND identity.fingerprint_sha256 = certops_normalize_fingerprint(current_cert.fingerprint_sha256)
          JOIN certops_management_associations association
            ON association.workspace_id = identity.workspace_id AND association.identity_id = identity.id
          JOIN certops_management_periods period
            ON period.workspace_id = association.workspace_id AND period.id = association.period_id
          WHERE current_cert.workspace_id = $1 AND current_cert.id = $7
            AND period.managed_certificate_id = e.certificate_id
            AND association.associated_at <= e.created_at
            AND (association.superseded_at IS NULL OR association.superseded_at >= e.created_at)
        ))) LIMIT 1`,
    [workspaceId, agentId, port, sni, OPEN_ENROLLMENT_STATES, source, certificateId || null, address],
  );
  if (result.rows.length) {
    const error = serviceError("This IIS binding already has an enrollment in progress or was renewed for this certificate.", "CERTOPS_ENROLLMENT_OPEN");
    error.statusCode = 409;
    throw error;
  }
}

async function identityRetired(client, workspaceId, certificateId) {
  if (!CERTIFICATE_ID_UUID.test(String(certificateId || ""))) return false;
  const result = await client.query(
    `SELECT identity.lifecycle_status
       FROM managed_certificates mc
       LEFT JOIN certops_certificate_identities identity
         ON identity.workspace_id = mc.workspace_id
        AND identity.fingerprint_sha256 = certops_normalize_fingerprint(mc.fingerprint_sha256)
      WHERE mc.workspace_id = $1 AND mc.id = $2::uuid`,
    [workspaceId, certificateId],
  );
  return ["revoked", "decommissioned"].includes(result.rows[0]?.lifecycle_status);
}

function isPool(db) {
  return Boolean(db) && typeof db.connect === "function" && typeof db.idleCount === "number";
}

async function inTransaction(db, fn) {
  await db.query("BEGIN");
  try {
    const result = await fn();
    await db.query("COMMIT");
    return result;
  } catch (error) {
    try {
      await db.query("ROLLBACK");
    } catch (_rollbackError) {
      // The original error is the one the caller can act on.
    }
    throw error;
  }
}

async function withTransaction(db, fn) {
  if (!isPool(db)) return inTransaction(db, () => fn(db));
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    try {
      const result = await fn(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch (_rollbackError) {
        // The original error is the one the caller can act on.
      }
      throw error;
    }
  } finally {
    client.release();
  }
}

async function createIssuer({ client, workspaceId, kind, name, actorUserId }) {
  assertIssuerKind(kind);
  const db = dbOf(client);
  const inserted = await db.query(
    `INSERT INTO certificate_issuers (workspace_id, kind, name)
     VALUES ($1, $2, $3)
     RETURNING id, workspace_id, kind, name, current_version, revalidation_required`,
    [workspaceId, kind, name],
  );
  const row = inserted.rows[0];
  await writeAudit({
    client: db,
    actorUserId: actorUserId || null,
    subjectUserId: actorUserId || null,
    action: "CERTOPS_ISSUER_CREATED",
    targetType: "certificate_issuer",
    workspaceId,
    metadata: { issuerId: row.id, issuerName: row.name, kind },
  });
  return row;
}

async function discardUnconfiguredIssuer({ client, workspaceId, issuerId }) {
  const deleted = await dbOf(client).query(
    `DELETE FROM certificate_issuers
      WHERE workspace_id = $1
        AND id = $2
        AND current_version = 0
        AND NOT EXISTS (
          SELECT 1
            FROM certificate_enrollments e
           WHERE e.workspace_id = certificate_issuers.workspace_id
             AND e.issuer_id = certificate_issuers.id
        )
      RETURNING id`,
    [workspaceId, issuerId],
  );
  if (!deleted.rows[0]) {
    throw serviceError("issuer not found", "CERTOPS_ISSUER_NOT_FOUND");
  }
  return { issuerId: deleted.rows[0].id };
}

function dispatchPreflight({
  client,
  workspaceId,
  issuerId,
  agentId,
  caConfig,
  template,
  actorUserId,
  createJob = createCertificateJob,
  audit = writeAudit,
  beforeLock,
  automatic = false,
  confirmedAt = null,
  unavailableTarget = null,
  env = process.env,
}) {
  if (automatic && (!confirmedAt || !Number.isFinite(new Date(confirmedAt).getTime()))) {
    throw serviceError("automatic preflight requires a confirmed issuer", "CERTOPS_ISSUER_REVALIDATION_REQUIRED");
  }
  const db = dbOf(client);
  return withTransaction(db, async (tx) => {
    if (automatic) await lockWorkspaceForCertOpsSideEffect({ client: tx, workspaceId, env });
    if (typeof beforeLock === "function") await beforeLock(tx);
    await tx.query("SELECT pg_advisory_xact_lock(hashtext($1::text))", [
      `adcs-preflight:${workspaceId}`,
    ]);
    let refreshKey;
    let boundVersion = null;
    if (automatic) {
      // Job rows precede the issuer lock, matching result ingestion's order.
      // A read-only check stranded before claim can safely terminate. Claimed
      // jobs retain their lease/nonce fences and are recovered by the reaper.
      await tx.query(`UPDATE certificate_jobs SET status='failed',
        error_code='CERTOPS_PREFLIGHT_QUEUE_TIMEOUT',completed_at=clock_timestamp(),updated_at=clock_timestamp()
        WHERE workspace_id=$1 AND operation='adcs-preflight' AND subject_id=$2
          AND assigned_agent_id=$3 AND source='automation' AND status='pending'
          AND created_at < clock_timestamp()-($4::text || ' milliseconds')::interval`,
      [workspaceId,String(issuerId),agentId,String(QUEUE_TIMEOUT_MS)]);
      const current = await tx.query(`SELECT v.version,v.ca_config,v.template,v.ca_key_sha256,v.confirmed_at,i.revalidation_required
        FROM certificate_issuers i JOIN certificate_issuer_versions v
          ON v.workspace_id=i.workspace_id AND v.issuer_id=i.id AND v.version=i.current_version
        WHERE i.workspace_id=$1 AND i.id=$2 AND i.kind='adcs' FOR SHARE OF i`, [workspaceId,issuerId]);
      const version = current.rows[0];
      boundVersion = version;
      if (!version || version.ca_config !== caConfig || version.template !== template ||
          new Date(version.confirmed_at).getTime() !== new Date(confirmedAt).getTime()) {
        throw serviceError("automatic preflight issuer changed", "CERTOPS_ISSUER_REVALIDATION_REQUIRED");
      }
      const context = { workspaceId,issuerId,agentId,version };
      if (unavailableTarget) {
        return null;
      }
      const jobs = await loadRefreshJobs(tx, context);
      const state = refreshState(jobs,version);
      if (state.state !== "required" && !(state.state === "retrying" && state.dispatch)) return null;
      refreshKey = refreshIdempotencyKey({ ...context,previousId: jobs[0]?.id });
    }
    const recent = await tx.query(
      `SELECT count(*)::int AS n
         FROM certificate_jobs
        WHERE workspace_id = $1
          AND operation = 'adcs-preflight'
          AND created_at > NOW() - INTERVAL '1 hour'`,
      [workspaceId],
    );
    if (Number(recent.rows[0]?.n || 0) >= PREFLIGHT_PER_HOUR) {
      if (automatic) return null; // Wait for capacity without rolling back an expiry alert.
      throw serviceError(
        "AD CS preflight rate limit exceeded for this workspace",
        "CERTOPS_PREFLIGHT_RATE_LIMITED",
      );
    }
    if (!automatic) {
      const current = await tx.query(`SELECT v.version,v.ca_config,v.template,v.ca_key_sha256,v.confirmed_at
        FROM certificate_issuers i JOIN certificate_issuer_versions v
          ON v.workspace_id=i.workspace_id AND v.issuer_id=i.id AND v.version=i.current_version
        WHERE i.workspace_id=$1 AND i.id=$2 FOR SHARE OF i`,[workspaceId,issuerId]);
      const version = current.rows[0];
      if (version?.ca_config === caConfig && version?.template === template) boundVersion = version;
    }
    const job = await createJob({
      client: tx,
      workspaceId,
      operation: "adcs-preflight",
      allowIssuerPreflight: true,
      source: automatic ? "automation" : "api",
      ...(automatic ? { idempotencyKey: refreshKey } : {}),
      subjectType: "external",
      subjectId: issuerId,
      assignedAgentId: agentId,
      payload: {
        schemaVersion: 1,
        action: "adcs-preflight",
        mode: "real",
        caConfig,
        template,
        transport: "dcom",
        issuerId,
      },
    });
    const sequenced = await tx.query(
      `UPDATE certificate_issuers
          SET preflight_seq = preflight_seq + 1, updated_at = NOW()
        WHERE workspace_id = $1 AND id = $2
        RETURNING preflight_seq, name`,
      [workspaceId, issuerId],
    );
    const preflightSeq = sequenced.rows[0]?.preflight_seq;
    if (preflightSeq == null) {
      throw serviceError("issuer not found", "CERTOPS_ISSUER_NOT_FOUND");
    }
    await tx.query(
      `UPDATE certificate_jobs
          SET preflight_seq = $3,
              result_metadata = result_metadata || $4::jsonb
        WHERE workspace_id = $1 AND id = $2`,
      [workspaceId, job.id, preflightSeq, JSON.stringify(boundVersion ? {
        preflightContext: { issuerVersion: boundVersion.version,caKeySha256: boundVersion.ca_key_sha256,
          confirmedAt: boundVersion.confirmed_at },
      } : {})],
    );
    await audit({
      client: tx,
      actorUserId: actorUserId || null,
      subjectUserId: actorUserId || null,
      action: "CERTOPS_ISSUER_PREFLIGHT_DISPATCHED",
      targetType: "certificate_issuer",
      workspaceId,
      metadata: { issuerId, issuerName: sequenced.rows[0]?.name, jobId: job.id, agentId, caConfig, template },
    });
    return job;
  });
}

function confirmIssuerKey({
  client,
  workspaceId,
  issuerId,
  caKeySha256,
  caConfig,
  template,
  actorUserId,
  audit = writeAudit,
}) {
  const db = dbOf(client);
  return withTransaction(db, async (tx) => {
  const issuer = await tx.query(
    `SELECT id, name, kind, current_version, last_preflight
       FROM certificate_issuers
      WHERE workspace_id = $1 AND id = $2
      FOR UPDATE`,
    [workspaceId, issuerId],
  );
  const row = issuer.rows[0];
  if (!row) throw serviceError("issuer not found", "CERTOPS_ISSUER_NOT_FOUND");
  if (row.kind !== "adcs") {
    throw serviceError("only an adcs issuer confirms a CA key", "CERTOPS_ISSUER_KIND_INVALID");
  }
  const preflight = row.last_preflight;
  if (!confirmedKeyAllowed(preflight, caKeySha256)) {
    throw serviceError(
      "caKeySha256 must be a key from a safe preflight result",
      "CERTOPS_SNAPSHOT_INVALID",
    );
  }
  if (caConfig && caConfig !== preflight.caConfig) {
    throw serviceError(
      "caConfig does not match the preflight result",
      "CERTOPS_SNAPSHOT_INVALID",
    );
  }
  if (template && template !== preflight.template) {
    throw serviceError(
      "template does not match the preflight result",
      "CERTOPS_SNAPSHOT_INVALID",
    );
  }
  const version = Number(row.current_version || 0) + 1;
  await tx.query(
    `INSERT INTO certificate_issuer_versions (
       workspace_id, issuer_id, version, ca_config, template, transport,
       ca_key_sha256, confirmed_at, config
     ) VALUES ($1,$2,$3,$4,$5,'dcom',$6,NOW(),$7::jsonb)`,
    [
      workspaceId,
      issuerId,
      version,
      preflight.caConfig,
      preflight.template,
      caKeySha256,
      JSON.stringify({ caKeySha256, templateOid: preflight.templateCheck?.templateOid || null }),
    ],
  );
  await tx.query(
    `UPDATE certificate_issuers
        SET current_version = $3, revalidation_required = false, updated_at = NOW()
      WHERE workspace_id = $1 AND id = $2`,
    [workspaceId, issuerId, version],
  );
  await audit({
    client: tx,
    actorUserId: actorUserId || null,
    subjectUserId: actorUserId || null,
    action: "CERTOPS_ISSUER_KEY_CONFIRMED",
    targetType: "certificate_issuer",
    workspaceId,
    metadata: { issuerId, issuerName: row.name, version, caKeySha256, caConfig: preflight.caConfig, template: preflight.template },
  });
  return { issuerId, version, caKeySha256 };
  });
}

function createEnrollment({
  client,
  workspaceId,
  issuerId,
  certificateId,
  agentId,
  target,
  authorizedDnsNames,
  keyAlgorithm,
  keySize,
  profileId,
  pollInterval,
  pendingTimeout,
  minimumRemainingValidity,
  requireLaterNotAfter,
  source = "api",
  mode = "real",
  env,
  idempotencyKey,
  actorUserId,
  requestedByApiTokenId,
  createJob = createCertificateJob,
  audit = writeAudit,
  transactionOwned = false,
  initialOperation = "renew",
  workspaceRequiresApprovalAlways = false,
  requiresApproval,
  expectedAutomationRetry,
}) {
  if (!validAdcsTarget(target)) {
    throw serviceError(
      "enrollment target must be a valid Windows certificate destination",
      "CERTOPS_SNAPSHOT_INVALID",
    );
  }
  if (transactionOwned && (!client || isPool(client))) {
    throw serviceError("transaction-owned enrollment requires a transaction client", "CERTOPS_SNAPSHOT_INVALID");
  }
  if (!["issue", "renew"].includes(initialOperation) ||
      (initialOperation === "issue" && !transactionOwned)) {
    throw serviceError("invalid initial enrollment operation", "CERTOPS_SNAPSHOT_INVALID");
  }
  const db = dbOf(client);
  const run = async (tx) => {
    if (source === "automation") {
      await lockWorkspaceForCertOpsSideEffect({
        client: tx,
        workspaceId,
        env,
      });
    }
    if (expectedAutomationRetry) {
      // Management replacement takes this fence before period and certificate
      // rows; use the same order to avoid a period/certificate deadlock.
      await require("./inventory").acquireManagedCertificateImportLock(tx,workspaceId);
    }
    // Every creator uses the same certificate-scoped transaction lock before
    // reading enrollment state, including manual and racing scheduler calls.
    if (CERTIFICATE_ID_UUID.test(String(certificateId || ""))) {
      await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))", [
        `certops-enrollment:${String(workspaceId).toLowerCase()}:${String(certificateId).toLowerCase()}`,
      ]);
      if (await findOpenEnrollment(tx, workspaceId, certificateId)) {
        const error = serviceError(
          "This certificate already has an enrollment in progress. Wait for it, or cancel or abandon it first.",
          "CERTOPS_ENROLLMENT_OPEN",
        );
        error.statusCode = 409;
        throw error;
      }
    }
    if (expectedAutomationRetry) {
      if (source !== "automation" || !profileId) throw serviceError("invalid automatic retry", "CERTOPS_ENROLLMENT_REPLAY");
      if (!await isSafeRetryableAutomaticEnrollment(tx,workspaceId,expectedAutomationRetry.previousJobId,{lock:true})) {
        throw serviceError("automatic renewal refusal changed before retry", "CERTOPS_ENROLLMENT_REPLAY");
      }
      const period = await tx.query(`SELECT id, automation_enabled, renewal_profile_id FROM certops_management_periods
        WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL FOR UPDATE`, [workspaceId, certificateId]);
      if (!period.rows[0]?.automation_enabled || String(period.rows[0].renewal_profile_id) !== String(profileId) ||
          String(period.rows[0].id) !== String(expectedAutomationRetry.periodId)) {
        throw serviceError("automatic renewal was stopped before retry", "CERTOPS_ENROLLMENT_REPLAY");
      }
      const current = await tx.query(`SELECT mc.not_after, mc.status AS certificate_status,
          mc.source, mc.source_ref, mc.fingerprint_sha256, mc.deployed_agent_id, mc.reconciliation_reason,
          cp.status AS profile_status, cp.issuer_id, cp.public_metadata
        FROM managed_certificates mc JOIN certificate_profiles cp
          ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id
        WHERE mc.workspace_id=$1 AND mc.id=$2 AND cp.id=$3 FOR UPDATE OF mc,cp`,
      [workspaceId,certificateId,profileId]);
      const row = current.rows[0];
      let profile;
      try { profile = require("./adcsRenewalRules").validateAdcsRenewalProfile(row?.public_metadata?.renewalProfile); }
      catch { throw serviceError("automatic renewal profile changed before retry", "CERTOPS_ENROLLMENT_REPLAY"); }
      const disabled = require("./renewalProfile").AUTO_RENEW_DISABLED_PROFILE_STATUSES;
      if (!row || ["revoked","decommissioned"].includes(row.certificate_status) || disabled.includes(row.profile_status) ||
          row.source !== expectedAutomationRetry.source || row.source_ref !== expectedAutomationRetry.sourceRef ||
          row.fingerprint_sha256 !== expectedAutomationRetry.fingerprint || row.reconciliation_reason === "windows_store_identity_conflict" ||
          (row.source === "agent_windows" && String(row.source_ref || "").includes("/windows_store/")) ||
          (expectedAutomationRetry.requireOwner && String(row.deployed_agent_id) !== String(agentId)) ||
          String(row.issuer_id) !== String(expectedAutomationRetry.issuerId) ||
          new Date(row.not_after).getTime() !== new Date(expectedAutomationRetry.notAfter).getTime() ||
          !isDeepStrictEqual(profile.target,target) || !isDeepStrictEqual(profile.sanPolicy.sans,authorizedDnsNames) ||
          profile.keyAlgorithm !== keyAlgorithm || profile.keySize !== keySize) {
        throw serviceError("automatic renewal profile changed before retry", "CERTOPS_ENROLLMENT_REPLAY");
      }
    }
    if (target.type === "windows-iis") {
      await assertIisTargetAvailable(tx, { workspaceId, certificateId, agentId, target, source });
    }
    let resolvedIssuerId = issuerId;
    if (profileId) {
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(profileId))) {
        throw serviceError("renewal profile not found", "CERTOPS_PROFILE_NOT_FOUND");
      }
      const profile = await tx.query(
        `SELECT issuer_id
           FROM certificate_profiles
          WHERE workspace_id = $1 AND id = $2`,
        [workspaceId, profileId],
      );
      if (!profile.rows[0]) {
        throw serviceError("renewal profile not found", "CERTOPS_PROFILE_NOT_FOUND");
      }
      const profileIssuerId = profile.rows[0].issuer_id;
      if (!profileIssuerId) {
        throw serviceError(
          "this profile uses ACME; select an AD CS issuer before enrolling",
          "CERTOPS_PROFILE_ISSUER_NOT_SELECTED",
        );
      }
      if (issuerId && issuerId !== profileIssuerId) {
        throw serviceError(
          "enrollment issuer does not match the renewal profile",
          "CERTOPS_PROFILE_ISSUER_MISMATCH",
        );
      }
      resolvedIssuerId = profileIssuerId;
    }
    const version = await tx.query(
      `SELECT v.version, v.ca_config, v.template, v.ca_key_sha256, v.confirmed_at, i.kind,
              i.revalidation_required
         FROM certificate_issuer_versions v
         JOIN certificate_issuers i
           ON i.workspace_id = v.workspace_id AND i.id = v.issuer_id
        WHERE v.workspace_id = $1
          AND v.issuer_id = $2
          AND v.version = i.current_version
          AND v.ca_key_sha256 IS NOT NULL
        FOR UPDATE OF i`,
      [workspaceId, resolvedIssuerId],
    );
    const issuer = version.rows[0];
    if (!issuer) throw serviceError("confirmed issuer version not found", "CERTOPS_ISSUER_NOT_FOUND");
    if (expectedAutomationRetry && (issuer.ca_config !== expectedAutomationRetry.caConfig ||
        issuer.template !== expectedAutomationRetry.template || issuer.ca_key_sha256 !== expectedAutomationRetry.caKeySha256 ||
        new Date(issuer.confirmed_at).getTime() !== new Date(expectedAutomationRetry.confirmedAt).getTime())) {
      throw serviceError("automatic renewal issuer changed before retry", "CERTOPS_ENROLLMENT_REPLAY");
    }
    if (issuer.revalidation_required === true) {
      throw serviceError(
        "issuer requires revalidation before new enrollments",
        "CERTOPS_ISSUER_REVALIDATION_REQUIRED",
      );
    }
    assertIssuerKind(issuer.kind);
    if (source === "automation") {
      // Recheck inside enrollment admission: the scheduler's earlier read may
      // cross the TTL boundary, a new unsafe result, or a pin confirmation.
      const { loadQualifyingAdcsAgents } = require("./adcsPreflightGate");
      const prepared = await loadQualifyingAdcsAgents({ db: tx,workspaceId,
        issuerId: resolvedIssuerId,reference: target.reference,version: issuer,target,
        ownerId: agentId,env });
      if (!prepared.some((candidate) => String(candidate.id) === String(agentId))) {
        throw serviceError("the selected agent needs a fresh safe AD CS preflight", "CERTOPS_ADCS_AGENT_NOT_PREPARED");
      }
    }
    let storeSnapshot = {};
    if (target.type === "windows-cert-store") {
      if (!Array.isArray(authorizedDnsNames) || !authorizedDnsNames.some((name) =>
        typeof name === "string" && name.toLowerCase() === target.reference.toLowerCase())) {
        throw serviceError("the store destination must be included in the authorized DNS names", "CERTOPS_SNAPSHOT_INVALID");
      }
      const owner = await tx.query(
        `SELECT status, fingerprint_sha256, deployed_agent_id
           FROM managed_certificates WHERE workspace_id = $1 AND id = $2::uuid FOR UPDATE`,
        [workspaceId, certificateId],
      );
      const certificate = owner.rows[0];
      if (!certificate || !agentId || String(certificate.deployed_agent_id || "") !== String(agentId)) {
        throw serviceError("the selected agent does not own this store installation", "CERTOPS_SNAPSHOT_INVALID");
      }
      const previous = certificate.fingerprint_sha256 == null ? null :
        String(certificate.fingerprint_sha256).replace(/:/g, "").toLowerCase();
      if ((certificate.status === "provisioning") !== (initialOperation === "issue") ||
          (certificate.status === "provisioning" && previous !== null) ||
          (certificate.status !== "provisioning" && !/^[a-f0-9]{64}$/.test(previous || ""))) {
        throw serviceError("the store installation predecessor identity is unavailable", "CERTOPS_SNAPSHOT_INVALID");
      }
      const destinationSha256 = require("crypto").createHash("sha256").update(JSON.stringify({
        type: "windows-cert-store", reference: target.reference, store: "My",
      }), "utf8").digest("hex");
      const iisConsumers = initialOperation === "renew"
        ? await require("./windowsIisConsent").snapshotWindowsIisConsumers({ client: tx, workspaceId, certificateId, agentId })
        : [];
      storeSnapshot = { destinationType: "windows-cert-store", destinationSha256, predecessorFingerprintSha256: previous, iisConsumers };
    }
    const frozen = freezeSnapshot({
      issuerId: resolvedIssuerId,
      issuerVersion: issuer.version,
      caConfig: issuer.ca_config,
      caKeySha256: issuer.ca_key_sha256,
      template: issuer.template,
      authorizedDnsNames,
      keyAlgorithm,
      keySize,
      pollInterval,
      pendingTimeout,
      minimumRemainingValidity,
      requireLaterNotAfter,
      ...storeSnapshot,
    });
    const inserted = await tx.query(
      `INSERT INTO certificate_enrollments (
         workspace_id, certificate_id, issuer_id, issuer_version, agent_id,
         state, attempt, snapshot_bytes, snapshot_sha256, deploy_target
       ) VALUES ($1,$2,$3,$4,$5,'requested',0,$6,$7,$8::jsonb)
       RETURNING id`,
      [
        workspaceId,
        certificateId,
        resolvedIssuerId,
        issuer.version,
        agentId,
        frozen.bytes,
        frozen.sha256,
        JSON.stringify(target),
      ],
    );
    const enrollmentId = inserted.rows[0].id;
    const payload = storedAdcsPayload({ certificateId, target });
    const outcome = await createJob({
      client: tx,
      workspaceId,
      operation: initialOperation,
      source,
      requestedByUserId: actorUserId || null,
      requestedByApiTokenId: requestedByApiTokenId || null,
      mode,
      idempotencyKey,
      env,
      subjectType: "managed_certificate",
      subjectId: certificateId,
      assignedAgentId: agentId,
      payload,
      enrollmentId,
      workspaceRequiresApprovalAlways,
      requiresApproval,
      capacityBucket: resolvedIssuerId ? adcsCaBucket(resolvedIssuerId) : null,
      returnOutcome: Boolean(idempotencyKey),
    });
    const job = idempotencyKey ? outcome.job : outcome;
    if (idempotencyKey && outcome.created === false) {
      throw serviceError(
        "an automatic renewal for this certificate expiry already exists",
        "CERTOPS_ENROLLMENT_REPLAY",
      );
    }
    await tx.query(
      `UPDATE certificate_enrollments
          SET current_job_id = $3, updated_at = NOW()
        WHERE workspace_id = $1 AND id = $2`,
      [workspaceId, enrollmentId, job.id],
    );
    await audit({
      client: tx,
      actorUserId: actorUserId || null,
      subjectUserId: actorUserId || null,
      action: "CERTOPS_ENROLLMENT_CREATED",
      targetType: "certificate_enrollment",
      workspaceId,
      metadata: { enrollmentId, issuerId: resolvedIssuerId, jobId: job.id },
    });
    return { enrollmentId, snapshotSha256: frozen.sha256, jobId: job.id, ...(transactionOwned ? { job } : {}) };
  };
  return transactionOwned ? run(db) : withTransaction(db, run);
}

// lock: false | true (wait for the row) | "skip" (return null if another tx holds it).
async function loadEnrollment(db, workspaceId, enrollmentId, { lock = false } = {}) {
  const lockClause = lock === "skip" ? "FOR UPDATE OF e SKIP LOCKED" : lock ? "FOR UPDATE OF e" : "";
  const result = await db.query(
    `SELECT e.id, e.workspace_id, e.state, e.attempt, e.snapshot_bytes, e.snapshot_sha256,
            e.operator_request_id, e.pending_since, e.next_poll_at,
            e.last_error_code, e.current_job_id, e.certificate_id, e.agent_id, e.request_id,
            e.deploy_target, j.status AS job_status, j.error_code AS job_error_code
       FROM certificate_enrollments e
       LEFT JOIN certificate_jobs j
         ON j.workspace_id = e.workspace_id AND j.id = e.current_job_id
      WHERE e.workspace_id = $1 AND e.id = $2
      ${lockClause}`,
    [workspaceId, enrollmentId],
  );
  return result.rows[0] || null;
}

function enrollmentView(row) {
  // An uncertain installation is deliberately not a terminal success or an
  // invitation to retry: only explicit operator reconciliation may proceed.
  const active = row.job_status && ["pending_approval", "approved", "pending", "claimed", "running", "orphaned_unknown_effect"].includes(row.job_status);
  return {
    id: row.id,
    state: row.state,
    attempt: row.attempt,
    snapshotB64: Buffer.from(row.snapshot_bytes).toString("base64"),
    snapshotSha256: row.snapshot_sha256,
    operatorRequestId: parseRequestId(row.operator_request_id),
    pendingSince: row.pending_since,
    nextPollAt: row.next_poll_at,
    lastErrorCode: row.last_error_code,
    activeJob: Boolean(active),
    certificateId: row.certificate_id,
    agentId: row.agent_id,
    deployTarget: row.deploy_target,
  };
}

async function recordEnrollmentResult(client, { workspaceId, job, enrollmentResult }) {
  const db = dbOf(client);
  assertSchema(validateEnrollmentResult, enrollmentResult, "CERTOPS_ENROLLMENT_TRANSITION_INVALID");
  if (!job.enrollment_id) {
    throw serviceError(
      "awaiting_issuer requires a bound enrollment",
      "CERTOPS_ENROLLMENT_UNBOUND",
    );
  }
  if (enrollmentResult.enrollmentId !== job.enrollment_id) {
    throw serviceError(
      "enrollmentResult.enrollmentId does not match the job",
      "CERTOPS_ENROLLMENT_UNBOUND",
    );
  }
  const row = await loadEnrollment(db, workspaceId, job.enrollment_id);
  if (!row) throw serviceError("enrollment not found", "CERTOPS_ENROLLMENT_NOT_FOUND");
  if (enrollmentResult.attempt !== row.attempt && row.attempt !== 0) {
    throw serviceError(
      "enrollmentResult.attempt does not match the enrollment",
      "CERTOPS_ENROLLMENT_UNBOUND",
    );
  }
  assertForwardTransition(row.state, enrollmentResult.state);
  const snapshot = JSON.parse(Buffer.from(row.snapshot_bytes).toString("utf8"));
  const pollSeconds = snapshot.pollInterval || 900;
  let pendingSince = row.pending_since;
  let nextAt = row.next_poll_at;
  if (enrollmentResult.state === "pending_issuance" && !pendingSince) pendingSince = new Date();
  if (
    enrollmentResult.state === "pending_issuance" ||
    enrollmentResult.state === "validation_deferred" ||
    enrollmentResult.state === "installing"
  ) {
    nextAt = nextPollAt(new Date(), pollSeconds);
  }
  if (enrollmentResult.state === "submitting" && enrollmentResult.errorCode === UNREACHABLE_ERROR) {
    nextAt = nextPollAt(new Date(), pollSeconds);
  }
  const retriesOperatorCandidate = enrollmentResult.state === "submission_uncertain" &&
    parseRequestId(row.operator_request_id) != null;
  if (retriesOperatorCandidate) nextAt = nextPollAt(new Date(), pollSeconds);
  // A poll date left over from an earlier pending attempt must not survive a
  // terminal result, or every maintenance sweep keeps selecting the row.
  const keepsPolling =
    retriesOperatorCandidate ||
    enrollmentResult.state === "pending_issuance" ||
    enrollmentResult.state === "validation_deferred" ||
    enrollmentResult.state === "installing" ||
    (enrollmentResult.state === "submitting" && enrollmentResult.errorCode === UNREACHABLE_ERROR);
  if (!keepsPolling) nextAt = null;
  const updated = await db.query(
    `UPDATE certificate_enrollments
        SET state = $3,
            request_id = COALESCE($4, request_id),
            last_error_code = $5,
            pending_since = $6,
            next_poll_at = $7,
            installed_at = CASE WHEN $3 = 'installed' THEN COALESCE(installed_at, NOW()) ELSE installed_at END,
            updated_at = NOW()
      WHERE workspace_id = $1 AND id = $2 AND state = $8
      RETURNING id`,
    [
      workspaceId,
      job.enrollment_id,
      enrollmentResult.state,
      Number.isInteger(enrollmentResult.requestId) ? enrollmentResult.requestId : null,
      enrollmentResult.errorCode || null,
      pendingSince,
      nextAt,
      row.state,
    ],
  );
  if (updated.rows.length !== 1) {
    throw serviceError(
      "enrollment state changed before the agent result was recorded",
      "CERTOPS_ENROLLMENT_TRANSITION_INVALID",
    );
  }
  if (enrollmentResult.errorCode === "ADCS_CA_KEY_CHANGED") {
    await db.query(
      `UPDATE certificate_issuers
          SET revalidation_required = true, updated_at = NOW()
        WHERE workspace_id = $1
          AND id = (SELECT issuer_id FROM certificate_enrollments WHERE workspace_id = $1 AND id = $2)`,
      [workspaceId, job.enrollment_id],
    );
  }
}

function preflightPayloadOf(job) {
  const payload = job && job.payload;
  if (typeof payload === "string") {
    try {
      return JSON.parse(payload);
    } catch (_error) {
      return null;
    }
  }
  return payload && typeof payload === "object" ? payload : null;
}

async function recordPreflightResult(client, { workspaceId, job, preflightResult, resultStatus }) {
  assertSchema(validatePreflightResult, preflightResult, "CERTOPS_SNAPSHOT_INVALID");
  if (resultStatus !== "succeeded" || !job || job.operation !== "adcs-preflight") {
    throw serviceError(
      "preflightResult requires a succeeded adcs-preflight job",
      "CERTOPS_AGENT_RESULT_STATUS_INVALID",
    );
  }
  const payload = preflightPayloadOf(job);
  if (
    !payload ||
    payload.caConfig !== preflightResult.caConfig ||
    payload.template !== preflightResult.template
  ) {
    throw serviceError(
      "preflightResult does not match the job CA and template",
      "CERTOPS_SNAPSHOT_INVALID",
    );
  }
  const issuerId = job.subject_id;
  if (!issuerId) return;
  if (!job.id) {
    throw serviceError(
      "preflightResult requires the reporting job",
      "CERTOPS_SNAPSHOT_INVALID",
    );
  }
  // last_preflight follows dispatch order, which is preflight_seq assigned
  // under the workspace lock. created_at is the transaction start and can
  // be older for the job that was inserted later. Equal sequences keep the
  // greater job id, and the same job may report again.
  await dbOf(client).query(
    `UPDATE certificate_issuers AS i
        SET last_preflight = $3::jsonb,
            last_preflight_job_id = $4,
            updated_at = NOW()
      WHERE i.workspace_id = $1
        AND i.id = $2
        AND EXISTS (
          SELECT 1
            FROM certificate_jobs incoming
           WHERE incoming.workspace_id = i.workspace_id
             AND incoming.id = $4
             AND incoming.preflight_seq IS NOT NULL
             AND (
               i.last_preflight_job_id IS NULL
               OR NOT EXISTS (
                 SELECT 1
                   FROM certificate_jobs stored
                  WHERE stored.workspace_id = i.workspace_id
                    AND stored.id = i.last_preflight_job_id
               )
               OR EXISTS (
                 SELECT 1
                   FROM certificate_jobs stored
                  WHERE stored.workspace_id = i.workspace_id
                    AND stored.id = i.last_preflight_job_id
                    AND (
                      incoming.preflight_seq > stored.preflight_seq
                      OR (
                        incoming.preflight_seq = stored.preflight_seq
                        AND incoming.id >= stored.id
                      )
                    )
               )
             )
        )`,
    [workspaceId, issuerId, JSON.stringify(preflightResult), job.id],
  );
}

async function proposeReconcileRequestId({
  client,
  workspaceId,
  enrollmentId,
  requestId,
  actorUserId,
  audit = writeAudit,
}) {
  const db = dbOf(client);
  const row = await loadEnrollment(db, workspaceId, enrollmentId);
  if (!row) throw serviceError("enrollment not found", "CERTOPS_ENROLLMENT_NOT_FOUND");
  if (row.state !== "submission_uncertain") {
    throw serviceError(
      "a RequestId can be proposed only while submission_uncertain",
      "CERTOPS_ENROLLMENT_TRANSITION_INVALID",
    );
  }
  const parsedRequestId = parseRequestId(requestId);
  if (parsedRequestId == null) {
    throw serviceError(
      "RequestId must be an integer from 1 to 2147483647",
      "CERTOPS_ENROLLMENT_TRANSITION_INVALID",
    );
  }
  await withTransaction(db, async (tx) => {
    const current = await loadEnrollment(tx, workspaceId, enrollmentId, { lock: true });
    if (!current) throw serviceError("enrollment not found", "CERTOPS_ENROLLMENT_NOT_FOUND");
    if (current.state !== "submission_uncertain") {
      throw serviceError(
        "a RequestId can be proposed only while submission_uncertain",
        "CERTOPS_ENROLLMENT_TRANSITION_INVALID",
      );
    }
    // Reconcile can end in an install, so a retired identity must be abandoned instead.
    if (await identityRetired(tx, workspaceId, current.certificate_id)) {
      throw serviceError("Certificate lifecycle blocks this operation", "CERTOPS_CERTIFICATE_RETIRED");
    }
    const updated = await tx.query(
      `UPDATE certificate_enrollments
          SET operator_request_id = $3, next_poll_at = NOW(), updated_at = NOW()
        WHERE workspace_id = $1 AND id = $2 AND state = 'submission_uncertain'
        RETURNING id`,
      [workspaceId, enrollmentId, parsedRequestId],
    );
    if (updated.rows.length !== 1) {
      throw serviceError(
        "enrollment state changed before the RequestId was proposed",
        "CERTOPS_ENROLLMENT_TRANSITION_INVALID",
      );
    }
    await audit({
      client: tx,
      actorUserId: actorUserId || null,
      subjectUserId: actorUserId || null,
      action: "CERTOPS_ENROLLMENT_RECONCILE_PROPOSED",
      targetType: "certificate_enrollment",
      workspaceId,
      metadata: { enrollmentId, requestId: parsedRequestId },
    });
  });
}

const RUNNING_JOB = new Set(["claimed", "running"]);
const UNSTARTED_JOB = new Set(["pending", "pending_approval", "approved"]);

async function cancelEnrollment({
  client,
  workspaceId,
  enrollmentId,
  actorUserId,
  audit = writeAudit,
}) {
  const db = dbOf(client);
  // Lock the enrollment, then its current job, so a concurrent claim or
  // scheduler tick either finishes first (and cancel sees its job) or waits.
  await withTransaction(db, async (tx) => {
    const row = await loadEnrollment(tx, workspaceId, enrollmentId, { lock: true });
    if (!row) throw serviceError("enrollment not found", "CERTOPS_ENROLLMENT_NOT_FOUND");
    if (row.current_job_id) {
      const job = await tx.query(
        `SELECT status FROM certificate_jobs
          WHERE workspace_id = $1 AND id = $2
          FOR UPDATE`,
        [workspaceId, row.current_job_id],
      );
      row.job_status = job.rows[0]?.status ?? row.job_status;
    }
    if (RUNNING_JOB.has(row.job_status)) {
      throw serviceError(
        "an attempt is still running on the agent",
        "CERTOPS_ENROLLMENT_JOB_ACTIVE",
      );
    }
    assertDirectTransition(row.state, "cancelled");
    const beforeCa = row.state === "requested" || row.state === "prepared";
    const cancelled = await tx.query(
      `UPDATE certificate_enrollments
          SET state = 'cancelled', next_poll_at = $3, updated_at = NOW()
        WHERE workspace_id = $1 AND id = $2 AND state = $4
        RETURNING id`,
      [workspaceId, enrollmentId, beforeCa ? null : new Date(), row.state],
    );
    if (cancelled.rows.length !== 1) {
      throw serviceError(
        "enrollment state changed before cancellation",
        "CERTOPS_ENROLLMENT_TRANSITION_INVALID",
      );
    }
    if (row.current_job_id && UNSTARTED_JOB.has(row.job_status)) {
      await tx.query(
        `UPDATE certificate_jobs
            SET status = 'cancelled', canceled_at = NOW(), updated_at = NOW()
          WHERE workspace_id = $1 AND id = $2
            AND status IN ('pending', 'pending_approval', 'approved')`,
        [workspaceId, row.current_job_id],
      );
    }
    await audit({
      client: tx,
      actorUserId: actorUserId || null,
      subjectUserId: actorUserId || null,
      action: "CERTOPS_ENROLLMENT_CANCELLED",
      targetType: "certificate_enrollment",
      workspaceId,
      metadata: { enrollmentId },
    });
  });
}

async function abandonEnrollment({
  client,
  workspaceId,
  enrollmentId,
  actorUserId,
  audit = writeAudit,
}) {
  const db = dbOf(client);
  await withTransaction(db, async (tx) => {
    const row = await loadEnrollment(tx, workspaceId, enrollmentId, { lock: true });
    if (!row) throw serviceError("enrollment not found", "CERTOPS_ENROLLMENT_NOT_FOUND");
    assertDirectTransition(row.state, "abandoned");
    const updated = await tx.query(
      `UPDATE certificate_enrollments
          SET state = 'abandoned', next_poll_at = NOW(), updated_at = NOW()
        WHERE workspace_id = $1 AND id = $2 AND state = $3
        RETURNING id`,
      [workspaceId, enrollmentId, row.state],
    );
    if (updated.rows.length !== 1) {
      throw serviceError(
        "enrollment state changed before abandon",
        "CERTOPS_ENROLLMENT_TRANSITION_INVALID",
      );
    }
    await audit({
      client: tx,
      actorUserId: actorUserId || null,
      subjectUserId: actorUserId || null,
      action: "CERTOPS_ENROLLMENT_ABANDONED",
      targetType: "certificate_enrollment",
      workspaceId,
      metadata: { enrollmentId },
    });
  });
}

async function countInstalledEnrollments({ client, workspaceId }) {
  const result = await dbOf(client).query(
    `SELECT count(*)::int AS n
       FROM certificate_enrollments
      WHERE workspace_id = $1 AND state = 'installed'`,
    [workspaceId],
  );
  return { enrollmentCount: Number(result.rows[0]?.n || 0) };
}

// Installation retry reuses the enrollment's immutable issuer/key/target.
// It is an explicit operator decision, not an automatic fresh enrollment.
async function retryEnrollmentInstallation({ client, workspaceId, enrollmentId, actorUserId,
  createJob = createCertificateJob, audit = writeAudit, env = process.env }) {
  return withTransaction(dbOf(client), async (tx) => {
    await lockWorkspaceForCertOpsSideEffect({ client: tx, workspaceId, env });
    const row = await loadEnrollment(tx, workspaceId, enrollmentId, { lock: true });
    if (!row) throw serviceError("enrollment not found", "CERTOPS_ENROLLMENT_NOT_FOUND");
    if (row.state !== "install_failed") {
      throw serviceError("only a failed installation can be retried", "CERTOPS_ENROLLMENT_TRANSITION_INVALID");
    }
    // A waiting SELECT FOR UPDATE can refresh e while retaining the joined
    // job from its pre-lock snapshot. Re-read that job after owning the row.
    if (row.current_job_id) {
      const current = await tx.query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2 AND enrollment_id=$3",
        [workspaceId,row.current_job_id,enrollmentId]);
      if (current.rows.length !== 1) throw serviceError("current installation job is not bound to this enrollment", "CERTOPS_ENROLLMENT_UNBOUND");
      if (enrollmentView({ ...row, job_status: current.rows[0].status }).activeJob) return { jobId: row.current_job_id, created: false };
    }
    if (!validAdcsTarget(row.deploy_target) || !row.agent_id) {
      throw serviceError("enrollment is missing its frozen installation target or agent", "CERTOPS_SNAPSHOT_INVALID");
    }
    if (await identityRetired(tx, workspaceId, row.certificate_id)) {
      throw serviceError("Certificate lifecycle blocks this operation", "CERTOPS_CERTIFICATE_RETIRED");
    }
    const attempt = Number(row.attempt || 0) + 1;
    const job = await createJob({ client: tx, workspaceId, operation: "continue-enrollment",
      allowEnrollmentContinuation: true, source: "api", requestedByUserId: actorUserId || null, subjectType: "managed_certificate",
      subjectId: row.certificate_id, assignedAgentId: row.agent_id,
      payload: storedAdcsPayload({ certificateId: row.certificate_id, target: row.deploy_target }),
      enrollmentId: row.id, env });
    await tx.query(`UPDATE certificate_enrollments
      SET attempt = $3, current_job_id = $4, next_poll_at = NULL, updated_at = NOW()
      WHERE workspace_id = $1 AND id = $2`, [workspaceId,enrollmentId,attempt,job.id]);
    await audit({ client: tx, actorUserId: actorUserId || null, subjectUserId: actorUserId || null,
      action: "certops.enrollment.installation_retry_requested", targetType: "certificate_enrollment",
      workspaceId, metadata: { enrollmentId, jobId: job.id, attempt } });
    return { jobId: job.id, created: true };
  });
}

async function recoverOrphanedEnrollment({ client, workspaceId, enrollmentId, orphanedJobId,
  acknowledgeUnknownEffect, reason, actorUserId, createJob = createCertificateJob,
  audit = writeAudit, env = process.env }) {
  if (typeof orphanedJobId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(orphanedJobId)) {
    throw serviceError("Recovery requires an orphaned job identifier", "CERTOPS_ENROLLMENT_UNBOUND");
  }
  orphanedJobId=orphanedJobId.toLowerCase();
  if (acknowledgeUnknownEffect !== true) throw serviceError("Unknown effects must be explicitly acknowledged", "CERTOPS_ENROLLMENT_RECOVERY_ACK_REQUIRED");
  if (typeof reason !== "string" || !reason.trim() || reason.trim().length > 500 || /[\u0000-\u001f\u007f]/.test(reason)) {
    throw serviceError("A printable recovery reason of 1 to 500 characters is required", "CERTOPS_ENROLLMENT_RECOVERY_REASON_INVALID");
  }
  const safeReason = redactGenericSecrets(reason.trim());
  return withTransaction(dbOf(client), async (tx) => {
    await lockWorkspaceForCertOpsSideEffect({ client: tx, workspaceId, env });
    const row = await loadEnrollment(tx, workspaceId, enrollmentId, { lock: true });
    if (!row) throw serviceError("enrollment not found", "CERTOPS_ENROLLMENT_NOT_FOUND");
    if (!["requested", "prepared", "submitting", "pending_issuance", "submission_uncertain", "issued", "validation_deferred", "validated", "installing"].includes(row.state)) {
      throw serviceError("terminal enrollments and failed installations cannot be revived by recovery", "CERTOPS_ENROLLMENT_TRANSITION_INVALID");
    }
    const jobs = await tx.query(`SELECT id,status,operation,mode,executor_kind,assigned_agent_id,needs_operator_reconciliation,payload
      FROM certificate_jobs WHERE workspace_id=$1 AND enrollment_id=$2 AND id=ANY($3::uuid[])`,
      [workspaceId,enrollmentId,[orphanedJobId,row.current_job_id].filter(Boolean)]);
    const original = jobs.rows.find(job => job.id === orphanedJobId);
    const current = jobs.rows.find(job => job.id === row.current_job_id);
    const recoverableOperation = original && (["renew", "continue-enrollment"].includes(original.operation) ||
      (original.operation === "issue" && row.deploy_target?.type === "windows-cert-store"));
    if (!original || original.status !== "orphaned_unknown_effect" || original.needs_operator_reconciliation !== true ||
        original.mode !== "real" || original.executor_kind !== "agent" || !recoverableOperation || original.assigned_agent_id !== row.agent_id) {
      throw serviceError("Recovery requires the exact enrollment-bound orphaned job awaiting reconciliation", "CERTOPS_ENROLLMENT_UNBOUND");
    }
    if (row.current_job_id !== orphanedJobId) {
      const linked = current?.payload?.metadata?.some(item => item.name === "adcs.recoveryFromJobId" && item.value === orphanedJobId);
      if (linked && current.operation === "continue-enrollment" && current.mode === "real" && current.executor_kind === "agent" &&
          current.assigned_agent_id === row.agent_id && enrollmentView({ ...row, job_status: current.status }).activeJob) {
        return {jobId:current.id,created:false};
      }
      throw serviceError("Another enrollment attempt has superseded the orphaned job", "CERTOPS_ENROLLMENT_JOB_ACTIVE");
    }
    if (!validAdcsTarget(row.deploy_target) || !row.agent_id) {
      throw serviceError("enrollment is missing its frozen installation target or agent", "CERTOPS_SNAPSHOT_INVALID");
    }
    // Recovery always starts a continuation that can retrieve and install, so
    // every state is refused for a retired identity. Abandonment stays available.
    if (await identityRetired(tx, workspaceId, row.certificate_id)) {
      throw serviceError("Certificate lifecycle blocks this operation", "CERTOPS_CERTIFICATE_RETIRED");
    }
    const attempt=Number(row.attempt || 0)+1;
    const job=await createJob({client:tx,workspaceId,operation:"continue-enrollment",allowEnrollmentContinuation:true,
      source:"api",requestedByUserId:actorUserId || null,subjectType:"managed_certificate",subjectId:row.certificate_id,
      assignedAgentId:row.agent_id,enrollmentId:row.id,env,
      payload:storedAdcsPayload({certificateId:row.certificate_id,target:row.deploy_target,
        metadata:[{name:"adcs.recoveryFromJobId",value:orphanedJobId}]})});
    await tx.query(`UPDATE certificate_enrollments SET attempt=$3,current_job_id=$4,next_poll_at=NULL,updated_at=NOW()
      WHERE workspace_id=$1 AND id=$2`,[workspaceId,enrollmentId,attempt,job.id]);
    // Preserve the orphan's unknown-effect flag as historical evidence. A new
    // native continuation must prove the actual outcome instead of clearing it.
    await audit({client:tx,actorUserId:actorUserId || null,subjectUserId:actorUserId || null,
      action:"certops.enrollment.recovery_requested",targetType:"certificate_enrollment",workspaceId,
      metadata:{enrollmentId,orphanedJobId,jobId:job.id,attempt,acknowledgeUnknownEffect:true,reason:safeReason}});
    return {jobId:job.id,created:true};
  });
}

async function loadDispatchEnrollment(client, workspaceId, enrollmentId) {
  const row = await loadEnrollment(dbOf(client), workspaceId, enrollmentId);
  if (!row) return null;
  const view = enrollmentView(row);
  const attempt = view.attempt > 0 ? view.attempt : 1;
  if (view.attempt === 0) {
    await dbOf(client).query(
      `UPDATE certificate_enrollments SET attempt = 1, updated_at = NOW()
        WHERE workspace_id = $1 AND id = $2 AND attempt = 0`,
      [workspaceId, enrollmentId],
    );
  }
  return { ...view, attempt };
}

async function claimDueEnrollment(db, workspaceId, enrollmentId, now) {
  const claimed = await db.query(
    `UPDATE certificate_enrollments
        SET next_poll_at = NULL, updated_at = NOW()
      WHERE workspace_id = $1 AND id = $2
        AND next_poll_at IS NOT NULL
        AND next_poll_at <= $3
      RETURNING id`,
    [workspaceId, enrollmentId, now],
  );
  return claimed.rows.length === 1;
}

async function scheduleDueEnrollments({ client, now = new Date(), createJob = createCertificateJob }) {
  const db = dbOf(client);
  const due = await db.query(
    `SELECT e.workspace_id, e.id
       FROM certificate_enrollments e
      WHERE e.next_poll_at IS NOT NULL AND e.next_poll_at <= $1`,
    [now],
  );
  const created = [];
  // The candidate list is only a hint. Each row is locked and re-decided
  // inside its own transaction, so a cancel or claim that committed after the
  // list was read wins.
  for (const candidate of due.rows) {
    let dispatched = null;
    try {
      dispatched = await withTransaction(db, async (tx) => {
      const row = await loadEnrollment(tx, candidate.workspace_id, candidate.id, {
        lock: "skip",
      });
      if (!row) return null;
      const view = enrollmentView(row);
      const snapshot = JSON.parse(Buffer.from(row.snapshot_bytes).toString("utf8"));
      const decision = decideContinuation(view, snapshot, now);
      if (!decision) return null;
      if (decision.dispatch && decision.reason !== "free_key" && row.job_status === "rejected" &&
          row.job_error_code === "CERTOPS_IIS_REASSOCIATION_UNSAFE") {
        if (!await claimDueEnrollment(tx, row.workspace_id, row.id, now)) return null;
        await tx.query(`UPDATE certificate_enrollments SET last_error_code=$3, updated_at=NOW()
          WHERE workspace_id=$1 AND id=$2`, [row.workspace_id, row.id, row.job_error_code]);
        return null;
      }
      if (decision.reason === "retrieve_reconciliation") {
        if (!await claimDueEnrollment(tx, row.workspace_id, row.id, now)) return null;
        await tx.query(`UPDATE certificate_enrollments
          SET state = 'submission_uncertain', last_error_code = 'ADCS_RETRIEVAL_RECONCILIATION_REQUIRED',
              operator_request_id = NULL, next_poll_at = NULL, updated_at = NOW()
          WHERE workspace_id = $1 AND id = $2`, [row.workspace_id, row.id]);
        await writeAudit({client: tx, workspaceId: row.workspace_id, actorUserId: null, subjectUserId: null,
          action: "CERTOPS_ENROLLMENT_RETRIEVAL_RECONCILIATION_REQUIRED", targetType: "certificate_enrollment",
          metadata: {enrollmentId: row.id, requestId: row.request_id, reason: "pending_timeout_after_uncertain_retrieve"}});
        return null;
      }
      if (!decision.dispatch && decision.state !== "expired") return null;
      // Poll, retry and operator reconcile can all retrieve an approved leaf
      // and install it. Only key cleanup and timeout expiry stay allowed.
      if (decision.dispatch && decision.reason !== "free_key" &&
          await identityRetired(tx, row.workspace_id, row.certificate_id)) {
        if (!await claimDueEnrollment(tx, row.workspace_id, row.id, now)) return null;
        logger.warn("certops enrollment installation blocked by certificate lifecycle", {
          workspaceId: row.workspace_id,
          enrollmentId: row.id,
          reason: decision.reason,
        });
        return null;
      }
      const target = row.deploy_target;
      if (!validAdcsTarget(target)) {
        throw serviceError(
          "enrollment is missing its Windows certificate destination",
          "CERTOPS_SNAPSHOT_INVALID",
        );
      }
      const claimed = await claimDueEnrollment(tx, row.workspace_id, row.id, now);
      if (!claimed) return null;
      if (decision.state === "expired") {
        await tx.query(
          `UPDATE certificate_enrollments
              SET state = 'expired', updated_at = NOW()
            WHERE workspace_id = $1 AND id = $2`,
          [row.workspace_id, row.id],
        );
      }
      const attempt = Number(row.attempt || 0) + 1;
      const requestId = parseRequestId(row.operator_request_id);
      const reconcileMetadata =
        requestId != null
          ? [{ name: "adcs.reconcileRequestId", value: requestId }]
          : undefined;
      const payload = storedAdcsPayload({
        certificateId: row.certificate_id,
        target,
        metadata: reconcileMetadata,
      });
      const job = await createJob({
        client: tx,
        workspaceId: row.workspace_id,
        operation: "continue-enrollment",
        allowEnrollmentContinuation: true,
        subjectType: "managed_certificate",
        subjectId: row.certificate_id,
        assignedAgentId: row.agent_id,
        payload,
        enrollmentId: row.id,
      });
      await tx.query(
        `UPDATE certificate_enrollments
            SET attempt = $3, current_job_id = $4, updated_at = NOW()
          WHERE workspace_id = $1 AND id = $2`,
        [row.workspace_id, row.id, attempt, job.id],
      );
      if (decision.state === "expired" || decision.reason === "free_key" || decision.reason === "reconcile" || decision.reason === "resume_installation") {
        // Claiming consumed the previous poll date. Keep a retry date until
        // the native agent acknowledges actual key cleanup; activeJob prevents
        // another dispatch while this continuation is still in progress.
        await tx.query(
          `UPDATE certificate_enrollments SET next_poll_at = $3, updated_at = NOW()
            WHERE workspace_id = $1 AND id = $2`,
          [row.workspace_id, row.id, nextPollAt(now, snapshot.pollInterval || 900)],
        );
      }
      return { enrollmentId: row.id, jobId: job.id, attempt, target: payload.target };
    });
    } catch (error) {
      // One malformed row must not abort continuations already due in other workspaces.
      logger.warn("certops enrollment continuation skipped", {
        workspaceId: candidate.workspace_id,
        enrollmentId: candidate.id,
        code: error.code || null,
      });
      continue;
    }
    if (dispatched) created.push(dispatched);
  }
  return created;
}

function clampPage(value, fallback) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) return fallback;
  return parsed;
}

function readLimit(value) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed)) return 50;
  return Math.min(100, Math.max(1, parsed));
}

function publicPreflight(value) {
  if (!value || typeof value !== "object") return null;
  const certs = Array.isArray(value.caCertificates) ? value.caCertificates : [];
  return {
    caConfig: value.caConfig || null,
    template: value.template || null,
    templateCheck: value.templateCheck || null,
    caCheck: value.caCheck || null,
    caCertificates: certs.slice(0, 8).map((cert) => ({
      keySha256: cert?.keySha256 || null,
      thumbprintSha1: cert?.thumbprintSha1 || null,
      notBefore: cert?.notBefore || null,
      notAfter: cert?.notAfter || null,
    })),
  };
}

function snapshotFields(bytes) {
  try {
    const snapshot = JSON.parse(Buffer.from(bytes).toString("utf8"));
    return {
      caConfig: snapshot.caConfig || null,
      template: snapshot.template || null,
      caKeySha256: snapshot.caKeySha256 || null,
      authorizedDnsNames: Array.isArray(snapshot.authorizedDnsNames)
        ? snapshot.authorizedDnsNames
        : [],
    };
  } catch (_error) {
    return { caConfig: null, template: null, caKeySha256: null, authorizedDnsNames: [] };
  }
}

async function listIssuers({
  client,
  workspaceId,
  limit = 50,
  offset = 0,
  includeUnconfigured = false,
  env = process.env,
  readinessLoader = require("./adcsPreflightIncidents").loadIssuerPreflightReadiness,
}) {
  const db = dbOf(client);
  const pageSize = readLimit(limit);
  const pageOffset = clampPage(offset, 0);
  const configuredOnly = includeUnconfigured
    ? ""
    : "AND (i.kind <> 'adcs' OR i.current_version > 0)";
  const [rows, total] = await Promise.all([
    db.query(
      `SELECT i.id, i.kind, i.name, i.current_version, i.revalidation_required,
              i.last_preflight, i.last_preflight_job_id, i.updated_at, v.ca_key_sha256 AS confirmed_key_sha256,
              v.ca_config, v.template, v.confirmed_at,w.certops_paused,
              (SELECT jsonb_agg(history ORDER BY history.preflight_seq DESC NULLS LAST,history.created_at DESC,history.id DESC) FROM (
                SELECT j.id,j.assigned_agent_id,j.status,j.source,j.error_code,j.result_metadata,
                       j.created_at,j.completed_at,j.updated_at,j.preflight_seq
                  FROM certificate_jobs j
                 WHERE j.workspace_id=i.workspace_id AND j.subject_id=i.id::text
                   AND j.operation='adcs-preflight' AND j.created_at >= v.confirmed_at
                   AND (j.result_metadata->'preflightContext'->>'issuerVersion' IS NULL
                        OR j.result_metadata->'preflightContext'->>'issuerVersion'=i.current_version::text)
                 ORDER BY j.preflight_seq DESC NULLS LAST,j.created_at DESC,j.id DESC LIMIT 100
              ) history) AS refresh_jobs
         FROM certificate_issuers i
         JOIN workspaces w ON w.id=i.workspace_id
         LEFT JOIN certificate_issuer_versions v
           ON v.workspace_id = i.workspace_id
          AND v.issuer_id = i.id
          AND v.version = i.current_version
        WHERE i.workspace_id = $1
          ${configuredOnly}
        ORDER BY i.name ASC, i.id ASC
        LIMIT $2 OFFSET $3`,
      [workspaceId, pageSize, pageOffset],
    ),
    db.query(
      `SELECT count(*)::int AS n
         FROM certificate_issuers i
        WHERE i.workspace_id = $1
          ${configuredOnly}`,
      [workspaceId],
    ),
  ]);
  const readinessService = require("./adcsPreflightIncidents");
  const readinessByIssuer = readinessLoader === readinessService.loadIssuerPreflightReadiness
    ? await readinessService.loadIssuerPreflightReadinessBatch({db,workspaceId,issuers:rows.rows.filter(row=>row.kind==="adcs"),env})
    : null;
  return {
    items: await Promise.all(rows.rows.map(async (row) => {
      const version = {
        version: row.current_version, ca_config: row.ca_config, template: row.template,
        ca_key_sha256: row.confirmed_key_sha256, confirmed_at: row.confirmed_at,
        revalidation_required: row.revalidation_required, certops_paused: row.certops_paused,
      };
      const readiness = row.kind === "adcs"
        ? (readinessByIssuer?.get(row.id) || await readinessLoader({ db, workspaceId, issuerId: row.id, version, env }))
        : { checks: [], agents: [] };
      const history = issuerRefreshStates(row.refresh_jobs, version).map((check) => {
        const agent = readiness.agents.find((a) => String(a.id) === String(check.agentId));
        const eligibility = agent && require("./adcsPreflightGate").renewalAgentEligibility(agent, { target: null, env });
        if (eligibility?.eligible) return { ...check, renewalReady: false };
        const unavailable = !agent || agent.status !== "active";
        return {
          ...check, state: unavailable ? "agent_unavailable" : "agent_ineligible", renewalReady: false,
          code: unavailable ? "CERTOPS_ADCS_AGENT_UNAVAILABLE" : "CERTOPS_ADCS_AGENT_INELIGIBLE",
          eligibilityReason: eligibility?.reason || "agent_unavailable",
        };
      });
      return {
        id: row.id,
        kind: row.kind,
        name: row.name,
        currentVersion: row.current_version,
        revalidationRequired: row.revalidation_required === true,
        confirmedKeySha256: row.confirmed_key_sha256 || null,
        caConfig: row.ca_config || null,
        template: row.template || null,
        lastPreflight: publicPreflight(row.last_preflight),
        lastPreflightJobId: row.last_preflight_job_id || null,
        preflightRefresh: history,
        renewalReadiness: {
          dueCount: readiness.dueCount || 0, affectedCount: readiness.affectedCount || 0,
          checks: readiness.checks, truncated: readiness.truncated === true,
        },
        updatedAt: row.updated_at,
      };
    })),
    pagination: { limit: pageSize, offset: pageOffset, total: Number(total.rows[0]?.n || 0) },
  };
}

async function listEnrollments({ client, workspaceId, limit = 50, offset = 0 }) {
  const db = dbOf(client);
  const pageSize = readLimit(limit);
  const pageOffset = clampPage(offset, 0);
  const [rows, total] = await Promise.all([
    db.query(
      `SELECT e.id, e.state, e.attempt, e.snapshot_bytes, e.operator_request_id,
              e.request_id, e.last_error_code, e.issuer_id, e.issuer_version,
              e.certificate_id, e.updated_at, i.name AS issuer_name,
              i.revalidation_required, i.current_version,
              j.status AS job_status, j.error_code AS job_error_code,
              left(j.error_message, 180) AS job_error_message
         FROM certificate_enrollments e
         JOIN certificate_issuers i
           ON i.workspace_id = e.workspace_id AND i.id = e.issuer_id
         LEFT JOIN certificate_jobs j
           ON j.workspace_id = e.workspace_id AND j.id = e.current_job_id
        WHERE e.workspace_id = $1
        ORDER BY e.updated_at DESC, e.id ASC
        LIMIT $2 OFFSET $3`,
      [workspaceId, pageSize, pageOffset],
    ),
    db.query(
      `SELECT count(*)::int AS n FROM certificate_enrollments WHERE workspace_id = $1`,
      [workspaceId],
    ),
  ]);
  return {
    items: rows.rows.map((row) => {
      const snapshot = snapshotFields(row.snapshot_bytes);
      return {
        id: row.id,
        state: row.state,
        attempt: row.attempt,
        requestId: parseRequestId(row.request_id),
        operatorRequestId: parseRequestId(row.operator_request_id),
        lastErrorCode: row.last_error_code,
        issuerId: row.issuer_id,
        issuerName: row.issuer_name,
        issuerVersion: row.issuer_version,
        issuerCurrentVersion: row.current_version,
        snapshotStale: Number(row.issuer_version) !== Number(row.current_version),
        revalidationRequired: row.revalidation_required === true,
        certificateId: row.certificate_id,
        updatedAt: row.updated_at,
        jobStatus: row.job_status || null,
        jobErrorCode: row.job_error_code || null,
        jobErrorMessage: row.job_error_message || null,
        ...snapshot,
      };
    }),
    pagination: { limit: pageSize, offset: pageOffset, total: Number(total.rows[0]?.n || 0) },
  };
}

module.exports = {
  OPEN_ENROLLMENT_STATES,
  findOpenEnrollment,
  isSafeInitialLocalRefusal,
  isSafeRetryableAutomaticEnrollment,
  abandonEnrollment,
  cancelEnrollment,
  attachEnrollmentDispatch,
  confirmIssuerKey,
  countInstalledEnrollments,
  createEnrollment,
  createIssuer,
  discardUnconfiguredIssuer,
  dispatchPreflight,
  listEnrollments,
  listIssuers,
  loadDispatchEnrollment,
  proposeReconcileRequestId,
  recordEnrollmentResult,
  recordPreflightResult,
  scheduleDueEnrollments,
  retryEnrollmentInstallation,
  retryDryRunBlockedRenewal,
  recoverOrphanedEnrollment,
};
