"use strict";

const Ajv = require("ajv");
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
const { createCertificateJob } = require("./jobs");
const { adcsCaBucket } = require("./renewalCapacity");
const { lockWorkspaceForCertOpsSideEffect } = require("./workspaceKillSwitch");
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
    metadata: { issuerId: row.id, kind },
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
}) {
  const db = dbOf(client);
  return withTransaction(db, async (tx) => {
    if (typeof beforeLock === "function") await beforeLock(tx);
    await tx.query("SELECT pg_advisory_xact_lock(hashtext($1::text))", [
      `adcs-preflight:${workspaceId}`,
    ]);
    const recent = await tx.query(
      `SELECT count(*)::int AS n
         FROM certificate_jobs
        WHERE workspace_id = $1
          AND operation = 'adcs-preflight'
          AND created_at > NOW() - INTERVAL '1 hour'`,
      [workspaceId],
    );
    if (Number(recent.rows[0]?.n || 0) >= PREFLIGHT_PER_HOUR) {
      throw serviceError(
        "AD CS preflight rate limit exceeded for this workspace",
        "CERTOPS_PREFLIGHT_RATE_LIMITED",
      );
    }
    const job = await createJob({
      client: tx,
      workspaceId,
      operation: "adcs-preflight",
      allowIssuerPreflight: true,
      source: "api",
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
        RETURNING preflight_seq`,
      [workspaceId, issuerId],
    );
    const preflightSeq = sequenced.rows[0]?.preflight_seq;
    if (preflightSeq == null) {
      throw serviceError("issuer not found", "CERTOPS_ISSUER_NOT_FOUND");
    }
    await tx.query(
      `UPDATE certificate_jobs
          SET preflight_seq = $3
        WHERE workspace_id = $1 AND id = $2`,
      [workspaceId, job.id, preflightSeq],
    );
    await audit({
      client: tx,
      actorUserId: actorUserId || null,
      subjectUserId: actorUserId || null,
      action: "CERTOPS_ISSUER_PREFLIGHT_DISPATCHED",
      targetType: "certificate_issuer",
      workspaceId,
      metadata: { issuerId, jobId: job.id, agentId },
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
    `SELECT id, kind, current_version, last_preflight
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
    metadata: { issuerId, version, caKeySha256 },
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
  source = "api",
  mode = "real",
  env,
  idempotencyKey,
  actorUserId,
  createJob = createCertificateJob,
  audit = writeAudit,
}) {
  if (!target || target.type !== "windows-iis" || !target.binding) {
    throw serviceError(
      "enrollment target must be a windows-iis binding",
      "CERTOPS_SNAPSHOT_INVALID",
    );
  }
  const db = dbOf(client);
  return withTransaction(db, async (tx) => {
    if (source === "automation") {
      await lockWorkspaceForCertOpsSideEffect({
        client: tx,
        workspaceId,
        env,
      });
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
      `SELECT v.version, v.ca_config, v.template, v.ca_key_sha256, i.kind,
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
    if (issuer.revalidation_required === true) {
      throw serviceError(
        "issuer requires revalidation before new enrollments",
        "CERTOPS_ISSUER_REVALIDATION_REQUIRED",
      );
    }
    assertIssuerKind(issuer.kind);
    const frozen = freezeSnapshot({
      issuerId: resolvedIssuerId,
      issuerVersion: issuer.version,
      caConfig: issuer.ca_config,
      caKeySha256: issuer.ca_key_sha256,
      template: issuer.template,
      authorizedDnsNames,
      keyAlgorithm,
      keySize,
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
      operation: "renew",
      source,
      mode,
      requestedByUserId: actorUserId || null,
      idempotencyKey,
      env,
      subjectType: "managed_certificate",
      subjectId: certificateId,
      assignedAgentId: agentId,
      payload,
      enrollmentId,
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
    return { enrollmentId, snapshotSha256: frozen.sha256, jobId: job.id };
  });
}

// lock: false | true (wait for the row) | "skip" (return null if another tx holds it).
async function loadEnrollment(db, workspaceId, enrollmentId, { lock = false } = {}) {
  const lockClause = lock === "skip" ? "FOR UPDATE OF e SKIP LOCKED" : lock ? "FOR UPDATE OF e" : "";
  const result = await db.query(
    `SELECT e.id, e.workspace_id, e.state, e.attempt, e.snapshot_bytes, e.snapshot_sha256,
            e.operator_request_id, e.pending_since, e.next_poll_at,
            e.last_error_code, e.current_job_id, e.certificate_id, e.agent_id,
            e.deploy_target, j.status AS job_status
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
  const active = row.job_status && ["pending_approval", "approved", "pending", "claimed", "running"].includes(row.job_status);
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
    enrollmentResult.state === "validation_deferred"
  ) {
    nextAt = nextPollAt(new Date(), pollSeconds);
  }
  if (enrollmentResult.state === "submitting" && enrollmentResult.errorCode === UNREACHABLE_ERROR) {
    nextAt = nextPollAt(new Date(), pollSeconds);
  }
  // A poll date left over from an earlier pending attempt must not survive a
  // terminal result, or every maintenance sweep keeps selecting the row.
  const keepsPolling =
    enrollmentResult.state === "pending_issuance" ||
    enrollmentResult.state === "validation_deferred" ||
    (enrollmentResult.state === "submitting" && enrollmentResult.errorCode === UNREACHABLE_ERROR);
  if (!keepsPolling) nextAt = null;
  await db.query(
    `UPDATE certificate_enrollments
        SET state = $3,
            request_id = COALESCE($4, request_id),
            last_error_code = $5,
            pending_since = $6,
            next_poll_at = $7,
            installed_at = CASE WHEN $3 = 'installed' THEN COALESCE(installed_at, NOW()) ELSE installed_at END,
            updated_at = NOW()
      WHERE workspace_id = $1 AND id = $2`,
    [
      workspaceId,
      job.enrollment_id,
      enrollmentResult.state,
      Number.isInteger(enrollmentResult.requestId) ? enrollmentResult.requestId : null,
      enrollmentResult.errorCode || null,
      pendingSince,
      nextAt,
    ],
  );
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
      "RequestId must be an integer from 1 to 4294967295",
      "CERTOPS_ENROLLMENT_TRANSITION_INVALID",
    );
  }
  await db.query(
    `UPDATE certificate_enrollments
        SET operator_request_id = $3, next_poll_at = NOW(), updated_at = NOW()
      WHERE workspace_id = $1 AND id = $2`,
    [workspaceId, enrollmentId, parsedRequestId],
  );
  await audit({
    client: db,
    actorUserId: actorUserId || null,
    subjectUserId: actorUserId || null,
    action: "CERTOPS_ENROLLMENT_RECONCILE_PROPOSED",
    targetType: "certificate_enrollment",
    workspaceId,
    metadata: { enrollmentId, requestId: parsedRequestId },
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
    await tx.query(
      `UPDATE certificate_enrollments
          SET state = 'cancelled', next_poll_at = $3, updated_at = NOW()
        WHERE workspace_id = $1 AND id = $2`,
      [workspaceId, enrollmentId, beforeCa ? null : new Date()],
    );
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
  const row = await loadEnrollment(db, workspaceId, enrollmentId);
  if (!row) throw serviceError("enrollment not found", "CERTOPS_ENROLLMENT_NOT_FOUND");
  assertDirectTransition(row.state, "abandoned");
  await db.query(
    `UPDATE certificate_enrollments
        SET state = 'abandoned', next_poll_at = NOW(), updated_at = NOW()
      WHERE workspace_id = $1 AND id = $2`,
    [workspaceId, enrollmentId],
  );
  await audit({
    client: db,
    actorUserId: actorUserId || null,
    subjectUserId: actorUserId || null,
    action: "CERTOPS_ENROLLMENT_ABANDONED",
    targetType: "certificate_enrollment",
    workspaceId,
    metadata: { enrollmentId },
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
    const dispatched = await withTransaction(db, async (tx) => {
      const row = await loadEnrollment(tx, candidate.workspace_id, candidate.id, {
        lock: "skip",
      });
      if (!row) return null;
      const view = enrollmentView(row);
      const snapshot = JSON.parse(Buffer.from(row.snapshot_bytes).toString("utf8"));
      const decision = decideContinuation(view, snapshot, now);
      if (!decision) return null;
      if (!decision.dispatch && decision.state !== "expired") return null;
      const target = row.deploy_target;
      if (!target || target.type !== "windows-iis") {
        throw serviceError(
          "enrollment is missing its IIS deployment target",
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
      return { enrollmentId: row.id, jobId: job.id, attempt, target: payload.target };
    });
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
              i.last_preflight, i.updated_at, v.ca_key_sha256 AS confirmed_key_sha256,
              v.ca_config, v.template
         FROM certificate_issuers i
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
  return {
    items: rows.rows.map((row) => ({
      id: row.id,
      kind: row.kind,
      name: row.name,
      currentVersion: row.current_version,
      revalidationRequired: row.revalidation_required === true,
      confirmedKeySha256: row.confirmed_key_sha256 || null,
      caConfig: row.ca_config || null,
      template: row.template || null,
      lastPreflight: publicPreflight(row.last_preflight),
      updatedAt: row.updated_at,
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
};
