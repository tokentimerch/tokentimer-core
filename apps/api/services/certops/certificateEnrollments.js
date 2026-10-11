"use strict";

const Ajv = require("ajv");
const addFormats = require("ajv-formats");
const { pool } = require("../../db/database");
const enrollmentResultSchema = require("../../../../packages/contracts/certops/enrollment-result-contract.schema.json");
const preflightResultSchema = require("../../../../packages/contracts/certops/adcs-preflight-result-contract.schema.json");
const snapshotSchema = require("../../../../packages/contracts/certops/enrollment-snapshot.schema.json");

const ajv = new Ajv({ allErrors: true, strict: false });
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
const {
  PREFLIGHT_PER_HOUR,
  UNREACHABLE_ERROR,
  assertForwardTransition,
  assertIssuerKind,
  attachEnrollmentDispatch,
  confirmedKeyAllowed,
  decideContinuation,
  freezeSnapshot,
  nextPollAt,
  serviceError,
  storedAdcsPayload,
} = require("./enrollmentLifecycle");

function dbOf(client) {
  return client || pool;
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
    action: "certops.issuer.created",
    targetType: "certificate_issuer",
    workspaceId,
    metadata: { issuerId: row.id, kind },
  });
  return row;
}

async function dispatchPreflight({
  client,
  workspaceId,
  issuerId,
  agentId,
  caConfig,
  template,
  actorUserId,
}) {
  const db = dbOf(client);
  const recent = await db.query(
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
  const job = await createCertificateJob({
    client: db,
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
  await writeAudit({
    client: db,
    actorUserId: actorUserId || null,
    subjectUserId: actorUserId || null,
    action: "certops.issuer.preflight_dispatched",
    targetType: "certificate_issuer",
    workspaceId,
    metadata: { issuerId, jobId: job.id, agentId },
  });
  return job;
}

async function confirmIssuerKey({
  client,
  workspaceId,
  issuerId,
  caKeySha256,
  caConfig,
  template,
  actorUserId,
}) {
  const db = dbOf(client);
  const issuer = await db.query(
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
  const version = Number(row.current_version || 0) + 1;
  await db.query(
    `INSERT INTO certificate_issuer_versions (
       workspace_id, issuer_id, version, ca_config, template, transport,
       ca_key_sha256, confirmed_at, config
     ) VALUES ($1,$2,$3,$4,$5,'dcom',$6,NOW(),$7::jsonb)`,
    [
      workspaceId,
      issuerId,
      version,
      caConfig || preflight.caConfig,
      template || preflight.template,
      caKeySha256,
      JSON.stringify({ caKeySha256, templateOid: preflight.templateCheck?.templateOid || null }),
    ],
  );
  await db.query(
    `UPDATE certificate_issuers
        SET current_version = $3, revalidation_required = false, updated_at = NOW()
      WHERE workspace_id = $1 AND id = $2`,
    [workspaceId, issuerId, version],
  );
  await writeAudit({
    client: db,
    actorUserId: actorUserId || null,
    subjectUserId: actorUserId || null,
    action: "certops.issuer.key_confirmed",
    targetType: "certificate_issuer",
    workspaceId,
    metadata: { issuerId, version, caKeySha256 },
  });
  return { issuerId, version, caKeySha256 };
}

async function createEnrollment({
  client,
  workspaceId,
  issuerId,
  certificateId,
  agentId,
  target,
  authorizedDnsNames,
  keyAlgorithm,
  keySize,
  actorUserId,
}) {
  const db = dbOf(client);
  const version = await db.query(
    `SELECT v.version, v.ca_config, v.template, v.ca_key_sha256, i.kind
       FROM certificate_issuer_versions v
       JOIN certificate_issuers i
         ON i.workspace_id = v.workspace_id AND i.id = v.issuer_id
      WHERE v.workspace_id = $1
        AND v.issuer_id = $2
        AND v.version = i.current_version
        AND v.ca_key_sha256 IS NOT NULL`,
    [workspaceId, issuerId],
  );
  const issuer = version.rows[0];
  if (!issuer) throw serviceError("confirmed issuer version not found", "CERTOPS_ISSUER_NOT_FOUND");
  assertIssuerKind(issuer.kind);
  const frozen = freezeSnapshot({
    issuerId,
    issuerVersion: issuer.version,
    caConfig: issuer.ca_config,
    caKeySha256: issuer.ca_key_sha256,
    template: issuer.template,
    authorizedDnsNames,
    keyAlgorithm,
    keySize,
  });
  const inserted = await db.query(
    `INSERT INTO certificate_enrollments (
       workspace_id, certificate_id, issuer_id, issuer_version, agent_id,
       state, attempt, snapshot_bytes, snapshot_sha256
     ) VALUES ($1,$2,$3,$4,$5,'requested',0,$6,$7)
     RETURNING id`,
    [
      workspaceId,
      certificateId,
      issuerId,
      issuer.version,
      agentId,
      frozen.bytes,
      frozen.sha256,
    ],
  );
  const enrollmentId = inserted.rows[0].id;
  const payload = storedAdcsPayload({ certificateId, target });
  const job = await createCertificateJob({
    client: db,
    workspaceId,
    operation: "renew",
    subjectType: "managed_certificate",
    subjectId: certificateId,
    assignedAgentId: agentId,
    payload,
    enrollmentId,
  });
  await db.query(
    `UPDATE certificate_enrollments
        SET current_job_id = $3, updated_at = NOW()
      WHERE workspace_id = $1 AND id = $2`,
    [workspaceId, enrollmentId, job.id],
  );
  await writeAudit({
    client: db,
    actorUserId: actorUserId || null,
    subjectUserId: actorUserId || null,
    action: "certops.enrollment.created",
    targetType: "certificate_enrollment",
    workspaceId,
    metadata: { enrollmentId, issuerId, jobId: job.id },
  });
  return { enrollmentId, snapshotSha256: frozen.sha256, jobId: job.id };
}

async function loadEnrollment(db, workspaceId, enrollmentId) {
  const result = await db.query(
    `SELECT e.id, e.state, e.attempt, e.snapshot_bytes, e.snapshot_sha256,
            e.operator_request_id, e.pending_since, e.next_poll_at,
            e.last_error_code, e.current_job_id, e.certificate_id, e.agent_id,
            j.status AS job_status
       FROM certificate_enrollments e
       LEFT JOIN certificate_jobs j
         ON j.workspace_id = e.workspace_id AND j.id = e.current_job_id
      WHERE e.workspace_id = $1 AND e.id = $2`,
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
    operatorRequestId: row.operator_request_id,
    pendingSince: row.pending_since,
    nextPollAt: row.next_poll_at,
    lastErrorCode: row.last_error_code,
    activeJob: Boolean(active),
    certificateId: row.certificate_id,
    agentId: row.agent_id,
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
  let pendingSince = row.pending_since;
  let nextAt = row.next_poll_at;
  if (enrollmentResult.state === "pending_issuance" && !pendingSince) pendingSince = new Date();
  if (enrollmentResult.state === "submitting" && enrollmentResult.errorCode === UNREACHABLE_ERROR) {
    const snapshot = JSON.parse(Buffer.from(row.snapshot_bytes).toString("utf8"));
    nextAt = nextPollAt(new Date(), snapshot.pollInterval || 900);
  }
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

async function recordPreflightResult(client, { workspaceId, job, preflightResult }) {
  assertSchema(validatePreflightResult, preflightResult, "CERTOPS_SNAPSHOT_INVALID");
  const issuerId = job.subject_id;
  if (!issuerId) return;
  await dbOf(client).query(
    `UPDATE certificate_issuers
        SET last_preflight = $3::jsonb, updated_at = NOW()
      WHERE workspace_id = $1 AND id = $2`,
    [workspaceId, issuerId, JSON.stringify(preflightResult)],
  );
}

async function proposeReconcileRequestId({ client, workspaceId, enrollmentId, requestId, actorUserId }) {
  const db = dbOf(client);
  const row = await loadEnrollment(db, workspaceId, enrollmentId);
  if (!row) throw serviceError("enrollment not found", "CERTOPS_ENROLLMENT_NOT_FOUND");
  if (row.state !== "submission_uncertain") {
    throw serviceError(
      "a RequestId can be proposed only while submission_uncertain",
      "CERTOPS_ENROLLMENT_TRANSITION_INVALID",
    );
  }
  await db.query(
    `UPDATE certificate_enrollments
        SET operator_request_id = $3, next_poll_at = NOW(), updated_at = NOW()
      WHERE workspace_id = $1 AND id = $2`,
    [workspaceId, enrollmentId, requestId],
  );
  await writeAudit({
    client: db,
    actorUserId: actorUserId || null,
    subjectUserId: actorUserId || null,
    action: "certops.enrollment.reconcile_proposed",
    targetType: "certificate_enrollment",
    workspaceId,
    metadata: { enrollmentId, requestId },
  });
}

async function abandonEnrollment({ client, workspaceId, enrollmentId, actorUserId }) {
  const db = dbOf(client);
  const row = await loadEnrollment(db, workspaceId, enrollmentId);
  if (!row) throw serviceError("enrollment not found", "CERTOPS_ENROLLMENT_NOT_FOUND");
  assertForwardTransition(row.state, "abandoned");
  await db.query(
    `UPDATE certificate_enrollments
        SET state = 'abandoned', next_poll_at = NOW(), updated_at = NOW()
      WHERE workspace_id = $1 AND id = $2`,
    [workspaceId, enrollmentId],
  );
  await writeAudit({
    client: db,
    actorUserId: actorUserId || null,
    subjectUserId: actorUserId || null,
    action: "certops.enrollment.abandoned",
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

async function scheduleDueEnrollments({ client, now = new Date(), createJob = createCertificateJob }) {
  const db = dbOf(client);
  const due = await db.query(
    `SELECT e.id, e.workspace_id, e.state, e.attempt, e.snapshot_bytes, e.snapshot_sha256,
            e.operator_request_id, e.pending_since, e.next_poll_at, e.last_error_code,
            e.certificate_id, e.agent_id, e.current_job_id, j.status AS job_status
       FROM certificate_enrollments e
       LEFT JOIN certificate_jobs j
         ON j.workspace_id = e.workspace_id AND j.id = e.current_job_id
      WHERE e.next_poll_at IS NOT NULL AND e.next_poll_at <= $1`,
    [now],
  );
  const created = [];
  for (const row of due.rows) {
    const view = enrollmentView(row);
    const snapshot = JSON.parse(Buffer.from(row.snapshot_bytes).toString("utf8"));
    const decision = decideContinuation(view, snapshot, now);
    if (!decision) continue;
    if (decision.state === "expired") {
      await db.query(
        `UPDATE certificate_enrollments
            SET state = 'expired', next_poll_at = NOW(), updated_at = NOW()
          WHERE workspace_id = $1 AND id = $2`,
        [row.workspace_id, row.id],
      );
    }
    if (!decision.dispatch && decision.state !== "expired") continue;
    const attempt = Number(row.attempt || 0) + 1;
    const payload = storedAdcsPayload({
      certificateId: row.certificate_id,
      target: { type: "windows-iis", reference: snapshot.authorizedDnsNames[0], store: "My" },
    });
    const job = await createJob({
      client: db,
      workspaceId: row.workspace_id,
      operation: "continue-enrollment",
      allowEnrollmentContinuation: true,
      subjectType: "managed_certificate",
      subjectId: row.certificate_id,
      assignedAgentId: row.agent_id,
      payload,
      enrollmentId: row.id,
    });
    await db.query(
      `UPDATE certificate_enrollments
          SET attempt = $3, current_job_id = $4, next_poll_at = NULL, updated_at = NOW()
        WHERE workspace_id = $1 AND id = $2`,
      [row.workspace_id, row.id, attempt, job.id],
    );
    created.push({ enrollmentId: row.id, jobId: job.id, attempt });
  }
  return created;
}

module.exports = {
  abandonEnrollment,
  attachEnrollmentDispatch,
  confirmIssuerKey,
  countInstalledEnrollments,
  createEnrollment,
  createIssuer,
  dispatchPreflight,
  loadDispatchEnrollment,
  proposeReconcileRequestId,
  recordEnrollmentResult,
  recordPreflightResult,
  scheduleDueEnrollments,
};
