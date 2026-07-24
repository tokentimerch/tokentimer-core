"use strict";

const { pool } = require("../../db/database");
const { writeAudit } = require("../audit");
const { assertNoPrivateKeyMaterial } = require("../../utils/secretMaterial");
const { createCertificateJob } = require("./jobs");
const { upsertManagedCertificateForControllerProvisioning } = require("./inventory");
const { lockWorkspaceForCertOpsSideEffect } = require("./workspaceKillSwitch");
const { jobLeaseSeconds } = require("./leaseTiming");

const CERTOPS_CONTROLLER_PROVISIONING_INVALID =
  "CERTOPS_CONTROLLER_PROVISIONING_INVALID";
const CERTOPS_CONTROLLER_PROVISIONING_WORKSPACE_MISMATCH =
  "CERTOPS_CONTROLLER_PROVISIONING_WORKSPACE_MISMATCH";
const CERTOPS_CONTROLLER_PROVISIONING_CLUSTER_MISMATCH =
  "CERTOPS_CONTROLLER_PROVISIONING_CLUSTER_MISMATCH";
const CERTOPS_CONTROLLER_PROVISIONING_CLUSTER_BINDING_REQUIRED =
  "CERTOPS_CONTROLLER_PROVISIONING_CLUSTER_BINDING_REQUIRED";
const CERTOPS_CONTROLLER_PROVISIONING_TERMINAL_IDENTITY =
  "CERTOPS_CONTROLLER_PROVISIONING_TERMINAL_IDENTITY";
const CERTOPS_CONTROLLER_PROVISIONING_MUTATION_NOT_AUTHORIZED =
  "CERTOPS_CONTROLLER_PROVISIONING_MUTATION_NOT_AUTHORIZED";
const CERTOPS_K8S_UNMANAGED_RESOURCE_CONFLICT =
  "CERTOPS_K8S_UNMANAGED_RESOURCE_CONFLICT";
const CONTROLLER_PROVISIONING_JOB_SOURCE = "controller_provisioning";
const INVALID_COMMAND_ERROR_CODE = "CERTOPS_CONTROLLER_PROVISIONING_INVALID_COMMAND";
const PERMANENT_COMMAND_VALIDATION_CODES = new Set([
  CERTOPS_CONTROLLER_PROVISIONING_INVALID,
  CERTOPS_CONTROLLER_PROVISIONING_WORKSPACE_MISMATCH,
  CERTOPS_CONTROLLER_PROVISIONING_CLUSTER_MISMATCH,
  CERTOPS_CONTROLLER_PROVISIONING_CLUSTER_BINDING_REQUIRED,
  "PRIVATE_KEY_MATERIAL_REJECTED",
]);

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RFC1123_LABEL = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const RFC1123_SUBDOMAIN = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$/;
const HUMAN_FIELDS = new Set([
  "schemaVersion", "clusterId", "namespace", "certificateName", "secretName", "issuerRef", "dnsNames",
]);
const DESIRED_FIELDS = new Set([
  "schemaVersion", "workspaceId", "clusterId", "jobId", "managedCertificateId", "namespace", "certificateName", "secretName", "issuerRef", "dnsNames",
]);
const ISSUER_FIELDS = new Set(["group", "kind", "name"]);
const DELIVERY_RETRY_INTERVAL_SECONDS = 30;
const CONTROLLER_PROVISIONING_TERMINAL_EVENTS = new Set([
  "job.completed",
  "job.failed",
]);

function provisioningError(message, code = CERTOPS_CONTROLLER_PROVISIONING_INVALID) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertKnownFields(value, allowed, name) {
  if (!isPlainObject(value)) throw provisioningError(`${name} is invalid`);
  for (const field of Object.keys(value)) {
    if (!allowed.has(field)) throw provisioningError(`${name} contains unsupported fields`);
  }
}

function requiredString(value, name, maximum = 253) {
  if (typeof value !== "string") throw provisioningError(`${name} is invalid`);
  const normalized = value.trim();
  if (!normalized || normalized.length > maximum || /[\u0000-\u001f\u007f]/.test(normalized)) {
    throw provisioningError(`${name} is invalid`);
  }
  return normalized;
}

function kubernetesLabel(value, name) {
  const normalized = requiredString(value, name, 63);
  if (!RFC1123_LABEL.test(normalized)) throw provisioningError(`${name} is invalid`);
  return normalized;
}

function kubernetesName(value, name) {
  const normalized = requiredString(value, name, 253);
  if (!RFC1123_SUBDOMAIN.test(normalized) || !normalized.split(".").every((item) => item.length <= 63)) {
    throw provisioningError(`${name} is invalid`);
  }
  return normalized;
}

function uuid(value, name) {
  const normalized = requiredString(value, name, 64).toLowerCase();
  if (!UUID_PATTERN.test(normalized)) throw provisioningError(`${name} is invalid`);
  return normalized;
}

function dnsName(value, name) {
  const normalized = requiredString(value, name, 253).toLowerCase();
  const base = normalized.startsWith("*.") ? normalized.slice(2) : normalized;
  if (!base || !RFC1123_SUBDOMAIN.test(base) || !base.split(".").every((item) => item.length <= 63)) {
    throw provisioningError(`${name} is invalid`);
  }
  return normalized;
}

function normalizeIssuerRef(value) {
  assertKnownFields(value, ISSUER_FIELDS, "issuerRef");
  const kind = requiredString(value.kind, "issuerRef.kind", 64);
  if (kind !== "Issuer" && kind !== "ClusterIssuer") {
    throw provisioningError("issuerRef.kind is invalid");
  }
  return {
    group: kubernetesName(value.group, "issuerRef.group"),
    kind,
    name: kubernetesName(value.name, "issuerRef.name"),
  };
}

function normalizeDnsNames(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 100) {
    throw provisioningError("dnsNames is invalid");
  }
  return [...new Set(value.map((item) => dnsName(item, "dnsNames item")))].sort();
}

function normalizeDesiredCertificate(value) {
  assertNoPrivateKeyMaterial(value);
  assertKnownFields(value, DESIRED_FIELDS, "desired certificate");
  if (value.schemaVersion !== 1) throw provisioningError("schemaVersion is invalid");
  const desired = {
    schemaVersion: 1,
    workspaceId: uuid(value.workspaceId, "workspaceId"),
    clusterId: kubernetesLabel(value.clusterId, "clusterId"),
    jobId: uuid(value.jobId, "jobId"),
    managedCertificateId: uuid(value.managedCertificateId, "managedCertificateId"),
    namespace: kubernetesLabel(value.namespace, "namespace"),
    certificateName: kubernetesName(value.certificateName, "certificateName"),
    secretName: kubernetesName(value.secretName, "secretName"),
    issuerRef: normalizeIssuerRef(value.issuerRef),
    dnsNames: normalizeDnsNames(value.dnsNames),
  };
  assertNoPrivateKeyMaterial(desired);
  return desired;
}

function normalizeHumanProvisionRequest(value, workspaceId) {
  assertNoPrivateKeyMaterial(value);
  assertKnownFields(value, HUMAN_FIELDS, "provision request");
  if (value.schemaVersion !== 1) throw provisioningError("schemaVersion is invalid");
  return {
    schemaVersion: 1,
    workspaceId: uuid(workspaceId, "workspaceId"),
    clusterId: kubernetesLabel(value.clusterId, "clusterId"),
    namespace: kubernetesLabel(value.namespace, "namespace"),
    certificateName: kubernetesName(value.certificateName, "certificateName"),
    secretName: kubernetesName(value.secretName, "secretName"),
    issuerRef: normalizeIssuerRef(value.issuerRef),
    dnsNames: normalizeDnsNames(value.dnsNames),
  };
}

function sourceRefFor(desired) {
  return `${desired.clusterId}/${desired.namespace}/${desired.certificateName}`;
}

function targetSourceRefFor(desired) {
  return `${desired.clusterId}/${desired.namespace}/${desired.secretName}`;
}

function keyReferenceFor(desired) {
  return `k8s://${desired.clusterId}/${desired.namespace}/secret/${desired.secretName}/tls.key`;
}

function normalizeIdempotencyKey(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(value)) {
    throw provisioningError("Idempotency-Key is invalid");
  }
  return value;
}

async function upsertProvisioningTarget(client, desired) {
  const result = await client.query(
    `INSERT INTO certificate_targets (
       workspace_id, name, target_type, status, source, source_ref,
       deployment_reference, public_metadata
     ) VALUES ($1, $2, 'kubernetes-secret', 'active', 'cert_manager', $3, $4, $5::jsonb)
     ON CONFLICT (workspace_id, source, source_ref)
       WHERE source = 'cert_manager' AND source_ref IS NOT NULL
     DO UPDATE SET
       name = EXCLUDED.name, target_type = 'kubernetes-secret', status = 'active',
       deployment_reference = EXCLUDED.deployment_reference,
       public_metadata = EXCLUDED.public_metadata, updated_at = NOW()
     RETURNING id`,
    [
      desired.workspaceId,
      desired.secretName,
      targetSourceRefFor(desired),
      `k8s://${desired.clusterId}/${desired.namespace}/secret/${desired.secretName}`,
      JSON.stringify({ clusterId: desired.clusterId, namespace: desired.namespace, secretName: desired.secretName }),
    ],
  );
  return result.rows[0];
}

async function createControllerProvisionIntent({
  request,
  workspaceId,
  idempotencyKey,
  actorUserId = null,
  dbPool = pool,
  jobCreator = createCertificateJob,
  auditWriter = writeAudit,
  lockWorkspace = lockWorkspaceForCertOpsSideEffect,
} = {}) {
  const initial = normalizeHumanProvisionRequest(request, workspaceId);
  const normalizedIdempotencyKey = normalizeIdempotencyKey(idempotencyKey);
  const client = await dbPool.connect();
  try {
    await client.query("BEGIN");
    await lockWorkspace({ client, workspaceId: initial.workspaceId });
    const existing = await client.query(
      `SELECT id, status FROM managed_certificates
       WHERE workspace_id = $1 AND source = 'cert_manager' AND source_ref = $2
       FOR UPDATE`,
      [initial.workspaceId, sourceRefFor(initial)],
    );
    if (["revoked", "decommissioned"].includes(existing.rows[0]?.status)) {
      throw provisioningError(
        "Provisioning cannot reactivate a terminal managed certificate",
        CERTOPS_CONTROLLER_PROVISIONING_TERMINAL_IDENTITY,
      );
    }
    const managedCertificate = await upsertManagedCertificateForControllerProvisioning(
      client,
      {
        workspaceId: initial.workspaceId,
        sourceRef: sourceRefFor(initial),
        name: initial.certificateName,
        keyReference: keyReferenceFor(initial),
        clusterId: initial.clusterId,
        namespace: initial.namespace,
        certificateName: initial.certificateName,
      },
    );
    const target = await upsertProvisioningTarget(client, initial);
    // The initial immutable creation hash intentionally uses a null job ID;
    // the generated UUID is not client input and must not make a retry conflict.
    const provisionalPayload = {
      kind: "cert_manager_provision",
      desiredCertificate: { ...initial, managedCertificateId: managedCertificate.id, jobId: null },
    };
    const outcome = await jobCreator({
      client,
      workspaceId: initial.workspaceId,
      operation: "deploy",
      // This source is server-owned; generic manual deploy jobs must never be
      // interpreted as executable cert-manager provisioning commands.
      source: CONTROLLER_PROVISIONING_JOB_SOURCE,
      executorKind: "controller",
      requestedByUserId: actorUserId,
      subjectType: "managed_certificate",
      subjectId: managedCertificate.id,
      idempotencyKey: normalizedIdempotencyKey,
      payload: provisionalPayload,
      returnOutcome: true,
    });
    const job = outcome.job;
    let desired;
    if (outcome.created) {
      desired = normalizeDesiredCertificate({
        ...initial,
        jobId: job.id,
        managedCertificateId: managedCertificate.id,
      });
      await client.query(
        `UPDATE certificate_jobs SET payload = $3::jsonb, updated_at = NOW()
          WHERE workspace_id = $1 AND id = $2`,
        [initial.workspaceId, job.id, JSON.stringify({ kind: "cert_manager_provision", desiredCertificate: desired })],
      );
      job.payload = { kind: "cert_manager_provision", desiredCertificate: desired };
      await auditWriter({
        client,
        actorUserId,
        subjectUserId: actorUserId,
        action: "CERTOPS_CONTROLLER_PROVISION_INTENT_CREATED",
        targetType: "certificate_job",
        workspaceId: initial.workspaceId,
        metadata: {
          clusterId: initial.clusterId,
          jobId: job.id,
          managedCertificateId: managedCertificate.id,
          targetId: target.id,
        },
      });
    } else {
      desired = normalizeDesiredCertificate(job.payload?.desiredCertificate);
    }
    await client.query("COMMIT");
    return {
      duplicate: !outcome.created,
      job,
      managedCertificateId: desired.managedCertificateId,
      targetId: target.id,
    };
  } catch (error) {
    try { await client.query("ROLLBACK"); } catch (_) { /* preserve failure */ }
    throw error;
  } finally {
    client.release();
  }
}

function validateAuthenticatedProvisioningBinding(apiToken, desired) {
  if (!apiToken?.workspaceId || desired.workspaceId !== apiToken.workspaceId) {
    throw provisioningError("Provisioning workspace does not match the authenticated token", CERTOPS_CONTROLLER_PROVISIONING_WORKSPACE_MISMATCH);
  }
  if (!apiToken.controllerClusterId) {
    throw provisioningError("Provisioning token has no controller cluster binding", CERTOPS_CONTROLLER_PROVISIONING_CLUSTER_BINDING_REQUIRED);
  }
  if (desired.clusterId !== apiToken.controllerClusterId) {
    throw provisioningError("Provisioning cluster does not match the authenticated token", CERTOPS_CONTROLLER_PROVISIONING_CLUSTER_MISMATCH);
  }
}

/**
 * Reauthorize one already delivered provisioning command immediately before
 * a Kubernetes create/patch. The workspace row lock and rollout resolution are
 * intentionally repeated here so a pause or global disable after delivery
 * cannot be bypassed by controller retries.
 */
async function authorizeControllerProvisioningMutation({
  apiToken,
  jobId,
  dbPool = pool,
} = {}) {
  if (!apiToken?.workspaceId || !apiToken?.controllerClusterId) {
    throw provisioningError(
      "Provisioning token binding is unavailable",
      CERTOPS_CONTROLLER_PROVISIONING_CLUSTER_BINDING_REQUIRED,
    );
  }
  const normalizedJobId = uuid(jobId, "jobId");
  const client = await dbPool.connect();
  try {
    await client.query("BEGIN");
    await lockWorkspaceForCertOpsSideEffect({
      client,
      workspaceId: apiToken.workspaceId,
    });
    const selected = await client.query(
      `SELECT j.id, j.payload, j.subject_type, j.subject_id
         FROM certificate_jobs j
         JOIN certificate_controller_provision_deliveries d
           ON d.job_id = j.id
          AND d.workspace_id = j.workspace_id
        WHERE j.id = $1
          AND j.workspace_id = $2
          AND j.executor_kind = 'controller'
          AND j.source = '${CONTROLLER_PROVISIONING_JOB_SOURCE}'
          AND j.operation = 'deploy'
          AND j.status NOT IN ('rejected', 'succeeded', 'failed', 'blocked', 'cancelled')
          AND j.payload->>'kind' = 'cert_manager_provision'
          AND j.payload #>> '{desiredCertificate,clusterId}' = $3
          AND d.controller_cluster_id = $3
          AND (
            j.claimed_by_controller_cluster_id IS NULL
            OR j.claimed_by_controller_cluster_id = $3
          )
        FOR UPDATE OF j`,
      [normalizedJobId, apiToken.workspaceId, apiToken.controllerClusterId],
    );
    const row = selected.rows[0];
    if (!row) {
      throw provisioningError(
        "Provisioning mutation is not authorized",
        CERTOPS_CONTROLLER_PROVISIONING_MUTATION_NOT_AUTHORIZED,
      );
    }

    let desired;
    try {
      desired = normalizeDesiredCertificate(row.payload?.desiredCertificate);
      if (
        row.subject_type !== "managed_certificate" ||
        row.subject_id !== desired.managedCertificateId ||
        row.id !== desired.jobId ||
        row.id !== normalizedJobId
      ) {
        throw provisioningError("Provisioning command identity is invalid");
      }
      validateAuthenticatedProvisioningBinding(apiToken, desired);
    } catch (error) {
      if (new Set([
        CERTOPS_CONTROLLER_PROVISIONING_CLUSTER_BINDING_REQUIRED,
        CERTOPS_CONTROLLER_PROVISIONING_CLUSTER_MISMATCH,
        CERTOPS_CONTROLLER_PROVISIONING_WORKSPACE_MISMATCH,
      ]).has(error?.code)) {
        throw error;
      }
      throw provisioningError(
        "Provisioning mutation is not authorized",
        CERTOPS_CONTROLLER_PROVISIONING_MUTATION_NOT_AUTHORIZED,
      );
    }

    const identity = await client.query(
      `SELECT mc.id
         FROM managed_certificates mc
        WHERE mc.id = $1
          AND mc.workspace_id = $2
          AND mc.source = 'cert_manager'
          AND mc.source_ref = $3
          AND mc.status NOT IN ('revoked', 'decommissioned')
          AND EXISTS (
            SELECT 1
              FROM certificate_targets ct
             WHERE ct.workspace_id = mc.workspace_id
               AND ct.source = 'cert_manager'
               AND ct.source_ref = $4
               AND ct.target_type = 'kubernetes-secret'
          )`,
      [
        desired.managedCertificateId,
        apiToken.workspaceId,
        sourceRefFor(desired),
        targetSourceRefFor(desired),
      ],
    );
    if (!identity.rows[0]) {
      throw provisioningError(
        "Provisioning mutation is not authorized",
        CERTOPS_CONTROLLER_PROVISIONING_MUTATION_NOT_AUTHORIZED,
      );
    }
    await client.query("COMMIT");
    return true;
  } catch (error) {
    try { await client.query("ROLLBACK"); } catch (_) { /* preserve failure */ }
    throw error;
  } finally {
    client.release();
  }
}

async function takeNextControllerProvisioningCommand({
  apiToken,
  dbPool = pool,
  env = process.env,
} = {}) {
  if (!apiToken?.workspaceId || !apiToken?.controllerClusterId) {
    throw provisioningError("Provisioning token binding is unavailable", CERTOPS_CONTROLLER_PROVISIONING_CLUSTER_BINDING_REQUIRED);
  }
  const leaseSeconds = jobLeaseSeconds(env);
  const client = await dbPool.connect();
  try {
    await client.query("BEGIN");
    await lockWorkspaceForCertOpsSideEffect({ client, workspaceId: apiToken.workspaceId });
    // B2: controller lane only. Atomically claim/lease to the authenticated
    // cluster identity so (a) agents never see these jobs and (b) another
    // cluster cannot steal a command mid-delivery.
    const selected = await client.query(
      `SELECT j.id, j.payload, j.subject_type, j.subject_id, j.status,
              j.claimed_by_controller_cluster_id, j.claim_id, j.lease_expires_at,
              d.started_at, d.completed_at, d.failed_at, d.delivered_at
         FROM certificate_jobs j
         LEFT JOIN certificate_controller_provision_deliveries d ON d.job_id = j.id
        WHERE j.workspace_id = $1
          AND j.executor_kind = 'controller'
          AND j.source = '${CONTROLLER_PROVISIONING_JOB_SOURCE}'
          AND j.operation = 'deploy'
          AND j.status IN ('pending', 'claimed', 'running')
          AND j.payload->>'kind' = 'cert_manager_provision'
          AND j.payload #>> '{desiredCertificate,clusterId}' = $2
          AND (
            j.claimed_by_controller_cluster_id IS NULL
            OR j.claimed_by_controller_cluster_id = $2
          )
          AND (
            d.delivered_at IS NULL
            OR d.delivered_at <= NOW() - ($3 || ' seconds')::interval
            OR (
              j.claimed_by_controller_cluster_id = $2
              AND j.lease_expires_at IS NOT NULL
              AND j.lease_expires_at < NOW()
            )
          )
        ORDER BY j.created_at ASC, j.id ASC
        FOR UPDATE OF j SKIP LOCKED
        LIMIT 1`,
      [apiToken.workspaceId, apiToken.controllerClusterId, String(DELIVERY_RETRY_INTERVAL_SECONDS)],
    );
    const row = selected.rows[0];
    if (!row) {
      await client.query("COMMIT");
      return null;
    }

    let desired;
    try {
      desired = normalizeDesiredCertificate(row.payload?.desiredCertificate);
      if (
        row.subject_type !== "managed_certificate" ||
        row.subject_id !== desired.managedCertificateId ||
        row.id !== desired.jobId
      ) {
        throw provisioningError("Provisioning command identity is invalid");
      }
      validateAuthenticatedProvisioningBinding(apiToken, desired);
    } catch (error) {
      if (!PERMANENT_COMMAND_VALIDATION_CODES.has(error?.code)) throw error;
      // A malformed or stale server-owned row is never command work. Mark it
      // terminal so it cannot hot-loop while still preserving an auditable job.
      await client.query(
        `UPDATE certificate_jobs
            SET status = 'blocked', error_code = $2,
                error_message = 'Controller provisioning command rejected',
                claimed_by_controller_cluster_id = NULL,
                claim_id = NULL,
                lease_expires_at = NULL,
                updated_at = NOW()
          WHERE id = $1`,
        [row.id, INVALID_COMMAND_ERROR_CODE],
      );
      await client.query("COMMIT");
      return null;
    }

    // Database failures must propagate through the outer transaction rollback.
    // Only an authoritative query result that proves this server-owned command
    // stale or terminal is a permanent, blockable command defect.
    const identity = await client.query(
      `SELECT mc.id
         FROM managed_certificates mc
        WHERE mc.id = $1
          AND mc.workspace_id = $2
          AND mc.source = 'cert_manager'
          AND mc.source_ref = $3
          AND mc.status NOT IN ('revoked', 'decommissioned')
          AND EXISTS (
            SELECT 1
              FROM certificate_targets ct
             WHERE ct.workspace_id = mc.workspace_id
               AND ct.source = 'cert_manager'
               AND ct.source_ref = $4
               AND ct.target_type = 'kubernetes-secret'
          )`,
      [
        desired.managedCertificateId,
        apiToken.workspaceId,
        sourceRefFor(desired),
        targetSourceRefFor(desired),
      ],
    );
    if (!identity.rows[0]) {
      await client.query(
        `UPDATE certificate_jobs
            SET status = 'blocked', error_code = $2,
                error_message = 'Controller provisioning command rejected',
                claimed_by_controller_cluster_id = NULL,
                claim_id = NULL,
                lease_expires_at = NULL,
                updated_at = NOW()
          WHERE id = $1`,
        [row.id, INVALID_COMMAND_ERROR_CODE],
      );
      await client.query("COMMIT");
      return null;
    }

    // Atomic claim/lease bound to this cluster identity.
    await client.query(
      `UPDATE certificate_jobs
          SET status = CASE
                WHEN status = 'pending' THEN 'claimed'
                ELSE status
              END,
              claimed_by_controller_cluster_id = $2,
              claim_id = COALESCE(claim_id, gen_random_uuid()),
              lease_expires_at = NOW() + make_interval(secs => $3),
              attempt_count = CASE
                WHEN status = 'pending' THEN attempt_count + 1
                ELSE attempt_count
              END,
              queued_at = COALESCE(queued_at, NOW()),
              updated_at = NOW()
        WHERE id = $1`,
      [row.id, apiToken.controllerClusterId, leaseSeconds],
    );

    await client.query(
      `INSERT INTO certificate_controller_provision_deliveries
         (job_id, workspace_id, controller_cluster_id, delivered_at, updated_at)
       VALUES ($1, $2, $3, NOW(), NOW())
       ON CONFLICT (job_id) DO UPDATE
         SET controller_cluster_id = EXCLUDED.controller_cluster_id,
             delivered_at = NOW(), updated_at = NOW()`,
      [row.id, apiToken.workspaceId, apiToken.controllerClusterId],
    );
    await client.query("COMMIT");
    const eventTimestamps = Object.fromEntries(
      [
        ["started", row.started_at],
        ["completed", row.completed_at],
        ["failed", row.failed_at],
      ]
        .filter(([, value]) => value)
        .map(([stage, value]) => [stage, new Date(value).toISOString()]),
    );
    return { command: desired, eventTimestamps };
  } catch (error) {
    try { await client.query("ROLLBACK"); } catch (_) { /* preserve failure */ }
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Persist first-seen real event times for the narrow controller delivery only.
 * These are idempotency aids, not agent attempts, claims, leases, or heartbeats.
 */
async function recordControllerProvisioningEventTimestamp({
  client,
  workspaceId,
  jobId,
  eventType,
  occurredAt,
} = {}) {
  if (!occurredAt) return;
  const terminalColumnByEventType = {
    "job.completed": "completed_at",
    "job.failed": "failed_at",
  };
  if (eventType === "job.started") {
    await client.query(
      `UPDATE certificate_controller_provision_deliveries d
          SET started_at = COALESCE(d.started_at, $3::timestamptz),
              updated_at = NOW()
         FROM certificate_jobs j
        WHERE d.job_id = j.id
          AND j.id = $1
          AND j.workspace_id = $2
          AND j.source = '${CONTROLLER_PROVISIONING_JOB_SOURCE}'`,
      [jobId, workspaceId, occurredAt],
    );
    return;
  }
  const column = terminalColumnByEventType[eventType];
  if (!column) return;
  // The executor route has already canonicalized this value against the
  // server-owned start time. Preserve that exact first accepted timestamp.
  await client.query(
    `UPDATE certificate_controller_provision_deliveries d
        SET ${column} = COALESCE(d.${column}, $3::timestamptz),
            updated_at = NOW()
       FROM certificate_jobs j
      WHERE d.job_id = j.id
        AND j.id = $1
        AND j.workspace_id = $2
        AND j.source = '${CONTROLLER_PROVISIONING_JOB_SOURCE}'`,
    [jobId, workspaceId, occurredAt],
  );
}

/**
 * Resolve the authoritative terminal time while the executor-event ingestion
 * transaction holds the job row lock. Generic jobs and non-terminal events
 * retain their caller-supplied, already-normalized timestamp unchanged.
 */
async function canonicalizeControllerProvisioningTerminalOccurredAt({
  client,
  workspaceId,
  jobId,
  eventType,
  occurredAt,
} = {}) {
  if (!CONTROLLER_PROVISIONING_TERMINAL_EVENTS.has(eventType)) {
    return occurredAt;
  }

  const result = await client.query(
    `SELECT j.source, d.started_at
       FROM certificate_jobs j
       LEFT JOIN certificate_controller_provision_deliveries d
         ON d.job_id = j.id
      WHERE j.workspace_id = $1
        AND j.id = $2
      LIMIT 1`,
    [workspaceId, jobId],
  );
  const row = result.rows[0];
  if (
    row?.source !== CONTROLLER_PROVISIONING_JOB_SOURCE ||
    !row.started_at
  ) {
    return occurredAt;
  }

  const startedAt = new Date(row.started_at).toISOString();
  return Date.parse(occurredAt) < Date.parse(startedAt)
    ? startedAt
    : occurredAt;
}

module.exports = {
  CERTOPS_CONTROLLER_PROVISIONING_CLUSTER_BINDING_REQUIRED,
  CERTOPS_CONTROLLER_PROVISIONING_CLUSTER_MISMATCH,
  CERTOPS_CONTROLLER_PROVISIONING_INVALID,
  CERTOPS_CONTROLLER_PROVISIONING_MUTATION_NOT_AUTHORIZED,
  CERTOPS_CONTROLLER_PROVISIONING_TERMINAL_IDENTITY,
  CERTOPS_CONTROLLER_PROVISIONING_WORKSPACE_MISMATCH,
  CERTOPS_K8S_UNMANAGED_RESOURCE_CONFLICT,
  CONTROLLER_PROVISIONING_JOB_SOURCE,
  DELIVERY_RETRY_INTERVAL_SECONDS,
  canonicalizeControllerProvisioningTerminalOccurredAt,
  authorizeControllerProvisioningMutation,
  createControllerProvisionIntent,
  normalizeDesiredCertificate,
  normalizeHumanProvisionRequest,
  recordControllerProvisioningEventTimestamp,
  takeNextControllerProvisioningCommand,
  validateAuthenticatedProvisioningBinding,
};
