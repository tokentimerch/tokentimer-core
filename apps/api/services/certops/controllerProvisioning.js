"use strict";

const { pool } = require("../../db/database");
const { writeAudit } = require("../audit");
const { assertNoPrivateKeyMaterial } = require("../../utils/secretMaterial");
const { createCertificateJob } = require("./jobs");
const { upsertManagedCertificateByMonitorSource } = require("./inventory");
const { lockWorkspaceForCertOpsSideEffect } = require("./workspaceKillSwitch");

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
const CERTOPS_K8S_UNMANAGED_RESOURCE_CONFLICT =
  "CERTOPS_K8S_UNMANAGED_RESOURCE_CONFLICT";

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
    const managedCertificate = await upsertManagedCertificateByMonitorSource(
      client,
      { commonName: initial.dnsNames[0], subjectAltNames: initial.dnsNames },
      {
        workspaceId: initial.workspaceId,
        status: "discovered",
        source: "cert_manager",
        sourceRef: sourceRefFor(initial),
        name: initial.certificateName,
        keyMode: "cert-manager-managed",
        keyReference: keyReferenceFor(initial),
        controllerProvisioningMetadata: {
          clusterId: initial.clusterId,
          namespace: initial.namespace,
          certificateName: initial.certificateName,
        },
      },
      0,
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
      source: "api",
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

async function takeNextControllerProvisioningCommand({ apiToken, dbPool = pool } = {}) {
  if (!apiToken?.workspaceId || !apiToken?.controllerClusterId) {
    throw provisioningError("Provisioning token binding is unavailable", CERTOPS_CONTROLLER_PROVISIONING_CLUSTER_BINDING_REQUIRED);
  }
  const client = await dbPool.connect();
  try {
    await client.query("BEGIN");
    await lockWorkspaceForCertOpsSideEffect({ client, workspaceId: apiToken.workspaceId });
    const selected = await client.query(
      `SELECT j.id, j.payload
         FROM certificate_jobs j
         LEFT JOIN certificate_controller_provision_deliveries d ON d.job_id = j.id
        WHERE j.workspace_id = $1
          AND j.operation = 'deploy'
          AND j.status NOT IN ('rejected', 'succeeded', 'failed', 'blocked', 'cancelled')
          AND j.payload->>'kind' = 'cert_manager_provision'
          AND j.payload #>> '{desiredCertificate,clusterId}' = $2
          AND (d.delivered_at IS NULL OR d.delivered_at <= NOW() - ($3 || ' seconds')::interval)
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
    const desired = normalizeDesiredCertificate(row.payload?.desiredCertificate);
    validateAuthenticatedProvisioningBinding(apiToken, desired);
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
    return desired;
  } catch (error) {
    try { await client.query("ROLLBACK"); } catch (_) { /* preserve failure */ }
    throw error;
  } finally {
    client.release();
  }
}

module.exports = {
  CERTOPS_CONTROLLER_PROVISIONING_CLUSTER_BINDING_REQUIRED,
  CERTOPS_CONTROLLER_PROVISIONING_CLUSTER_MISMATCH,
  CERTOPS_CONTROLLER_PROVISIONING_INVALID,
  CERTOPS_CONTROLLER_PROVISIONING_TERMINAL_IDENTITY,
  CERTOPS_CONTROLLER_PROVISIONING_WORKSPACE_MISMATCH,
  CERTOPS_K8S_UNMANAGED_RESOURCE_CONFLICT,
  DELIVERY_RETRY_INTERVAL_SECONDS,
  createControllerProvisionIntent,
  normalizeDesiredCertificate,
  normalizeHumanProvisionRequest,
  takeNextControllerProvisioningCommand,
  validateAuthenticatedProvisioningBinding,
};
