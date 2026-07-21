"use strict";

const crypto = require("crypto");

const { pool } = require("../../db/database");
const { writeAudit } = require("../audit");
const {
  assertNoPrivateKeyMaterial,
  redactGenericSecretsWithReport,
} = require("../../utils/secretMaterial");
const { upsertManagedCertificateByMonitorSource } = require("./inventory");
const { createControllerObservationEvidence } = require("./evidence");

const CERTOPS_CONTROLLER_OBSERVATION_INVALID =
  "CERTOPS_CONTROLLER_OBSERVATION_INVALID";
const CERTOPS_CONTROLLER_OBSERVATION_CONFLICT =
  "CERTOPS_CONTROLLER_OBSERVATION_CONFLICT";
const CERTOPS_CONTROLLER_OBSERVATION_WORKSPACE_MISMATCH =
  "CERTOPS_CONTROLLER_OBSERVATION_WORKSPACE_MISMATCH";
const CERTOPS_CONTROLLER_OBSERVATION_CLUSTER_MISMATCH =
  "CERTOPS_CONTROLLER_OBSERVATION_CLUSTER_MISMATCH";
const CERTOPS_CONTROLLER_CLUSTER_BINDING_REQUIRED =
  "CERTOPS_CONTROLLER_CLUSTER_BINDING_REQUIRED";

const OBSERVATION_TOP_LEVEL_FIELDS = new Set([
  "schemaVersion",
  "observationId",
  "idempotencyKey",
  "workspaceId",
  "clusterId",
  "namespace",
  "certificateName",
  "certificateUid",
  "certificateGeneration",
  "resourceVersion",
  "issuerRef",
  "secretName",
  "certificateRequestRef",
  "dnsNames",
  "revision",
  "conditions",
  "ready",
  "failureReason",
  "failureMessage",
  "notBefore",
  "notAfter",
  "renewalTime",
  "publicCertificate",
  "observationSource",
  "observedAt",
]);
const ISSUER_REF_FIELDS = new Set(["group", "kind", "name"]);
const REQUEST_REF_FIELDS = new Set(["name", "uid"]);
const CONDITION_FIELDS = new Set([
  "type",
  "status",
  "reason",
  "message",
  "lastTransitionTime",
]);
const PUBLIC_CERTIFICATE_FIELDS = new Set([
  "fingerprintSha256",
  "serialNumber",
  "subject",
  "issuer",
  "subjectAltNames",
  "publicKeyAlgorithm",
  "publicKeySize",
  "signatureAlgorithm",
  "certificatePem",
]);
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const RFC1123_LABEL_PATTERN = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const RFC3339_PATTERN =
  /^(?:200[0-9]|20[1-9][0-9]|2100)-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]+)?(?:Z|[+-](?:(?:0[0-9]|1[0-3]):[0-5][0-9]|14:00))$/;
const MAX_DNS_NAMES = 64;
const MAX_CONDITIONS = 16;
const MAX_TEXT = 1024;
const MAX_IDENTITY = 253;
const MAX_PUBLIC_PEM = 64 * 1024;

function observationError(message, code = CERTOPS_CONTROLLER_OBSERVATION_INVALID) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertKnownFields(value, allowed, fieldName) {
  if (!isPlainObject(value)) throw observationError(`${fieldName} is invalid`);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw observationError(`${fieldName} contains unsupported fields`);
  }
}

function requiredString(value, fieldName, maximumLength = MAX_TEXT) {
  if (typeof value !== "string") throw observationError(`${fieldName} is invalid`);
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > maximumLength) {
    throw observationError(`${fieldName} is invalid`);
  }
  return trimmed;
}

function optionalString(value, fieldName, maximumLength = MAX_TEXT) {
  if (value === undefined || value === null || value === "") return null;
  return requiredString(value, fieldName, maximumLength);
}

function validKubernetesName(value, fieldName, maximumLength = MAX_IDENTITY) {
  const name = requiredString(value, fieldName, maximumLength);
  if (
    name.length > maximumLength ||
    !name.split(".").every(
      (label) => label.length > 0 && label.length <= 63 && RFC1123_LABEL_PATTERN.test(label),
    )
  ) {
    throw observationError(`${fieldName} is invalid`);
  }
  return name;
}

function validClusterId(value) {
  const clusterId = requiredString(value, "clusterId", 63);
  if (!RFC1123_LABEL_PATTERN.test(clusterId)) {
    throw observationError("clusterId is invalid");
  }
  return clusterId;
}

function validUuid(value, fieldName) {
  const id = requiredString(value, fieldName, 64);
  if (!UUID_PATTERN.test(id)) throw observationError(`${fieldName} is invalid`);
  return id.toLowerCase();
}

function validSha256(value, fieldName) {
  const hash = requiredString(value, fieldName, 64);
  if (!SHA256_PATTERN.test(hash)) throw observationError(`${fieldName} is invalid`);
  return hash;
}

function validTimestamp(value, fieldName) {
  const timestamp = requiredString(value, fieldName, 64);
  if (!RFC3339_PATTERN.test(timestamp) || Number.isNaN(Date.parse(timestamp))) {
    throw observationError(`${fieldName} is invalid`);
  }
  return new Date(timestamp).toISOString();
}

function optionalTimestamp(value, fieldName) {
  if (value === undefined || value === null || value === "") return null;
  return validTimestamp(value, fieldName);
}

function optionalInteger(value, fieldName) {
  if (value === undefined || value === null) return null;
  if (!Number.isSafeInteger(value) || value < 0) {
    throw observationError(`${fieldName} is invalid`);
  }
  return value;
}

function redactFreeText(value, fieldName, redaction) {
  const text = optionalString(value, fieldName);
  if (text === null) return null;
  const report = redactGenericSecretsWithReport(text);
  if (typeof report.value !== "string" || report.value.length > MAX_TEXT) {
    throw observationError(`${fieldName} is invalid`);
  }
  if (report.redactionApplied) {
    redaction.applied = true;
    redaction.count += report.redactionCount || 1;
  }
  return report.value;
}

function normalizeIssuerRef(value) {
  assertKnownFields(value, ISSUER_REF_FIELDS, "issuerRef");
  return {
    group: optionalString(value.group, "issuerRef.group", 253) || "cert-manager.io",
    kind: optionalString(value.kind, "issuerRef.kind", 253) || "Issuer",
    name: validKubernetesName(value.name, "issuerRef.name"),
  };
}

function normalizeCertificateRequestRef(value) {
  if (value === undefined || value === null) return null;
  assertKnownFields(value, REQUEST_REF_FIELDS, "certificateRequestRef");
  const normalized = { name: validKubernetesName(value.name, "certificateRequestRef.name") };
  if (value.uid !== undefined && value.uid !== null && value.uid !== "") {
    normalized.uid = validUuid(value.uid, "certificateRequestRef.uid");
  }
  return normalized;
}

function normalizeDnsNames(value) {
  if (!Array.isArray(value) || value.length > MAX_DNS_NAMES) {
    throw observationError("dnsNames is invalid");
  }
  const names = value.map((name) => validKubernetesName(name, "dnsNames item"));
  return [...new Set(names)].sort();
}

function normalizeConditions(value, redaction) {
  if (!Array.isArray(value) || value.length > MAX_CONDITIONS) {
    throw observationError("conditions is invalid");
  }
  return value.map((condition) => {
    assertKnownFields(condition, CONDITION_FIELDS, "condition");
    const normalized = {
      type: requiredString(condition.type, "condition.type", 253),
      status: requiredString(condition.status, "condition.status", 32),
    };
    const reason = redactFreeText(condition.reason, "condition.reason", redaction);
    const message = redactFreeText(condition.message, "condition.message", redaction);
    const lastTransitionTime = optionalTimestamp(
      condition.lastTransitionTime,
      "condition.lastTransitionTime",
    );
    if (reason) normalized.reason = reason;
    if (message) normalized.message = message;
    if (lastTransitionTime) normalized.lastTransitionTime = lastTransitionTime;
    return normalized;
  });
}

function normalizePublicCertificate(value) {
  if (value === undefined || value === null) return null;
  assertKnownFields(value, PUBLIC_CERTIFICATE_FIELDS, "publicCertificate");
  const normalized = {};
  if (value.fingerprintSha256 !== undefined && value.fingerprintSha256 !== null) {
    normalized.fingerprintSha256 = validSha256(
      value.fingerprintSha256,
      "publicCertificate.fingerprintSha256",
    );
  }
  for (const fieldName of [
    "serialNumber",
    "subject",
    "issuer",
    "publicKeyAlgorithm",
    "signatureAlgorithm",
  ]) {
    const normalizedValue = optionalString(
      value[fieldName],
      `publicCertificate.${fieldName}`,
      MAX_TEXT,
    );
    if (normalizedValue) normalized[fieldName] = normalizedValue;
  }
  if (value.subjectAltNames !== undefined) {
    normalized.subjectAltNames = normalizeDnsNames(value.subjectAltNames);
  }
  if (value.publicKeySize !== undefined && value.publicKeySize !== null) {
    if (!Number.isSafeInteger(value.publicKeySize) || value.publicKeySize < 1 || value.publicKeySize > 16384) {
      throw observationError("publicCertificate.publicKeySize is invalid");
    }
    normalized.publicKeySize = value.publicKeySize;
  }
  if (value.certificatePem !== undefined && value.certificatePem !== null) {
    const certificatePem = requiredString(
      value.certificatePem,
      "publicCertificate.certificatePem",
      MAX_PUBLIC_PEM,
    );
    if (Buffer.byteLength(certificatePem, "utf8") > MAX_PUBLIC_PEM) {
      throw observationError("publicCertificate.certificatePem is invalid");
    }
    normalized.certificatePem = certificatePem;
  }
  return normalized;
}

function normalizeControllerObservation(value) {
  assertNoPrivateKeyMaterial(value);
  assertKnownFields(value, OBSERVATION_TOP_LEVEL_FIELDS, "controller observation");
  const redaction = { applied: false, count: 0 };
  if (value.schemaVersion !== 1 || value.observationSource !== "cert_manager") {
    throw observationError("controller observation schema version or source is invalid");
  }
  if (typeof value.ready !== "boolean") throw observationError("ready is invalid");
  const normalized = {
    schemaVersion: 1,
    observationId: validUuid(value.observationId, "observationId"),
    idempotencyKey: validSha256(value.idempotencyKey, "idempotencyKey"),
    workspaceId: validUuid(value.workspaceId, "workspaceId"),
    clusterId: validClusterId(value.clusterId),
    namespace: validKubernetesName(value.namespace, "namespace", 63),
    certificateName: validKubernetesName(value.certificateName, "certificateName"),
    certificateUid: validUuid(value.certificateUid, "certificateUid"),
    issuerRef: normalizeIssuerRef(value.issuerRef),
    secretName: value.secretName === null ? null : validKubernetesName(value.secretName, "secretName"),
    certificateRequestRef: normalizeCertificateRequestRef(value.certificateRequestRef),
    dnsNames: normalizeDnsNames(value.dnsNames),
    conditions: normalizeConditions(value.conditions, redaction),
    ready: value.ready,
    publicCertificate: normalizePublicCertificate(value.publicCertificate),
    observationSource: "cert_manager",
    observedAt: validTimestamp(value.observedAt, "observedAt"),
  };
  for (const fieldName of ["certificateGeneration", "revision"]) {
    const normalizedValue = optionalInteger(value[fieldName], fieldName);
    if (normalizedValue !== null) normalized[fieldName] = normalizedValue;
  }
  const resourceVersion = optionalString(value.resourceVersion, "resourceVersion", 256);
  if (resourceVersion) normalized.resourceVersion = resourceVersion;
  const failureReason = redactFreeText(value.failureReason, "failureReason", redaction);
  const failureMessage = redactFreeText(value.failureMessage, "failureMessage", redaction);
  if (failureReason) normalized.failureReason = failureReason;
  if (failureMessage) normalized.failureMessage = failureMessage;
  for (const fieldName of ["notBefore", "notAfter", "renewalTime"]) {
    const normalizedValue = optionalTimestamp(value[fieldName], fieldName);
    if (normalizedValue) normalized[fieldName] = normalizedValue;
  }
  assertNoPrivateKeyMaterial(normalized);
  return { observation: normalized, redaction };
}

function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
    .join(",")}}`;
}

function semanticObservation(observation) {
  const { observationId: _observationId, observedAt: _observedAt, ...semantic } = observation;
  return semantic;
}

function semanticRequestHash(observation) {
  return crypto
    .createHash("sha256")
    .update(stableStringify(semanticObservation(observation)), "utf8")
    .digest("hex");
}

function sourceRefFor(observation) {
  return `${observation.clusterId}/${observation.namespace}/${observation.certificateName}`;
}

function targetSourceRefFor(observation) {
  return `${observation.clusterId}/${observation.namespace}/${observation.secretName}`;
}

function certificateFor(observation) {
  const publicCertificate = observation.publicCertificate || {};
  return {
    certificatePem: publicCertificate.certificatePem || null,
    commonName: publicCertificate.subject || observation.dnsNames[0] || observation.certificateName,
    fingerprintSha256: publicCertificate.fingerprintSha256 || null,
    issuer: publicCertificate.issuer || null,
    notAfter: observation.notAfter || null,
    notBefore: observation.notBefore || null,
    publicKeyAlgorithm: publicCertificate.publicKeyAlgorithm || null,
    publicKeySize: publicCertificate.publicKeySize || null,
    serialNumber: publicCertificate.serialNumber || null,
    signatureAlgorithm: publicCertificate.signatureAlgorithm || null,
    subject: publicCertificate.subject || null,
    subjectAltNames: publicCertificate.subjectAltNames || observation.dnsNames,
  };
}

function observationMetadata(observation, resourceRecreated) {
  return {
    certificateGeneration: observation.certificateGeneration ?? null,
    certificateRequestRef: observation.certificateRequestRef || null,
    certificateUid: observation.certificateUid,
    clusterId: observation.clusterId,
    namespace: observation.namespace,
    ready: observation.ready,
    resourceRecreated,
    resourceVersion: observation.resourceVersion || null,
    revision: observation.revision ?? null,
  };
}

function publicStatusSummary(observation, redaction) {
  return {
    certificateGeneration: observation.certificateGeneration ?? null,
    certificateName: observation.certificateName,
    certificateUid: observation.certificateUid,
    clusterId: observation.clusterId,
    failureReason: observation.failureReason || null,
    namespace: observation.namespace,
    ready: observation.ready,
    redaction: { applied: Boolean(redaction.applied), count: redaction.count },
    resourceVersion: observation.resourceVersion || null,
    revision: observation.revision ?? null,
  };
}

async function findExistingSourceIdentity(client, observation) {
  const result = await client.query(
    `SELECT id, public_metadata
       FROM managed_certificates
      WHERE workspace_id = $1 AND source = 'cert_manager' AND source_ref = $2
      FOR UPDATE`,
    [observation.workspaceId, sourceRefFor(observation)],
  );
  return result.rows[0] || null;
}

function previousCertificateUid(row) {
  const metadata = row?.public_metadata;
  let parsed = metadata;
  if (typeof metadata === "string") {
    try {
      parsed = JSON.parse(metadata);
    } catch (_error) {
      return null;
    }
  }
  return parsed?.controllerObservation?.certificateUid || null;
}

async function upsertControllerTarget(client, observation) {
  const sourceRef = targetSourceRefFor(observation);
  const metadata = JSON.stringify({
    clusterId: observation.clusterId,
    namespace: observation.namespace,
    observationOnly: true,
    secretName: observation.secretName,
  });
  const existing = await client.query(
    `SELECT id FROM certificate_targets
      WHERE workspace_id = $1 AND source = 'cert_manager' AND source_ref = $2
      FOR UPDATE`,
    [observation.workspaceId, sourceRef],
  );
  if (existing.rows[0]) {
    const result = await client.query(
      `UPDATE certificate_targets
          SET name = $3, target_type = 'kubernetes-secret', status = 'active',
              deployment_reference = $4, public_metadata = $5::jsonb, updated_at = NOW()
        WHERE workspace_id = $1 AND id = $2
        RETURNING *`,
      [
        observation.workspaceId,
        existing.rows[0].id,
        observation.secretName,
        `k8s://${observation.clusterId}/${observation.namespace}/secret/${observation.secretName}`,
        metadata,
      ],
    );
    return result.rows[0];
  }
  const result = await client.query(
    `INSERT INTO certificate_targets (
       workspace_id, name, target_type, status, source, source_ref,
       deployment_reference, public_metadata
     ) VALUES ($1, $2, 'kubernetes-secret', 'active', 'cert_manager', $3, $4, $5::jsonb)
     RETURNING *`,
    [
      observation.workspaceId,
      observation.secretName,
      sourceRef,
      `k8s://${observation.clusterId}/${observation.namespace}/secret/${observation.secretName}`,
      metadata,
    ],
  );
  return result.rows[0];
}

async function upsertControllerInstance(client, observation, certificate, managedCertificate, target) {
  if (!certificate.fingerprintSha256) return null;
  const result = await client.query(
    `INSERT INTO certificate_instances (
       workspace_id, managed_certificate_id, target_id, status, source, source_ref,
       observed_fingerprint_sha256, observed_serial_number, observed_subject,
       observed_issuer, observed_not_before, observed_not_after,
       deployment_reference, observed_at, public_metadata
     ) VALUES ($1, $2, $3, $4, 'cert_manager', $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb)
     ON CONFLICT (workspace_id, target_id, managed_certificate_id, observed_fingerprint_sha256)
     DO UPDATE SET
       status = EXCLUDED.status, source = EXCLUDED.source, source_ref = EXCLUDED.source_ref,
       observed_serial_number = EXCLUDED.observed_serial_number,
       observed_subject = EXCLUDED.observed_subject, observed_issuer = EXCLUDED.observed_issuer,
       observed_not_before = EXCLUDED.observed_not_before, observed_not_after = EXCLUDED.observed_not_after,
       deployment_reference = EXCLUDED.deployment_reference, observed_at = EXCLUDED.observed_at,
       public_metadata = EXCLUDED.public_metadata, updated_at = NOW()
     RETURNING *`,
    [
      observation.workspaceId,
      managedCertificate.id,
      target.id,
      observation.ready ? "active" : "discovered",
      sourceRefFor(observation),
      certificate.fingerprintSha256,
      certificate.serialNumber || null,
      certificate.subject || null,
      certificate.issuer || null,
      certificate.notBefore || null,
      certificate.notAfter || null,
      `k8s://${observation.clusterId}/${observation.namespace}/secret/${observation.secretName}`,
      observation.observedAt,
      JSON.stringify(publicStatusSummary(observation, { applied: false, count: 0 })),
    ],
  );
  return result.rows[0];
}

function safeResultFromRow(row) {
  return {
    managedCertificateId: row.managed_certificate_id || null,
    targetId: row.target_id || null,
    certificateInstanceId: row.certificate_instance_id || null,
  };
}

async function persistControllerObservation({
  apiTokenId,
  dbPool = pool,
  observation,
  redaction = { applied: false, count: 0 },
} = {}) {
  const client = await dbPool.connect();
  const requestHash = semanticRequestHash(observation);
  try {
    await client.query("BEGIN");
    const inserted = await client.query(
      `INSERT INTO certificate_controller_observations (
         workspace_id, controller_cluster_id, idempotency_key, request_hash, status, created_by_api_token_id
       ) VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (workspace_id, controller_cluster_id, idempotency_key) DO NOTHING
       RETURNING id`,
      [
        observation.workspaceId,
        observation.clusterId,
        observation.idempotencyKey,
        requestHash,
        redaction.applied ? "redacted" : "accepted",
        apiTokenId || null,
      ],
    );
    if (!inserted.rows[0]) {
      const existing = await client.query(
        `SELECT request_hash, managed_certificate_id, target_id, certificate_instance_id
           FROM certificate_controller_observations
          WHERE workspace_id = $1 AND controller_cluster_id = $2 AND idempotency_key = $3
          FOR UPDATE`,
        [observation.workspaceId, observation.clusterId, observation.idempotencyKey],
      );
      const row = existing.rows[0];
      if (!row || row.request_hash !== requestHash) {
        throw observationError(
          "Observation idempotency key was already used with a different payload",
          CERTOPS_CONTROLLER_OBSERVATION_CONFLICT,
        );
      }
      await client.query("COMMIT");
      return { ...safeResultFromRow(row), duplicate: true };
    }

    const prior = await findExistingSourceIdentity(client, observation);
    const resourceRecreated = Boolean(
      prior && previousCertificateUid(prior) && previousCertificateUid(prior) !== observation.certificateUid,
    );
    const certificate = certificateFor(observation);
    const managedCertificate = await upsertManagedCertificateByMonitorSource(
      client,
      certificate,
      {
        workspaceId: observation.workspaceId,
        status: observation.ready ? "active" : "discovered",
        source: "cert_manager",
        sourceRef: sourceRefFor(observation),
        name: observation.certificateName,
        keyMode: "cert-manager-managed",
        keyReference: observation.secretName
          ? `k8s://${observation.clusterId}/${observation.namespace}/secret/${observation.secretName}/tls.key`
          : null,
        controllerObservationMetadata: observationMetadata(observation, resourceRecreated),
      },
      0,
    );
    const target = observation.secretName
      ? await upsertControllerTarget(client, observation)
      : null;
    const instance = target
      ? await upsertControllerInstance(client, observation, certificate, managedCertificate, target)
      : null;
    const statusSummary = publicStatusSummary(observation, redaction);
    await createControllerObservationEvidence({
      client,
      workspaceId: observation.workspaceId,
      evidenceType: "certificate.observed",
      subjectType: "managed_certificate",
      subjectId: managedCertificate.id,
      observedAt: observation.observedAt,
      createdByApiTokenId: apiTokenId || null,
      metadata: {
        certificateInstanceId: instance?.id || null,
        clusterId: observation.clusterId,
        eventType: "certificate.observed",
        observationId: observation.observationId,
        source: "cert_manager",
        status: redaction.applied ? "redacted" : "accepted",
        targetId: target?.id || null,
        statusSummary,
      },
    });
    const result = {
      managedCertificateId: managedCertificate.id,
      targetId: target?.id || null,
      certificateInstanceId: instance?.id || null,
    };
    await writeAudit({
      client,
      action: "CERTOPS_CONTROLLER_OBSERVATION_ACCEPTED",
      targetType: "certops_controller_observation",
      workspaceId: observation.workspaceId,
      metadata: {
        apiTokenId: apiTokenId || null,
        clusterId: observation.clusterId,
        managedCertificateId: result.managedCertificateId,
        observationId: observation.observationId,
        resourceRecreated,
        targetId: result.targetId,
        certificateInstanceId: result.certificateInstanceId,
      },
    });
    if (redaction.applied) {
      await writeAudit({
        client,
        action: "CERTOPS_GENERIC_SECRET_REDACTION_APPLIED",
        targetType: "certops_controller_observation",
        workspaceId: observation.workspaceId,
        metadata: {
          apiTokenId: apiTokenId || null,
          clusterId: observation.clusterId,
          observationId: observation.observationId,
          redactionApplied: true,
          redactionCount: redaction.count,
        },
      });
    }
    await client.query(
      `UPDATE certificate_controller_observations
          SET managed_certificate_id = $4, target_id = $5, certificate_instance_id = $6, updated_at = NOW()
        WHERE workspace_id = $1 AND controller_cluster_id = $2 AND idempotency_key = $3`,
      [
        observation.workspaceId,
        observation.clusterId,
        observation.idempotencyKey,
        result.managedCertificateId,
        result.targetId,
        result.certificateInstanceId,
      ],
    );
    await client.query("COMMIT");
    return { ...result, duplicate: false };
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (_rollbackError) {
      // Preserve the transaction failure.
    }
    throw error;
  } finally {
    client.release();
  }
}

function validateAuthenticatedObservationBinding(apiToken, observation) {
  if (!apiToken?.workspaceId || observation.workspaceId !== apiToken.workspaceId) {
    throw observationError(
      "Observation workspace does not match the authenticated token",
      CERTOPS_CONTROLLER_OBSERVATION_WORKSPACE_MISMATCH,
    );
  }
  if (!apiToken.controllerClusterId) {
    throw observationError(
      "Observation token has no controller cluster binding",
      CERTOPS_CONTROLLER_CLUSTER_BINDING_REQUIRED,
    );
  }
  if (observation.clusterId !== apiToken.controllerClusterId) {
    throw observationError(
      "Observation cluster does not match the authenticated token",
      CERTOPS_CONTROLLER_OBSERVATION_CLUSTER_MISMATCH,
    );
  }
}

module.exports = {
  CERTOPS_CONTROLLER_CLUSTER_BINDING_REQUIRED,
  CERTOPS_CONTROLLER_OBSERVATION_CLUSTER_MISMATCH,
  CERTOPS_CONTROLLER_OBSERVATION_CONFLICT,
  CERTOPS_CONTROLLER_OBSERVATION_INVALID,
  CERTOPS_CONTROLLER_OBSERVATION_WORKSPACE_MISMATCH,
  normalizeControllerObservation,
  persistControllerObservation,
  semanticObservation,
  semanticRequestHash,
  stableStringify,
  validateAuthenticatedObservationBinding,
  _test: {
    normalizeControllerObservation,
    semanticObservation,
    semanticRequestHash,
    stableStringify,
  },
};
