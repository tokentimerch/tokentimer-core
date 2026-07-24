"use strict";

/**
 * Agent filesystem discovery observations (B17 + B18).
 *
 * Jobless certificate.observed evidence from a credential-authenticated agent
 * must:
 *   1. advance the agent sequence, prove ownership, and insert evidence rows
 *      in one transaction (safe retry);
 *   2. upsert managed certificate / target / instance inventory rows in that
 *      same transaction so discovered certs become inventory-visible (M4);
 *   3. never let client metadata override server-owned fields (agentId,
 *      summary/fingerprint attribution, created_by_agent_id).
 */

const { pool } = require("../../db/database");
const { assertNoPrivateKeyMaterial } = require("../../utils/secretMaterial");
const {
  upsertManagedCertificateByMonitorSource,
  upsertAgentFilesystemTarget,
  upsertAgentFilesystemInstance,
} = require("./inventory");
const { createControllerObservationEvidence, createCertificateEvidence } = require("./evidence");
const {
  enforceAgentSequence,
  assertEvidenceClaimOwnership,
} = require("./agentDispatch");

const CERTOPS_AGENT_OBSERVATION_INVALID = "CERTOPS_AGENT_OBSERVATION_INVALID";
const CERTOPS_AGENT_EVIDENCE_ID_REQUIRED = "CERTOPS_AGENT_EVIDENCE_ID_REQUIRED";
const AGENT_ID_PATTERN = /^[A-Za-z0-9_.:-]+$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const MAX_PATH = 512;
const MAX_TEXT = 1024;

function observationError(
  message,
  code = CERTOPS_AGENT_OBSERVATION_INVALID,
) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function metadataMapFromItem(item) {
  if (!Array.isArray(item?.metadata)) return {};
  const out = {};
  for (const entry of item.metadata) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
    if (typeof entry.name !== "string" || !entry.name.trim()) continue;
    out[entry.name.trim()] = entry.value;
  }
  return out;
}

function requiredId(value, fieldName) {
  if (typeof value !== "string" || !value.trim() || value.length > 128) {
    throw observationError(`${fieldName} is invalid`);
  }
  const trimmed = value.trim();
  if (!AGENT_ID_PATTERN.test(trimmed)) {
    throw observationError(`${fieldName} is invalid`);
  }
  return trimmed;
}

function optionalText(value, fieldName, max = MAX_TEXT) {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string") {
    throw observationError(`${fieldName} is invalid`);
  }
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > max) {
    throw observationError(`${fieldName} is invalid`);
  }
  return trimmed;
}

function optionalSha256(value, fieldName) {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    throw observationError(`${fieldName} is invalid`);
  }
  return value;
}

function optionalTimestamp(value, fieldName) {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
    throw observationError(`${fieldName} is invalid`);
  }
  return new Date(value).toISOString();
}

function optionalStringArray(value, fieldName) {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    if (typeof value === "string") {
      return value
        .split(/[,\n]/)
        .map((part) => part.trim())
        .filter(Boolean)
        .slice(0, 64);
    }
    throw observationError(`${fieldName} is invalid`);
  }
  return value
    .filter((entry) => typeof entry === "string")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .slice(0, 64);
}

/**
 * Structured agent-observation contract for filesystem discovery.
 * Client-provided fields are validated first; server-owned fields are applied
 * AFTER spreading client input so they can never be spoofed (B18 invariant).
 */
function normalizeAgentFilesystemObservation({
  agent,
  evidenceItem,
  serverObservedAt = new Date().toISOString(),
}) {
  assertNoPrivateKeyMaterial(evidenceItem);
  if (!isPlainObject(evidenceItem)) {
    throw observationError("evidence item is invalid");
  }
  if (evidenceItem.eventType !== "certificate.observed") {
    throw observationError("evidence eventType is invalid");
  }

  const clientMeta = metadataMapFromItem(evidenceItem);
  const evidenceId = requiredId(
    evidenceItem.evidenceId || clientMeta.evidenceId,
    "evidenceId",
  );
  const fingerprintSha256 = optionalSha256(
    evidenceItem.fingerprintSha256 || clientMeta.fingerprintSha256,
    "fingerprintSha256",
  );
  if (!fingerprintSha256) {
    throw observationError("fingerprintSha256 is required for discovery evidence");
  }

  const filePath = optionalText(
    clientMeta.filePath || clientMeta.path || clientMeta.certificatePath,
    "filePath",
    MAX_PATH,
  );
  if (!filePath) {
    throw observationError("filePath is required for discovery evidence");
  }

  const targetHost = optionalText(
    clientMeta.targetHost ||
      clientMeta.hostname ||
      clientMeta.host ||
      agent.hostname,
    "targetHost",
    255,
  );
  if (!targetHost) {
    throw observationError("targetHost is required for discovery evidence");
  }

  const observedAt =
    optionalTimestamp(evidenceItem.observedAt, "observedAt") ||
    serverObservedAt;

  const publicCertificate = {
    fingerprintSha256,
    subject: optionalText(
      clientMeta.subject || clientMeta.observedSubject,
      "subject",
    ),
    issuer: optionalText(
      clientMeta.issuer || clientMeta.observedIssuer,
      "issuer",
    ),
    serialNumber: optionalText(clientMeta.serialNumber, "serialNumber"),
    subjectAltNames: optionalStringArray(
      clientMeta.subjectAltNames || clientMeta.sans,
      "subjectAltNames",
    ),
    notBefore: optionalTimestamp(
      clientMeta.notBefore || clientMeta.validFrom,
      "notBefore",
    ),
    notAfter: optionalTimestamp(
      clientMeta.notAfter || clientMeta.validTo,
      "notAfter",
    ),
    certificatePem: optionalText(
      clientMeta.certificatePem,
      "certificatePem",
      65536,
    ),
  };

  // Security-relevant invariant (B18): server-owned fields MUST be assigned
  // AFTER any client-submitted metadata is assembled so a compromised or
  // buggy agent cannot spoof agentId, summary, fingerprint attribution, or
  // created_by_agent_id.
  const clientSubmitted = {
    evidenceId,
    filePath,
    targetHost,
    publicCertificate,
    summary: optionalText(evidenceItem.summary || clientMeta.summary, "summary"),
    clientMetadata: clientMeta,
    observedAt,
  };

  return {
    ...clientSubmitted,
    schemaVersion: 1,
    source: "agent_filesystem",
    agentId: agent.agentId,
    agentRowId: agent.id,
    workspaceId: agent.workspaceId,
    fingerprintSha256,
    summary: clientSubmitted.summary,
    observedAtServer: serverObservedAt,
  };
}

function certSourceRefFor(observation) {
  return `${observation.agentId}/${observation.targetHost}/${observation.filePath}`;
}

function targetSourceRefFor(observation) {
  return `${observation.agentId}/${observation.targetHost}`;
}

function certificateFor(observation) {
  const publicCertificate = observation.publicCertificate || {};
  return {
    certificatePem: publicCertificate.certificatePem || null,
    commonName:
      publicCertificate.subjectAltNames?.[0] ||
      observation.targetHost ||
      observation.filePath,
    fingerprintSha256: observation.fingerprintSha256,
    issuer: publicCertificate.issuer || null,
    notAfter: publicCertificate.notAfter || null,
    notBefore: publicCertificate.notBefore || null,
    serialNumber: publicCertificate.serialNumber || null,
    subject: publicCertificate.subject || null,
    subjectAltNames: publicCertificate.subjectAltNames || [],
  };
}

async function findExistingEvidenceByClientId(client, observation) {
  const result = await client.query(
    `SELECT id, workspace_id, job_id, evidence_type, subject_type, subject_id,
            metadata, redacted_output, output_truncated, output_sha256,
            output_size_bytes, observed_at, created_by_user_id,
            created_by_api_token_id, created_by_agent_id, client_evidence_id,
            created_at
       FROM certificate_evidence
      WHERE workspace_id = $1
        AND created_by_agent_id = $2
        AND client_evidence_id = $3
      LIMIT 1`,
    [observation.workspaceId, observation.agentRowId, observation.evidenceId],
  );
  return result.rows[0] || null;
}

async function upsertInventoryForObservation(client, observation) {
  const certificate = certificateFor(observation);
  const certSourceRef = certSourceRefFor(observation);
  const targetSourceRef = targetSourceRefFor(observation);

  const managedCertificate = await upsertManagedCertificateByMonitorSource(
    client,
    certificate,
    {
      workspaceId: observation.workspaceId,
      status: "discovered",
      source: "agent_filesystem",
      sourceRef: certSourceRef,
      name: certificate.commonName || observation.filePath,
      keyMode: "agent-local",
      keyReference: `file://${observation.filePath}`,
      controllerObservationMetadata: {
        agentId: observation.agentId,
        filePath: observation.filePath,
        targetHost: observation.targetHost,
        observedAt: observation.observedAt,
        observedAtServer: observation.observedAtServer,
        source: "agent_filesystem",
      },
    },
    0,
  );

  const target = await upsertAgentFilesystemTarget(client, {
    workspaceId: observation.workspaceId,
    sourceRef: targetSourceRef,
    hostname: observation.targetHost,
    name: observation.targetHost,
    deploymentReference: `agent://${observation.agentId}/${observation.targetHost}`,
    publicMetadata: {
      agentId: observation.agentId,
      targetHost: observation.targetHost,
      observationOnly: true,
    },
  });

  const instance = await upsertAgentFilesystemInstance(client, {
    workspaceId: observation.workspaceId,
    managedCertificateId: managedCertificate.id,
    targetId: target.id,
    status: "discovered",
    sourceRef: certSourceRef,
    fingerprintSha256: observation.fingerprintSha256,
    serialNumber: certificate.serialNumber,
    subject: certificate.subject,
    issuer: certificate.issuer,
    notBefore: certificate.notBefore,
    notAfter: certificate.notAfter,
    deploymentReference: `file://${observation.filePath}`,
    observedAt: observation.observedAt,
    publicMetadata: {
      agentId: observation.agentId,
      filePath: observation.filePath,
      evidenceId: observation.evidenceId,
      observedAtServer: observation.observedAtServer,
    },
  });

  return { managedCertificate, target, instance };
}

async function persistOneObservation(client, observation) {
  const existing = await findExistingEvidenceByClientId(client, observation);
  if (existing) {
    return {
      duplicate: true,
      evidence: existing,
      managedCertificateId:
        existing.metadata?.managedCertificateId ||
        existing.subject_id ||
        null,
    };
  }

  const inventory = await upsertInventoryForObservation(client, observation);

  // Server-owned metadata fields set AFTER client metadata (B18).
  const clientMetadata = {
    ...(observation.clientMetadata && typeof observation.clientMetadata === "object"
      ? observation.clientMetadata
      : {}),
  };
  delete clientMetadata.agentId;
  delete clientMetadata.summary;
  delete clientMetadata.fingerprintSha256;
  delete clientMetadata.created_by_agent_id;
  delete clientMetadata.createdByAgentId;

  const metadata = {
    ...clientMetadata,
    // Security-relevant invariant: server-owned fields win.
    agentId: observation.agentId,
    summary: observation.summary,
    fingerprintSha256: observation.fingerprintSha256,
    filePath: observation.filePath,
    targetHost: observation.targetHost,
    evidenceId: observation.evidenceId,
    source: "agent_filesystem",
    eventType: "certificate.observed",
    managedCertificateId: inventory.managedCertificate.id,
    targetId: inventory.target.id,
    certificateInstanceId: inventory.instance?.id || null,
    observedAtServer: observation.observedAtServer,
  };

  const evidence = await createControllerObservationEvidence({
    client,
    workspaceId: observation.workspaceId,
    evidenceType: "certificate.observed",
    subjectType: "managed_certificate",
    subjectId: inventory.managedCertificate.id,
    observedAt: observation.observedAt,
    createdByAgentId: observation.agentRowId,
    clientEvidenceId: observation.evidenceId,
    metadata,
  });

  return {
    duplicate: false,
    evidence,
    managedCertificateId: inventory.managedCertificate.id,
    targetId: inventory.target.id,
    certificateInstanceId: inventory.instance?.id || null,
  };
}

/**
 * Persist a batch of jobless discovery observations atomically with the
 * agent sequence CAS (B17 + B18).
 */
async function persistAgentDiscoveryEvidenceBatch({
  dbPool = pool,
  agent,
  envelope,
  evidenceItems,
  deps = {},
} = {}) {
  if (!agent?.id || !agent?.workspaceId || !agent?.agentId) {
    throw observationError("Authenticated agent identity is required");
  }
  if (!Array.isArray(evidenceItems) || evidenceItems.length < 1) {
    throw observationError("evidenceItems is invalid");
  }

  const enforceSequence = deps.enforceAgentSequence || enforceAgentSequence;
  const serverObservedAt = new Date().toISOString();
  const observations = evidenceItems.map((item) =>
    normalizeAgentFilesystemObservation({
      agent,
      evidenceItem: item,
      serverObservedAt,
    }),
  );

  const client = await dbPool.connect();
  try {
    await client.query("BEGIN");
    await enforceSequence({
      client,
      agentRowId: agent.id,
      envelope,
    });

    const results = [];
    for (const observation of observations) {
      results.push(await persistOneObservation(client, observation));
    }

    await client.query("COMMIT");
    return {
      ok: true,
      evidenceCount: results.length,
      duplicateCount: results.filter((row) => row.duplicate).length,
      items: results,
    };
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (_rollbackError) {
      // Preserve the original failure.
    }
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Persist job-bound agent evidence atomically with sequence CAS and claim
 * ownership proof (B18).
 */
async function persistAgentJobEvidenceBatch({
  dbPool = pool,
  agent,
  envelope,
  jobId,
  evidenceItems,
  deps = {},
} = {}) {
  if (!agent?.id || !agent?.workspaceId || !agent?.agentId) {
    throw observationError("Authenticated agent identity is required");
  }
  if (typeof jobId !== "string" || !jobId.trim()) {
    throw observationError("jobId is required");
  }
  if (!Array.isArray(evidenceItems) || evidenceItems.length < 1) {
    throw observationError("evidenceItems is invalid");
  }

  const enforceSequence = deps.enforceAgentSequence || enforceAgentSequence;
  const assertOwnership =
    deps.assertEvidenceClaimOwnership || assertEvidenceClaimOwnership;
  const persist = deps.createCertificateEvidence || createCertificateEvidence;

  const client = await dbPool.connect();
  try {
    await client.query("BEGIN");
    await enforceSequence({
      client,
      agentRowId: agent.id,
      envelope,
    });
    await assertOwnership({
      dbPool: client,
      agent,
      jobId,
    });

    const created = [];
    for (const item of evidenceItems) {
      if (!item || typeof item !== "object" || Array.isArray(item)) {
        throw observationError("evidence item is invalid");
      }
      const evidenceId =
        typeof item.evidenceId === "string" ? item.evidenceId.trim() : "";
      if (!evidenceId) {
        throw observationError(
          "evidenceId is required",
          CERTOPS_AGENT_EVIDENCE_ID_REQUIRED,
        );
      }

      const clientMeta = metadataMapFromItem(item);
      // Security-relevant invariant (B18): server-owned fields win.
      const metadata = {
        ...clientMeta,
        summary: item.summary ?? null,
        fingerprintSha256: item.fingerprintSha256 ?? null,
        agentId: agent.agentId,
        evidenceId,
      };

      const evidence = await persist({
        client,
        workspaceId: agent.workspaceId,
        jobId,
        evidenceType: item.eventType,
        metadata,
        serverOwnedMetadata: {
          agentId: agent.agentId,
          summary: item.summary ?? null,
          fingerprintSha256: item.fingerprintSha256 ?? null,
          evidenceId,
        },
        observedAt: item.observedAt,
        createdByAgentId: agent.id,
        clientEvidenceId: evidenceId,
      });
      if (evidence) created.push(evidence);
    }

    await client.query("COMMIT");
    return { ok: true, evidenceCount: created.length, items: created };
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (_rollbackError) {
      // Preserve the original failure.
    }
    throw error;
  } finally {
    client.release();
  }
}

module.exports = {
  CERTOPS_AGENT_EVIDENCE_ID_REQUIRED,
  CERTOPS_AGENT_OBSERVATION_INVALID,
  normalizeAgentFilesystemObservation,
  persistAgentDiscoveryEvidenceBatch,
  persistAgentJobEvidenceBatch,
  _test: {
    certificateFor,
    certSourceRefFor,
    metadataMapFromItem,
    normalizeAgentFilesystemObservation,
    targetSourceRefFor,
  },
};
