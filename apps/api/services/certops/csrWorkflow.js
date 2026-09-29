"use strict";

const { createHash } = require("node:crypto");
const { pool } = require("../../db/database");
const { writeAudit } = require("../audit");
const { logger } = require("../../utils/logger");
const { containsGenericSecretMaterial, containsPrivateKeyMaterial } = require("../../utils/secretMaterial");
const { parsePublicCertificateMaterial } = require("./parser");
const { parsePublicCsr } = require("./csrParser");
const {
  acquireManagedCertificateImportLock,
  linkReconciledCertificateToken,
  normalizeLimit,
  normalizeOffset,
  upsertManagedCertificate,
} = require("./inventory");

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TARGET_TYPES = new Set(["host", "load-balancer", "appliance", "other"]);
const RETIRED = new Set(["revoked", "decommissioned"]);

class CsrWorkflowError extends Error {
  constructor(message, code, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

function fail(message, code, status = 400) {
  throw new CsrWorkflowError(message, code, status);
}

function iso(value) {
  return value ? new Date(value).toISOString() : null;
}

function publicWorkflow(row, includeMaterial = false) {
  if (!row) return null;
  const namesChanged = row.name_additions.length > 0 || row.name_omissions.length > 0;
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    targetId: row.target_id,
    existingCertificateId: row.existing_certificate_id,
    managedCertificateId: row.managed_certificate_id,
    csrDerSha256: row.csr_der_sha256,
    spkiFingerprintSha256: row.spki_fingerprint_sha256,
    subject: row.subject,
    requestedNames: row.requested_names,
    status: row.status,
    signedFingerprintSha256: row.signed_fingerprint_sha256,
    issuedNames: row.issued_names,
    nameAdditions: row.name_additions,
    nameOmissions: row.name_omissions,
    namesChanged,
    namesAcknowledgedAt: iso(row.names_acknowledged_at),
    namesAcknowledgedBy: row.names_acknowledged_by,
    observedInstanceId: row.observed_instance_id,
    identityConflict: row.identity_conflict_at ? {
      code: "CERTOPS_CSR_OBSERVED_IDENTITY_CONFLICT",
      observedAt: iso(row.identity_conflict_at),
      observedInstanceId: row.identity_conflict_instance_id,
      observedCertificateId: row.identity_conflict_certificate_id,
    } : null,
    confirmedAt: iso(row.confirmed_at),
    confirmedBy: row.confirmed_by,
    confirmationMethod: row.confirmation_method,
    createdBy: row.created_by,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
    ...(includeMaterial ? {
      csrPem: row.csr_pem,
      signedLeafPem: row.signed_leaf_pem,
      signedChainPem: row.signed_chain_pem,
    } : {}),
  };
}

async function transaction(work) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await work(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function workflowRow(client, workspaceId, workflowId, lock = false) {
  if (!UUID.test(String(workflowId || ""))) fail("CSR workflow not found", "CERTOPS_CSR_NOT_FOUND", 404);
  const result = await client.query(
    `SELECT * FROM certificate_csr_workflows WHERE workspace_id = $1 AND id = $2 ${lock ? "FOR UPDATE" : ""}`,
    [workspaceId, workflowId],
  );
  if (!result.rows[0]) fail("CSR workflow not found", "CERTOPS_CSR_NOT_FOUND", 404);
  return result.rows[0];
}

async function audit(client, workspaceId, actorUserId, workflowId, action, metadata = {}) {
  await writeAudit({
    client,
    workspaceId,
    actorUserId,
    subjectUserId: actorUserId,
    action,
    targetType: "certificate_csr_workflow",
    targetId: workflowId,
    metadata: { workflow_id: workflowId, ...metadata },
  });
}

async function resolveTarget(client, workspaceId, targetId, target) {
  if (targetId) {
    if (!UUID.test(String(targetId))) fail("Target not found", "CERTOPS_CSR_TARGET_NOT_FOUND", 404);
    const found = await client.query(
      "SELECT id FROM certificate_targets WHERE workspace_id = $1 AND id = $2 AND status <> 'decommissioned'",
      [workspaceId, targetId],
    );
    if (!found.rows[0]) fail("Target not found", "CERTOPS_CSR_TARGET_NOT_FOUND", 404);
    return found.rows[0].id;
  }
  const name = typeof target?.name === "string" ? target.name.trim() : "";
  const type = target?.type;
  if (!name || name.length > 120 || !TARGET_TYPES.has(type) || containsGenericSecretMaterial(name)) {
    fail("Invalid CSR target", "CERTOPS_CSR_TARGET_INVALID");
  }
  const identity = `csr-target:${createHash("sha256").update(`${type}\0${name.toLowerCase()}`).digest("hex")}`;
  const inserted = await client.query(
    `INSERT INTO certificate_targets (workspace_id, name, target_type, source, source_ref)
     VALUES ($1, $2, $3, 'api', $4)
     ON CONFLICT (workspace_id, source, source_ref)
       WHERE source = 'api' AND source_ref LIKE 'csr-target:%'
     DO UPDATE SET name = certificate_targets.name
     RETURNING id`,
    [workspaceId, name, type, identity],
  );
  return inserted.rows[0].id;
}

async function createCsrWorkflow({ workspaceId, actorUserId, csrPem, targetId, target, existingCertificateId }) {
  const csr = await parsePublicCsr(csrPem);
  if (Boolean(targetId) === Boolean(target)) fail("Select or name one target", "CERTOPS_CSR_TARGET_INVALID");
  return transaction(async (client) => {
    const resolvedTargetId = await resolveTarget(client, workspaceId, targetId, target);
    if (existingCertificateId) {
      if (!UUID.test(String(existingCertificateId))) fail("Certificate not found", "CERTOPS_CERTIFICATE_NOT_FOUND", 404);
      const certificate = await client.query(
        "SELECT status FROM managed_certificates WHERE workspace_id = $1 AND id = $2",
        [workspaceId, existingCertificateId],
      );
      if (!certificate.rows[0]) fail("Certificate not found", "CERTOPS_CERTIFICATE_NOT_FOUND", 404);
      if (RETIRED.has(certificate.rows[0].status)) fail("Certificate is retired", "CERTOPS_CSR_IDENTITY_CONFLICT", 409);
    }
    const existing = await client.query(
      `SELECT * FROM certificate_csr_workflows
       WHERE workspace_id = $1 AND target_id = $2 AND csr_der_sha256 = $3`,
      [workspaceId, resolvedTargetId, csr.csrDerSha256],
    );
    if (existing.rows[0]) {
      if ((existing.rows[0].existing_certificate_id || null) !== (existingCertificateId || null)) {
        fail("CSR already belongs to another certificate identity", "CERTOPS_CSR_IDENTITY_CONFLICT", 409);
      }
      return publicWorkflow(existing.rows[0], true);
    }
    const result = await client.query(
      `INSERT INTO certificate_csr_workflows
       (workspace_id, target_id, existing_certificate_id, csr_der_sha256,
        spki_fingerprint_sha256, csr_pem, subject, requested_names, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text[], $9)
       ON CONFLICT (workspace_id, target_id, csr_der_sha256) DO NOTHING
       RETURNING *`,
      [workspaceId, resolvedTargetId, existingCertificateId || null, csr.csrDerSha256,
        csr.spkiFingerprintSha256, csr.csrPem, csr.subject, csr.requestedNames, actorUserId || null],
    );
    if (!result.rows[0]) {
      const raced = await client.query(
        `SELECT * FROM certificate_csr_workflows
         WHERE workspace_id = $1 AND target_id = $2 AND csr_der_sha256 = $3`,
        [workspaceId, resolvedTargetId, csr.csrDerSha256],
      );
      if ((raced.rows[0]?.existing_certificate_id || null) !== (existingCertificateId || null)) {
        fail("CSR already belongs to another certificate identity", "CERTOPS_CSR_IDENTITY_CONFLICT", 409);
      }
      return publicWorkflow(raced.rows[0], true);
    }
    await audit(client, workspaceId, actorUserId, result.rows[0].id, "CERTOPS_CSR_IMPORTED", {
      csr_der_sha256: csr.csrDerSha256,
      target_id: resolvedTargetId,
    });
    return publicWorkflow(result.rows[0], true);
  });
}

async function listCsrWorkflows({ workspaceId, limit, offset }) {
  const pageSize = normalizeLimit(limit);
  const skip = normalizeOffset(offset);
  const result = await pool.query(
    `SELECT * FROM certificate_csr_workflows WHERE workspace_id = $1
     ORDER BY updated_at DESC, id DESC LIMIT $2 OFFSET $3`,
    [workspaceId, pageSize, skip],
  );
  return { items: result.rows.map((row) => publicWorkflow(row)), pagination: { limit: pageSize, offset: skip } };
}

async function getCsrWorkflow({ workspaceId, workflowId }) {
  const row = await workflowRow(pool, workspaceId, workflowId);
  if (containsPrivateKeyMaterial({ csrPem: row.csr_pem, signedLeafPem: row.signed_leaf_pem, signedChainPem: row.signed_chain_pem })) {
    fail("CSR export is unavailable", "PRIVATE_KEY_MATERIAL_REJECTED", 422);
  }
  return publicWorkflow(row, true);
}

function issuedNamesFor(certificate) {
  return [...new Set([certificate.commonName, ...(certificate.subjectAltNames || [])].filter(Boolean))].sort();
}

async function findFingerprintOwners(client, workspaceId, fingerprint) {
  const result = await client.query(
    `SELECT id, status, token_id FROM managed_certificates
     WHERE workspace_id = $1 AND fingerprint_sha256 = $2 FOR UPDATE`,
    [workspaceId, fingerprint],
  );
  return result.rows;
}

function importSignedCertificate({ workspaceId, workflowId, actorUserId, certificatePem }) {
  const certificates = parsePublicCertificateMaterial(certificatePem);
  const leaf = certificates[0];
  const chain = certificates.slice(1).map((item) => item.certificatePem).join("\n") || null;
  return transaction(async (client) => {
    const row = await workflowRow(client, workspaceId, workflowId, true);
    if (row.status === "cancelled") fail("CSR workflow is cancelled", "CERTOPS_CSR_STATE_CONFLICT", 409);
    if (row.status !== "pending_signature") {
      if (row.signed_fingerprint_sha256 === leaf.fingerprintSha256) return publicWorkflow(row, true);
      fail("CSR already has a different signed certificate", "CERTOPS_CSR_STATE_CONFLICT", 409);
    }
    if (row.spki_fingerprint_sha256 !== leaf.spkiFingerprintSha256) {
      fail("Signed certificate public key does not match CSR", "CERTOPS_CSR_PUBLIC_KEY_MISMATCH", 422);
    }
    await acquireManagedCertificateImportLock(client, workspaceId);
    const owners = await findFingerprintOwners(client, workspaceId, leaf.fingerprintSha256);
    if (owners.some((owner) => RETIRED.has(owner.status))) {
      fail("Signed certificate belongs to a retired identity", "CERTOPS_CSR_IDENTITY_CONFLICT", 409);
    }
    let managedCertificateId = row.existing_certificate_id;
    if (managedCertificateId) {
      const selected = await client.query(
        "SELECT status FROM managed_certificates WHERE workspace_id = $1 AND id = $2 FOR UPDATE",
        [workspaceId, managedCertificateId],
      );
      if (!selected.rows[0] || RETIRED.has(selected.rows[0].status)) {
        fail("Selected certificate is unavailable", "CERTOPS_CSR_IDENTITY_CONFLICT", 409);
      }
      if (owners.some((owner) => owner.id !== managedCertificateId)) {
        fail("Signed certificate belongs to another identity", "CERTOPS_CSR_IDENTITY_CONFLICT", 409);
      }
    } else if (owners.length === 1) {
      managedCertificateId = owners[0].id;
    } else if (owners.length > 1) {
      fail("Signed certificate identity is ambiguous", "CERTOPS_CSR_IDENTITY_CONFLICT", 409);
    } else {
      const provisional = await upsertManagedCertificate(client, leaf, {
        workspaceId,
        status: "provisioning",
        source: "api",
        sourceRef: `csr:${row.id}`,
        createdBy: actorUserId || null,
      }, 0);
      managedCertificateId = provisional.id;
    }
    const requested = row.requested_names;
    const issued = issuedNamesFor(leaf);
    const additions = issued.filter((name) => !requested.includes(name));
    const omissions = requested.filter((name) => !issued.includes(name));
    const updated = await client.query(
      `UPDATE certificate_csr_workflows SET status = 'signed_pending_install',
        managed_certificate_id = $3, signed_leaf_pem = $4, signed_chain_pem = $5,
        signed_fingerprint_sha256 = $6, issued_names = $7::text[],
        name_additions = $8::text[], name_omissions = $9::text[], updated_at = NOW()
       WHERE workspace_id = $1 AND id = $2 RETURNING *`,
      [workspaceId, row.id, managedCertificateId, leaf.certificatePem, chain,
        leaf.fingerprintSha256, issued, additions, omissions],
    );
    await audit(client, workspaceId, actorUserId, row.id, "CERTOPS_CSR_SIGNED_IMPORTED", {
      fingerprint_sha256: leaf.fingerprintSha256,
      managed_certificate_id: managedCertificateId,
      names_changed: additions.length > 0 || omissions.length > 0,
    });
    return publicWorkflow(updated.rows[0], true);
  });
}

function namesNeedAcknowledgement(row) {
  return (row.name_additions.length > 0 || row.name_omissions.length > 0) && !row.names_acknowledged_at;
}

async function promote(client, row, actorUserId, method, instanceId = null) {
  if (row.status !== "signed_pending_install") return row;
  if (namesNeedAcknowledgement(row)) fail("Name changes require acknowledgement", "CERTOPS_CSR_NAMES_ACK_REQUIRED", 409);
  const leaf = parsePublicCertificateMaterial(row.signed_leaf_pem)[0];
  const owners = await findFingerprintOwners(client, row.workspace_id, leaf.fingerprintSha256);
  if (owners.some((owner) => RETIRED.has(owner.status) || owner.id !== row.managed_certificate_id)) {
    fail("Signed certificate identity changed", "CERTOPS_CSR_IDENTITY_CONFLICT", 409);
  }
  const existing = await client.query(
    "SELECT id, status, token_id FROM managed_certificates WHERE workspace_id = $1 AND id = $2 FOR UPDATE",
    [row.workspace_id, row.managed_certificate_id],
  );
  const current = existing.rows[0];
  if (!current || RETIRED.has(current.status)) fail("Certificate is retired", "CERTOPS_CSR_IDENTITY_CONFLICT", 409);
  const result = await client.query(
    `UPDATE managed_certificates SET status = 'active', common_name = $3,
      subject_alt_names = $4::text[], issuer = $5, subject = $6,
      serial_number = $7, certificate_pem = $8, fingerprint_sha256 = $9,
      spki_fingerprint_sha256 = $10, public_key_algorithm = $11,
      public_key_size = $12, signature_algorithm = $13, not_before = $14,
      not_after = $15, updated_at = NOW()
     WHERE workspace_id = $1 AND id = $2 RETURNING id`,
    [row.workspace_id, row.managed_certificate_id, leaf.commonName, leaf.subjectAltNames,
      leaf.issuer, leaf.subject, leaf.serialNumber, leaf.certificatePem,
      leaf.fingerprintSha256, leaf.spkiFingerprintSha256, leaf.publicKeyAlgorithm,
      leaf.publicKeySize, leaf.signatureAlgorithm, leaf.notBefore, leaf.notAfter],
  );
  if (!result.rows[0]) fail("Certificate not found", "CERTOPS_CERTIFICATE_NOT_FOUND", 404);
  await linkReconciledCertificateToken({
    client, workspaceId: row.workspace_id, certificateId: row.managed_certificate_id,
    certificate: leaf, existingTokenId: current.token_id, createdBy: actorUserId,
  });
  const updated = await client.query(
    `UPDATE certificate_csr_workflows SET status = 'completed',
      observed_instance_id = COALESCE($3, observed_instance_id),
      confirmed_at = CASE WHEN $5 = 'manual' THEN NOW() ELSE confirmed_at END,
      confirmed_by = CASE WHEN $5 = 'manual' THEN $4 ELSE confirmed_by END,
      confirmation_method = CASE WHEN $5 = 'manual' THEN 'manual' ELSE confirmation_method END,
      updated_at = NOW() WHERE workspace_id = $1 AND id = $2 RETURNING *`,
    [row.workspace_id, row.id, instanceId, actorUserId || null, method],
  );
  await audit(client, row.workspace_id, actorUserId, row.id, "CERTOPS_CSR_COMPLETED", {
    method, managed_certificate_id: row.managed_certificate_id,
    observed_instance_id: instanceId,
  });
  return updated.rows[0];
}

function acknowledgeCsrNames({ workspaceId, workflowId, actorUserId }) {
  return transaction(async (client) => {
    let row = await workflowRow(client, workspaceId, workflowId, true);
    if (row.status !== "signed_pending_install") fail("CSR is not awaiting installation", "CERTOPS_CSR_STATE_CONFLICT", 409);
    if (!row.names_acknowledged_at) {
      const result = await client.query(
        `UPDATE certificate_csr_workflows SET names_acknowledged_at = NOW(),
          names_acknowledged_by = $3, updated_at = NOW()
         WHERE workspace_id = $1 AND id = $2 RETURNING *`,
        [workspaceId, workflowId, actorUserId || null],
      );
      row = result.rows[0];
      await audit(client, workspaceId, actorUserId, workflowId, "CERTOPS_CSR_NAMES_ACKNOWLEDGED", {
        additions: row.name_additions, omissions: row.name_omissions,
      });
    }
    if (row.observed_instance_id && !row.identity_conflict_at) {
      row = await promote(client, row, actorUserId, "observation", row.observed_instance_id);
    }
    return publicWorkflow(row, true);
  });
}

function confirmCsrInstallation({ workspaceId, workflowId, actorUserId }) {
  return transaction(async (client) => {
    const row = await workflowRow(client, workspaceId, workflowId, true);
    if (row.status !== "signed_pending_install") fail("CSR is not awaiting installation", "CERTOPS_CSR_STATE_CONFLICT", 409);
    if (row.identity_conflict_at) {
      fail("Observed certificate belongs to another managed identity", "CERTOPS_CSR_IDENTITY_CONFLICT", 409);
    }
    const target = await client.query(
      "SELECT source, domain_monitor_id FROM certificate_targets WHERE workspace_id = $1 AND id = $2",
      [workspaceId, row.target_id],
    );
    if (!target.rows[0] || !["api", "manual", "import"].includes(target.rows[0].source) ||
        target.rows[0].domain_monitor_id) {
      fail("Monitored targets require an observation", "CERTOPS_CSR_MANUAL_CONFIRMATION_UNAVAILABLE", 409);
    }
    return publicWorkflow(await promote(client, row, actorUserId, "manual"), true);
  });
}

function cancelCsrWorkflow({ workspaceId, workflowId, actorUserId }) {
  return transaction(async (client) => {
    const row = await workflowRow(client, workspaceId, workflowId, true);
    if (row.status === "completed") fail("Completed CSR cannot be cancelled", "CERTOPS_CSR_STATE_CONFLICT", 409);
    if (row.status === "cancelled") return publicWorkflow(row, true);
    const result = await client.query(
      `UPDATE certificate_csr_workflows SET status = 'cancelled', updated_at = NOW()
       WHERE workspace_id = $1 AND id = $2 RETURNING *`,
      [workspaceId, workflowId],
    );
    await audit(client, workspaceId, actorUserId, workflowId, "CERTOPS_CSR_CANCELLED");
    return publicWorkflow(result.rows[0], true);
  });
}

async function recordCsrObservation(client, { workspaceId, targetId, fingerprintSha256, instanceId }) {
  if (!instanceId || !fingerprintSha256 || !targetId) return;
  const found = await client.query(
    `SELECT * FROM certificate_csr_workflows WHERE workspace_id = $1
      AND target_id = $2 AND signed_fingerprint_sha256 = $3
      AND status = 'signed_pending_install' FOR UPDATE`,
    [workspaceId, targetId, fingerprintSha256],
  );
  for (const row of found.rows) {
    const observed = await client.query(
      `SELECT managed_certificate_id FROM certificate_instances
       WHERE workspace_id = $1 AND id = $2 AND target_id = $3
         AND observed_fingerprint_sha256 = $4`,
      [workspaceId, instanceId, targetId, fingerprintSha256],
    );
    const observedCertificateId = observed.rows[0]?.managed_certificate_id;
    if (!observedCertificateId) continue;
    let current = row;
    if (observedCertificateId && observedCertificateId !== row.managed_certificate_id) {
      if (row.existing_certificate_id) {
        // The observation remains factual; a rotation may not silently switch
        // the operator's chosen certificate identity.
        const changed = row.identity_conflict_instance_id !== instanceId ||
          row.identity_conflict_certificate_id !== observedCertificateId;
        await client.query(
          `UPDATE certificate_csr_workflows SET identity_conflict_at = NOW(),
             identity_conflict_instance_id = $3, identity_conflict_certificate_id = $4,
             updated_at = NOW() WHERE workspace_id = $1 AND id = $2`,
          [workspaceId, row.id, instanceId, observedCertificateId],
        );
        if (changed) {
          await client.query("SAVEPOINT csr_identity_conflict_audit");
          try {
            await audit(client, workspaceId, null, row.id, "CERTOPS_CSR_OBSERVED_IDENTITY_CONFLICT", {
              expected_certificate_id: row.managed_certificate_id,
              observed_certificate_id: observedCertificateId,
              observed_instance_id: instanceId,
            });
            await client.query("RELEASE SAVEPOINT csr_identity_conflict_audit");
          } catch (error) {
            await client.query("ROLLBACK TO SAVEPOINT csr_identity_conflict_audit");
            await client.query("RELEASE SAVEPOINT csr_identity_conflict_audit");
            logger.warn("CSR identity conflict audit failed; observation saved", {
              workflowId: row.id, workspaceId, code: error.code || null,
            });
          }
        }
        logger.warn("CSR observation belongs to a different managed certificate", {
          workflowId: row.id, workspaceId,
        });
        continue;
      }
      const reassigned = await client.query(
        `UPDATE certificate_csr_workflows SET managed_certificate_id = $3, updated_at = NOW()
         WHERE workspace_id = $1 AND id = $2 RETURNING *`,
        [workspaceId, row.id, observedCertificateId],
      );
      current = reassigned.rows[0];
      // Other new-certificate workflows may have reused this same provisional
      // fingerprint before the observation arrived. Move those workflows to
      // the observed identity too; otherwise their foreign keys keep the
      // provisional owner alive and block promotion for every workflow.
      await client.query(
        `UPDATE certificate_csr_workflows SET managed_certificate_id = $3,
           updated_at = NOW()
         WHERE workspace_id = $1 AND managed_certificate_id = $2
           AND existing_certificate_id IS NULL
           AND signed_fingerprint_sha256 = $4
           AND status = 'signed_pending_install'`,
        [workspaceId, row.managed_certificate_id, observedCertificateId, fingerprintSha256],
      );
      // The provisional row has no token or deployment. The observer's
      // certificate identity now owns the real instance and must be reused.
      await client.query(
        `DELETE FROM managed_certificates WHERE workspace_id = $1 AND id = $2
           AND status = 'provisioning' AND token_id IS NULL AND source_ref = $3`,
        [workspaceId, row.managed_certificate_id, `csr:${row.id}`],
      );
    }
    const otherOwners = row.existing_certificate_id
      ? (await findFingerprintOwners(client, workspaceId, fingerprintSha256))
        .filter((owner) => owner.id !== row.managed_certificate_id)
      : [];
    const conflictResolved = otherOwners.length === 0;
    await client.query(
      `UPDATE certificate_csr_workflows SET observed_instance_id = $3,
         identity_conflict_at = CASE WHEN $4 THEN NULL ELSE identity_conflict_at END,
         identity_conflict_instance_id = CASE WHEN $4 THEN NULL ELSE identity_conflict_instance_id END,
         identity_conflict_certificate_id = CASE WHEN $4 THEN NULL ELSE identity_conflict_certificate_id END,
         updated_at = NOW()
       WHERE workspace_id = $1 AND id = $2`,
      [workspaceId, row.id, instanceId, conflictResolved],
    );
    if (conflictResolved && !namesNeedAcknowledgement(current)) {
      await client.query("SAVEPOINT csr_workflow_promotion");
      try {
        await promote(client, current, null, "observation", instanceId);
        await client.query("RELEASE SAVEPOINT csr_workflow_promotion");
      } catch (error) {
        await client.query("ROLLBACK TO SAVEPOINT csr_workflow_promotion");
        await client.query("RELEASE SAVEPOINT csr_workflow_promotion");
        logger.warn("CSR observation saved; promotion deferred", {
          workflowId: row.id, workspaceId, code: error.code || null,
        });
      }
    }
  }
}

module.exports = {
  CsrWorkflowError,
  acknowledgeCsrNames,
  cancelCsrWorkflow,
  confirmCsrInstallation,
  createCsrWorkflow,
  getCsrWorkflow,
  importSignedCertificate,
  listCsrWorkflows,
  recordCsrObservation,
};
