"use strict";

const { pool } = require("../../db/database");
const { assertDistributionPolicy: lockWorkspaceForCertOpsSideEffect } = require("./distributionPolicy");
const material = require("./materialDistribution");
const { parsePublicCertificateMaterial } = require("./parser");
const { ensureDerivedRenewalProfile } = require("./renewalProfileDerivation");
const { writeAudit } = require("../audit");

function fail(code, statusCode = 409) {
  const error = new Error(code);
  error.code = code;
  error.statusCode = statusCode;
  throw error;
}

// Restore missing public metadata from accepted publication evidence only.
// This never contacts Vault, issues a certificate, or accepts execution inputs.
async function repairPublicationRenewalProfile({
  workspaceId,
  certificateId,
  actorUserId,
  dbPool = pool,
}) {
  certificateId = certificateId.toLowerCase();
  const client = await dbPool.connect();
  try {
    await client.query("BEGIN");
    await lockWorkspaceForCertOpsSideEffect({ client, workspaceId });
    const found = (
      await client.query(
        `SELECT g.id FROM certops_distribution_groups g
      JOIN certops_management_periods p ON p.workspace_id=g.workspace_id AND p.id=g.management_period_id
      WHERE g.workspace_id=$1 AND g.managed_certificate_id=$2 AND p.ended_at IS NULL`,
        [workspaceId, certificateId],
      )
    ).rows[0];
    if (!found) fail("CERTOPS_DISTRIBUTION_NOT_FOUND", 404);
    // Same lock order as publication: group/period, then certificate.
    const group = await material.lockGroup(client, workspaceId, found.id);
    const certificate = (
      await client.query(
        `SELECT id,profile_id,key_mode,status,fingerprint_sha256,certificate_pem
      FROM managed_certificates WHERE workspace_id=$1 AND id=$2 FOR UPDATE`,
        [workspaceId, certificateId],
      )
    ).rows[0];
    if (
      !certificate ||
      certificate.key_mode !== "vault-managed" ||
      certificate.status !== "active"
    ) {
      fail("CERTOPS_PUBLICATION_REPAIR_INELIGIBLE");
    }
    if (certificate.profile_id) {
      await client.query("COMMIT");
      return { profileId: certificate.profile_id, created: false };
    }
    const issuer = await client.query(
      `SELECT 1 FROM certops_agents
      WHERE workspace_id=$1 AND id=$2 AND status<>'retired' FOR SHARE`,
      [workspaceId, group.issuer_agent_id],
    );
    if (!issuer.rowCount) fail("CERTOPS_PUBLICATION_REPAIR_INELIGIBLE");
    const proof = (
      await client.query(
        `SELECT j.id,j.operation,j.payload,j.assigned_agent_id
      FROM certops_material_versions v JOIN certificate_jobs j
        ON j.workspace_id=v.workspace_id AND j.id=v.publishing_job_id
      WHERE v.workspace_id=$1 AND v.group_id=$2 AND v.id=$3 AND v.state='published'
        AND v.fingerprint_sha256=$4 AND j.status='succeeded'
        AND v.publishing_claim_id=j.claim_id::text AND j.subject_type='managed_certificate'
        AND j.subject_id=$5 AND j.management_period_id=$6`,
        [
          workspaceId,
          group.id,
          group.latest_material_version_id,
          certificate.fingerprint_sha256,
          certificateId,
          group.management_period_id,
        ],
      )
    ).rows[0];
    if (!proof?.payload?.publication)
      fail("CERTOPS_PUBLICATION_REPAIR_EVIDENCE_REQUIRED");
    await material.resolveDistributionJobDefaults({
      client,
      workspaceId,
      operation: proof.operation,
      subjectId: certificateId,
      payload: proof.payload,
      assignedAgentId: proof.assigned_agent_id,
      jobId: proof.id,
    });
    const leaf = parsePublicCertificateMaterial(certificate.certificate_pem)[0];
    if (
      !leaf ||
      leaf.fingerprintSha256 !== certificate.fingerprint_sha256 ||
      JSON.stringify([...leaf.subjectAltNames].sort()) !==
        JSON.stringify([...(proof.payload.sans || [])].sort())
    ) {
      fail("CERTOPS_PUBLICATION_REPAIR_EVIDENCE_REQUIRED");
    }
    const result = await ensureDerivedRenewalProfile({
      client,
      workspaceId,
      certificateId,
      payload: proof.payload,
      certificate: leaf,
      operation: proof.operation,
    });
    if (!result.profileId) fail("CERTOPS_PUBLICATION_REPAIR_PROFILE_REFUSED");
    await writeAudit({
      client,
      workspaceId,
      actorUserId,
      action: "CERTOPS_PUBLICATION_RENEWAL_PROFILE_REPAIRED",
      targetType: "managed_certificate",
      targetId: certificateId,
      metadata: {
        profileId: result.profileId,
        publishingJobId: proof.id,
        groupId: group.id,
      },
    });
    await client.query("COMMIT");
    return { profileId: result.profileId, created: result.created };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

module.exports = { repairPublicationRenewalProfile };
