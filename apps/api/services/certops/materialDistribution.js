"use strict";

// Public control-plane metadata only. All entrypoints require a transaction-
// owned client from the caller; never connect to Vault or accept bundle bytes.
const crypto = require("node:crypto");
const contract = require("../../../../packages/contracts/certops/validate-material-distribution.cjs");
const { canonicalizeJobPayload } = require("../../../../packages/contracts/certops/canonical-json.cjs");
const { assertNoPrivateKeyMaterial, containsGenericSecretMaterial } = require("../../utils/secretMaterial");
const { parsePublicCertificateMaterial } = require("./parser");
const { linkReconciledCertificateToken } = require("./inventory");


function fail(code, statusCode = 409) {
  const error = new Error(code);
  error.code = code;
  error.statusCode = statusCode;
  throw error;
}

function validateDistributionContract(name, value) {
  assertNoPrivateKeyMaterial(value);
  if (containsGenericSecretMaterial(value) || !contract.validate(name, value)) fail("CERTOPS_MATERIAL_CONTRACT_INVALID", 422);
  return value;
}

function normalizeDistributionId(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    fail("CERTOPS_MATERIAL_CONTRACT_INVALID", 422);
  }
  return value.toLowerCase();
}

function hashIntent(value) {
  return crypto.createHash("sha256").update(canonicalizeJobPayload(value)).digest("hex");
}

function enqueueDistributionEvent(client, workspaceId, eventType, dedupeKey, payload) {
  return require("./outbox").enqueueOutboxEvent({ client,workspaceId,eventType,dedupeKey,payload });
}

async function lockGroup(client, workspaceId, groupId, { allowInactive = false } = {}) {
  groupId = normalizeDistributionId(groupId);
  const group = (await client.query(`SELECT g.*, p.ended_at FROM certops_distribution_groups g
    JOIN certops_management_periods p ON p.workspace_id=g.workspace_id AND p.id=g.management_period_id
    WHERE g.workspace_id=$1 AND g.id=$2 FOR UPDATE OF g,p`, [workspaceId, groupId])).rows[0];
  if (!group) fail("CERTOPS_DISTRIBUTION_NOT_FOUND", 404);
  if (!allowInactive && (group.state !== "active" || group.ended_at)) fail("CERTOPS_DISTRIBUTION_INACTIVE");
  return group;
}

async function resolveDistributionJobDefaults({ client, workspaceId, operation, subjectId, payload, assignedAgentId, jobId }) {
  const intent = validateDistributionContract(payload.publication ? "publication" : "materialDeployment", payload.publication || payload.materialDeployment);
  const group = await lockGroup(client, workspaceId, intent.groupId);
  // Manual renewals may omit routing. Publication always belongs to this
  // group's issuer; an explicitly different agent remains forbidden.
  if (payload.publication && !assignedAgentId) assignedAgentId = group.issuer_agent_id;
  if (!assignedAgentId || group.managed_certificate_id !== subjectId || group.material_store_ref !== intent.materialStoreRef) fail("CERTOPS_MATERIAL_ASSIGNMENT_REQUIRED", 422);
  if (payload.publication) {
    if (!["issue", "renew"].includes(operation) || group.issuer_agent_id !== assignedAgentId ||
      group.management_period_id !== intent.managementPeriodId || group.issuance_profile_ref !== intent.issuanceProfileRef ||
      group.profile_revision !== intent.profileRevision) fail("CERTOPS_PUBLICATION_INTENT_MISMATCH");
    if (jobId && !(await client.query(`SELECT 1 FROM certops_material_versions WHERE workspace_id=$1
      AND group_id=$2 AND id=$3 AND publishing_job_id=$4 AND state IN ('allocated','staged','published','orphaned_unknown_effect')`,
    [workspaceId,group.id,intent.materialVersionId,jobId])).rowCount) fail("CERTOPS_PUBLICATION_INTENT_MISMATCH");
  } else {
    await assertDeployableVersion(client, workspaceId, intent.groupId, intent.materialVersionId);
    const binding = (await client.query(`SELECT d.*,r.generation,r.material_version_id,v.provider_version,v.fingerprint_sha256,
      r.verification_only,s.desired_generation,b.state AS binding_state,b.authorization_revision AS current_revision,r.state AS rollout_state
      FROM certops_consumer_deployments d JOIN certops_distribution_rollouts r ON r.workspace_id=d.workspace_id AND r.id=d.rollout_id
      JOIN certops_material_versions v ON v.workspace_id=r.workspace_id AND v.id=r.material_version_id
      JOIN certops_consumer_current_state s ON s.workspace_id=d.workspace_id AND s.binding_id=d.binding_id
      JOIN certops_consumer_bindings b ON b.workspace_id=d.workspace_id AND b.id=d.binding_id
      WHERE d.workspace_id=$1 AND d.group_id=$2 AND d.rollout_id=$3 AND d.binding_id=$4 FOR UPDATE OF d`,
    [workspaceId, group.id, intent.rolloutId, intent.bindingId])).rows[0];
    if (!binding || jobId && binding.job_id !== jobId || operation !== "deploy-from-store" || binding.assigned_agent_id !== assignedAgentId ||
      (intent.verificationOnly === true) !== binding.verification_only || binding.binding_state !== "active" || !["pending","deploying"].includes(binding.rollout_state) || binding.current_revision !== intent.authorizationRevision ||
      Number(binding.generation) !== intent.generation || Number(binding.desired_generation) !== intent.generation ||
      binding.material_version_id !== intent.materialVersionId || binding.provider_version !== intent.providerVersion ||
      binding.fingerprint_sha256 !== intent.fingerprintSha256 || binding.deployment_profile_ref !== intent.deploymentProfileRef ||
      binding.profile_revision !== intent.profileRevision || binding.verification_policy !== intent.verificationPolicy) fail("CERTOPS_DEPLOYMENT_INTENT_MISMATCH");
  }
  return { autoAssignedAgentId: assignedAgentId };
}

async function createGroupForSource({ client, workspaceId, certificateId, issuerAgentId, materialStoreRef, issuanceProfileRef, profileRevision, groupId = crypto.randomUUID() }) {
  const period = (await client.query(`SELECT id FROM certops_management_periods WHERE workspace_id=$1
    AND managed_certificate_id=$2 AND ended_at IS NULL FOR UPDATE`, [workspaceId, certificateId])).rows[0];
  if (!period) fail("CERTOPS_DISTRIBUTION_PERIOD_REQUIRED");
  await client.query(`INSERT INTO certops_distribution_groups(id,workspace_id,managed_certificate_id,management_period_id,
    issuer_agent_id,material_store_ref,issuance_profile_ref,profile_revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
    ON CONFLICT(workspace_id,managed_certificate_id,management_period_id) DO NOTHING`,
  [groupId, workspaceId, certificateId, period.id, issuerAgentId, materialStoreRef, issuanceProfileRef, profileRevision]);
  return (await client.query(`SELECT * FROM certops_distribution_groups WHERE workspace_id=$1 AND managed_certificate_id=$2 AND management_period_id=$3`,
  [workspaceId, certificateId, period.id])).rows[0];
}

async function allocateMaterialVersion({ client, workspaceId, groupId, job }) {
  const intent = validateDistributionContract("publication", job.payload.publication);
  const group = await lockGroup(client, workspaceId, groupId);
  if (group.id !== intent.groupId || group.management_period_id !== intent.managementPeriodId ||
    group.material_store_ref !== intent.materialStoreRef || group.issuance_profile_ref !== intent.issuanceProfileRef ||
    group.profile_revision !== intent.profileRevision || group.issuer_agent_id !== job.assigned_agent_id ||
    group.managed_certificate_id !== job.subject_id || !["issue", "renew"].includes(job.operation)) fail("CERTOPS_PUBLICATION_INTENT_MISMATCH");
  // Group lock serializes competing issuers; a pending publication never
  // authorizes a fresh ACME order merely because a report was lost.
  const pending = await client.query(`SELECT id FROM certops_material_versions
    WHERE workspace_id=$1 AND group_id=$2 AND state IN ('allocated','staged','orphaned_unknown_effect')
      AND publishing_job_id<>$3`, [workspaceId, groupId, job.id]);
  if (pending.rowCount) fail("CERTOPS_PUBLICATION_UNRESOLVED");
  await client.query(`INSERT INTO certops_material_versions(id,workspace_id,group_id,management_period_id,
    publishing_job_id,profile_revision) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (workspace_id,publishing_job_id) DO NOTHING`,
  [intent.materialVersionId, workspaceId, groupId, intent.managementPeriodId, job.id, intent.profileRevision]);
}

// Called only inside the existing claim/nonce/result transaction, while its
// job row is locked. A receipt is not a generic external-executor event.
async function acceptPublicationReceipt({ client, workspaceId, agentId, job, receipt, certificatePem }) {
  validateDistributionContract("publicationReceipt", receipt);
  const intent = validateDistributionContract("publication", job.payload.publication);
  const group = await lockGroup(client, workspaceId, intent.groupId);
  const current = (await client.query(`SELECT * FROM certops_material_versions
    WHERE workspace_id=$1 AND group_id=$2 AND id=$3 FOR UPDATE`, [workspaceId, group.id, intent.materialVersionId])).rows[0];
  if (!current || receipt.workspaceId !== workspaceId || receipt.groupId !== group.id ||
    receipt.materialVersionId !== current.id || receipt.materialStoreRef !== group.material_store_ref ||
    current.publishing_job_id !== job.id || job.claimed_by_agent_id !== agentId ||
    job.assigned_agent_id !== group.issuer_agent_id || agentId !== group.issuer_agent_id ||
    job.management_period_id !== group.management_period_id || intent.managementPeriodId !== group.management_period_id ||
    current.profile_revision !== group.profile_revision || intent.profileRevision !== group.profile_revision) fail("CERTOPS_PUBLICATION_RECEIPT_MISMATCH");
  const lease = await client.query(`SELECT 1 FROM certificate_jobs WHERE workspace_id=$1 AND id=$2
    AND claim_id=$3 AND lease_expires_at>clock_timestamp()`, [workspaceId, job.id, job.claim_id]);
  if (!lease.rowCount) fail("CERTOPS_PUBLICATION_CLAIM_EXPIRED");
  assertNoPrivateKeyMaterial(certificatePem);
  const certificates = parsePublicCertificateMaterial(certificatePem);
  const leaf = certificates[0];
  if (!leaf || leaf.fingerprintSha256 !== receipt.fingerprintSha256 ||
    new Date(leaf.notAfter).toISOString() !== receipt.validTo || Date.parse(receipt.validTo) <= Date.now()) fail("CERTOPS_PUBLICATION_CERTIFICATE_MISMATCH", 422);
  const approvedSans = [...(job.payload.sans || [])].sort();
  if (JSON.stringify([...leaf.subjectAltNames].sort()) !== JSON.stringify(approvedSans)) fail("CERTOPS_PUBLICATION_SAN_MISMATCH", 422);
  if (current.state === "published") {
    if (current.fingerprint_sha256 !== receipt.fingerprintSha256 || current.provider_version !== receipt.providerVersion ||
      current.publishing_claim_id !== job.claim_id) fail("CERTOPS_PUBLICATION_CONFLICT");
    return { duplicate: true, materialVersionId: current.id };
  }
  // Existing identity triggers establish the new immutable fingerprint,
  // management association and history; never rewrite a previous identity.
  await client.query(`UPDATE managed_certificates SET status='active', certificate_pem=$3,
    fingerprint_sha256=$4, not_after=$5, not_before=$6, issuer=$7, subject=$8, serial_number=$9,
    subject_alt_names=$10, key_mode='vault-managed', key_reference=$11,
    identity_observed_at=clock_timestamp(), updated_at=clock_timestamp()
    WHERE workspace_id=$1 AND id=$2`, [workspaceId, group.managed_certificate_id,
    certificatePem, receipt.fingerprintSha256, receipt.validTo, leaf.notBefore, leaf.issuer,
    leaf.subject, leaf.serialNumber, leaf.subjectAltNames, `vault:${intent.materialStoreRef}/${group.id}`]);
  const identity = (await client.query(`SELECT current_identity_id FROM certops_management_periods
    WHERE workspace_id=$1 AND id=$2 AND ended_at IS NULL`, [workspaceId, group.management_period_id])).rows[0]?.current_identity_id;
  if (!identity) fail("CERTOPS_PUBLICATION_IDENTITY_MISSING");
  await linkReconciledCertificateToken({ client, workspaceId, certificateId: group.managed_certificate_id, certificate: leaf });
  await require("./renewalProfileDerivation").ensureDerivedRenewalProfile({ client, workspaceId,
    certificateId: group.managed_certificate_id, payload: job.payload, certificate: leaf, operation: job.operation });
  await client.query(`UPDATE certops_material_versions SET state='published', publishing_claim_id=$4,
    provider_version=$5, fingerprint_sha256=$6, valid_to=$7, certificate_identity_id=$8, published_at=clock_timestamp()
    WHERE workspace_id=$1 AND group_id=$2 AND id=$3`, [workspaceId, group.id, current.id,
    job.claim_id, receipt.providerVersion, receipt.fingerprintSha256, receipt.validTo, identity]);
  await client.query(`UPDATE certops_distribution_groups SET latest_material_version_id=$3
    WHERE workspace_id=$1 AND id=$2`, [workspaceId, group.id, current.id]);
  await enqueueDistributionEvent(client, workspaceId, "material_published", current.id,
    { groupId: group.id, materialVersionId: current.id });
  return { duplicate: false, materialVersionId: current.id };
}

async function buildRolloutIntent({ client, workspaceId, groupId, materialVersionId, maxParallel = 1, verificationOnly = false }) {
  const group = await lockGroup(client, workspaceId, groupId);
  await assertDeployableVersion(client, workspaceId, groupId, materialVersionId);
  const version = (await client.query(`SELECT * FROM certops_material_versions
    WHERE workspace_id=$1 AND group_id=$2 AND id=$3 AND state='published'`, [workspaceId, groupId, materialVersionId])).rows[0];
  if (!version || new Date(version.valid_to).getTime() <= Date.now()) fail("CERTOPS_ROLLOUT_VERSION_INVALID");
  const bindings = (await client.query(`SELECT * FROM certops_consumer_bindings WHERE workspace_id=$1
    AND group_id=$2 AND state='active' ORDER BY id FOR SHARE`, [workspaceId, groupId])).rows;
  if (!bindings.length || bindings.length > 1000 || !Number.isInteger(maxParallel) || maxParallel < 1 || maxParallel > 16) fail("CERTOPS_ROLLOUT_POLICY_INVALID", 422);
  const generation = Number(group.generation) + 1;
  if (typeof verificationOnly !== "boolean") fail("CERTOPS_ROLLOUT_POLICY_INVALID",422);
  const intent = { workspaceId, groupId, materialVersionId, generation, maxParallel, verificationOnly,
    managementPeriodId: group.management_period_id, materialStoreRef: group.material_store_ref,
    issuanceProfileRevision: group.profile_revision, fingerprintSha256: version.fingerprint_sha256,
    providerVersion: version.provider_version, bindings: bindings.map((b) => ({
    bindingId: b.id, agentId: b.assigned_agent_id, profileRef: b.deployment_profile_ref,
    profileRevision: b.profile_revision, authorizationRevision: b.authorization_revision,
    required: b.required, wave: b.wave, verificationPolicy: b.verification_policy, freshnessSeconds: b.freshness_seconds })) };
  return { group, bindings, intent };
}

async function assertDeployableVersion(client, workspaceId, groupId, materialVersionId) {
  const version = await client.query(`SELECT v.id FROM certops_material_versions v
    JOIN certops_certificate_identities i ON i.workspace_id=v.workspace_id AND i.id=v.certificate_identity_id
    WHERE v.workspace_id=$1 AND v.group_id=$2 AND v.id=$3 AND v.state='published'
      AND v.valid_to>clock_timestamp() AND i.lifecycle_status='active' FOR SHARE OF i`,
  [workspaceId,groupId,materialVersionId]);
  if (!version.rowCount) fail("CERTOPS_ROLLOUT_VERSION_INVALID");
}

async function createRolloutSnapshot({ client, workspaceId, groupId, materialVersionId, approvalJobId, approvedIntentHash, maxParallel = 1, verificationOnly = false }) {
  const existing = (await client.query(`SELECT id FROM certops_distribution_rollouts WHERE workspace_id=$1 AND approval_job_id=$2`, [workspaceId, approvalJobId])).rows[0];
  if (existing) return { rolloutId: existing.id, duplicate: true };
  const { bindings, intent } = await buildRolloutIntent({ client, workspaceId, groupId, materialVersionId, maxParallel, verificationOnly });
  const generation = intent.generation;
  if (hashIntent(intent) !== approvedIntentHash) fail("CERTOPS_ROLLOUT_APPROVAL_MISMATCH");
  const approval = (await client.query(`SELECT approved_canonical_intent_hash, approved_payload_hash, status, payload
    FROM certificate_jobs WHERE workspace_id=$1 AND id=$2 FOR SHARE`, [workspaceId, approvalJobId])).rows[0];
  const { computeJobPayloadApprovalHash } = require("./jobApprovals");
  if (!approval || approval.status !== "pending" || !approval.approved_payload_hash ||
    computeJobPayloadApprovalHash(approval.payload) !== approval.approved_payload_hash ||
    hashIntent(approval.payload.distributionRollout) !== approvedIntentHash) fail("CERTOPS_ROLLOUT_APPROVAL_REQUIRED");
  const rolloutId = crypto.randomUUID();
  await client.query(`INSERT INTO certops_distribution_rollouts(id,workspace_id,group_id,material_version_id,
    generation,approved_intent_hash,approval_job_id,max_parallel,verification_only) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
  [rolloutId, workspaceId, groupId, materialVersionId, generation, approvedIntentHash, approvalJobId, maxParallel, verificationOnly]);
  for (const b of bindings) {
    await client.query(`INSERT INTO certops_consumer_deployments(workspace_id,group_id,rollout_id,binding_id,
      assigned_agent_id,deployment_profile_ref,profile_revision,authorization_revision,required,wave,verification_policy,freshness_seconds)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, [workspaceId, groupId, rolloutId, b.id,
      b.assigned_agent_id, b.deployment_profile_ref, b.profile_revision, b.authorization_revision, b.required, b.wave, b.verification_policy, b.freshness_seconds]);
    await client.query(`INSERT INTO certops_consumer_current_state(workspace_id,group_id,binding_id,desired_material_version_id,desired_generation)
      VALUES($1,$2,$3,$4,$5) ON CONFLICT(workspace_id,binding_id) DO UPDATE
      SET desired_material_version_id=EXCLUDED.desired_material_version_id, desired_generation=EXCLUDED.desired_generation`,
    [workspaceId, groupId, b.id, materialVersionId, generation]);
  }
  await client.query(`UPDATE certops_distribution_groups SET generation=$3 WHERE workspace_id=$1 AND id=$2`, [workspaceId, groupId, generation]);
  await enqueueDistributionEvent(client, workspaceId, "distribution_rollout_requested", rolloutId, { groupId, rolloutId });
  return { rolloutId, ...intent };
}

async function acceptDeploymentReceipt({ client, workspaceId, agentId, job, receipt, jobStatus }) {
  validateDistributionContract("deploymentReceipt", receipt);
  const intent = validateDistributionContract("materialDeployment", job.payload.materialDeployment);
  await lockGroup(client, workspaceId, intent.groupId);
  const row = (await client.query(`SELECT d.*, r.generation, r.material_version_id, r.state AS rollout_state,
    b.state AS binding_state,b.authorization_revision AS current_authorization_revision,
    s.desired_generation,s.desired_material_version_id,v.fingerprint_sha256,v.valid_to
    FROM certops_consumer_deployments d JOIN certops_distribution_rollouts r
      ON r.workspace_id=d.workspace_id AND r.id=d.rollout_id
    JOIN certops_consumer_bindings b ON b.workspace_id=d.workspace_id AND b.id=d.binding_id
    JOIN certops_consumer_current_state s ON s.workspace_id=d.workspace_id AND s.binding_id=d.binding_id
    JOIN certops_material_versions v ON v.workspace_id=r.workspace_id AND v.id=r.material_version_id
    WHERE d.workspace_id=$1 AND d.rollout_id=$2 AND d.binding_id=$3 FOR UPDATE OF d,s`,
  [workspaceId, intent.rolloutId, intent.bindingId])).rows[0];
  if (!row || row.job_id !== job.id || row.assigned_agent_id !== agentId ||
    job.claimed_by_agent_id !== agentId || receipt.workspaceId !== workspaceId || receipt.groupId !== row.group_id ||
    receipt.bindingId !== row.binding_id || receipt.materialVersionId !== row.material_version_id ||
    receipt.generation !== Number(row.generation) || receipt.fingerprintSha256 !== row.fingerprint_sha256 ||
    receipt.validTo !== new Date(row.valid_to).toISOString()) fail("CERTOPS_DEPLOYMENT_RECEIPT_MISMATCH");
  if (receipt.trustValidated && !receipt.servedVerified || receipt.servedVerified && !receipt.bound || receipt.bound && !receipt.installed || receipt.installed && !receipt.fetched) fail("CERTOPS_DEPLOYMENT_STAGES_INVALID", 422);
  if (jobStatus === "succeeded" && (!receipt.servedVerified || (row.verification_policy === "trust" && !receipt.trustValidated))) fail("CERTOPS_DEPLOYMENT_ASSURANCE_MISSING", 422);
  const lease = await client.query(`SELECT 1 FROM certificate_jobs WHERE workspace_id=$1 AND id=$2 AND claim_id=$3 AND lease_expires_at>clock_timestamp()`, [workspaceId, job.id, job.claim_id]);
  if (!lease.rowCount) fail("CERTOPS_DEPLOYMENT_CLAIM_EXPIRED");
  const age = Date.now() - Date.parse(receipt.observedAt);
  if (!Number.isFinite(age) || age < -30000 || age > row.freshness_seconds * 1000) fail("CERTOPS_DEPLOYMENT_EVIDENCE_STALE");
  const stage = jobStatus === "orphaned_unknown_effect" ? "orphaned_unknown_effect" : jobStatus === "failed" ? "failed" : receipt.trustValidated ? "trust_validated" : receipt.servedVerified ? "served_verified" : receipt.bound ? "bound" : receipt.installed ? "installed" : "fetched";
  await client.query(`UPDATE certops_consumer_deployments SET stage=$4,observed_fingerprint_sha256=$5,
    observed_valid_to=$6,observed_at=$7 WHERE workspace_id=$1 AND rollout_id=$2 AND binding_id=$3`,
  [workspaceId, intent.rolloutId, intent.bindingId, stage, receipt.fingerprintSha256, receipt.validTo, receipt.observedAt]);
  const current = row.binding_state === "active" && row.current_authorization_revision === row.authorization_revision &&
    Number(row.desired_generation) === receipt.generation && row.desired_material_version_id === receipt.materialVersionId &&
    ["pending","deploying"].includes(row.rollout_state) && jobStatus === "succeeded" && receipt.servedVerified && (row.verification_policy !== "trust" || receipt.trustValidated);
  if (current) await client.query(`UPDATE certops_consumer_current_state SET accepted_generation=$3,
    observed_material_version_id=$4,observed_fingerprint_sha256=$5,observed_valid_to=$6,verification_method=$7,observed_at=$8
    WHERE workspace_id=$1 AND binding_id=$2 AND accepted_generation<=$3`, [workspaceId, intent.bindingId,
    receipt.generation, receipt.materialVersionId, receipt.fingerprintSha256, receipt.validTo,
    receipt.trustValidated ? "trust" : "served", receipt.observedAt]);
  await enqueueDistributionEvent(client, workspaceId, "distribution_rollout_requested", `${intent.rolloutId}:${job.id}:${job.claim_id}`, { groupId: intent.groupId, rolloutId: intent.rolloutId });
  return { historicalOnly: !current, stage };
}

async function consumerMatrix({ client, workspaceId, groupId }) {
  groupId = normalizeDistributionId(groupId);
  return (await client.query(`SELECT b.id AS binding_id,b.assigned_agent_id,b.required,b.verification_policy,
    s.desired_material_version_id,s.desired_generation,s.accepted_generation,s.observed_material_version_id,
    s.observed_fingerprint_sha256,s.observed_valid_to,s.verification_method,s.observed_at,
    (s.accepted_generation=s.desired_generation AND s.observed_material_version_id=s.desired_material_version_id
      AND s.observed_valid_to>clock_timestamp() AND b.state='active'
      AND EXISTS (SELECT 1 FROM certops_consumer_deployments proof
        JOIN certops_distribution_rollouts rollout ON rollout.workspace_id=proof.workspace_id AND rollout.id=proof.rollout_id
        JOIN certops_material_versions material ON material.workspace_id=rollout.workspace_id AND material.id=rollout.material_version_id
        JOIN certops_certificate_identities identity ON identity.workspace_id=material.workspace_id AND identity.id=material.certificate_identity_id
        WHERE proof.workspace_id=b.workspace_id AND proof.binding_id=b.id AND rollout.generation=s.accepted_generation
          AND proof.authorization_revision=b.authorization_revision AND identity.lifecycle_status='active'
          AND proof.stage IN ('served_verified','trust_validated'))
      AND s.observed_at>clock_timestamp()-b.freshness_seconds*interval '1 second') AS converged,
    (SELECT jsonb_build_object('stage',d.stage,'failureCode',d.failure_code,'jobId',d.job_id)
      FROM certops_consumer_deployments d JOIN certops_distribution_rollouts r ON r.workspace_id=d.workspace_id AND r.id=d.rollout_id
      WHERE d.workspace_id=b.workspace_id AND d.binding_id=b.id ORDER BY r.generation DESC LIMIT 1) AS latest_deployment
    FROM certops_consumer_bindings b LEFT JOIN certops_consumer_current_state s
    ON s.workspace_id=b.workspace_id AND s.binding_id=b.id WHERE b.workspace_id=$1 AND b.group_id=$2 ORDER BY b.id`,
  [workspaceId, groupId])).rows;
}

module.exports = { validateDistributionContract, normalizeDistributionId, hashIntent, enqueueDistributionEvent, buildRolloutIntent, lockGroup, resolveDistributionJobDefaults, createGroupForSource, allocateMaterialVersion,
  acceptPublicationReceipt, createRolloutSnapshot, acceptDeploymentReceipt, consumerMatrix, assertDeployableVersion };
