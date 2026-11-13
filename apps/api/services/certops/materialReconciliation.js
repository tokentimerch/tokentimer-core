"use strict";

// A reconciliation inspection proves present customer-local state only. It
// never installs material, promotes consumer proof or clears a different job.
const material = require("./materialDistribution");
const { assertDistributionPolicy } = require("./distributionPolicy");

function fail(code, status = 409) {
  const error = new Error(code);
  error.code = code;
  error.statusCode = status;
  throw error;
}

async function lockedOriginal(
  client,
  workspaceId,
  originalJobId,
  { forClaim = false } = {},
) {
  originalJobId = material.normalizeDistributionId(originalJobId);
  // Resolve the lock key first, then re-read the job under the group lock.
  const hint = (
    await client.query(
      "SELECT payload FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
      [workspaceId, originalJobId],
    )
  ).rows[0];
  const hinted = hint?.payload?.materialDeployment;
  if (!hinted) fail("CERTOPS_RECONCILIATION_NOT_FOUND", 404);
  const group = await material.lockGroup(client, workspaceId, hinted.groupId, {
    forClaim,
  });
  // Retry owns the original before acquiring its group. Yield instead of
  // inverting that lock order; SKIP LOCKED also keeps a claim transaction usable.
  const old = (
    await client.query(
      "SELECT * FROM certificate_jobs WHERE workspace_id=$1 AND id=$2 FOR UPDATE SKIP LOCKED",
      [workspaceId, originalJobId],
    )
  ).rows[0];
  if (!old) fail("CERTOPS_RECONCILIATION_CONCURRENT_WORK");
  const intent = old?.payload?.materialDeployment;
  if (
    !intent ||
    material.hashIntent(intent) !== material.hashIntent(hinted) ||
    intent.groupId !== group.id
  )
    fail("CERTOPS_RECONCILIATION_STALE");
  material.validateDistributionContract("materialDeployment", intent);
  if (
    old.needs_operator_reconciliation !== true ||
    !["rejected", "failed", "blocked", "orphaned_unknown_effect"].includes(
      old.status,
    )
  )
    fail("CERTOPS_RECONCILIATION_UNAVAILABLE");
  const binding = (
    await client.query(
      `SELECT d.assigned_agent_id,d.authorization_revision,d.freshness_seconds,
      b.state,b.assigned_agent_id AS current_agent,b.authorization_revision AS current_revision,
      r.generation,r.material_version_id,s.desired_generation,s.desired_material_version_id
    FROM certops_consumer_deployments d JOIN certops_consumer_bindings b ON b.workspace_id=d.workspace_id AND b.id=d.binding_id
    JOIN certops_distribution_rollouts r ON r.workspace_id=d.workspace_id AND r.id=d.rollout_id
    JOIN certops_consumer_current_state s ON s.workspace_id=d.workspace_id AND s.binding_id=d.binding_id
    WHERE d.workspace_id=$1 AND d.group_id=$2 AND d.rollout_id=$3 AND d.binding_id=$4
      AND (d.job_id=$5 OR d.staging_job_id=$5) FOR UPDATE OF d,b,r,s`,
      [workspaceId, intent.groupId, intent.rolloutId, intent.bindingId, old.id],
    )
  ).rows[0];
  if (
    !binding ||
    binding.state !== "active" ||
    binding.assigned_agent_id !== old.assigned_agent_id ||
    binding.current_agent !== old.assigned_agent_id ||
    binding.current_revision !== binding.authorization_revision ||
    binding.authorization_revision !== intent.authorizationRevision ||
    Number(binding.generation) !== intent.generation ||
    Number(binding.desired_generation) !== intent.generation ||
    Number(group.generation) !== intent.generation ||
    binding.material_version_id !== intent.materialVersionId ||
    binding.desired_material_version_id !== intent.materialVersionId
  )
    fail("CERTOPS_RECONCILIATION_STALE");
  const live = (
    await client.query(
      `SELECT j.id FROM certops_consumer_deployments d JOIN certificate_jobs j
    ON j.workspace_id=d.workspace_id AND (j.id=d.job_id OR j.id=d.staging_job_id)
    WHERE d.workspace_id=$1 AND d.binding_id=$2 AND j.id<>$3 AND j.status IN ('claimed','running') LIMIT 1 FOR UPDATE OF j`,
      [workspaceId, intent.bindingId, old.id],
    )
  ).rowCount;
  if (live) fail("CERTOPS_RECONCILIATION_CONCURRENT_WORK");
  return { group, old, intent, binding };
}

async function workspaceAuthority(client, workspaceId, scope, job, requester) {
  const workspace = (
    await client.query(
      `SELECT created_by,certops_paused,certops_distribution_authorization_revision
    FROM workspaces WHERE id=$1 FOR SHARE`,
      [workspaceId],
    )
  ).rows[0];
  if (
    !workspace ||
    workspace.certops_paused ||
    (scope &&
      String(workspace.certops_distribution_authorization_revision) !==
        scope.workspaceAuthorizationRevision)
  )
    fail("CERTOPS_RECONCILIATION_AUTHORITY_STALE");
  if (job || requester) {
    const members = (
      await client.query(
        "SELECT user_id FROM workspace_memberships WHERE workspace_id=$1 AND role IN ('admin','workspace_manager')",
        [workspaceId],
      )
    ).rows;
    const active = new Set(
      [workspace.created_by, ...members.map((m) => m.user_id)]
        .filter(Boolean)
        .map(String),
    );
    if (requester && !active.has(String(requester)))
      fail("CERTOPS_RECONCILIATION_AUTHORITY_STALE");
    if (!job) return workspace;
    const approvals = require("./jobApprovals");
    const canonical = approvals.computeCanonicalIntentHash({
      operation: job.operation,
      subjectType: job.subject_type,
      subjectId: job.subject_id,
      requestedByConnectionId: job.requested_by_connection_id,
      assignedAgentId: job.assigned_agent_id,
      requiredTargetSelector: job.required_target_selector,
      requiredDnsProvider: job.required_dns_provider,
      requiredCommandProfile: job.required_command_profile,
      payload: job.payload,
    });
    if (
      !job.approved_at ||
      !job.approved_payload_hash ||
      !job.approved_canonical_intent_hash ||
      !active.has(String(job.requested_by_user_id)) ||
      !active.has(String(job.approved_by_user_id)) ||
      String(job.requested_by_user_id) === String(job.approved_by_user_id) ||
      approvals.computeJobPayloadApprovalHash(job.payload) !==
        job.approved_payload_hash ||
      canonical !== job.approved_canonical_intent_hash
    )
      fail("CERTOPS_RECONCILIATION_AUTHORITY_STALE");
  }
  return workspace;
}

function requestReconciliation({ workspaceId, jobId, actorUserId }) {
  if (!actorUserId) fail("CERTOPS_RECONCILIATION_AUTHORITY_STALE");
  return require("./distributionOperations").transaction(async (client) => {
    await assertDistributionPolicy({ client, workspaceId });
    const snapshot = await lockedOriginal(client, workspaceId, jobId);
    const workspace = await workspaceAuthority(
      client,
      workspaceId,
      null,
      null,
      actorUserId,
    );
    // A claim/result may hold the existing inspection row. A nonlocking check
    // returns the conflict without waiting behind it while holding the group.
    if (
      (
        await client.query(
          `SELECT 1 FROM certificate_jobs WHERE workspace_id=$1
      AND operation='reconcile-from-store' AND payload->'materialReconciliation'->>'originalJobId'=$2
      AND status IN ('pending_approval','pending','claimed','running')`,
          [workspaceId, snapshot.old.id],
        )
      ).rowCount
    )
      fail("CERTOPS_RECONCILIATION_ALREADY_REQUESTED");
    const scope = {
      originalJobId: snapshot.old.id,
      assignedAgentId: snapshot.old.assigned_agent_id,
      workspaceAuthorizationRevision: String(
        workspace.certops_distribution_authorization_revision,
      ),
      intent: snapshot.intent,
    };
    let job;
    try {
      job = await require("./jobs").createCertificateJob({
        client,
        workspaceId,
        operation: "reconcile-from-store",
        source: "control-plane",
        subjectType: "managed_certificate",
        subjectId: snapshot.old.subject_id,
        assignedAgentId: snapshot.old.assigned_agent_id,
        requestedByUserId: actorUserId,
        requiresApproval: true,
        allowMaterialReconciliation: true,
        payload: {
          keyMode: "vault-managed",
          target: { type: "endpoint", reference: snapshot.intent.bindingId },
          materialReconciliation: scope,
        },
      });
    } catch (error) {
      if (
        error.code === "23505" &&
        error.constraint === "certops_one_live_material_reconciliation"
      )
        fail("CERTOPS_RECONCILIATION_ALREADY_REQUESTED");
      throw error;
    }
    await require("../audit").writeAudit({
      client,
      workspaceId,
      actorUserId,
      action: "CERTOPS_MATERIAL_RECONCILIATION_REQUESTED",
      targetType: "certificate_job",
      targetId: job.id,
      metadata: { originalJobId: snapshot.old.id },
    });
    return job;
  });
}

async function assertClaimable({ client, workspaceId, job, agentId }) {
  job = (
    await client.query(
      "SELECT * FROM certificate_jobs WHERE workspace_id=$1 AND id=$2 FOR UPDATE",
      [workspaceId, job.id],
    )
  ).rows[0];
  if (!job?.payload?.materialReconciliation)
    fail("CERTOPS_RECONCILIATION_STALE");
  const scope = material.validateDistributionContract(
    "materialReconciliation",
    job.payload.materialReconciliation,
  );
  await workspaceAuthority(client, workspaceId, scope, job);
  const snapshot = await lockedOriginal(
    client,
    workspaceId,
    scope.originalJobId,
    { forClaim: true },
  );
  if (
    job.operation !== "reconcile-from-store" ||
    !["pending", "claimed", "running"].includes(job.status) ||
    job.assigned_agent_id !== agentId ||
    scope.assignedAgentId !== agentId ||
    snapshot.old.assigned_agent_id !== agentId ||
    material.hashIntent(snapshot.intent) !== material.hashIntent(scope.intent)
  )
    fail("CERTOPS_RECONCILIATION_STALE");
  return snapshot;
}

async function acceptReceipt({ client, workspaceId, agentId, job, receipt }) {
  material.validateDistributionContract("reconciliationReceipt", receipt);
  const scope = job.payload.materialReconciliation;
  const snapshot = await assertClaimable({ client, workspaceId, job, agentId });
  const now = Date.now(),
    observed = Date.parse(receipt.observedAt);
  const live = (
    await client.query(
      "SELECT 1 FROM certificate_jobs WHERE workspace_id=$1 AND id=$2 AND claimed_by_agent_id=$3 AND claim_id=$4 AND lease_expires_at>clock_timestamp()",
      [workspaceId, job.id, agentId, job.claim_id],
    )
  ).rowCount;
  if (
    !live ||
    receipt.workspaceId !== workspaceId ||
    receipt.originalJobId !== scope.originalJobId ||
    receipt.groupId !== scope.intent.groupId ||
    receipt.bindingId !== scope.intent.bindingId ||
    receipt.materialVersionId !== scope.intent.materialVersionId ||
    receipt.generation !== scope.intent.generation ||
    receipt.fingerprintSha256 !== scope.intent.fingerprintSha256 ||
    receipt.proofKind !==
      (scope.intent.preparationOnly === true ? "staged" : "deployed") ||
    !Number.isSafeInteger(snapshot.binding.freshness_seconds) ||
    snapshot.binding.freshness_seconds < 1 ||
    !Number.isFinite(observed) ||
    observed > now + 30000 ||
    now - observed > snapshot.binding.freshness_seconds * 1000
  )
    fail("CERTOPS_RECONCILIATION_RECEIPT_MISMATCH");
  await client.query(
    "UPDATE certificate_jobs SET needs_operator_reconciliation=FALSE,reconciliation_reason=NULL,updated_at=clock_timestamp() WHERE workspace_id=$1 AND id=$2",
    [workspaceId, scope.originalJobId],
  );
  await require("../audit").writeAudit({
    client,
    workspaceId,
    actorUserId: null,
    action: "CERTOPS_MATERIAL_RECONCILIATION_PROVED",
    targetType: "certificate_job",
    targetId: scope.originalJobId,
    metadata: {
      reconciliationJobId: job.id,
      claimId: job.claim_id,
      agentId,
      materialVersionId: scope.intent.materialVersionId,
    },
  });
}
module.exports = { requestReconciliation, assertClaimable, acceptReceipt };
