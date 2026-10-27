"use strict";

// Public metadata only. All mutations share the existing workspace/group locks.
const material = require("./materialDistribution");
const { assertSafePublicValue, createCertificateJob } = require("./jobs");
const { computeJobPayloadApprovalHash } = require("./jobApprovals");
const { assertDistributionPolicy } = require("./distributionPolicy");
const { writeAudit } = require("../audit");

const DEFAULT_POLICY = Object.freeze({
  mode: "manual",
  maxParallel: 1,
  authorizationExpiresAt: null,
  verification: {
    enabled: false,
    intervalSeconds: 3600,
    maxBackoffSeconds: 86400,
    staleJobSeconds: 3600,
    failureThreshold: 3,
  },
  alerts: {
    enabled: false,
    offlineSeconds: 900,
    stuckSeconds: 3600,
    convergenceSeconds: 3600,
    expiryWarningDays: 14,
    repeatSeconds: 86400,
    contactGroupIds: [],
  },
  retention: {
    minimumSeconds: 2592000,
    minimumVersions: 3,
    rollbackSeconds: 604800,
    cleanupEnabled: false,
    reportOnly: true,
    requiresApproval: true,
  },
});
function fail(code, statusCode = 422) {
  const e = new Error(code);
  e.code = code;
  e.statusCode = statusCode;
  throw e;
}
function object(value, fields) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).some((key) => !fields.includes(key)) ||
    fields.some((key) => !Object.hasOwn(value, key))
  )
    fail("CERTOPS_LIFECYCLE_POLICY_INVALID");
}
function integer(value, min, max) {
  if (!Number.isInteger(value) || value < min || value > max)
    fail("CERTOPS_LIFECYCLE_POLICY_INVALID");
}
function boolean(value) {
  if (typeof value !== "boolean") fail("CERTOPS_LIFECYCLE_POLICY_INVALID");
}
function validatePolicy(value, now = Date.now()) {
  assertSafePublicValue(value);
  object(value, Object.keys(DEFAULT_POLICY));
  if (!["manual", "approval_request", "preauthorized"].includes(value.mode))
    fail("CERTOPS_LIFECYCLE_POLICY_INVALID");
  integer(value.maxParallel, 1, 16);
  if (
    value.authorizationExpiresAt !== null &&
    (typeof value.authorizationExpiresAt !== "string" ||
      !Number.isFinite(Date.parse(value.authorizationExpiresAt)) ||
      Date.parse(value.authorizationExpiresAt) <= now ||
      Date.parse(value.authorizationExpiresAt) > now + 30 * 86400000)
  )
    fail("CERTOPS_LIFECYCLE_AUTHORIZATION_EXPIRY_INVALID");
  if (value.mode === "preauthorized" && !value.authorizationExpiresAt)
    fail("CERTOPS_LIFECYCLE_AUTHORIZATION_EXPIRY_INVALID");
  object(value.verification, Object.keys(DEFAULT_POLICY.verification));
  boolean(value.verification.enabled);
  integer(value.verification.intervalSeconds, 300, 604800);
  integer(
    value.verification.maxBackoffSeconds,
    value.verification.intervalSeconds,
    604800,
  );
  integer(value.verification.staleJobSeconds, 300, 86400);
  integer(value.verification.failureThreshold, 1, 20);
  object(value.alerts, Object.keys(DEFAULT_POLICY.alerts));
  boolean(value.alerts.enabled);
  for (const key of ["offlineSeconds", "stuckSeconds", "convergenceSeconds"])
    integer(value.alerts[key], 60, 604800);
  integer(value.alerts.expiryWarningDays, 0, 90);
  integer(value.alerts.repeatSeconds, 3600, 604800);
  if (
    !Array.isArray(value.alerts.contactGroupIds) ||
    value.alerts.contactGroupIds.length > 20 ||
    value.alerts.contactGroupIds.some(
      (id) => typeof id !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(id),
    ) ||
    new Set(value.alerts.contactGroupIds).size !==
      value.alerts.contactGroupIds.length
  )
    fail("CERTOPS_LIFECYCLE_POLICY_INVALID");
  object(value.retention, Object.keys(DEFAULT_POLICY.retention));
  integer(value.retention.minimumSeconds, 86400, 315360000);
  integer(value.retention.minimumVersions, 2, 1000);
  integer(value.retention.rollbackSeconds, 86400, 31536000);
  for (const key of ["cleanupEnabled", "reportOnly", "requiresApproval"])
    boolean(value.retention[key]);
  // This baseline has no qualified provider deletion operation. Never pretend
  // that a metadata preview authorizes destructive customer-side effects.
  if (
    value.retention.cleanupEnabled ||
    !value.retention.reportOnly ||
    !value.retention.requiresApproval
  )
    fail("CERTOPS_MATERIAL_CLEANUP_NOT_QUALIFIED");
  return structuredClone(value);
}

async function authorizationScope(client, workspaceId, group, policy) {
  const workspace = (
    await client.query(
      `SELECT created_by,certops_require_approval_always,certops_distribution_authorization_revision
    FROM workspaces WHERE id=$1 FOR SHARE`,
      [workspaceId],
    )
  ).rows[0];
  if (!workspace) fail("CERTOPS_WORKSPACE_NOT_FOUND", 404);
  const reviewers = (
    await client.query(
      `SELECT user_id,role FROM workspace_memberships WHERE workspace_id=$1
    AND role IN ('admin','workspace_manager') ORDER BY user_id FOR SHARE`,
      [workspaceId],
    )
  ).rows;
  const bindings = (
    await client.query(
      `SELECT b.id,b.assigned_agent_id,b.deployment_profile_ref,b.profile_revision,
    b.authorization_revision,b.required,b.wave,b.verification_policy,b.freshness_seconds,c.policy AS activation_policy
    FROM certops_consumer_bindings b LEFT JOIN certops_consumer_lifecycle c ON c.workspace_id=b.workspace_id AND c.binding_id=b.id
    WHERE b.workspace_id=$1 AND b.group_id=$2 AND b.state='active' ORDER BY b.id FOR SHARE OF b`,
      [workspaceId, group.id],
    )
  ).rows;
  const snapshot={
      workspaceId,
      groupId: group.id,
      managementPeriodId: group.management_period_id,
      materialStoreRef: group.material_store_ref,
      issuerAgentId: group.issuer_agent_id,
      issuanceProfileRef: group.issuance_profile_ref,
      profileRevision: group.profile_revision,
      workspaceAuthorizationRevision: String(
        workspace.certops_distribution_authorization_revision,
      ),
      workspaceRequiresApproval: workspace.certops_require_approval_always,
      workspaceOwner: workspace.created_by,
      reviewers,
      policy,
      bindings:bindings.map(binding=>({bindingId:binding.id,agentId:binding.assigned_agent_id,
        profileRef:binding.deployment_profile_ref,profileRevision:binding.profile_revision,
        authorizationRevision:binding.authorization_revision,required:binding.required,wave:binding.wave,
        verificationPolicy:binding.verification_policy,freshnessSeconds:binding.freshness_seconds,
        activationClass:binding.activation_policy?.method || (binding.verification_policy==="installed"?"none":"reload"),
        activationPolicy:binding.activation_policy || null})),
      rolloutBehavior:{requiredFailure:"pause",optionalFailure:"degraded",waveOrder:"ascending",rollback:"explicit_approval",verificationBeforeNextWave:true},
  };
  return {workspace,bindings,snapshot,hash:material.hashIntent(snapshot)};
}
async function loadPolicy(client, workspaceId, groupId) {
  return (
    (
      await client.query(
        `SELECT * FROM certops_distribution_policies WHERE workspace_id=$1 AND group_id=$2`,
        [workspaceId, groupId],
      )
    ).rows[0] || null
  );
}
async function notifyApproval(client, workspaceId, job) {
  const intent =
    job.payload?.distributionRollout || job.payload?.distributionPolicyApproval;
  if (job.status !== "pending_approval" || !intent) return;
  await client.query(
    `INSERT INTO operational_notifications(workspace_id,category,type,severity,dedupe_key,title,message,metadata)
    VALUES($1,'certops','distribution_approval_requested','info',$2,$3,$4,$5)
    ON CONFLICT(workspace_id,dedupe_key) WHERE resolved_at IS NULL DO NOTHING`,
    [
      workspaceId,
      `distribution_approval:${job.id}`,
      job.payload.distributionRollout
        ? "Review certificate distribution rollout"
        : "Review bounded certificate distribution policy",
      "An authorized reviewer must approve the exact public intent in Jobs before execution.",
      {
        groupId: intent.groupId,
        jobId: job.id,
        materialVersionId: intent.materialVersionId || null,
        href: `/certops/jobs?workspace=${workspaceId}&job=${job.id}`,
      },
    ],
  );
}
async function putPolicy({
  workspaceId,
  groupId,
  policy,
  expectedRevision,
  actorUserId,
  dbPool,
}) {
  workspaceId = material.normalizeDistributionId(workspaceId);
  groupId = material.normalizeDistributionId(groupId);
  policy = validatePolicy(policy);
  return require("./distributionOperations").transaction(async (client) => {
    await assertDistributionPolicy({ client, workspaceId });
    const group = await material.lockGroup(client, workspaceId, groupId);
    const prior = await loadPolicy(client, workspaceId, groupId);
    if (expectedRevision !== (prior?.revision || 0))
      fail("CERTOPS_LIFECYCLE_POLICY_REVISION_CHANGED", 409);
    const unchanged=prior && material.hashIntent(prior.policy)===material.hashIntent(policy);
    if(unchanged && policy.mode!=="preauthorized")return prior;
    const settings = (
      await client.query(
        `SELECT contact_groups FROM workspace_settings WHERE workspace_id=$1`,
        [workspaceId],
      )
    ).rows[0];
    const groups = Array.isArray(settings?.contact_groups)
      ? settings.contact_groups
      : [];
    if (
      policy.alerts.contactGroupIds.some(
        (id) => !groups.some((group) => String(group.id) === id),
      )
    )
      fail("CERTOPS_CONTACT_GROUP_NOT_FOUND", 422);
    const scope = await authorizationScope(client, workspaceId, group, policy);
    if(unchanged && prior.scope_hash===scope.hash && prior.approval_job_id){
      const previousApproval=(await client.query(`SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2 FOR SHARE`,[workspaceId,prior.approval_job_id])).rows[0];
      if(["pending_approval","pending","succeeded"].includes(previousApproval?.status))return prior;
    }
    if (policy.mode !== "manual" && !scope.bindings.length)
      fail("CERTOPS_ROLLOUT_POLICY_INVALID", 422);
    const row = (
      await client.query(
        `INSERT INTO certops_distribution_policies(workspace_id,group_id,policy,scope_hash,configured_by_user_id)
      VALUES($1,$2,$3,$4,$5) ON CONFLICT(workspace_id,group_id) DO UPDATE SET policy=EXCLUDED.policy,
      revision=certops_distribution_policies.revision+1,scope_hash=EXCLUDED.scope_hash,approval_job_id=NULL,
      configured_by_user_id=EXCLUDED.configured_by_user_id,updated_at=clock_timestamp() RETURNING *`,
        [workspaceId, groupId, policy, scope.hash, actorUserId],
      )
    ).rows[0];
    if (policy.mode === "preauthorized") {
      const job = await createCertificateJob({
        client,
        workspaceId,
        operation: "noop",
        source: "control-plane",
        subjectType: "managed_certificate",
        subjectId: group.managed_certificate_id,
        assignedAgentId: group.issuer_agent_id,
        requestedByUserId: actorUserId,
        requiresApproval: true,
        idempotencyKey: `distribution-policy:${groupId}:${row.revision}`,
        payload: {
          distributionPolicyApproval: {
            groupId,
            revision: row.revision,
            scopeHash: scope.hash,
            scope:scope.snapshot,
            expiresAt: policy.authorizationExpiresAt,
          },
        },
      });
      await client.query(
        `UPDATE certops_distribution_policies SET approval_job_id=$3 WHERE workspace_id=$1 AND group_id=$2`,
        [workspaceId, groupId, job.id],
      );
      row.approval_job_id = job.id;
      await notifyApproval(client, workspaceId, job);
    }
    await client.query(
      `INSERT INTO certops_distribution_schedules(workspace_id,group_id) VALUES($1,$2)
      ON CONFLICT(workspace_id,group_id) DO UPDATE SET next_run_at=clock_timestamp(),failures=0`,
      [workspaceId, groupId],
    );
    await writeAudit({
      client,
      workspaceId,
      actorUserId,
      action: "CERTOPS_DISTRIBUTION_POLICY_CHANGED",
      targetType: "certops_distribution_group",
      targetId: groupId,
      metadata: {
        revision: row.revision,
        scopeHash: scope.hash,
        mode: policy.mode,
        approvalJobId: row.approval_job_id,
      },
    });
    return row;
  }, dbPool);
}
function approvalMatches(job, policy) {
  const intent = job?.payload?.distributionPolicyApproval;
  return !!(
    intent &&
    job.approved_payload_hash &&
    job.approved_by_user_id &&
    job.approved_at &&
    ["pending", "succeeded"].includes(job.status) &&
    computeJobPayloadApprovalHash(job.payload) === job.approved_payload_hash &&
    intent.groupId === policy.group_id &&
    intent.revision === policy.revision &&
    intent.scopeHash === policy.scope_hash &&
    intent.scope && material.hashIntent(intent.scope)===intent.scopeHash &&
    intent.expiresAt === policy.policy.authorizationExpiresAt &&
    Date.parse(intent.expiresAt) > Date.now()
  );
}
async function isPreauthorized(client, workspaceId, group, policy) {
  if (
    !policy ||
    policy.policy.mode !== "preauthorized" ||
    !policy.approval_job_id
  )
    return false;
  const job = (
    await client.query(
      `SELECT * FROM certificate_jobs WHERE workspace_id=$1 AND id=$2 FOR SHARE`,
      [workspaceId, policy.approval_job_id],
    )
  ).rows[0];
  if (!approvalMatches(job, policy) || job.status !== "succeeded") return false;
  const scope = await authorizationScope(
    client,
    workspaceId,
    group,
    policy.policy,
  );
  const authorizedUsers = (
    await client.query(
      `SELECT created_by AS id FROM workspaces WHERE id=$1
    UNION SELECT user_id AS id FROM workspace_memberships WHERE workspace_id=$1 AND role IN ('admin','workspace_manager')`,
      [workspaceId],
    )
  ).rows.map((row) => String(row.id));
  if (
    !authorizedUsers.includes(String(policy.configured_by_user_id)) ||
    !authorizedUsers.includes(String(job.approved_by_user_id))
  )
    return false;
  // Mandatory approval always wins; standing authority cannot authorize a
  // human decision for any future exact-version job in such a workspace.
  return (
    scope.workspace.certops_require_approval_always === false &&
    scope.hash === policy.scope_hash
  );
}
async function acceptPolicyApproval({ client, workspaceId, job }) {
  if (job.status === "succeeded")
    return { queued: true, reason: "policy_already_reviewed" };
  const group = await material.lockGroup(
    client,
    workspaceId,
    job.payload.distributionPolicyApproval.groupId,
  );
  const policy = await loadPolicy(client, workspaceId, group.id);
  const valid =
    policy &&
    policy.approval_job_id === job.id &&
    approvalMatches(job, policy) &&
    (await authorizationScope(client, workspaceId, group, policy.policy))
      .hash === policy.scope_hash;
  await client.query(
    `UPDATE certificate_jobs SET status=$3,error_code=$4,completed_at=clock_timestamp(),updated_at=clock_timestamp()
    WHERE workspace_id=$1 AND id=$2 AND status='pending'`,
    [
      workspaceId,
      job.id,
      valid ? "succeeded" : "failed",
      valid ? null : "CERTOPS_DISTRIBUTION_POLICY_STALE",
    ],
  );
  return {
    queued: !!valid,
    reason: valid ? "policy_reviewed" : "policy_authorization_stale",
  };
}
async function onMaterialPublished({ client, workspaceId, payload }) {
  await assertDistributionPolicy({ client, workspaceId });
  const group = await material.lockGroup(client, workspaceId, payload.groupId);
  const prior = (
    await client.query(
      `SELECT outcome FROM certops_distribution_automations WHERE workspace_id=$1 AND group_id=$2 AND material_version_id=$3`,
      [workspaceId, group.id, payload.materialVersionId],
    )
  ).rows[0];
  if (prior) return { queued: true, reason: "publication_already_handled" };
  const published = await client.query(
    `SELECT 1 FROM certops_material_versions WHERE workspace_id=$1 AND group_id=$2 AND id=$3 AND state='published'`,
    [workspaceId, group.id, payload.materialVersionId],
  );
  if (!published.rowCount)
    return { queued: false, reason: "publication_not_available" };
  const policy = await loadPolicy(client, workspaceId, group.id);
  let outcome = "manual",
    job = null;
  if (
    group.latest_material_version_id &&
    group.latest_material_version_id !== payload.materialVersionId
  )
    outcome = "authorization_stale";
  else if ((policy?.revision || 0) !== (payload.policyRevision || 0))
    outcome = "policy_changed";
  else if (policy && policy.policy.mode !== "manual") {
    const scope = await authorizationScope(
      client,
      workspaceId,
      group,
      policy.policy,
    );
    if (!scope.bindings.length) outcome = "no_consumers";
    else if (
      policy.policy.mode === "preauthorized" &&
      !(await isPreauthorized(client, workspaceId, group, policy))
    )
      outcome = "authorization_stale";
    else {
      job = await require("./distributionOperations").requestRollout({
        client,
        workspaceId,
        groupId: group.id,
        materialVersionId: payload.materialVersionId,
        maxParallel: policy.policy.maxParallel,
        requiresApproval: policy.policy.mode === "approval_request",
        actorUserId: policy.configured_by_user_id,
        idempotencyKey: `post-publication:${payload.materialVersionId}`,
      });
      outcome =
        job.status === "pending_approval" ? "approval_requested" : "authorized";
    }
  }
  await client.query(
    `INSERT INTO certops_distribution_automations(workspace_id,group_id,material_version_id,policy_revision,outcome,job_id)
    VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
    [
      workspaceId,
      group.id,
      payload.materialVersionId,
      payload.policyRevision || 0,
      outcome,
      job?.id || null,
    ],
  );
  await writeAudit({
    client,
    workspaceId,
    action: "CERTOPS_POST_PUBLICATION_DISTRIBUTION",
    targetType: "certops_distribution_group",
    targetId: group.id,
    metadata: {
      materialVersionId: payload.materialVersionId,
      outcome,
      policyRevision: payload.policyRevision || 0,
      jobId: job?.id || null,
    },
  });
  return { queued: true, reason: outcome };
}
async function assertAutomaticRolloutAuthorized(
  client,
  workspaceId,
  group,
  approvalJobId,
) {
  const automation = (
    await client.query(
      `SELECT policy_revision FROM certops_distribution_automations
    WHERE workspace_id=$1 AND group_id=$2 AND job_id=$3 AND outcome='authorized'`,
      [workspaceId, group.id, approvalJobId],
    )
  ).rows[0];
  if (!automation) return;
  const policy = await loadPolicy(client, workspaceId, group.id);
  if (
    !policy ||
    policy.revision !== automation.policy_revision ||
    !(await isPreauthorized(client, workspaceId, group, policy))
  )
    fail("CERTOPS_DISTRIBUTION_POLICY_STALE", 409);
}

module.exports = {
  DEFAULT_POLICY,
  validatePolicy,
  loadPolicy,
  putPolicy,
  notifyApproval,
  authorizationScope,
  approvalMatches,
  isPreauthorized,
  acceptPolicyApproval,
  onMaterialPublished,
  assertAutomaticRolloutAuthorized,
};
