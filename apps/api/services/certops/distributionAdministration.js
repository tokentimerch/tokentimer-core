"use strict";
const { pool } = require("../../db/database");
const material = require("./materialDistribution");
const { DEFAULT_POLICY, loadPolicy,isPreauthorized } = require("./distributionLifecycle");
const { consumerHealth } = require("./distributionMonitoring");
const {
  nextActivation,
  supportedActivation,
  activationDeadline,
} = require("./distributionMaintenance");
const {
  CONNECTORS,
} = require("../../../../packages/contracts/certops/service-connectors.cjs");
function fail(code, statusCode = 404) {
  const e = new Error(code);
  e.code = code;
  e.statusCode = statusCode;
  throw e;
}
async function groupFor(client, workspaceId, groupId) {
  groupId = material.normalizeDistributionId(groupId);
  const group = (
    await client.query(
      `SELECT g.*,m.ended_at FROM certops_distribution_groups g
    JOIN certops_management_periods m ON m.workspace_id=g.workspace_id AND m.id=g.management_period_id WHERE g.workspace_id=$1 AND g.id=$2`,
      [workspaceId, groupId],
    )
  ).rows[0];
  if (!group) fail("CERTOPS_DISTRIBUTION_NOT_FOUND");
  return group;
}
async function overview({ client = pool, workspaceId, groupId }) {
  const group = await groupFor(client, workspaceId, groupId);
  const policy = await loadPolicy(client, workspaceId, group.id);
  const authorization=policy?.policy.mode==="preauthorized"?
    {state:await isPreauthorized(client,workspaceId,group,policy)?"authorized":"review_required_or_scope_changed",expiresAt:policy.policy.authorizationExpiresAt}:
    {state:policy?.policy.mode || "manual",expiresAt:null};
  const consumers = await material.consumerMatrix({
    client,
    workspaceId,
    groupId: group.id,
  });
  const versions = (
    await client.query(
      `SELECT id,state,provider_version,fingerprint_sha256,valid_to,published_at,created_at,publishing_job_id
    FROM certops_material_versions WHERE workspace_id=$1 AND group_id=$2 ORDER BY created_at DESC LIMIT 1000`,
      [workspaceId, group.id],
    )
  ).rows;
  const rollouts = (
    await client.query(
      `SELECT * FROM certops_distribution_rollouts WHERE workspace_id=$1 AND group_id=$2 ORDER BY generation DESC LIMIT 50`,
      [workspaceId, group.id],
    )
  ).rows;
  const approvals = (
    await client.query(
      `SELECT id,status,operation,created_at,approved_at FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2
    AND (payload ? 'distributionRollout' OR payload ? 'distributionPolicyApproval') ORDER BY created_at DESC LIMIT 50`,
      [workspaceId, group.managed_certificate_id],
    )
  ).rows;
  const incidents = (
    await client.query(
      `SELECT * FROM certops_distribution_incidents WHERE workspace_id=$1 AND group_id=$2 ORDER BY updated_at DESC LIMIT 100`,
      [workspaceId, group.id],
    )
  ).rows;
  const schedule =
    (
      await client.query(
        `SELECT * FROM certops_distribution_schedules WHERE workspace_id=$1 AND group_id=$2`,
        [workspaceId, group.id],
      )
    ).rows[0] || null;
  const agents = (
    await client.query(
      `SELECT id,name,hostname,status,platform,declared_capabilities FROM certops_agents WHERE workspace_id=$1 AND status<>'retired' ORDER BY name,hostname,id LIMIT 1000`,
      [workspaceId],
    )
  ).rows;
  const settings = (
    await client.query(
      `SELECT contact_groups FROM workspace_settings WHERE workspace_id=$1`,
      [workspaceId],
    )
  ).rows[0];
  const contactGroups = (
    Array.isArray(settings?.contact_groups) ? settings.contact_groups : []
  ).map((group) => ({ id: group.id, name: group.name }));
  const discoveries = (
    await client.query(
      `SELECT d.*,
    CASE WHEN d.last_observed_at<clock_timestamp()-interval '1 hour' OR a.status<>'active' THEN 'stale' ELSE d.relationship_state END AS confidence
    FROM certops_discovered_consumers d JOIN certops_agents a ON a.workspace_id=d.workspace_id AND a.id=d.agent_id
    WHERE d.workspace_id=$1 AND EXISTS(SELECT 1 FROM certops_material_versions v WHERE v.workspace_id=d.workspace_id AND v.group_id=$2 AND v.fingerprint_sha256=d.observed_fingerprint_sha256)
    ORDER BY d.last_observed_at DESC LIMIT 1000`,
      [workspaceId, group.id],
    )
  ).rows;
  return {
    evaluated_at: new Date().toISOString(),
    group,
    policy,
    defaults: DEFAULT_POLICY,
    consumers: consumers.map((row) => ({
      ...row,
      health_status: consumerHealth(row, {
        offlineSeconds: (policy?.policy || DEFAULT_POLICY).alerts
          .offlineSeconds,
        latestVersionId: group.latest_material_version_id,
      }),
    })),
    authorization,
    versions,
    rollouts,
    approvals,
    incidents,
    schedule,
    discoveries,
    discoveryCoverage: "partial",
    connectors: CONNECTORS,
    agents,
    contactGroups,
  };
}
async function preflight({
  client = pool,
  workspaceId,
  groupId,
  materialVersionId,
}) {
  const group = await groupFor(client, workspaceId, groupId);
  const versionId = materialVersionId
    ? material.normalizeDistributionId(materialVersionId)
    : group.latest_material_version_id;
  const version = (
    await client.query(
      `SELECT id,state,valid_to FROM certops_material_versions WHERE workspace_id=$1 AND group_id=$2 AND id=$3`,
      [workspaceId, group.id, versionId],
    )
  ).rows[0];
  const rows = await material.consumerMatrix({
    client,
    workspaceId,
    groupId: group.id,
  });
  const agents = (
    await client.query(
      `SELECT id,declared_capabilities,capabilities_updated_at FROM certops_agents WHERE workspace_id=$1 AND id=ANY($2::uuid[])`,
      [workspaceId, rows.map((row) => row.assigned_agent_id)],
    )
  ).rows;
  const { hasFreshCapability } = require("./agentJobEligibility");
  const consumers = rows
    .filter((row) => row.binding_state === "active")
    .map((row) => {
      const diagnostics = [];
      if (
        row.agent_status !== "active" ||
        !row.agent_last_seen_at ||
        Date.now() - new Date(row.agent_last_seen_at).getTime() > 900000
      )
        diagnostics.push({ code: "CERTOPS_AGENT_OFFLINE", status: "blocked" });
      const agent = agents.find((agent) => agent.id === row.assigned_agent_id);
      for (const capability of [
        "material-store-vault-kv2-v1",
        "deploy-from-store-v1",
        "evidence-claim-binding-v1",
        ...(row.activation_policy ? ["maintenance-calendar-v1"] : []),
      ]) {
        if (
          !hasFreshCapability({
            declaredCapabilities: agent?.declared_capabilities,
            capabilitiesUpdatedAt: agent?.capabilities_updated_at,
            capability,
          })
        )
          diagnostics.push({
            code: "CERTOPS_AGENT_CAPABILITY_UNAVAILABLE",
            status: "blocked",
            capability,
          });
      }
      if (
        !version ||
        version.state !== "published" ||
        new Date(version.valid_to).getTime() <= Date.now()
      )
        diagnostics.push({
          code: "CERTOPS_PINNED_VERSION_UNAVAILABLE",
          status: "blocked",
        });
      if (!supportedActivation(row.activation_policy, row.verification_policy))
        diagnostics.push({
          code: "CERTOPS_ACTIVATION_CONNECTOR_UNSUPPORTED",
          status: "blocked",
        });
      if (row.latest_deployment?.stage === "orphaned_unknown_effect")
        diagnostics.push({
          code: "CERTOPS_LOCAL_RECONCILIATION_REQUIRED",
          status: "blocked",
        });
      const window = nextActivation(row.activation_policy, activationDeadline(version?.valid_to,row.observed_valid_to));
      if (!window.at)
        diagnostics.push({
          code: "CERTOPS_ACTIVATION_WINDOW_UNAVAILABLE",
          status: "blocked",
          reason: window.reason,
        });
      diagnostics.push({
        code: "CERTOPS_CUSTOMER_LOCAL_PREFLIGHT_REQUIRED",
        status: "unknown",
      });
      return {
        bindingId: row.binding_id,
        authorizationRevision: row.authorization_revision,
        profileRevision: row.profile_revision,
        diagnostics,
        nextActivationAt: window.at,
        ready: false,
      };
    });
  return {
    scope: "control-plane-metadata",
    nonMutating: true,
    materialVersionId: versionId,
    consumers,
    customerLocalChecks: [
      "store_authorization",
      "exact_version_read",
      "local_configuration_revision",
      "destination_permissions",
      "service_target",
      "reload_allowlist",
      "listener_probe",
      "local_execution_policy",
      "live_lock_and_uncertain_journal",
    ],
  };
}
function retentionReasons(
  version,
  { rank, policy, now, references, latestId },
) {
  const reasons = [];
  if (version.state !== "published") reasons.push("publication_not_resolved");
  if (version.id === latestId) reasons.push("latest_published_version");
  if (rank < policy.minimumVersions) reasons.push("minimum_version_count");
  const published = new Date(
    version.published_at || version.created_at,
  ).getTime();
  if (
    !Number.isFinite(published) ||
    now - published < policy.minimumSeconds * 1000
  )
    reasons.push("minimum_retention_duration");
  if (
    !Number.isFinite(published) ||
    now - published < policy.rollbackSeconds * 1000
  )
    reasons.push("rollback_preservation_period");
  for (const reason of references.get(version.id) || [])
    if (!reasons.includes(reason)) reasons.push(reason);
  return reasons;
}
async function retentionPreview({ client = pool, workspaceId, groupId }) {
  const group = await groupFor(client, workspaceId, groupId),
    policy =
      (await loadPolicy(client, workspaceId, group.id))?.policy.retention ||
      DEFAULT_POLICY.retention;
  const versions = (
    await client.query(
      `SELECT id,state,provider_version,created_at,published_at,valid_to FROM certops_material_versions WHERE workspace_id=$1 AND group_id=$2 ORDER BY created_at DESC,id DESC`,
      [workspaceId, group.id],
    )
  ).rows;
  const refs = (
    await client.query(
      `SELECT desired_material_version_id AS id,'desired_consumer_version' AS reason FROM certops_consumer_current_state WHERE workspace_id=$1 AND group_id=$2
    UNION ALL SELECT observed_material_version_id,'observed_consumer_version' FROM certops_consumer_current_state WHERE workspace_id=$1 AND group_id=$2 AND observed_material_version_id IS NOT NULL
    UNION ALL SELECT material_version_id,'resumable_rollout' FROM certops_distribution_rollouts WHERE workspace_id=$1 AND group_id=$2 AND state IN ('pending','deploying','paused')
    UNION ALL SELECT material_version_id,'uncertain_or_reconcilable_deployment' FROM certops_distribution_rollouts r WHERE r.workspace_id=$1 AND r.group_id=$2 AND EXISTS
      (SELECT 1 FROM certops_consumer_deployments d WHERE d.workspace_id=r.workspace_id AND d.rollout_id=r.id AND d.stage IN ('failed','orphaned_unknown_effect'))
    UNION ALL SELECT (COALESCE(payload->'materialDeployment',payload->'distributionRollout',payload->'publication')->>'materialVersionId')::uuid,'job_or_pending_approval'
      FROM certificate_jobs WHERE workspace_id=$1 AND COALESCE(payload->'materialDeployment',payload->'distributionRollout',payload->'publication')->>'groupId'=$2::text
      AND status IN ('pending_approval','approved','pending','claimed','running','blocked','failed','orphaned_unknown_effect')`,
      [workspaceId, group.id],
    )
  ).rows;
  const references = new Map();
  for (const ref of refs) {
    if (!references.has(ref.id)) references.set(ref.id, []);
    references.get(ref.id).push(ref.reason);
  }
  const now = Date.now();
  return {
    evaluated_at: new Date(now).toISOString(),
    reportOnly: true,
    cleanupAvailable: false,
    diagnosticCode: "CERTOPS_MATERIAL_CLEANUP_NOT_QUALIFIED",
    policy,
    providerSemantics: {
      vault_kv2:
        "Version soft deletion, destroy and metadata deletion are distinct; no deletion job is enabled.",
      openbao_kv2:
        "Requires merged provider extension and reviewed KV v2 deletion qualification.",
      azure_key_vault:
        "Arbitrary individual secret-version deletion is unavailable. Object deletion, soft delete, recovery and purge protection need separate authorization.",
    },
    versions: versions.map((version) => {
      const rank = versions
        .filter((value) => value.state === "published")
        .findIndex((value) => value.id === version.id);
      const reasons = retentionReasons(version, {
        rank: rank < 0 ? 0 : rank,
        policy,
        now,
        references,
        latestId: group.latest_material_version_id,
      });
      return {
        ...version,
        retainedReasons: reasons,
        metadataEligible: !reasons.length,
        cleanupAuthorized: false,
      };
    }),
  };
}
module.exports = { overview, preflight, retentionPreview, retentionReasons };
