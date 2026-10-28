"use strict";
const { pool } = require("../../db/database");
const material = require("./materialDistribution");
const { loadPolicy } = require("./distributionLifecycle");
const { activationPlanner,activationDeadline } = require("./distributionMaintenance");
const {
  resolveContactGroupsForAsset,
  deliveryChannelsFromEligibleGroups,
} = require("../../src/shared/contactGroups");
const { writeAudit } = require("../audit");
const TITLES = Object.freeze({
  publication_failed: "Certificate publication failed",
  rollout_failed: "Certificate rollout failed",
  rollout_stuck: "Certificate rollout is stuck",
  required_consumer_offline: "Required certificate consumer is offline",
  verification_overdue: "Consumer verification evidence expired",
  certificate_drift: "Consumer certificate drift detected",
  old_certificate_active: "Consumer still uses an older certificate",
  consumer_certificate_expired: "Deployed consumer certificate expired",
  consumer_certificate_expiring: "Deployed consumer certificate expires soon",
  uncertain_effects: "Certificate deployment has uncertain effects",
  maintenance_window_missed:
    "Certificate activation needs maintenance escalation",
  renewal_not_converged:
    "Published certificate has not reached required consumers",
  verification_failed: "Recurring consumer verification failed",
  unknown_coverage: "Certificate consumer coverage is incomplete",
});
function consumerHealth(
  row,
  { now = Date.now(), offlineSeconds = 900, latestVersionId = null } = {},
) {
  if (row.binding_state !== "active") return "inactive";
  if (
    row.latest_deployment?.needsOperatorReconciliation === true ||
    row.latest_deployment?.stage === "orphaned_unknown_effect" ||
    row.latest_deployment?.jobStatus === "orphaned_unknown_effect"
  )
    return "uncertain_external_effects";
  if (
    row.agent_status !== "active" ||
    !row.agent_last_seen_at ||
    now - new Date(row.agent_last_seen_at).getTime() > offlineSeconds * 1000
  )
    return "agent_offline";
  if (
    row.observed_fingerprint_sha256 &&
    row.desired_fingerprint_sha256 &&
    row.observed_material_version_id === row.desired_material_version_id &&
    row.observed_fingerprint_sha256 !== row.desired_fingerprint_sha256
  )
    return "drift_detected";
  if (/drift/i.test(row.latest_deployment?.failureCode || ""))
    return "drift_detected";
  if (
    row.observed_material_version_id &&
    (row.observed_material_version_id !== row.desired_material_version_id ||
      (latestVersionId && row.observed_material_version_id !== latestVersionId))
  )
    return "old_certificate_active";
  if (
    row.observed_at &&
    now - new Date(row.observed_at).getTime() >= row.freshness_seconds * 1000
  )
    return "verification_overdue";
  if (row.converged === true)
    return row.verification_policy === "installed"
      ? "installed_not_proven_served"
      : "up_to_date_fresh";
  // Old installation/served evidence cannot hide a failed current cycle.
  if (
    row.latest_deployment?.stage === "failed" ||
    ["failed", "blocked", "rejected", "cancelled"].includes(
      row.latest_deployment?.jobStatus,
    )
  )
    return "failed_verification";
  if (row.verification_method === "installed")
    return "installed_not_proven_served";
  if (
    row.verification_method === "served" &&
    row.verification_policy === "trust"
  )
    return "served_trust_unknown";
  return "unknown_coverage";
}
function consumerConditions(
  row,
  policy,
  now = Date.now(),
  latestVersionId = null,
) {
  const health = consumerHealth(row, {
    now,
    offlineSeconds: policy.alerts.offlineSeconds,
    latestVersionId,
  });
  const map = {
    uncertain_external_effects: "uncertain_effects",
    agent_offline: row.required ? "required_consumer_offline" : null,
    drift_detected: "certificate_drift",
    old_certificate_active: "old_certificate_active",
    verification_overdue: "verification_overdue",
    failed_verification: "verification_failed",
    unknown_coverage: "unknown_coverage",
  };
  const codes = new Set(map[health] ? [map[health]] : []);
  // Health is a primary display label; independent conditions must not hide
  // overdue proof or an offline required consumer behind an older version.
  if(row.required && (row.agent_status!=="active" || !row.agent_last_seen_at ||
    now-new Date(row.agent_last_seen_at).getTime()>policy.alerts.offlineSeconds*1000))codes.add("required_consumer_offline");
  if(row.observed_at && now-new Date(row.observed_at).getTime()>=row.freshness_seconds*1000)codes.add("verification_overdue");
  const expiry = new Date(row.observed_valid_to).getTime();
  if (row.observed_valid_to && Number.isFinite(expiry)) {
    if (expiry <= now) codes.add("consumer_certificate_expired");
    else if (expiry - now <= policy.alerts.expiryWarningDays * 86400000)
      codes.add("consumer_certificate_expiring");
  }
  return { health, codes:[...codes] };
}
function evidenceFor(row) {
  return {
    bindingId: row.binding_id,
    agentId: row.assigned_agent_id,
    desiredVersionId: row.desired_material_version_id || null,
    observedVersionId: row.observed_material_version_id || null,
    observedFingerprint: row.observed_fingerprint_sha256 || null,
    deployedExpiry: row.observed_valid_to
      ? new Date(row.observed_valid_to).toISOString()
      : null,
    observedAt: row.observed_at
      ? new Date(row.observed_at).toISOString()
      : null,
    jobId: row.latest_deployment?.jobId || null,
    rolloutId: row.latest_deployment?.rolloutId || null,
  };
}
async function verificationFailureCounts(client, workspaceId, groupId) {
  const result = await client.query(
    `SELECT b.id,
    CASE WHEN s.verification_failure_revision=b.authorization_revision THEN s.verification_failure_count ELSE 0 END AS failures,
    CASE WHEN s.verification_failure_revision=b.authorization_revision THEN s.verification_outcome_generation ELSE 0 END AS generation,
    COALESCE(j.needs_operator_reconciliation,false) AS uncertain
    FROM certops_consumer_bindings b LEFT JOIN certops_consumer_current_state s
      ON s.workspace_id=b.workspace_id AND s.binding_id=b.id
    LEFT JOIN certops_distribution_rollouts r ON r.workspace_id=s.workspace_id AND r.group_id=s.group_id AND r.generation=s.desired_generation
    LEFT JOIN certops_consumer_deployments d ON d.workspace_id=r.workspace_id AND d.rollout_id=r.id AND d.binding_id=b.id
    LEFT JOIN certificate_jobs j ON j.workspace_id=d.workspace_id AND j.id=d.job_id
    WHERE b.workspace_id=$1 AND b.group_id=$2 AND b.state='active'`,
    [workspaceId, groupId],
  );
  return new Map(result.rows.map((row) => [row.id, {
    failures: Number(row.failures),
    generation: Number(row.generation),
    uncertain: row.uncertain,
  }]));
}
function consumerVerificationFailureCount(row, counts) {
  const own = counts.get(row.binding_id);
  // Only the currently failing verification can use this streak. A manual
  // deployment failure or a newer pending cycle cannot borrow an older count.
  return own && own.generation === Number(row.desired_generation) ? own.failures : 0;
}
async function queueIncident(
  client,
  workspaceId,
  group,
  policy,
  incident,
  transition,
) {
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
    `distribution-alert:${workspaceId}`,
  ]);
  const settings =
    (
      await client.query(
        `SELECT * FROM workspace_settings WHERE workspace_id=$1`,
        [workspaceId],
      )
    ).rows[0] || {};
  const groups = resolveContactGroupsForAsset({
    contactGroups: settings.contact_groups,
    assignedIds: policy.alerts.contactGroupIds,
    defaultContactGroupId: settings.default_contact_group_id,
  });
  const channels = deliveryChannelsFromEligibleGroups(groups, {
    emailAlertsEnabled: settings.email_alerts_enabled,
    alertKey: "cert_distribution:",
  });
  if (!channels.length) return false;
  // Bound workspace incident traffic independently of consumer fleet size.
  const count =
    (
      await client.query(
        `SELECT count(*)::int AS count FROM alert_queue q JOIN certops_agents a ON a.id=q.certops_agent_id
    WHERE a.workspace_id=$1 AND q.alert_key LIKE 'cert_distribution:%' AND q.created_at>clock_timestamp()-interval '1 hour'`,
        [workspaceId],
      )
    ).rows[0]?.count || 0;
  if (count >= 20) return false;
  const owner = (
    await client.query(`SELECT created_by FROM workspaces WHERE id=$1`, [
      workspaceId,
    ])
  ).rows[0]?.created_by;
  if (!owner) return false;
  const key = `cert_distribution:${incident.id}:${incident.revision}:${transition}`;
  const data = {
    incidentId: incident.id,
    groupId: group.id,
    code: incident.code,
    transition,
    severity: incident.severity,
    evidence: incident.evidence,
  };
  await client.query(
    `INSERT INTO alert_queue(user_id,certops_agent_id,alert_key,threshold_days,due_date,channels,status,metadata)
    VALUES($1,$2,$3,0,CURRENT_DATE,$4,'pending',$5) ON CONFLICT(alert_key) WHERE alert_key LIKE 'cert_distribution:%' DO NOTHING`,
    [
      owner,
      incident.evidence.agentId || group.issuer_agent_id,
      key,
      JSON.stringify(channels),
      data,
    ],
  );
  await client.query(
    `UPDATE certops_distribution_incidents SET last_notified_at=clock_timestamp() WHERE workspace_id=$1 AND id=$2`,
    [workspaceId, incident.id],
  );
  return true;
}
async function recordIncident(
  client,
  workspaceId,
  group,
  policy,
  { bindingId = null, code, evidence, notificationEligible = true },
  now,
) {
  const key = `distribution:${group.id}:${bindingId || "group"}:${code}`;
  const existing = (
    await client.query(
      `SELECT * FROM certops_distribution_incidents WHERE workspace_id=$1 AND dedupe_key=$2 AND resolved_at IS NULL FOR UPDATE`,
      [workspaceId, key],
    )
  ).rows[0];
  const severity = [
    "consumer_certificate_expired",
    "uncertain_effects",
    "publication_failed",
    "rollout_failed",
    "renewal_not_converged",
    "maintenance_window_missed",
  ].includes(code)
    ? "critical"
    : "warning";
  const changed =
    !existing ||
    material.hashIntent(existing.evidence) !== material.hashIntent(evidence) ||
    existing.severity !== severity;
  let incident = existing;
  if (!existing)
    incident = (
      await client.query(
        `INSERT INTO certops_distribution_incidents(workspace_id,group_id,binding_id,code,dedupe_key,severity,evidence)
    VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
        [workspaceId, group.id, bindingId, code, key, severity, evidence],
      )
    ).rows[0];
  else if (changed)
    incident = (
      await client.query(
        `UPDATE certops_distribution_incidents SET evidence=$3,severity=$4,revision=revision+1,updated_at=clock_timestamp()
    WHERE workspace_id=$1 AND id=$2 RETURNING *`,
        [workspaceId, existing.id, evidence, severity],
      )
    ).rows[0];
  await client.query(
    `INSERT INTO operational_notifications(workspace_id,category,type,severity,dedupe_key,title,message,metadata)
    VALUES($1,'certops',$2,$3,$4,$5,$6,$7) ON CONFLICT(workspace_id,dedupe_key) WHERE resolved_at IS NULL
    DO UPDATE SET severity=EXCLUDED.severity,message=EXCLUDED.message,metadata=EXCLUDED.metadata,updated_at=NOW()`,
    [
      workspaceId,
      code,
      severity,
      key,
      TITLES[code],
      "Review Distribution Management, inspect signed job evidence and obtain fresh consumer verification.",
      {
        incidentId: incident.id,
        groupId: group.id,
        code,
        evidence,
        href: `/certops/distribution?workspace=${workspaceId}&group=${group.id}`,
      },
    ],
  );
  if (
    notificationEligible &&
    (!incident.last_notified_at ||
      now - new Date(incident.last_notified_at).getTime() >=
        policy.alerts.repeatSeconds * 1000)
  ) {
    if (!changed && incident.last_notified_at)
      incident = (
        await client.query(
          `UPDATE certops_distribution_incidents SET revision=revision+1 WHERE workspace_id=$1 AND id=$2 RETURNING *`,
          [workspaceId, incident.id],
        )
      ).rows[0];
    await queueIncident(
      client,
      workspaceId,
      group,
      policy,
      incident,
      existing ? "updated" : "opened",
    );
  }
  if (changed)
    await writeAudit({
      client,
      workspaceId,
      action: existing
        ? "CERTOPS_DISTRIBUTION_INCIDENT_UPDATED"
        : "CERTOPS_DISTRIBUTION_INCIDENT_OPENED",
      targetType: "certops_distribution_incident",
      targetId: incident.id,
      metadata: { groupId: group.id, code, evidence },
    });
  return key;
}
async function monitorGroup({
  client,
  workspaceId,
  groupId,
  now = Date.now(),
}) {
  // Monitoring continues while paused, using the same lock order as policy
  // changes, retirement and transactional incident writes.
  await client.query("SELECT id FROM workspaces WHERE id=$1 FOR SHARE",[workspaceId]);
  const group = await material.lockGroup(client, workspaceId, groupId);
  const policyRow = await loadPolicy(client, workspaceId, groupId);
  const policy = policyRow?.policy;
  if (!policy?.alerts.enabled) return { monitored: false };
  const rows = await material.consumerMatrix({ client, workspaceId, groupId });
  const version = (
    await client.query(
      `SELECT v.*,j.status AS publishing_status FROM certops_material_versions v JOIN certificate_jobs j ON j.workspace_id=v.workspace_id AND j.id=v.publishing_job_id
        WHERE v.workspace_id=$1 AND v.group_id=$2 ORDER BY v.created_at DESC,v.id DESC LIMIT 1`,
      [workspaceId, groupId],
    )
  ).rows[0];
  const conditions = [];
  const failureCounts = await verificationFailureCounts(client, workspaceId, groupId);
  const plan=activationPlanner(now);
  for (const row of rows.filter((row) => row.binding_state === "active")) {
    if (failureCounts.get(row.binding_id)?.uncertain)
      row.latest_deployment = { ...row.latest_deployment, needsOperatorReconciliation: true };
    const { codes } = consumerConditions(
      row,
      policy,
      now,
      group.latest_material_version_id,
    );
    for (const code of codes) {
      const failureCount = code === "verification_failed"
        ? consumerVerificationFailureCount(row, failureCounts) : row.latest_deployment?.attemptCount || 0;
      if (
        code === "unknown_coverage" &&
        now - new Date(group.created_at).getTime() <
          policy.alerts.convergenceSeconds * 1000
      )
        continue;
      conditions.push({
        bindingId: row.binding_id,
        code,
        evidence: {
          ...evidenceFor(row),
          failureCount,
        },
        notificationEligible:
          code !== "verification_failed" ||
          failureCount >= policy.verification.failureThreshold,
      });
    }
    if (
      row.activation_policy &&
      row.desired_material_version_id &&
      !row.converged
    ) {
      const expiry = (
        await client.query(
          `SELECT valid_to FROM certops_material_versions WHERE workspace_id=$1 AND group_id=$2 AND id=$3`,
          [workspaceId, groupId, row.desired_material_version_id],
        )
      ).rows[0]?.valid_to;
      const deadline=activationDeadline(expiry,row.observed_valid_to);
      const next = plan(row.activation_policy, deadline);
      if (!next.at)
        conditions.push({
          bindingId: row.binding_id,
          code: "maintenance_window_missed",
          evidence: { ...evidenceFor(row), reason: next.reason },
        });
    }
  }
  if (version && (version.state==="orphaned_unknown_effect" || version.state==="failed" && !version.allocation_release_reason ||
    ["failed","blocked","orphaned_unknown_effect"].includes(version.publishing_status)))
    conditions.push({
      code: "publication_failed",
      evidence: {
        materialVersionId: version.id,
        jobId: version.publishing_job_id,
      },
    });
  const rollout = (
    await client.query(
      `SELECT * FROM certops_distribution_rollouts WHERE workspace_id=$1 AND group_id=$2 ORDER BY generation DESC LIMIT 1`,
      [workspaceId, groupId],
    )
  ).rows[0];
  if (
    rollout &&
    ["pending", "deploying", "paused"].includes(rollout.state) &&
    now - new Date(rollout.created_at).getTime() >
      policy.alerts.stuckSeconds * 1000
  )
    conditions.push({
      code: rollout.state === "paused" ? "rollout_failed" : "rollout_stuck",
      evidence: {
        rolloutId: rollout.id,
        materialVersionId: rollout.material_version_id,
      },
    });
  if (
    version?.state === "published" &&
    now - new Date(version.published_at).getTime() >
      policy.alerts.convergenceSeconds * 1000 &&
    rows.some(
      (row) =>
        row.required &&
        row.binding_state === "active" &&
        (!row.converged || row.observed_material_version_id !== version.id),
    )
  )
    conditions.push({
      code: "renewal_not_converged",
      evidence: {
        materialVersionId: version.id,
        publishingJobId: version.publishing_job_id,
      },
    });
  await client.query(
    `UPDATE certops_distribution_policies SET next_monitor_at=clock_timestamp()+interval '1 minute' WHERE workspace_id=$1 AND group_id=$2`,
    [workspaceId, groupId],
  );
  const active = new Set();
  for (const condition of conditions)
    active.add(
      await recordIncident(client, workspaceId, group, policy, condition, now),
    );
  const open = (
    await client.query(
      `SELECT * FROM certops_distribution_incidents WHERE workspace_id=$1 AND group_id=$2 AND resolved_at IS NULL FOR UPDATE`,
      [workspaceId, groupId],
    )
  ).rows;
  for (const incident of open) {
    if (active.has(incident.dedupe_key)) continue;
    const relevant = incident.binding_id
      ? rows.filter((row) => row.binding_id === incident.binding_id)
      : rows.filter((row) => row.required && row.binding_state === "active");
    // Old proof, source renewal, local repair and deleting a binding cannot
    // resolve an incident. Proof must postdate its latest changed condition.
    if (
      !relevant.length ||
      !relevant.every(
        (row) =>
          row.converged &&
          row.observed_material_version_id ===
            group.latest_material_version_id &&
          new Date(row.observed_at).getTime() >
            new Date(incident.updated_at).getTime(),
      )
    )
      continue;
    const resolved = (
      await client.query(
        `UPDATE certops_distribution_incidents SET resolved_at=clock_timestamp(),updated_at=clock_timestamp(),revision=revision+1
      WHERE workspace_id=$1 AND id=$2 RETURNING *`,
        [workspaceId, incident.id],
      )
    ).rows[0];
    await client.query(
      `UPDATE operational_notifications SET resolved_at=NOW(),updated_at=NOW() WHERE workspace_id=$1 AND dedupe_key=$2 AND resolved_at IS NULL`,
      [workspaceId, incident.dedupe_key],
    );
    await queueIncident(
      client,
      workspaceId,
      group,
      policy,
      resolved,
      "resolved",
    );
    await writeAudit({
      client,
      workspaceId,
      action: "CERTOPS_DISTRIBUTION_INCIDENT_RESOLVED",
      targetType: "certops_distribution_incident",
      targetId: incident.id,
      metadata: { groupId, code: incident.code },
    });
  }
  return { monitored: true, conditions: conditions.length };
}
async function runDistributionMonitoring({
  dbPool = pool,
  batchSize = 50,
} = {}) {
  const groups = (
    await dbPool.query(
      `SELECT p.workspace_id,p.group_id FROM certops_distribution_policies p
    JOIN certops_distribution_groups g ON g.workspace_id=p.workspace_id AND g.id=p.group_id
    JOIN certops_management_periods m ON m.workspace_id=g.workspace_id AND m.id=g.management_period_id
    WHERE p.policy->'alerts'->>'enabled'='true' AND p.next_monitor_at<=clock_timestamp() AND g.state='active' AND m.ended_at IS NULL
    ORDER BY p.next_monitor_at,p.workspace_id LIMIT $1`,
      [Math.max(1, Math.min(100, batchSize))],
    )
  ).rows;
  const summary = { scanned: groups.length, monitored: 0, errors: 0 };
  for (const row of groups)
    try {
      await require("./distributionOperations").transaction(
        (client) =>
          monitorGroup({
            client,
            workspaceId: row.workspace_id,
            groupId: row.group_id,
          }),
        dbPool,
      );
      summary.monitored++;
    } catch {
      summary.errors++;
      await dbPool.query(
        `UPDATE certops_distribution_policies SET next_monitor_at=clock_timestamp()+interval '5 minutes' WHERE workspace_id=$1 AND group_id=$2 AND next_monitor_at<=clock_timestamp()`,
        [row.workspace_id, row.group_id],
      );
    }
  return summary;
}
module.exports = {
  TITLES,
  consumerHealth,
  consumerConditions,
  evidenceFor,
  verificationFailureCounts,
  consumerVerificationFailureCount,
  recordIncident,
  monitorGroup,
  runDistributionMonitoring,
};
