"use strict";
const { pool } = require("../../db/database");
const material = require("./materialDistribution");
const { loadPolicy } = require("./distributionLifecycle");
const { assertDistributionPolicy } = require("./distributionPolicy");
const operations = require("./distributionOperations");
function backoffSeconds(policy, failures) {
  return Math.min(
    policy.maxBackoffSeconds,
    policy.intervalSeconds * 2 ** Math.min(failures, 16),
  );
}
async function scheduleGroup({
  client,
  workspaceId,
  groupId,
  now = Date.now(),
}) {
  await assertDistributionPolicy({ client, workspaceId });
  await material.lockGroup(client, workspaceId, groupId);
  const policy = await loadPolicy(client, workspaceId, groupId);
  if (!policy?.policy.verification.enabled)
    return { scheduled: false, reason: "verification_disabled" };
  const schedule = (
    await client.query(
      `SELECT * FROM certops_distribution_schedules WHERE workspace_id=$1 AND group_id=$2
    AND next_run_at<=clock_timestamp() FOR UPDATE`,
      [workspaceId, groupId],
    )
  ).rows[0];
  if (!schedule) return { scheduled: false, reason: "not_due" };
  const verification = policy.policy.verification;
  async function defer(reason, failed = false) {
    const failures = failed ? schedule.failures + 1 : schedule.failures;
    const seconds = failed
      ? backoffSeconds(verification, failures)
      : Math.min(verification.intervalSeconds, 300);
    await client.query(
      `UPDATE certops_distribution_schedules SET next_run_at=clock_timestamp()+$3*interval '1 second',
      failures=$4,last_outcome=$5 WHERE workspace_id=$1 AND group_id=$2`,
      [workspaceId, groupId, seconds, failures, reason],
    );
    return { scheduled: false, reason };
  }
  const pending = (
    await client.query(
      `SELECT r.id,r.state,r.created_at FROM certops_distribution_rollouts r
    WHERE r.workspace_id=$1 AND r.group_id=$2 AND r.state IN ('pending','deploying','paused') ORDER BY r.generation DESC LIMIT 1`,
      [workspaceId, groupId],
    )
  ).rows[0];
  if (pending)
    return defer(
      now - new Date(pending.created_at).getTime() >
        verification.staleJobSeconds * 1000
        ? "verification_stuck"
        : "rollout_in_progress",
    );
  if (schedule.last_job_id) {
    const last = (
      await client.query(
        `SELECT status,created_at FROM certificate_jobs WHERE workspace_id=$1 AND id=$2`,
        [workspaceId, schedule.last_job_id],
      )
    ).rows[0];
    if (
      last &&
      ["pending_approval", "pending", "claimed", "running"].includes(
        last.status,
      )
    )
      return defer(
        last.status === "pending_approval"
          ? "verification_approval_pending"
          : "verification_job_in_progress",
      );
    if (last?.status === "succeeded") {
      const proof = await material.consumerMatrix({
        client,
        workspaceId,
        groupId,
      });
      if (
        proof.length &&
        proof.every((row) => row.binding_state !== "active" || row.converged)
      )
        schedule.failures = 0;
    } else if (
      last &&
      ["failed", "blocked", "cancelled", "rejected"].includes(last.status)
    )
      schedule.failures++;
  }
  const bindings = (
    await client.query(
      `SELECT b.id,b.required,a.status,a.last_seen_at,s.desired_material_version_id,
    s.desired_generation,s.accepted_generation FROM certops_consumer_bindings b
    JOIN certops_agents a ON a.workspace_id=b.workspace_id AND a.id=b.assigned_agent_id
    LEFT JOIN certops_consumer_current_state s ON s.workspace_id=b.workspace_id AND s.binding_id=b.id
    WHERE b.workspace_id=$1 AND b.group_id=$2 AND b.state='active' ORDER BY b.id`,
      [workspaceId, groupId],
    )
  ).rows;
  if (!bindings.length) return defer("no_consumers", true);
  const desired = [
    ...new Set(bindings.map((b) => b.desired_material_version_id)),
  ];
  // Verification observes the approved desired version, never adopts a new
  // publication or installs a version because a timer fired.
  if (desired.length !== 1 || !desired[0])
    return defer("desired_version_unknown", true);
  if (
    bindings.some(
      (b) =>
        b.required &&
        (b.status !== "active" ||
          !b.last_seen_at ||
          now - new Date(b.last_seen_at).getTime() >
            policy.policy.alerts.offlineSeconds * 1000),
    )
  )
    return defer("required_agent_offline", true);
  const uncertain = await client.query(
    `SELECT 1 FROM certops_consumer_deployments d JOIN certificate_jobs j ON j.workspace_id=d.workspace_id AND j.id=d.job_id
    WHERE d.workspace_id=$1 AND d.group_id=$2 AND (d.stage='orphaned_unknown_effect' OR j.status='orphaned_unknown_effect')
      AND NOT EXISTS(SELECT 1 FROM certops_consumer_deployments later
        JOIN certops_distribution_rollouts lr ON lr.workspace_id=later.workspace_id AND lr.id=later.rollout_id
        JOIN certops_distribution_rollouts dr ON dr.workspace_id=d.workspace_id AND dr.id=d.rollout_id
        WHERE later.workspace_id=d.workspace_id AND later.binding_id=d.binding_id AND lr.generation>dr.generation
          AND later.stage IN ('installed','served_verified','trust_validated')) LIMIT 1`,
    [workspaceId, groupId],
  );
  if (uncertain.rowCount) return defer("unresolved_uncertain_effects", true);
  const sequence = Number(schedule.sequence) + 1;
  const job = await operations.requestRollout({
    client,
    workspaceId,
    groupId,
    materialVersionId: desired[0],
    verificationOnly: true,
    maxParallel: policy.policy.maxParallel,
    actorUserId: policy.configured_by_user_id,
    idempotencyKey: `verification:${groupId}:${sequence}`,
  });
  await client.query(
    `UPDATE certops_distribution_schedules SET sequence=$3,last_job_id=$4,last_outcome=$5,
    next_run_at=clock_timestamp()+$6*interval '1 second',failures=$7 WHERE workspace_id=$1 AND group_id=$2`,
    [
      workspaceId,
      groupId,
      sequence,
      job.id,
      job.status === "pending_approval"
        ? "verification_approval_pending"
        : "verification_requested",
      backoffSeconds(verification, schedule.failures),
      schedule.failures,
    ],
  );
  return { scheduled: true, jobId: job.id, reason: "verification_requested" };
}
async function runDistributionScheduler({
  dbPool = pool,
  batchSize = 50,
} = {}) {
  const due = (
    await dbPool.query(
      `SELECT s.workspace_id,s.group_id FROM certops_distribution_schedules s
    JOIN certops_distribution_policies p ON p.workspace_id=s.workspace_id AND p.group_id=s.group_id
    JOIN certops_distribution_groups g ON g.workspace_id=s.workspace_id AND g.id=s.group_id
    JOIN certops_management_periods m ON m.workspace_id=g.workspace_id AND m.id=g.management_period_id
    WHERE s.next_run_at<=clock_timestamp() AND p.policy->'verification'->>'enabled'='true' AND g.state='active' AND m.ended_at IS NULL
    ORDER BY s.next_run_at,s.workspace_id LIMIT $1`,
      [Math.max(1, Math.min(100, batchSize))],
    )
  ).rows;
  const summary = { scanned: due.length, scheduled: 0, deferred: 0, errors: 0 };
  for (const row of due) {
    try {
      const result = await operations.transaction(
        (client) =>
          scheduleGroup({
            client,
            workspaceId: row.workspace_id,
            groupId: row.group_id,
          }),
        dbPool,
      );
      if (result.scheduled) summary.scheduled++;
      else summary.deferred++;
    } catch (error) {
      if (
        ![
          "CERTOPS_WORKSPACE_PAUSED",
          "CERTOPS_DISABLED",
          "CERTOPS_DISTRIBUTION_INACTIVE",
        ].includes(error.code)
      )
        summary.errors++;
      else summary.deferred++;
      await dbPool.query(
        `UPDATE certops_distribution_schedules SET next_run_at=clock_timestamp()+interval '5 minutes',last_outcome='scheduling_deferred'
      WHERE workspace_id=$1 AND group_id=$2 AND next_run_at<=clock_timestamp()`,
        [row.workspace_id, row.group_id],
      );
    }
  }
  return summary;
}
module.exports = { backoffSeconds, scheduleGroup, runDistributionScheduler };
