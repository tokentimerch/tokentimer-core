"use strict";

/**
 * Advisory explanation for a certificate job that is waiting to be claimed
 * or to make progress. Never written to the job row: computed on list/get
 * from the assigned/claiming agent's current eligibility and liveness, the
 * same way trust-anchor installations attach pendingReason.
 *
 * Lives in its own module so jobs.js can decorate list/get without importing
 * trustAnchors.js (jobs <-> trustAnchors would cycle).
 */

const { getAgentsByIds } = require("./agentRegistry");
const { evaluateAgentJobEligibility } = require("./agentJobEligibility");

const AWAITING_EXECUTION_STATUSES = new Set(["pending", "claimed"]);
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function declaredOperations(agent) {
  return Array.isArray(agent?.supportedOperations)
    ? agent.supportedOperations.filter((entry) => typeof entry === "string")
    : [];
}

function messageForEligibility({ job, agent, reason }) {
  if (reason === "agent_retired") {
    return "This agent has been retired and can no longer claim any job.";
  }
  if (reason === "compatibility_blocked") {
    return (
      "This agent's build or protocol version is outside what this " +
      "control plane accepts. It cannot claim any job until it is upgraded."
    );
  }
  if (reason === "operation_unsupported") {
    const declared = declaredOperations(agent);
    if (declared.length > 0) {
      return (
        `The assigned agent has declared support for ${declared.join(", ")}, ` +
        `but not for ${job.operation}. It is not idle; it simply has not ` +
        `been configured (or does not support) this job.`
      );
    }
    return (
      "The assigned agent has not declared any executable action the last " +
      "time it claimed a job. Most often this means it is running " +
      "observe-only (no execution block, or execution.enabled is not true, " +
      "in its config.json), though a brand-new agent that has not polled " +
      "for a job yet looks identical here."
    );
  }
  if (reason === "trust_anchor_deploy_capability_unavailable") {
    return (
      "This agent has not declared (or recently re-declared) support for " +
      "trust-anchor distribution. Confirm the agent is running a build that " +
      "supports distribute-trust/revoke-trust and has heartbeated recently."
    );
  }
  return `The assigned agent cannot currently claim this job (${reason}).`;
}

function isAgentOffline(agent) {
  if (!agent) return false;
  if (agent.livenessState === "stale") return true;
  const status = String(agent.status || "").toLowerCase();
  return status === "offline" || status === "stale";
}

function pendingReasonForJob(job, agent) {
  if (!job || !AWAITING_EXECUTION_STATUSES.has(job.status)) return null;

  if (job.status === "claimed") {
    return {
      code: "awaiting_progress",
      message:
        "This job has been claimed and is waiting for the agent to start or report progress.",
    };
  }

  if (!agent) {
    if (job.assignedAgentId) {
      return {
        code: "assigned_agent_missing",
        message:
          "The assigned agent is no longer registered, so this job cannot be claimed.",
      };
    }
    return {
      code: "awaiting_claim",
      message: "Waiting for an eligible agent to poll and claim this job.",
    };
  }

  const evaluation = evaluateAgentJobEligibility({
    agent,
    job: {
      operation: job.operation,
      executorKind: job.executorKind || "agent",
      assignedAgentId: job.assignedAgentId || agent.id,
      requiredTargetSelector: job.requiredTargetSelector,
      requiredDnsProvider: job.requiredDnsProvider,
      requiredCommandProfile: job.requiredCommandProfile,
      payload: job.payload || {},
    },
    compatibility: { compatibilityState: agent.compatibilityState },
  });
  if (evaluation.determinate === true && !evaluation.eligible) {
    return {
      code: evaluation.reason,
      message: messageForEligibility({
        job,
        agent,
        reason: evaluation.reason,
      }),
    };
  }

  if (isAgentOffline(agent)) {
    return {
      code: "agent_offline",
      message:
        "The assigned agent is offline and cannot claim this job until it heartbeats again.",
    };
  }

  return {
    code: "awaiting_claim",
    message: "Waiting for the assigned agent to poll and claim this job.",
  };
}

function collectAgentIds(jobs) {
  const ids = [];
  for (const job of jobs) {
    if (!AWAITING_EXECUTION_STATUSES.has(job.status)) continue;
    if (typeof job.assignedAgentId === "string" && UUID_RE.test(job.assignedAgentId)) {
      ids.push(job.assignedAgentId);
    }
    if (typeof job.claimedByAgentId === "string" && UUID_RE.test(job.claimedByAgentId)) {
      ids.push(job.claimedByAgentId);
    }
  }
  return ids;
}

async function attachJobPendingReasons({ db, workspaceId, jobs, env }) {
  if (!Array.isArray(jobs) || jobs.length === 0) return jobs || [];
  const ids = collectAgentIds(jobs);
  const agentsById =
    ids.length === 0
      ? new Map()
      : await getAgentsByIds({
          client: db,
          workspaceId,
          ids,
          env,
        });
  return jobs.map((job) => {
    const agentId = job.assignedAgentId || job.claimedByAgentId || null;
    const agent = agentId ? agentsById.get(String(agentId)) || null : null;
    return { ...job, pendingReason: pendingReasonForJob(job, agent) };
  });
}

module.exports = {
  AWAITING_EXECUTION_STATUSES,
  attachJobPendingReasons,
  pendingReasonForJob,
};
