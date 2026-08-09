"use strict";

/**
 * Pure agent-job eligibility rules shared by dispatch and renewal-path
 * health. SQL may pre-filter candidates for efficiency, but this predicate is
 * the authoritative answer to "could this persisted agent claim this job?".
 */

const { certopsCapabilityFreshnessMs } = require("./agentRegistry");

const EVIDENCE_CLAIM_BINDING_CAPABILITY = "evidence-claim-binding-v1";
const WIRE_ACTION_BY_OPERATION = Object.freeze({ issue: "renew" });

function wireActionForOperation(operation) {
  return WIRE_ACTION_BY_OPERATION[operation] || operation;
}

function persistedTextArray(value) {
  if (Array.isArray(value)) {
    return value.filter((entry) => typeof entry === "string");
  }
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed)
        ? parsed.filter((entry) => typeof entry === "string")
        : null;
    } catch (_error) {
      return null;
    }
  }
  return value == null ? [] : null;
}

function hasFreshCapability({
  declaredCapabilities,
  capabilitiesUpdatedAt,
  capability,
  env = process.env,
  now = Date.now(),
}) {
  const capabilities = persistedTextArray(declaredCapabilities);
  if (!capabilities || !capabilities.includes(capability)) return false;
  if (!capabilitiesUpdatedAt) return false;
  const updatedAtMs = new Date(capabilitiesUpdatedAt).getTime();
  if (!Number.isFinite(updatedAtMs)) return false;
  const ageMs = now - updatedAtMs;
  if (ageMs < 0) return true;
  return ageMs <= certopsCapabilityFreshnessMs(env);
}

function resolveAgentJobRoutingRequirements({
  executorKind = "agent",
  assignedAgentId = null,
  requiredTargetSelector = null,
  requiredDnsProvider = null,
  requiredCommandProfile = null,
  payload = {},
} = {}) {
  const body = payload && typeof payload === "object" && !Array.isArray(payload)
    ? payload
    : {};
  return {
    executorKind,
    assignedAgentId: assignedAgentId ?? body.assignedAgentId ?? null,
    requiredTargetSelector:
      requiredTargetSelector ??
      body.targetSelector ??
      (body.target && typeof body.target === "object"
        ? body.target.reference
        : null) ??
      null,
    requiredDnsProvider:
      requiredDnsProvider ?? body.dnsProvider ?? null,
    requiredCommandProfile:
      requiredCommandProfile ?? body.commandRef ?? null,
  };
}

function result(eligible, reason, determinate = true) {
  return { eligible, reason, determinate };
}

/**
 * Evaluate every persisted business rule that controls agent claimability.
 * Liveness is deliberately separate: dispatch authentication proves the
 * caller is live, while health combines this result with last-seen state.
 */
function evaluateAgentJobEligibility({
  agent,
  job,
  compatibility,
  env = process.env,
  now = Date.now(),
} = {}) {
  if (!agent || !job) return result(false, "facts_unavailable", false);

  const routing = resolveAgentJobRoutingRequirements(job);
  if (routing.executorKind !== "agent") {
    return result(false, "executor_lane_mismatch");
  }
  if (agent.status === "retired") return result(false, "agent_retired");
  if (!compatibility || typeof compatibility.compatibilityState !== "string") {
    return result(false, "compatibility_unknown", false);
  }
  if (compatibility.compatibilityState === "blocked") {
    return result(false, "compatibility_blocked");
  }

  // Assignment alone is enough to rule an agent out. Check it before reading
  // unrelated capability arrays so malformed facts on another agent cannot
  // make a pinned path look indeterminate.
  if (
    routing.assignedAgentId != null &&
    String(routing.assignedAgentId) !== String(agent.id)
  ) {
    return result(false, "assigned_agent_mismatch");
  }

  const supportedOperations = persistedTextArray(agent.supportedOperations);
  if (!supportedOperations) {
    return result(false, "persisted_capabilities_invalid", false);
  }
  if (!supportedOperations.includes(wireActionForOperation(job.operation))) {
    return result(false, "operation_unsupported");
  }

  const needsClaimBoundEvidence =
    job.operation === "issue" || job.subjectIsProvisioning === true;
  if (
    needsClaimBoundEvidence &&
    !hasFreshCapability({
      declaredCapabilities: agent.declaredCapabilities,
      capabilitiesUpdatedAt: agent.capabilitiesUpdatedAt,
      capability: EVIDENCE_CLAIM_BINDING_CAPABILITY,
      env,
      now,
    })
  ) {
    return result(false, "claim_bound_evidence_unavailable");
  }

  if (
    routing.requiredTargetSelector
  ) {
    const targetSelectors = persistedTextArray(agent.targetSelectors);
    if (!targetSelectors) {
      return result(false, "persisted_capabilities_invalid", false);
    }
    if (!targetSelectors.includes(routing.requiredTargetSelector)) {
      return result(false, "target_selector_unsupported");
    }
  }
  if (
    routing.requiredDnsProvider
  ) {
    const dnsProviders = persistedTextArray(agent.dnsProviders);
    if (!dnsProviders) {
      return result(false, "persisted_capabilities_invalid", false);
    }
    if (!dnsProviders.includes(routing.requiredDnsProvider)) {
      return result(false, "dns_provider_unsupported");
    }
  }
  if (
    routing.requiredCommandProfile
  ) {
    const commandProfiles = persistedTextArray(agent.commandProfiles);
    if (!commandProfiles) {
      return result(false, "persisted_capabilities_invalid", false);
    }
    if (!commandProfiles.includes(routing.requiredCommandProfile)) {
      return result(false, "command_profile_unsupported");
    }
  }

  const agentKind = agent.agentKind === "diagnostic" ? "diagnostic" : "normal";
  if (
    (job.operation === "protocol_smoke" && agentKind !== "diagnostic") ||
    (job.operation !== "protocol_smoke" && agentKind === "diagnostic")
  ) {
    return result(false, "agent_kind_mismatch");
  }
  return result(true, "eligible");
}

module.exports = {
  EVIDENCE_CLAIM_BINDING_CAPABILITY,
  evaluateAgentJobEligibility,
  hasFreshCapability,
  persistedTextArray,
  resolveAgentJobRoutingRequirements,
  wireActionForOperation,
};
