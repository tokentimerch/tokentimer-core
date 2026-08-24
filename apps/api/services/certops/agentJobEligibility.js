"use strict";

/**
 * Pure agent-job eligibility rules shared by dispatch and renewal-path
 * health. SQL may pre-filter candidates for efficiency, but this predicate is
 * the authoritative answer to "could this persisted agent claim this job?".
 */

const { certopsCapabilityFreshnessMs } = require("./agentRegistry");

const EVIDENCE_CLAIM_BINDING_CAPABILITY = "evidence-claim-binding-v1";
// Freshness-gated capability an agent must declare before it can claim a
// distribute-trust/revoke-trust job (ADR-0012 decisions 17 and 20i): a trust
// anchor mutation is destined for the machine trust store, a higher-stakes
// surface than an ordinary certificate deploy, so dispatch requires the same
// "declared AND fresh" proof evidence-claim-binding already requires, not
// mere presence in a possibly-stale declared-capabilities array.
const TRUST_ANCHOR_DEPLOY_CAPABILITY = "trust-anchor-deploy-v1";
// Duplicated locally (not imported from jobs.js's isTrustAnchorOperation)
// because jobs.js itself requires this module for
// resolveAgentJobRoutingRequirements; importing jobs.js back here would be a
// circular require. Kept in sync by hand -- both lists are two-element and
// have not changed since ADR-0012 decision 4 introduced them.
const TRUST_ANCHOR_OPERATION_SET = new Set(["distribute-trust", "revoke-trust"]);
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

  // ADR-0012 decision 20i: an agent may only claim a trust-anchor job while
  // its trust-anchor-deploy-v1 declaration is fresh, mirroring the
  // evidence-claim-binding gate above exactly. A trust job is dispatched to
  // one specific agent (assignedAgentId is mandatory for these operations,
  // enforced by the trust-anchor orchestration service, not by this
  // predicate), so an agent that goes stale on this capability makes its
  // pinned job unclaimable by anyone else until the next heartbeat refreshes
  // capabilitiesUpdatedAt -- the reconciliation sweep, not a different
  // agent, is what eventually reports that as stale rather than silently
  // stuck (ADR-0012 decision 20b/20f).
  if (
    TRUST_ANCHOR_OPERATION_SET.has(job.operation) &&
    !hasFreshCapability({
      declaredCapabilities: agent.declaredCapabilities,
      capabilitiesUpdatedAt: agent.capabilitiesUpdatedAt,
      capability: TRUST_ANCHOR_DEPLOY_CAPABILITY,
      env,
      now,
    })
  ) {
    return result(false, "trust_anchor_deploy_capability_unavailable");
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
  TRUST_ANCHOR_DEPLOY_CAPABILITY,
  evaluateAgentJobEligibility,
  hasFreshCapability,
  persistedTextArray,
  resolveAgentJobRoutingRequirements,
  wireActionForOperation,
};
