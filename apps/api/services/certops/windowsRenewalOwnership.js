"use strict";

const { WINDOWS_SNI_HOST_PATTERN } = require("./renewalProfile");

// Current Windows IIS jobs always use a wildcard IP listener. A hostname SNI
// selector covers every listening IP, so its site name is not part of the key.
function iisSelectorKey(binding) {
  if (!binding || !Number.isInteger(binding.port) || binding.port < 1 || binding.port > 65535) {
    throw new Error("invalid IIS binding port");
  }
  if (binding.address != null && binding.address !== "*" && binding.address !== "0.0.0.0") {
    throw new Error("unsupported IIS binding address");
  }
  if (binding.sniHost == null || binding.sniHost === "") return `ipport:0.0.0.0:${binding.port}`;
  if (typeof binding.sniHost !== "string" || !WINDOWS_SNI_HOST_PATTERN.test(binding.sniHost)) {
    throw new Error("invalid IIS SNI hostname");
  }
  return `hostnameport:${binding.sniHost.toLowerCase()}:${binding.port}`;
}

// These functions evaluate server-owned observations. A matching certificate
// name alone, or a client-supplied relationship, is never sufficient evidence.
function sameText(a, b) {
  return typeof a === "string" && a.length > 0 &&
    typeof b === "string" && b.length > 0 && a.toLowerCase() === b.toLowerCase();
}

function validFingerprint(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/i.test(value);
}

function sameFingerprint(a, b) {
  return validFingerprint(a) && validFingerprint(b) && sameText(a, b);
}

/** Classify an observed IIS location without granting permission to change it. */
function classifyBinding({ owner, binding, agentOnline, observationFresh }) {
  if (!owner || !binding || !owner.workspaceId || !owner.agentId ||
      !owner.managementPeriodId || !owner.storeName || !binding.id ||
      owner.workspaceId !== binding.workspaceId || owner.agentId !== binding.agentId ||
      !sameText(owner.storeName, binding.storeName)) {
    return { relationship: "unrelated", deployment: "unavailable" };
  }
  if (owner.managementActive !== true || owner.renewalEligible !== true) {
    return { relationship: "unknown", deployment: "unavailable" };
  }
  if (agentOnline !== true || observationFresh !== true || binding.presence !== "confirmed_present") {
    return {
      relationship: binding.presence === "confirmed_absent" && agentOnline === true && observationFresh === true ? "absent" : "unknown",
      deployment: "unavailable",
    };
  }
  if (!validFingerprint(owner.fingerprintSha256) || !validFingerprint(binding.fingerprintSha256)) {
    return { relationship: "unknown", deployment: "unavailable" };
  }
  if (!sameFingerprint(owner.fingerprintSha256, binding.fingerprintSha256)) {
    return { relationship: "changed", deployment: "unavailable" };
  }
  if (binding.renewalProfileId) {
    return { relationship: "observed", deployment: "conflict" };
  }
  return {
    relationship: "observed",
    deployment: binding.automaticUpdate === true ? "authorized" : "observed_only",
  };
}

/**
 * A verified renewal changes the store fingerprint before IIS has necessarily
 * switched. Classify against the predecessor recorded for that renewal, not
 * against the store's new fingerprint. The agent must re-check the live binding
 * at execution: a prior observation is not mutation authority.
 */
function classifyPendingCutover({ owner, binding, agentOnline, observationFresh, predecessorSha256, replacementSha256 }) {
  if (!sameFingerprint(owner?.fingerprintSha256, replacementSha256) ||
      !validFingerprint(predecessorSha256) ||
      sameFingerprint(predecessorSha256, replacementSha256)) {
    return { relationship: "unknown", deployment: "unavailable" };
  }
  const sameScope = { ...owner, fingerprintSha256: predecessorSha256 };
  const predecessor = classifyBinding({ owner: sameScope, binding, agentOnline, observationFresh });
  if (predecessor.relationship !== "changed") return predecessor;
  const replacement = classifyBinding({ owner, binding, agentOnline, observationFresh });
  if (replacement.relationship === "observed") {
    return replacement.deployment === "authorized"
      ? { relationship: "observed", deployment: "verify_only" }
      : replacement;
  }
  return predecessor;
}

/** Build a read-only decision for each binding; store renewal is independent. */
function planPendingCutovers({ owner, bindings, agentOnline, predecessorSha256, replacementSha256 }) {
  if (!Array.isArray(bindings)) throw new TypeError("bindings must be an array");
  const ids = new Set();
  const selectors = new Set();
  return bindings.map((binding) => {
    if (!binding?.id || ids.has(binding.id)) throw new Error("binding identifiers must be unique");
    const selectorKey = iisSelectorKey(binding.binding);
    if (selectors.has(selectorKey)) throw new Error("binding selectors must be unique");
    ids.add(binding.id);
    selectors.add(selectorKey);
    return {
      bindingId: binding.id,
      ...classifyPendingCutover({ owner, binding, agentOnline, observationFresh: binding.observationFresh, predecessorSha256, replacementSha256 }),
    };
  });
}

module.exports = { classifyBinding, classifyPendingCutover, iisSelectorKey, planPendingCutovers };
