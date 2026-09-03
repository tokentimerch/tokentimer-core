"use strict";

/**
 * Pure, DB-free unit tests for the agent-capability-visibility helpers
 * added to trustAnchors.js: the creation-time eligibility guard
 * (assertTargetAgentEligibleForTrustJob) and the advisory pendingReason
 * projection surfaced on already-created installation rows
 * (pendingReasonForInstallation). Both are thin wrappers around
 * evaluateAgentJobEligibility (already covered by its own test surface via
 * dispatch), so these tests focus on the parts unique to this file: WHICH
 * reasons block creation vs. which are advisory-only, and that both paths
 * agree on the same reason taxonomy/prose.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const trustAnchors = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/trustAnchors.js",
  ),
);

const { TRUST_JOB_INELIGIBLE_MESSAGE_BY_REASON } = trustAnchors;
const {
  assertTargetAgentEligibleForTrustJob,
  BLOCKING_TRUST_JOB_CREATION_REASONS,
  pendingReasonForInstallation,
} = trustAnchors._test;

function baseAgent(overrides = {}) {
  return {
    id: "agent-uuid-1",
    status: "active",
    compatibilityState: "compatible",
    supportedOperations: ["distribute-trust", "revoke-trust"],
    declaredCapabilities: ["trust-anchor-deploy-v1"],
    capabilitiesUpdatedAt: new Date().toISOString(),
    targetSelectors: [],
    dnsProviders: [],
    commandProfiles: [],
    agentKind: "normal",
    ...overrides,
  };
}

describe("assertTargetAgentEligibleForTrustJob (creation-time guard)", () => {
  it("allows a healthy, fully-eligible agent through without throwing", () => {
    assert.doesNotThrow(() =>
      assertTargetAgentEligibleForTrustJob({
        agent: baseAgent(),
        operation: "distribute-trust",
      }),
    );
  });

  it("blocks a retired agent (agent_retired is in the hard-block set)", () => {
    assert.throws(
      () =>
        assertTargetAgentEligibleForTrustJob({
          agent: baseAgent({ status: "retired" }),
          operation: "distribute-trust",
        }),
      (err) => err.code === "CERTOPS_TARGET_AGENT_INELIGIBLE",
    );
  });

  it("blocks a compatibility-blocked agent", () => {
    assert.throws(
      () =>
        assertTargetAgentEligibleForTrustJob({
          agent: baseAgent({ compatibilityState: "blocked" }),
          operation: "distribute-trust",
        }),
      (err) => err.code === "CERTOPS_TARGET_AGENT_INELIGIBLE",
    );
  });

  it("does NOT block an agent with an empty supportedOperations (operation_unsupported is excluded from creation-time blocking - see BLOCKING_TRUST_JOB_CREATION_REASONS's header comment on why this reason is ambiguous between observe-only and never-yet-polled)", () => {
    assert.doesNotThrow(() =>
      assertTargetAgentEligibleForTrustJob({
        agent: baseAgent({ supportedOperations: [] }),
        operation: "distribute-trust",
      }),
    );
  });

  it("does NOT block on a stale/missing trust-anchor-deploy-v1 capability at creation time either, for the same staleness-ambiguity reason", () => {
    assert.doesNotThrow(() =>
      assertTargetAgentEligibleForTrustJob({
        agent: baseAgent({
          declaredCapabilities: [],
          capabilitiesUpdatedAt: null,
        }),
        operation: "distribute-trust",
      }),
    );
  });

  it("BLOCKING_TRUST_JOB_CREATION_REASONS contains exactly agent_retired and compatibility_blocked", () => {
    assert.deepEqual(
      Array.from(BLOCKING_TRUST_JOB_CREATION_REASONS).sort(),
      ["agent_retired", "compatibility_blocked"],
    );
  });
});

describe("pendingReasonForInstallation (advisory, never-blocking)", () => {
  it("returns null for a live (non-pending) installation regardless of agent state", () => {
    assert.equal(
      pendingReasonForInstallation(
        { transitionState: "installed", lastError: null },
        baseAgent({ status: "retired" }),
      ),
      null,
    );
  });

  it("returns null once a real lastError has already been recorded (that is already surfaced elsewhere; this field must not duplicate/contradict it)", () => {
    assert.equal(
      pendingReasonForInstallation(
        {
          transitionState: "pending_install",
          lastError: "some_real_dispatch_error",
        },
        baseAgent({ supportedOperations: [] }),
      ),
      null,
    );
  });

  it("returns null when the agent record is missing (row references an agent that could not be resolved)", () => {
    assert.equal(
      pendingReasonForInstallation(
        { transitionState: "pending_install", lastError: null },
        null,
      ),
      null,
    );
  });

  it("returns null for a healthy, fully-eligible agent (nothing to explain)", () => {
    assert.equal(
      pendingReasonForInstallation(
        { transitionState: "pending_install", lastError: null },
        baseAgent(),
      ),
      null,
    );
  });

  it("surfaces a reason for a pending_install row pinned to a retired agent", () => {
    const reason = pendingReasonForInstallation(
      { transitionState: "pending_install", lastError: null },
      baseAgent({ status: "retired" }),
    );
    assert.equal(reason.code, "agent_retired");
    assert.equal(
      reason.message,
      TRUST_JOB_INELIGIBLE_MESSAGE_BY_REASON.agent_retired,
    );
  });

  it("surfaces a reason for a pending_remove row whose agent never declared operation_unsupported (unlike the creation-time guard, this IS worth surfacing here - non-blocking, advisory only)", () => {
    const reason = pendingReasonForInstallation(
      { transitionState: "pending_remove", lastError: null },
      baseAgent({ supportedOperations: [] }),
    );
    assert.equal(reason.code, "operation_unsupported");
    assert.match(reason.message, /observe-only/);
  });

  it("evaluates revoke-trust (not distribute-trust) for a pending_remove row", () => {
    // An agent that supports distribute-trust but was never re-declared for
    // revoke-trust specifically (contrived, but exercises that the two
    // operations are not conflated).
    const reason = pendingReasonForInstallation(
      { transitionState: "pending_remove", lastError: null },
      baseAgent({ supportedOperations: ["distribute-trust"] }),
    );
    assert.equal(reason.code, "operation_unsupported");
  });
});
