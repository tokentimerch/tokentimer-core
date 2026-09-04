"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { pendingReasonForJob } = require(
  path.resolve(__dirname, "../../apps/api/services/certops/jobPendingReason.js"),
);

function agent(overrides = {}) {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    status: "active",
    compatibilityState: "compatible",
    livenessState: "live",
    supportedOperations: ["distribute-trust", "revoke-trust"],
    declaredCapabilities: ["trust-anchor-deploy-v1"],
    capabilitiesUpdatedAt: new Date().toISOString(),
    targetSelectors: [],
    dnsProviders: [],
    commandProfiles: [],
    ...overrides,
  };
}

function job(overrides = {}) {
  return {
    operation: "distribute-trust",
    status: "pending",
    executorKind: "agent",
    assignedAgentId: "11111111-1111-4111-8111-111111111111",
    payload: {},
    ...overrides,
  };
}

describe("pendingReasonForJob", () => {
  it("returns null for a terminal job", () => {
    assert.equal(
      pendingReasonForJob(job({ status: "succeeded" }), agent()),
      null,
    );
  });

  it("explains a claimed job without re-evaluating eligibility", () => {
    const reason = pendingReasonForJob(job({ status: "claimed" }), agent());
    assert.equal(reason.code, "awaiting_progress");
  });

  it("names declared operations when the pin cannot run this job", () => {
    const reason = pendingReasonForJob(
      job(),
      agent({ supportedOperations: ["issue", "deploy"] }),
    );
    assert.equal(reason.code, "operation_unsupported");
    assert.match(reason.message, /issue, deploy/);
    assert.match(reason.message, /not for distribute-trust/);
    assert.doesNotMatch(reason.message, /has not declared any/);
  });

  it("explains an offline assigned agent that is otherwise eligible", () => {
    const reason = pendingReasonForJob(
      job(),
      agent({ livenessState: "stale", status: "offline" }),
    );
    assert.equal(reason.code, "agent_offline");
  });

  it("says the job is waiting to be claimed when the assigned agent is live and eligible", () => {
    const reason = pendingReasonForJob(job(), agent());
    assert.equal(reason.code, "awaiting_claim");
    assert.match(reason.message, /assigned agent to poll/);
  });

  it("says an unpinned pending job is waiting for any eligible agent", () => {
    const reason = pendingReasonForJob(
      job({ assignedAgentId: null }),
      null,
    );
    assert.equal(reason.code, "awaiting_claim");
    assert.match(reason.message, /eligible agent/);
  });

  it("says a missing assigned agent cannot claim the job", () => {
    const reason = pendingReasonForJob(job(), null);
    assert.equal(reason.code, "assigned_agent_missing");
  });
});
