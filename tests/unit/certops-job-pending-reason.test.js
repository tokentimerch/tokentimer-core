"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  attachJobPendingReasons,
  markAdcsJob,
  pendingReasonForJob,
} = require(
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

  describe("AD CS jobs", () => {
    const adcsJob = () =>
      job({ operation: "renew", issuerKind: "adcs" });
    const adcsAgent = (overrides = {}) =>
      agent({
        supportedOperations: ["renew"],
        declaredCapabilities: [],
        ...overrides,
      });

    it("names the missing adcs-enroll-v1 declaration instead of reporting awaiting_claim", () => {
      const reason = pendingReasonForJob(adcsJob(), adcsAgent());
      assert.equal(reason.code, "adcs_enroll_capability_unavailable");
      assert.match(reason.message, /adcs-enroll-v1/);
    });

    it("names a stale declaration the same way", () => {
      const reason = pendingReasonForJob(
        adcsJob(),
        adcsAgent({
          declaredCapabilities: ["adcs-enroll-v1"],
          capabilitiesUpdatedAt: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
        }),
      );
      assert.equal(reason.code, "adcs_enroll_capability_unavailable");
    });

    it("waits for claim once the agent declares a fresh adcs-enroll-v1", () => {
      const reason = pendingReasonForJob(
        adcsJob(),
        adcsAgent({
          declaredCapabilities: ["adcs-enroll-v1"],
          capabilitiesUpdatedAt: new Date().toISOString(),
        }),
      );
      assert.equal(reason.code, "awaiting_claim");
    });

    it("leaves a non-AD CS job unaffected by the missing declaration", () => {
      const reason = pendingReasonForJob(
        job({ operation: "renew" }),
        adcsAgent(),
      );
      assert.equal(reason.code, "awaiting_claim");
    });

    it("reads the AD CS marker from the job list path, not from the job payload", async () => {
      const liveAgentRow = (declaredCapabilities) => ({
        id: "11111111-1111-4111-8111-111111111111",
        agent_id: "agent-one",
        status: "active",
        agent_kind: "normal",
        agent_version: "0.1.0",
        protocol_version: "1.0.0",
        last_seen_at: new Date().toISOString(),
        created_at: new Date(Date.now() - 86_400_000).toISOString(),
        clock_offset_ms: 0,
        supported_operations: ["renew"],
        declared_capabilities: declaredCapabilities,
        capabilities_updated_at: new Date().toISOString(),
        declared_target_selectors: [],
        declared_command_profile_names: [],
        supported_dns_providers: [],
      });
      const db = (rows) => ({ query: async () => ({ rows }) });
      const jobRow = () => ({
        id: "job-1",
        workspaceId: "ws-1",
        status: "pending",
        operation: "renew",
        executorKind: "agent",
        assignedAgentId: "11111111-1111-4111-8111-111111111111",
        payload: {},
      });

      const marked = jobRow();
      markAdcsJob(marked);
      const [blocked] = await attachJobPendingReasons({
        db: db([liveAgentRow([])]),
        workspaceId: "ws-1",
        jobs: [marked],
        env: {},
      });
      assert.equal(blocked.pendingReason.code, "adcs_enroll_capability_unavailable");

      const unmarked = jobRow();
      const [plain] = await attachJobPendingReasons({
        db: db([liveAgentRow([])]),
        workspaceId: "ws-1",
        jobs: [unmarked],
        env: {},
      });
      assert.equal(plain.pendingReason.code, "awaiting_claim");
      assert.equal("issuerKind" in plain, false);
    });
  });
});
