"use strict";

const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert/strict");

const {
  agentLogRateKey,
  takeAgentLogPermit,
  logRateBuckets,
} = require("../../apps/api/routes/certops-agent")._test;

describe("agent log rate-limit key", () => {
  beforeEach(() => {
    logRateBuckets.clear();
  });

  it("scopes buckets by workspace and DB agent row id", () => {
    assert.equal(
      agentLogRateKey({ workspaceId: "ws-a", id: "row-1", agentId: "shared" }),
      "ws-a:row-1",
    );
    assert.notEqual(
      agentLogRateKey({ workspaceId: "ws-a", id: "row-1", agentId: "shared" }),
      agentLogRateKey({ workspaceId: "ws-b", id: "row-2", agentId: "shared" }),
    );
  });

  it("keeps rate limits independent for the same public agentId in two workspaces", () => {
    const a = agentLogRateKey({ workspaceId: "ws-a", id: "row-a", agentId: "edge-01" });
    const b = agentLogRateKey({ workspaceId: "ws-b", id: "row-b", agentId: "edge-01" });
    for (let i = 0; i < 40; i += 1) {
      assert.equal(takeAgentLogPermit(a, 1_000), true);
    }
    assert.equal(takeAgentLogPermit(a, 1_000), false);
    assert.equal(takeAgentLogPermit(b, 1_000), true);
  });
});
