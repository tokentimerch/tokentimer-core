"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { pool } = require(
  path.resolve(__dirname, "../../apps/api/db/database.js"),
);
const certOpsRouter = require(
  path.resolve(__dirname, "../../apps/api/routes/certops.js"),
);

const { withInstanceAgentConnectivity } = certOpsRouter._test;

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";

function agentRow(overrides = {}) {
  return {
    id: "agent-row-1",
    workspace_id: WORKSPACE_A,
    agent_id: "edge-agent-01",
    name: "edge agent",
    hostname: "edge01.internal",
    platform: "linux",
    agent_version: "1.2.3",
    protocol_version: 2,
    credential_prefix: "ttagent_0123456789abcdef",
    credential_hash: "a".repeat(64),
    status: "active",
    last_seen_at: new Date(Date.now() - 60 * 1000),
    clock_offset_ms: 0,
    created_at: new Date("2026-06-01T00:00:00.000Z"),
    retired_at: null,
    retired_by_user_id: null,
    retire_reason: null,
    updated_at: new Date("2026-06-01T00:00:00.000Z"),
    downtime_alerts_enabled: true,
    contact_group_id: null,
    ...overrides,
  };
}

let originalQuery;
let originalConnect;

beforeEach(() => {
  originalQuery = pool.query;
  originalConnect = pool.connect;
});

afterEach(() => {
  pool.query = originalQuery;
  pool.connect = originalConnect;
});

describe("withInstanceAgentConnectivity", () => {
  it("attaches liveness for the responsible agent of each location", async () => {
    pool.query = async (sql, params) => {
      const normalized = String(sql).replace(/\s+/g, " ").trim();
      if (normalized.includes("FROM certops_agents")) {
        assert.deepEqual(params[1], ["edge-agent-01"]);
        return { rows: [agentRow()] };
      }
      throw new Error(`Unexpected query: ${normalized}`);
    };

    const items = await withInstanceAgentConnectivity({
      workspaceId: WORKSPACE_A,
      items: [
        {
          id: "instance-1",
          responsibleAgentId: "edge-agent-01",
          status: "active",
        },
      ],
    });

    assert.equal(items.length, 1);
    assert.equal(items[0].agent.agentId, "edge-agent-01");
    assert.equal(items[0].agent.name, "edge agent");
    assert.equal(items[0].agent.hostname, "edge01.internal");
    // Reference last_seen_at is well within the 10-minute default threshold.
    assert.equal(items[0].agent.livenessState, "live");
    // The original instance fields must survive untouched.
    assert.equal(items[0].id, "instance-1");
    assert.equal(items[0].status, "active");
  });

  it("reports stale liveness for an agent quiet past the offline threshold", async () => {
    pool.query = async () => ({
      rows: [
        agentRow({
          last_seen_at: new Date(Date.now() - 20 * 60 * 1000),
        }),
      ],
    });

    const [item] = await withInstanceAgentConnectivity({
      workspaceId: WORKSPACE_A,
      items: [{ id: "instance-1", responsibleAgentId: "edge-agent-01" }],
    });

    assert.equal(item.agent.livenessState, "stale");
  });

  it("sets agent to null for a location with no responsible agent (e.g. cert-manager)", async () => {
    let queried = false;
    pool.query = async () => {
      queried = true;
      return { rows: [] };
    };

    const items = await withInstanceAgentConnectivity({
      workspaceId: WORKSPACE_A,
      items: [
        { id: "instance-1", responsibleAgentId: null, status: "active" },
      ],
    });

    assert.equal(items[0].agent, null);
    // No agent ids to resolve means no query at all, not a wasted round trip.
    assert.equal(queried, false);
  });

  it("does not fail the request when the agent lookup errors; locations still render", async () => {
    pool.query = async () => {
      throw new Error("connection reset");
    };

    const items = await withInstanceAgentConnectivity({
      workspaceId: WORKSPACE_A,
      items: [
        { id: "instance-1", responsibleAgentId: "edge-agent-01", status: "active" },
      ],
    });

    assert.equal(items.length, 1);
    assert.equal(items[0].id, "instance-1");
    assert.equal(items[0].agent, null);
  });

  it("returns an empty list unchanged without querying", async () => {
    let queried = false;
    pool.query = async () => {
      queried = true;
      return { rows: [] };
    };

    const items = await withInstanceAgentConnectivity({
      workspaceId: WORKSPACE_A,
      items: [],
    });

    assert.deepEqual(items, []);
    assert.equal(queried, false);
  });

  it("resolves one agent for several locations sharing the same responsible agent with a single lookup", async () => {
    let queryCount = 0;
    pool.query = async () => {
      queryCount += 1;
      return { rows: [agentRow()] };
    };

    const items = await withInstanceAgentConnectivity({
      workspaceId: WORKSPACE_A,
      items: [
        { id: "instance-1", responsibleAgentId: "edge-agent-01" },
        { id: "instance-2", responsibleAgentId: "edge-agent-01" },
      ],
    });

    assert.equal(queryCount, 1);
    assert.equal(items[0].agent.agentId, "edge-agent-01");
    assert.equal(items[1].agent.agentId, "edge-agent-01");
  });
});
