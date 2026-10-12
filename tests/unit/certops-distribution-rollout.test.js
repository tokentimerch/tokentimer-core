"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const material = require("../../apps/api/services/certops/materialDistribution");
const {
  advanceRollout,
} = require("../../apps/api/services/certops/distributionOperations");

test("rollout completion requires current authorization even for previously verified optional consumers", async (t) => {
  t.mock.method(material, "lockGroup", async () => ({
    state: "active",
    generation: 1,
  }));
  t.mock.method(material, "assertDeployableVersion", async () => ({}));
  for (const change of [
    { current_revision: 2 },
    { binding_state: "paused" },
    { job_status: "failed" },
    {},
  ]) {
    let state;
    const row = {
      stage: "served_verified",
      verification_policy: "served",
      required: false,
      binding_state: "active",
      current_revision: 1,
      authorization_revision: 1,
      job_status: "succeeded",
      ...change,
    };
    const client = {
      async query(sql, params) {
        if (sql.includes("FROM workspaces"))
          return { rows: [{ id: "workspace", certops_paused: false }] };
        if (sql.includes("FROM system_settings"))
          return { rows: [{ certops_settings: { enabled: true } }] };
        if (sql.includes("SELECT r.*"))
          return {
            rows: [
              {
                state: "deploying",
                generation: 1,
                material_version_id: "version",
              },
            ],
          };
        if (sql.includes("SELECT d.*")) return { rows: [row] };
        if (sql.includes("UPDATE certops_distribution_rollouts SET state=$3")) {
          state = params[2];
          return { rows: [] };
        }
        throw new Error(`Unexpected query: ${sql}`);
      },
    };
    await advanceRollout(client, "workspace", "group", "rollout");
    assert.equal(
      state,
      Object.keys(change).length ? "degraded" : "verified",
      JSON.stringify(change),
    );
    assert.equal(
      row.stage,
      "served_verified",
      "Historical verification remains available",
    );
  }
});
