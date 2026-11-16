"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { retireInstalledAgent } = require("../tests/e2e/linux-systemd-real-journey");

test("installed retirement resolves a public agent identity to its workspace row UUID", async () => {
  const workspaceId = "11111111-1111-4111-8111-111111111111";
  const id = "22222222-2222-4222-8222-222222222222";
  const agentId = "candidate-qualification-host-1234";
  const pool = { async query(sql, values) {
    assert.match(sql, /WHERE workspace_id=\$1 AND agent_id=\$2/);
    assert.deepEqual(values, [workspaceId, agentId]);
    return { rows: [{ id }] };
  } };
  let calls = 0;
  const retired = await retireInstalledAgent({ pool, workspaceId, agentId, userId: 17 }, async (options) => {
    calls++;
    assert.deepEqual(options, { client: pool, workspaceId, agentId: id,
      retiredBy: 17, reason: "disposable installer qualification" });
    return { retiredNow: true, agent: { id, agentId } };
  });
  assert.equal(calls, 1);
  assert.equal(retired.agent.id, id);
});

test("missing or ambiguous installed identities cannot retire an agent", async () => {
  for (const rows of [[], [{ id: "first" }, { id: "second" }]]) {
    let retired = false;
    await assert.rejects(retireInstalledAgent({
      pool: { query: async () => ({ rows }) }, workspaceId: "owned-workspace",
      agentId: "candidate-owned-host-1234", userId: 17,
    }, async () => { retired = true; }), /resolve uniquely in its owned workspace/);
    assert.equal(retired, false);
  }
});
