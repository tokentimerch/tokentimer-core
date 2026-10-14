"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict"), fs = require("node:fs"), crypto = require("node:crypto");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createRegisteredAgent } = require("./helpers/certops-registered-agent");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("agent alert governance persists policy and rejects foreign groups and unauthorized roles", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable API PostgreSQL and registration signing
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl); let viewer, ready = false, primaryError;
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  const scenarios = ["agent-alert-default-enabled", "agent-alert-toggle-persisted", "agent-alert-invalid-atomic", "agent-alert-viewer-denial", "agent-alert-foreign-concealment", "agent-alert-cleanup"];
  const gate = createHostGate({ suite: "agent-alert-api", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_AGENT_ALERT_REPORT, requiredCapabilities: ["api", "postgres"], fixtureSource: { file: "tests/e2e/certops-agent-alert-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true } }) });
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    const agent = await createRegisteredAgent(fixture, baseUrl);
    const id = (await fixture.pool.query("SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [fixture.workspaceId, agent.agentId])).rows[0].id;
    const route = `${prefix}/agents/${id}/alert-settings`;
    const current = async () => (await fixture.request(`${prefix}/agents`)).body.items.find((item) => item.agentId === agent.agentId);
    viewer = await createApiFixture(baseUrl); await fixture.pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'viewer')", [fixture.workspaceId, viewer.userId]);
    await gate.scenario(scenarios[0], async () => { const row = await current(); assert.equal(row.downtimeAlertsEnabled, true); assert.deepEqual(row.contactGroupIds, []); });
    await gate.scenario(scenarios[1], async () => {
      for (const enabled of [false, true, false]) { const response = await fixture.request(route, "PATCH", { downtimeAlertsEnabled: enabled }); assert.equal(response.status, 200); assert.equal(response.body.agent.downtimeAlertsEnabled, enabled); assert.equal((await current()).downtimeAlertsEnabled, enabled); }
      assert.equal((await fixture.pool.query("SELECT downtime_alerts_enabled FROM certops_agents WHERE id=$1", [id])).rows[0].downtime_alerts_enabled, false);
    }, { oracle: "Actual public alert preferences survive independent reads; notification delivery is not claimed" });
    await gate.scenario(scenarios[2], async () => {
      for (const body of [{}, { downtimeAlertsEnabled: "true" }, { downtimeAlertsEnabled: true, contactGroupIds: [999999999] }, { contactGroupIds: ["invalid"] }]) { assert.equal((await fixture.request(route, "PATCH", body)).status, 400); assert.equal((await current()).downtimeAlertsEnabled, false); assert.deepEqual((await current()).contactGroupIds, []); }
    });
    await gate.scenario(scenarios[3], async () => { assert.equal((await viewer.request(route, "PATCH", { downtimeAlertsEnabled: true })).status, 403); assert.equal((await current()).downtimeAlertsEnabled, false); });
    await gate.scenario(scenarios[4], async () => { const foreign = `/api/v1/workspaces/${viewer.workspaceId}/certops/agents/${id}/alert-settings`; assert.equal((await viewer.request(foreign, "PATCH", { downtimeAlertsEnabled: true })).status, 404); assert.equal((await current()).downtimeAlertsEnabled, false); });
  } catch (error) { primaryError = error; throw error; }
  finally { const cleanup = async () => { try { await fixture.cleanup(); } finally { if (viewer) await viewer.cleanup(); } }; try { if (ready) { await gate.scenario(scenarios.at(-1), cleanup); await gate.finish({ requiredScenarios: scenarios }); } else await cleanup(); } catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Agent alert qualification and cleanup failed"); throw error; } }
});
