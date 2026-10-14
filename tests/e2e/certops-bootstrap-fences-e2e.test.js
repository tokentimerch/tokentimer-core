/**
 * Supporting API/PostgreSQL qualification: unused bootstrap revocation, expiry and workspace ownership through real API.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * Public requests and persisted rows are the oracle; prerequisite state is isolated.
 * Native certificate deployment is qualified separately; strict reports and cleanup apply. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const crypto = require("node:crypto");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("unused bootstrap revocation, expiry and workspace ownership through real API", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires isolated authenticated API and PostgreSQL
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl);
  let other; let ready = false; let primaryError;
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops/agent-bootstrap-tokens`;
  const gate = createHostGate({ suite: "bootstrap-api-fences", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_BOOTSTRAP_FENCES_REPORT, requiredCapabilities: ["api", "postgres"], fixtureSource: { file: "tests/e2e/certops-bootstrap-fences-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true } }) });
  const create = async (expiresAt = new Date(Date.now() + 60000).toISOString()) => {
    const result = await fixture.request(prefix, "POST", { name: "Unused bootstrap qualification", expiresAt }); assert.equal(result.status, 201); return result.body;
  };
  const registerResponse = async (token, registrationId = crypto.randomUUID(), agentId = crypto.randomUUID()) => {
    const response = await fetch(new URL("/api/v1/certops/agent/register", baseUrl), { method: "POST", signal: AbortSignal.timeout(15000), headers: { "content-type": "application/json", authorization: `Bearer ${token.plaintextToken}` }, body: JSON.stringify({ schemaVersion: 1, protocolVersion: "1.0.0", messageType: "register", agentId, sentAt: new Date().toISOString(), body: { bootstrapTokenId: token.token.id, registrationId, hostname: "bootstrap-fence-fixture", platform: "linux", agentVersion: "1.0.0" } }) });
    return { status: response.status, body: await response.json() };
  };
  const register = async (token) => (await registerResponse(token)).status;
  const noAgents = async () => assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certops_agents WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count, 0);
  try {
    assert.equal(await gate.preflight(), true); ready = true; other = await createApiFixture(baseUrl);
    await gate.scenario("bootstrap-cross-workspace-revoke-refusal", async () => {
      const token = await create();
      assert.equal((await other.request(`/api/v1/workspaces/${other.workspaceId}/certops/agent-bootstrap-tokens/${token.token.id}/revoke`, "POST", {})).status, 404);
      const list = await fixture.request(prefix); assert.equal(list.status, 200); assert.ok(list.body.items.some((item) => item.id === token.token.id && item.status === "active"));
      assert.equal((await fixture.request(`${prefix}/${token.token.id}/revoke`, "POST", {})).status, 200);
    });
    await gate.scenario("bootstrap-revoked-unused-refusal", async () => {
      const token = await create();
      for (let i = 0; i < 2; i++) assert.equal((await fixture.request(`${prefix}/${token.token.id}/revoke`, "POST", {})).status, 200);
      assert.equal(await register(token), 401); await noAgents();
    });
    await gate.scenario("bootstrap-expired-unused-refusal", async () => {
      const expiresAt = new Date(Date.now() + 2500).toISOString(); const token = await create(expiresAt);
      const remaining = Date.parse(expiresAt) - Date.now(); if (remaining > 0) await new Promise((resolve) => setTimeout(resolve, remaining + 100));
      assert.equal(await register(token), 401); await noAgents();
    }, { oracle: "Real server clock crosses requested expiry; unused token cannot register, with no database status or clock rewrites" });
    await gate.scenario("bootstrap-concurrent-single-use", async () => {
      const token = await create();
      const results = await Promise.all([registerResponse(token), registerResponse(token)]);
      assert.deepEqual(results.map((result) => result.status).sort(), [201, 401]);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certops_agents WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count, 1);
      const list = await fixture.request(prefix); assert.ok(list.body.items.some((item) => item.id === token.token.id && item.status === "used"));
    }, { oracle: "Concurrent real registrations with distinct registration IDs consume one bootstrap token once and mint one agent" });
    await gate.scenario("bootstrap-concurrent-registration-recovery", async () => {
      const token = await create(); const registrationId = crypto.randomUUID(); const agentId = crypto.randomUUID();
      const results = await Promise.all([registerResponse(token, registrationId, agentId), registerResponse(token, registrationId, agentId)]);
      for (const result of results) assert.equal(result.status, 201);
      assert.ok(results[0].body.credential === results[1].body.credential, "Same-registration recovery must return identical credential without logging it");
      assert.equal(results[0].body.agentId, results[1].body.agentId);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certops_agents WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count, 2);
      assert.equal((await registerResponse(token)).status, 401);
    }, { oracle: "Same-registration lost-response retries recover one encrypted credential envelope; spent token cannot create a different registration" });
  } catch (error) { primaryError = error; throw error; }
  finally {
    const cleanup = async () => { try { await fixture.cleanup(); } finally { if (other) await other.cleanup(); } };
    try { if (ready) { await gate.scenario("bootstrap-fences-cleanup", cleanup); await gate.finish({ requiredScenarios: require("../../docs/certops/qualification-suites.json").suites["bootstrap-api-fences"] }); } else await cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Bootstrap fence qualification and cleanup failed"); throw error; }
  }
});
