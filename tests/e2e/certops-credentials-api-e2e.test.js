/**
 * Supporting API/PostgreSQL qualification: public machine credential and agent enrollment lifecycle.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * Public requests and persisted rows are the oracle; prerequisite state is isolated.
 * Native certificate deployment is qualified separately; strict reports and cleanup apply. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("public machine credential and agent enrollment lifecycle", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - needs disposable real authenticated API and PostgreSQL
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl);
  const gate = createHostGate({ suite: "credentials-api-lifecycle", strict: process.env.CERTOPS_E2E_REQUIRED === "1", evidenceLevel: "integration", reportPath: process.env.CERTOPS_CREDENTIALS_API_REPORT, requiredCapabilities: ["api", "postgres"], probeCapabilities: async () => ({ api: { available: true }, postgres: { available: true } }) });
  gate.report.fixtureSource = { file: "tests/e2e/certops-credentials-api-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") };
  gate.report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  let ready = false; let primaryError; let apiTokenId; let apiToken; let bootstrapId; let bootstrap; let registered;
  const agentId = crypto.randomUUID();
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  const envelope = (messageType, body) => ({ schemaVersion: 1, protocolVersion: "1.0.0", messageType, agentId, sentAt: new Date().toISOString(), body });
  async function agentRequest(route, credential, body) {
    const response = await fetch(new URL(`/api/v1/certops/agent/${route}`, baseUrl), { method: "POST", signal: AbortSignal.timeout(15000), headers: { "content-type": "application/json", authorization: `Bearer ${credential}` }, body: JSON.stringify(envelope(route === "jobs/claim" ? "claim" : route, body)) });
    return { status: response.status, body: await response.json() };
  }
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    await gate.scenario("credentials-api-show-once", async () => {
      const result = await fixture.request(`${prefix}/tokens`, "POST", { name: "Qualification API token", scopes: ["certops:read"] }); assert.equal(result.status, 201);
      apiTokenId = result.body.token.id; apiToken = result.body.plaintextToken; assert.ok(typeof apiToken === "string" && apiToken.startsWith("ttx_"), "Invalid show-once API token format");
      const list = await fixture.request(`${prefix}/tokens`); assert.equal(list.status, 200); assert.ok(!JSON.stringify(list.body).includes(apiToken)); assert.ok(!JSON.stringify(list.body).includes("token_hash"));
    });
    await gate.scenario("credentials-api-invalid-expiry-scope", async () => {
      assert.equal((await fixture.request(`${prefix}/tokens`, "POST", { name: "Expired fixture", scopes: ["certops:read"], expiresAt: "2000-01-01T00:00:00Z" })).status, 400);
      assert.equal((await fixture.request(`${prefix}/tokens`, "POST", { name: "Scope fixture", scopes: ["certops:unsupported"] })).status, 400);
    });
    await gate.scenario("credentials-api-revoke-repeat", async () => {
      assert.equal((await fixture.request(`${prefix}/tokens/${apiTokenId}/revoke`, "POST", {})).status, 200);
      assert.equal((await fixture.request(`${prefix}/tokens/${apiTokenId}/revoke`, "POST", {})).status, 200);
      const list = await fixture.request(`${prefix}/tokens?status=revoked`);
      assert.equal(list.status, 200);
      assert.ok(list.body.items.some((token) => token.id === apiTokenId && token.status === "revoked"));
    });
    await gate.scenario("credentials-bootstrap-show-once", async () => {
      const result = await fixture.request(`${prefix}/agent-bootstrap-tokens`, "POST", { name: "Qualification enrollment", expiresAt: new Date(Date.now() + 3600000).toISOString() }); assert.equal(result.status, 201, `Bootstrap create rejected: ${result.body.code || "unknown code"}`);
      bootstrapId = result.body.token.id; bootstrap = result.body.plaintextToken; assert.ok(typeof bootstrap === "string" && bootstrap.startsWith("ttboot_"), "Invalid show-once bootstrap format");
      const list = await fixture.request(`${prefix}/agent-bootstrap-tokens`); assert.equal(list.status, 200); assert.ok(!JSON.stringify(list.body).includes(bootstrap));
    });
    await gate.scenario("credentials-agent-register-replay", async () => {
      const body = { bootstrapTokenId: String(bootstrapId), agentVersion: "1.0.0", hostname: "credential-qualification", platform: "linux", registrationId: crypto.randomUUID() };
      const registration = await agentRequest("register", bootstrap, body); assert.equal(registration.status, 201); registered = registration.body;
      assert.equal((await agentRequest("register", bootstrap, { ...body, registrationId: crypto.randomUUID() })).status, 401);
      assert.equal((await agentRequest("heartbeat", registered.credential, { agentVersion: "1.0.0" })).status, 200);
    });
    await gate.scenario("credentials-agent-retire-fence", async () => {
      const row = (await fixture.pool.query("SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [fixture.workspaceId, agentId])).rows[0];
      assert.equal((await fixture.request(`${prefix}/agents/${row.id}/retire`, "POST", {})).status, 200);
      assert.equal((await agentRequest("heartbeat", registered.credential, { agentVersion: "1.0.0" })).status, 410);
      assert.equal((await agentRequest("jobs/claim", registered.credential, { maxJobs: 1, supportedActions: ["renew"] })).status, 410);
    });
  } catch (error) { primaryError = error; throw error; }
  finally {
    try { if (ready) { await gate.scenario("credentials-api-cleanup", fixture.cleanup); await gate.finish({ requiredScenarios: require("../../docs/certops/qualification-suites.json").suites["credentials-api-lifecycle"] }); } else await fixture.cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Credential lifecycle and finalization failed"); throw error; }
  }
});
