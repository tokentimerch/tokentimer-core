"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("scoped machine token expiry and revocation through executor HTTP", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - needs disposable real API and PostgreSQL
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl);
  const gate = createHostGate({ suite: "token-api-boundaries", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_TOKEN_BOUNDARIES_REPORT, evidenceLevel: "integration", requiredCapabilities: ["api", "postgres"], probeCapabilities: async () => ({ api: { available: true }, postgres: { available: true } }) });
  gate.report.fixtureSource = { file: "tests/e2e/certops-token-boundaries-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") };
  gate.report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  let ready = false; let primaryError;
  async function events(token) {
    const response = await fetch(new URL("/api/v1/certops/executor/events", baseUrl), { method: "POST", signal: AbortSignal.timeout(15000), headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify({ workspaceId: fixture.workspaceId }) });
    return { status: response.status, body: await response.json() };
  }
  async function createToken(scopes, extra = {}) {
    const result = await fixture.request(`/api/v1/workspaces/${fixture.workspaceId}/certops/tokens`, "POST", { name: `Boundary ${crypto.randomUUID()}`, scopes, ...extra });
    assert.equal(result.status, 201); return result.body;
  }
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    await gate.scenario("token-api-scope-denial", async () => {
      const token = await createToken(["certops:read"]);
      const denied = await events(token.plaintextToken); assert.equal(denied.status, 403);
      assert.ok(!JSON.stringify(denied.body).includes(token.plaintextToken));
    });
    await gate.scenario("token-api-expiry-clock", async () => {
      const expiresAt = new Date(Date.now() + 3000).toISOString();
      const token = await createToken(["certops:events:write"], { expiresAt });
      const before = await events(token.plaintextToken); assert.equal(before.status, 400, "Authenticated malformed event reaches public body validation before expiry");
      const remaining = Date.parse(expiresAt) - Date.now();
      if (remaining > 0) await new Promise((resolve) => setTimeout(resolve, remaining + 100));
      const after = await events(token.plaintextToken); assert.equal(after.status, 401);
      assert.ok(!JSON.stringify(after.body).includes(token.plaintextToken));
    }, { oracle: "Real server clock crosses explicitly bounded expiry; no database clock/status injection" });
    await gate.scenario("token-api-revocation-fence", async () => {
      const token = await createToken(["certops:events:write"]);
      assert.equal((await events(token.plaintextToken)).status, 400);
      assert.equal((await fixture.request(`/api/v1/workspaces/${fixture.workspaceId}/certops/tokens/${token.token.id}/revoke`, "POST", {})).status, 200);
      assert.equal((await events(token.plaintextToken)).status, 401);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_jobs WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count, 0);
    });
  } catch (error) { primaryError = error; throw error; }
  finally {
    try { if (ready) { await gate.scenario("token-api-cleanup", fixture.cleanup); await gate.finish({ requiredScenarios: require("../../docs/certops/qualification-suites.json").suites["token-api-boundaries"] }); } else await fixture.cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Token boundaries and finalization failed"); throw error; }
  }
});
