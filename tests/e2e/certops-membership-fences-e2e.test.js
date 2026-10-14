"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const crypto = require("node:crypto");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("live workspace membership and machine workspace fences", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires isolated authenticated API and PostgreSQL
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl);
  let member; let ready = false; let primaryError;
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  const gate = createHostGate({ suite: "membership-api-fences", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_MEMBERSHIP_REPORT, requiredCapabilities: ["api", "postgres"], fixtureSource: { file: "tests/e2e/certops-membership-fences-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: async () => ({ api: { available: true }, postgres: { available: true } }) });
  try {
    assert.equal(await gate.preflight(), true); ready = true; member = await createApiFixture(baseUrl);
    // Initial role is fixture setup only. Subsequent transitions use the real
    // membership API while preserving the existing authenticated session.
    await fixture.pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'workspace_manager')", [fixture.workspaceId, member.userId]);
    await gate.scenario("membership-manager-write", async () => {
      assert.equal((await member.request(`${prefix}/jobs`, "POST", { operation: "noop" })).status, 201);
      assert.equal((await fixture.request(`${prefix}/settings`, "PUT", { certOpsPaused: false, reason: "Qualification resume" })).status, 200);
    });
    await gate.scenario("membership-live-downgrade", async () => {
      assert.equal((await fixture.request(`/api/v1/workspaces/${fixture.workspaceId}/members/${member.userId}`, "PATCH", { role: "viewer" })).status, 200);
      assert.equal((await member.request(`${prefix}/settings`)).status, 200);
      assert.equal((await member.request(`${prefix}/jobs`, "POST", { operation: "noop" })).status, 403);
      assert.equal((await member.request(`${prefix}/settings`, "PUT", { certOpsPaused: true, reason: "Downgraded session write" })).status, 403);
      assert.equal((await fixture.pool.query("SELECT certops_paused FROM workspaces WHERE id=$1", [fixture.workspaceId])).rows[0].certops_paused, false);
    });
    await gate.scenario("membership-live-removal", async () => {
      assert.equal((await fixture.request(`/api/v1/workspaces/${fixture.workspaceId}/members/${member.userId}`, "DELETE")).status, 204);
      assert.equal((await member.request(`${prefix}/settings`)).status, 404);
      assert.equal((await member.request(`${prefix}/jobs`, "POST", { operation: "noop" })).status, 403);
      assert.equal((await member.request(`/api/v1/workspaces/${member.workspaceId}/certops/settings`)).status, 200);
    }, { oracle: "Existing real session loses only the removed workspace's access; independently owned workspace remains accessible" });
    await gate.scenario("membership-machine-workspace-fence", async () => {
      const token = await fixture.request(`${prefix}/tokens`, "POST", { name: "Workspace scoped machine fixture", scopes: ["certops:events:write"] }); assert.equal(token.status, 201);
      const invoke = async (workspaceId) => {
        const response = await fetch(new URL("/api/v1/certops/executor/events", baseUrl), { method: "POST", signal: AbortSignal.timeout(15000), headers: { "content-type": "application/json", authorization: `Bearer ${token.body.plaintextToken}` }, body: JSON.stringify({ workspaceId }) });
        return response.status;
      };
      assert.equal(await invoke(fixture.workspaceId), 400);
      assert.equal(await invoke(member.workspaceId), 401);
      assert.equal((await fixture.request(`${prefix}/tokens/${token.body.token.id}/revoke`, "POST", {})).status, 200);
      assert.equal(await invoke(fixture.workspaceId), 401);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_jobs WHERE workspace_id=ANY($1::uuid[])", [[fixture.workspaceId, member.workspaceId]])).rows[0].count, 1);
    });
  } catch (error) { primaryError = error; throw error; }
  finally {
    const cleanup = async () => { try { await fixture.cleanup(); } finally { if (member) await member.cleanup(); } };
    try { if (ready) { await gate.scenario("membership-fences-cleanup", cleanup); await gate.finish({ requiredScenarios: require("../../docs/certops/qualification-suites.json").suites["membership-api-fences"] }); } else await cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Membership fence qualification and cleanup failed"); throw error; }
  }
});
