/**
 * Supporting API/PostgreSQL qualification: active claim force retirement fences real agent HTTP.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * The registered fixture sends genuine machine-protocol requests; it does not run
 * an installed native agent. Named strict reports and owned cleanup are mandatory. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createRegisteredAgent } = require("./helpers/certops-registered-agent");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("active claim force retirement fences real agent HTTP", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - needs disposable real API and PostgreSQL signing configuration
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl);
  const gate = createHostGate({ suite: "agent-lease-api", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_AGENT_LEASE_API_REPORT, evidenceLevel: "integration", requiredCapabilities: ["api", "postgres"], probeCapabilities: async () => ({ api: { available: true }, postgres: { available: true } }) });
  gate.report.fixtureSource = { file: "tests/e2e/certops-agent-lease-api-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") };
  gate.report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  gate.report.fixtureTraffic = "Real noop claim through authenticated machine API; no certificate execution or fabricated running state";
  let ready = false; let primaryError;
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    const agent = await createRegisteredAgent(fixture, baseUrl, ["job-log-stream-v1"]);
    const { jobId, claimId } = await agent.claimNoop();
    const agentDbId = (await fixture.pool.query("SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [fixture.workspaceId, agent.agentId])).rows[0].id;
    const retireRoute = `/api/v1/workspaces/${fixture.workspaceId}/certops/agents/${agentDbId}/retire`;
    const status = async () => (await fixture.pool.query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, jobId])).rows[0].status;
    await gate.scenario("agent-lease-retire-blocked", async () => {
      assert.equal(await status(), "claimed");
      const result = await fixture.request(retireRoute, "POST", {}); assert.equal(result.status, 409); assert.equal(result.body.code, "CERTOPS_AGENT_RETIRE_BLOCKED");
      assert.equal(await status(), "claimed");
    });
    await gate.scenario("agent-lease-force-reason-required", async () => {
      assert.equal((await fixture.request(retireRoute, "POST", { force: true })).status, 400);
      assert.equal(await status(), "claimed");
    });
    await gate.scenario("agent-lease-force-cancellation", async () => {
      const result = await fixture.request(retireRoute, "POST", { force: true, reason: "Qualification deliberate claim fencing" }); assert.equal(result.status, 200);
      assert.equal(await status(), "cancelled");
      assert.equal((await fixture.pool.query("SELECT status FROM certops_agents WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, agentDbId])).rows[0].status, "retired");
      assert.equal((await fixture.request(retireRoute, "POST", { force: true, reason: "Repeated qualification fencing" })).status, 200);
    });
    await gate.scenario("agent-lease-stale-result-fence", async () => {
      assert.equal((await agent.machine("jobs/results", "result", { jobId, claimId, status: "succeeded", completedAt: new Date().toISOString() })).status, 410);
      assert.equal((await agent.machine("jobs/claim", "claim", { maxJobs: 1, supportedActions: ["noop"] })).status, 410);
      assert.equal(await status(), "cancelled");
    }, { oracle: "Retired credential cannot revive a force-cancelled genuine lease with a late success report" });
  } catch (error) { primaryError = error; throw error; }
  finally {
    try { if (ready) { await gate.scenario("agent-lease-cleanup", fixture.cleanup); await gate.finish({ requiredScenarios: require("../../scripts/certops-qualification-manifest").suites["agent-lease-api"] }); } else await fixture.cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Agent lease qualification and finalization failed"); throw error; }
  }
});
