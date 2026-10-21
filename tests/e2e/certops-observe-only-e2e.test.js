/**
 * Supporting API/PostgreSQL qualification: observe-only polling preserves queued work until explicit execution advertisement.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * The registered fixture sends genuine machine-protocol requests; it does not run
 * an installed native agent. Named strict reports and owned cleanup are mandatory. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict"), fs = require("node:fs"), crypto = require("node:crypto");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createRegisteredAgent } = require("./helpers/certops-registered-agent");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("observe-only polling preserves queued work until explicit execution advertisement", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable API and PostgreSQL signing configuration
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl); let ready = false, primaryError;
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  const scenarios = ["observe-only-empty-actions", "observe-only-public-projection", "observe-only-explicit-enable", "observe-only-disable-again", "observe-only-heartbeat-preserve", "observe-only-heartbeat-disable", "observe-only-cleanup"];
  const gate = createHostGate({ suite: "observe-only-api", strict: process.env.CERTOPS_E2E_REQUIRED === "1", evidenceLevel: "integration", reportPath: process.env.CERTOPS_OBSERVE_ONLY_REPORT, requiredCapabilities: ["api", "postgres"], fixtureSource: { file: "tests/e2e/certops-observe-only-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true } }) });
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    const agent = await createRegisteredAgent(fixture, baseUrl);
    const created = await fixture.request(`${prefix}/jobs`, "POST", { operation: "noop" }); assert.equal(created.status, 201); const jobId = created.body.job.id;
    const state = async () => (await fixture.pool.query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, jobId])).rows[0].status;
    const attempts = async () => (await fixture.pool.query("SELECT attempt_count AS count FROM certificate_jobs WHERE id=$1", [jobId])).rows[0].count;
    await gate.scenario(scenarios[0], async () => {
      for (let i = 0; i < 2; i++) { const claimed = await agent.machine("jobs/claim", "claim", { maxJobs: 1, supportedActions: [] }); assert.equal(claimed.status, 200); assert.deepEqual(claimed.body.jobs, []); }
      assert.equal(await state(), "pending"); assert.equal(await attempts(), 0);
    }, { oracle: "Actual authenticated machine polls advertise zero actions; queued noop remains unclaimed without manufacturing certificate execution" });
    await gate.scenario(scenarios[1], async () => {
      const row = (await fixture.pool.query("SELECT supported_operations FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [fixture.workspaceId, agent.agentId])).rows[0]; assert.deepEqual(row.supported_operations, []);
      const list = await fixture.request(`${prefix}/agents`); assert.equal(list.status, 200); const current = list.body.items.find((item) => item.agentId === agent.agentId); assert.ok(current); assert.deepEqual(current.supportedOperations, []);
    });
    await gate.scenario(scenarios[2], async () => {
      const claimed = await agent.machine("jobs/claim", "claim", { maxJobs: 1, supportedActions: ["noop"] }); assert.equal(claimed.status, 200); const job = claimed.body.jobs.find((item) => (item.jobId || item.id) === jobId); assert.ok(job); assert.ok(job.claimId); assert.equal(await state(), "claimed"); assert.equal(await attempts(), 1);
      assert.equal((await agent.machine("jobs/results", "result", { jobId, attemptId: job.attemptId, nonce: job.nonce, status: "succeeded", keyRotated: false })).status, 200); assert.equal(await state(), "succeeded");
    });
    await gate.scenario(scenarios[4], async () => {
      assert.equal((await agent.machine("heartbeat", "heartbeat", { agentVersion: "1.0.0" })).status, 200);
      assert.deepEqual((await fixture.pool.query("SELECT supported_operations FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [fixture.workspaceId, agent.agentId])).rows[0].supported_operations, ["noop"]);
    });
    await gate.scenario(scenarios[5], async () => {
      assert.equal((await agent.machine("heartbeat", "heartbeat", { agentVersion: "1.0.0", supportedOperations: [] })).status, 200);
      assert.deepEqual((await fixture.pool.query("SELECT supported_operations FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [fixture.workspaceId, agent.agentId])).rows[0].supported_operations, []);
      const list = await fixture.request(`${prefix}/agents`); assert.equal(list.status, 200);
      assert.deepEqual(list.body.items.find((item) => item.agentId === agent.agentId).supportedOperations, []);
    });
    await gate.scenario(scenarios[3], async () => {
      const next = await fixture.request(`${prefix}/jobs`, "POST", { operation: "noop" }); assert.equal(next.status, 201);
      const result = await agent.machine("jobs/claim", "claim", { maxJobs: 1, supportedActions: [] }); assert.equal(result.status, 200); assert.deepEqual(result.body.jobs, []);
      assert.equal((await fixture.pool.query("SELECT status FROM certificate_jobs WHERE id=$1", [next.body.job.id])).rows[0].status, "pending");
      assert.deepEqual((await fixture.pool.query("SELECT supported_operations FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [fixture.workspaceId, agent.agentId])).rows[0].supported_operations, []);
    });
  } catch (error) { primaryError = error; throw error; }
  finally { try { if (ready) { await gate.scenario(scenarios.at(-1), fixture.cleanup); await gate.finish({ requiredScenarios: scenarios }); } else await fixture.cleanup(); } catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Observe-only qualification and cleanup failed"); throw error; } }
});
