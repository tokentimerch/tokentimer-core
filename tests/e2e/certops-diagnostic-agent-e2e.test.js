/**
 * Supporting API/PostgreSQL qualification: diagnostic agent kind fences ordinary work and preserves bootstrap idempotency.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * The registered fixture sends genuine machine-protocol requests; it does not run
 * an installed native agent. Named strict reports and owned cleanup are mandatory. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict"), fs = require("node:fs"), crypto = require("node:crypto");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createRegisteredAgent } = require("./helpers/certops-registered-agent");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("diagnostic agent kind fences ordinary work and preserves bootstrap idempotency", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable API PostgreSQL and diagnostic signing
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl); let ready = false, primaryError;
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  const scenarios = ["diagnostic-api-bootstrap-replay", "diagnostic-api-normal-agent-fence", "diagnostic-api-ordinary-job-fence", "diagnostic-api-owned-smoke-claim", "diagnostic-api-cleanup"];
  const gate = createHostGate({ suite: "diagnostic-agent-api", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_DIAGNOSTIC_REPORT, requiredCapabilities: ["api", "postgres"], fixtureSource: { file: "tests/e2e/certops-diagnostic-agent-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true } }) });
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    const requestId = crypto.randomUUID(); let diagnostic; let sequence = 0;
    const machine = async (actions) => { const response = await fetch(new URL("/api/v1/certops/agent/jobs/claim", baseUrl), { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${diagnostic.credential}` }, body: JSON.stringify({ schemaVersion: 1, protocolVersion: "1.0.0", messageType: "claim", agentId: diagnostic.agentId, sequence: ++sequence, sentAt: new Date().toISOString(), body: { maxJobs: 5, supportedActions: actions } }), signal: AbortSignal.timeout(15000) }); return { status: response.status, body: await response.json() }; };
    await gate.scenario(scenarios[0], async () => {
      const first = await fixture.request(`${prefix}/agents/diagnostic-bootstrap`, "POST", { requestId }); assert.equal(first.status, 201); diagnostic = first.body;
      const repeated = await fixture.request(`${prefix}/agents/diagnostic-bootstrap`, "POST", { requestId }); assert.equal(repeated.status, 409); assert.equal(repeated.body.code, "diagnostic_bootstrap_already_consumed"); assert.ok(!JSON.stringify(repeated.body).includes(diagnostic.credential), "Consumed diagnostic bootstrap must never reveal the original credential");
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certops_agents WHERE workspace_id=$1 AND agent_kind='diagnostic'", [fixture.workspaceId])).rows[0].count, 1);
    });
    const heartbeat = await fetch(new URL("/api/v1/certops/agent/heartbeat", baseUrl), { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${diagnostic.credential}` }, body: JSON.stringify({ schemaVersion: 1, protocolVersion: "1.0.0", messageType: "heartbeat", agentId: diagnostic.agentId, sequence: ++sequence, sentAt: new Date().toISOString(), body: { agentVersion: "1.0.0" } }), signal: AbortSignal.timeout(15000) }); assert.equal(heartbeat.status, 200);
    await gate.scenario(scenarios[1], async () => { const normal = await createRegisteredAgent(fixture, baseUrl); const claim = await normal.machine("jobs/claim", "claim", { maxJobs: 5, supportedActions: ["protocol_smoke"] }); assert.equal(claim.status, 200); assert.deepEqual(claim.body.jobs, []); });
    const noop = await fixture.request(`${prefix}/jobs`, "POST", { operation: "noop" }); assert.equal(noop.status, 201);
    await gate.scenario(scenarios[2], async () => { const claim = await machine(["noop"]); assert.equal(claim.status, 200, String(claim.body.code || "claim rejected")); assert.deepEqual(claim.body.jobs, []); assert.equal((await fixture.pool.query("SELECT status FROM certificate_jobs WHERE id=$1", [noop.body.job.id])).rows[0].status, "pending"); });
    await gate.scenario(scenarios[3], async () => { const claim = await machine(["noop", "protocol_smoke"]); assert.equal(claim.status, 200); assert.equal(claim.body.jobs.length, 1); assert.equal(String(claim.body.jobs[0].jobId || claim.body.jobs[0].id), diagnostic.job.id); assert.equal((await fixture.pool.query("SELECT status FROM certificate_jobs WHERE id=$1", [noop.body.job.id])).rows[0].status, "pending"); }, { oracle: "Genuine machine claim SQL isolates immutable diagnostic kind from normal actions; no native protocol-smoke process execution is claimed" });
  } catch (error) { primaryError = error; throw error; }
  finally { try { if (ready) { await gate.scenario(scenarios.at(-1), fixture.cleanup); await gate.finish({ requiredScenarios: scenarios }); } else await fixture.cleanup(); } catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Diagnostic API qualification and cleanup failed"); throw error; } }
});
