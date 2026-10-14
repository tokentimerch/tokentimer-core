"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createRegisteredAgent } = require("./helpers/certops-registered-agent");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("agent log size and ownership boundaries through real API", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable API, PostgreSQL and signing configuration
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl);
  const gate = createHostGate({ suite: "agent-log-boundaries", strict: process.env.CERTOPS_E2E_REQUIRED === "1", evidenceLevel: "integration", reportPath: process.env.CERTOPS_AGENT_LOG_BOUNDARIES_REPORT, requiredCapabilities: ["api", "postgres"], probeCapabilities: async () => ({ api: { available: true }, postgres: { available: true } }) });
  gate.report.fixtureSource = { file: "tests/e2e/certops-agent-log-boundaries-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") };
  gate.report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  let ready = false; let primaryError;
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    const agent = await createRegisteredAgent(fixture, baseUrl, ["job-log-stream-v1"]);
    const { jobId, claimId } = await agent.claimNoop();
    const line = { seq: 1, ts: new Date().toISOString(), level: "info", step: "verify", message: "Bounded public diagnostic" };
    const read = () => fixture.request(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs/${jobId}/agent-log`);
    const log = (body, routeJob = jobId) => agent.machine(`jobs/${routeJob}/logs`, "log", { jobId: routeJob, claimId, final: false, firstSeq: 1, lines: [line], ...body });
    await gate.scenario("agent-log-overlong-line-refusal", async () => {
      assert.equal((await log({ lines: [{ ...line, message: "x".repeat(1025) }] })).status, 400);
      assert.equal((await read()).body.items.length, 0);
    });
    await gate.scenario("agent-log-oversized-batch-refusal", async () => {
      assert.equal((await log({ lines: Array.from({ length: 201 }, (_, index) => ({ ...line, seq: index + 1 })) })).status, 400);
      assert.equal((await read()).body.items.length, 0);
    });
    await gate.scenario("agent-log-wrong-claim-refusal", async () => {
      const result = await log({ claimId: crypto.randomUUID() }); assert.equal(result.status, 409);
      assert.equal((await read()).body.items.length, 0);
    });
    await gate.scenario("agent-log-route-authority", async () => {
      const foreignJobId = crypto.randomUUID();
      const result = await log({ jobId: foreignJobId }); assert.equal(result.status, 200);
      assert.equal((await read()).body.items.length, 1);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certops_agent_log_stream WHERE workspace_id=$1 AND job_id=$2", [fixture.workspaceId, foreignJobId])).rows[0].count, 0);
    }, { oracle: "Authenticated route job and claim govern persistence; caller body jobId cannot redirect writes" });
    await gate.scenario("agent-log-valid-after-refusals", async () => {
      assert.equal((await log({ final: true, firstSeq: 2, lines: [{ ...line, seq: 2 }] })).status, 200);
      const result = await read(); assert.equal(result.body.items.length, 2); assert.equal(result.body.items[1].message, line.message);
    });
  } catch (error) { primaryError = error; throw error; }
  finally {
    try { if (ready) { await gate.scenario("agent-log-boundaries-cleanup", fixture.cleanup); await gate.finish({ requiredScenarios: require("../../docs/certops/qualification-suites.json").suites["agent-log-boundaries"] }); } else await fixture.cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Agent log boundaries and finalization failed"); throw error; }
  }
});
