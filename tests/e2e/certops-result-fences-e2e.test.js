/**
 * Supporting API/PostgreSQL qualification: real result API rejects forged nonce and attempt before consuming an owned lease.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * The registered fixture sends genuine machine-protocol requests; it does not run
 * an installed native agent. Named strict reports and owned cleanup are mandatory. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict"), fs = require("node:fs"), crypto = require("node:crypto");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createRegisteredAgent } = require("./helpers/certops-registered-agent");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("real result API rejects forged nonce and attempt before consuming an owned lease", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable API PostgreSQL and dispatch signing
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl); let ready = false, primaryError;
  const scenarios = ["result-fence-invalid-shape", "result-fence-forged-nonce", "result-fence-forged-attempt", "result-fence-valid-owner", "result-fence-conflicting-terminal-replay", "result-fence-cleanup"];
  const gate = createHostGate({ suite: "result-fences-api", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_RESULT_FENCES_REPORT, requiredCapabilities: ["api", "postgres"], fixtureSource: { file: "tests/e2e/certops-result-fences-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true } }) });
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    const agent = await createRegisteredAgent(fixture, baseUrl); const claimed = await agent.claimNoop();
    const result = { jobId: claimed.jobId, attemptId: claimed.job.attemptId, nonce: claimed.job.nonce, status: "succeeded", keyRotated: false };
    const state = async () => (await fixture.pool.query("SELECT status,claim_id,attempt_count FROM certificate_jobs WHERE id=$1", [claimed.jobId])).rows[0];
    const before = await state();
    await gate.scenario(scenarios[0], async () => { const response = await agent.machine("jobs/results", "result", { ...result, status: "invented-success" }); assert.equal(response.status, 400); assert.deepEqual(await state(), before); });
    await gate.scenario(scenarios[1], async () => { const response = await agent.machine("jobs/results", "result", { ...result, nonce: crypto.randomUUID() }); assert.equal(response.status, 409); assert.equal(response.body.code, "CERTOPS_AGENT_RESULT_NONCE_REJECTED"); assert.deepEqual(await state(), before); });
    await gate.scenario(scenarios[2], async () => { const response = await agent.machine("jobs/results", "result", { ...result, attemptId: crypto.randomUUID() }); assert.equal(response.status, 409); assert.deepEqual(await state(), before); });
    await gate.scenario(scenarios[3], async () => { assert.equal((await agent.machine("jobs/results", "result", result)).status, 200); assert.equal((await state()).status, "succeeded"); const replay = await agent.machine("jobs/results", "result", result); assert.equal(replay.status, 200); assert.equal(replay.body.duplicate, true); });
    await gate.scenario(scenarios[4], async () => { const response = await agent.machine("jobs/results", "result", { ...result, status: "failed", errorMessage: "Qualification conflicting terminal result" }); assert.equal(response.status, 409); assert.equal((await state()).status, "succeeded"); assert.equal((await state()).attempt_count, 1); }, { oracle: "Actual authenticated protocol noop proves replay/ownership fences; no native certificate side effect or uncertain deployment is synthesized" });
  } catch (error) { primaryError = error; throw error; }
  finally { try { if (ready) { await gate.scenario(scenarios.at(-1), fixture.cleanup); await gate.finish({ requiredScenarios: scenarios }); } else await fixture.cleanup(); } catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Result fencing qualification and cleanup failed"); throw error; } }
});
