/**
 * Supporting API/PostgreSQL qualification: registered agent log redaction and replay through real API.
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
test("registered agent log redaction and replay through real API", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires isolated API, PostgreSQL and signing configuration
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl);
  let viewer; let ready = false; let primaryError;
  const gate = createHostGate({ suite: "agent-log-api", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_AGENT_LOG_API_REPORT, evidenceLevel: "integration", requiredCapabilities: ["api", "postgres"], probeCapabilities: async () => ({ api: { available: true }, postgres: { available: true } }) });
  gate.report.fixtureSource = { file: "tests/e2e/certops-agent-logs-api-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") };
  gate.report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  gate.report.fixtureTraffic = "Synthetic diagnostic sentinel lines through genuine registered-agent authentication and claim; no completed certificate execution claim";
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  const agentId = crypto.randomUUID();
  let credential; let jobId; let claimId;
  async function machine(route, type, body, token = credential) {
    if (type === "log") body = { jobId, final: false, ...body, claimId: String(body.claimId), ...(body.lines.length ? { firstSeq: body.lines[0].seq } : {}), lines: body.lines.map(({ fields, ...line }) => fields === null ? line : { ...line, fields }) };
    const response = await fetch(new URL(`/api/v1/certops/agent/${route}`, baseUrl), { method: "POST", signal: AbortSignal.timeout(15000), headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify({ schemaVersion: 1, protocolVersion: "1.0.0", messageType: type, agentId, sentAt: new Date().toISOString(), body }) });
    return { status: response.status, body: await response.json() };
  }
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    await gate.scenario("agent-log-register-claim", async () => {
      const bootstrap = await fixture.request(`${prefix}/agent-bootstrap-tokens`, "POST", { name: "Log stream fixture", expiresAt: new Date(Date.now() + 3600000).toISOString() }); assert.equal(bootstrap.status, 201);
      const registered = await machine("register", "register", { bootstrapTokenId: bootstrap.body.token.id, registrationId: crypto.randomUUID(), hostname: "log-qualification", platform: "linux", agentVersion: "1.0.0", declaredCapabilities: ["job-log-stream-v1"] }, bootstrap.body.plaintextToken); assert.equal(registered.status, 201); credential = registered.body.credential;
      const created = await fixture.request(`${prefix}/jobs`, "POST", { operation: "noop" }); assert.equal(created.status, 201); jobId = created.body.job.id;
      const claimed = await machine("jobs/claim", "claim", { maxJobs: 1, supportedActions: ["noop"] }); assert.equal(claimed.status, 200);
      assert.equal(claimed.body.jobs[0].jobId || claimed.body.jobs[0].id, jobId); claimId = claimed.body.jobs[0].claimId;
      assert.ok(claimed.body.logStreams.some((stream) => stream.enabled));
    });
    const lines = [{ seq: 1, ts: new Date().toISOString(), level: "info", step: "verify", message: "public diagnostic fixture" }, { seq: 2, ts: new Date().toISOString(), level: "warn", step: "verify", message: "password=fixture-password-sentinel Authorization: Bearer fixture-bearer-sentinel" }];
    await gate.scenario("agent-log-redaction-persistence", async () => {
      assert.equal((await machine(`jobs/${jobId}/logs`, "log", { claimId, lines })).status, 200);
      const result = await fixture.request(`${prefix}/jobs/${jobId}/agent-log`); assert.equal(result.status, 200); assert.equal(result.body.linesVisible, true);
      const text = JSON.stringify(result.body); assert.ok(text.includes("public diagnostic fixture")); assert.ok(!text.includes("fixture-password-sentinel") && !text.includes("fixture-bearer-sentinel"));
    });
    await gate.scenario("agent-log-replay-idempotency", async () => {
      assert.equal((await machine(`jobs/${jobId}/logs`, "log", { claimId, lines })).status, 200);
      const result = await fixture.request(`${prefix}/jobs/${jobId}/agent-log`); assert.equal(result.body.items.length, 2);
    });
    await gate.scenario("agent-log-final-cursor", async () => {
      assert.equal((await machine(`jobs/${jobId}/logs`, "log", { claimId, lines: [], final: true })).status, 200);
      const first = await fixture.request(`${prefix}/jobs/${jobId}/agent-log?limit=1`); assert.equal(first.body.items.length, 1); assert.ok(first.body.nextCursor);
      const second = await fixture.request(`${prefix}/jobs/${jobId}/agent-log?limit=1&cursor=${encodeURIComponent(first.body.nextCursor)}`); assert.equal(second.body.items.length, 1); assert.notEqual(first.body.items[0].seq, second.body.items[0].seq);
    });
    await gate.scenario("agent-log-viewer-status-only", async () => {
      viewer = await createApiFixture(baseUrl);
      await fixture.pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'viewer')", [fixture.workspaceId, viewer.userId]);
      const result = await viewer.request(`${prefix}/jobs/${jobId}/agent-log`); assert.equal(result.status, 200); assert.equal(result.body.linesVisible, false); assert.deepEqual(result.body.items, []); assert.equal(result.body.nextCursor, null);
      assert.ok(!JSON.stringify(result.body).includes("public diagnostic fixture"));
    });
  } catch (error) { primaryError = error; throw error; }
  finally {
    const cleanup = async () => { try { await fixture.cleanup(); } finally { if (viewer) await viewer.cleanup(); } };
    try { if (ready) { await gate.scenario("agent-log-cleanup", cleanup); await gate.finish({ requiredScenarios: require("../../scripts/certops-qualification-manifest").suites["agent-log-api"] }); } else await cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Agent log qualification and finalization failed"); throw error; }
  }
});
