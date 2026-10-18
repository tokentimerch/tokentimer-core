/**
 * Supporting API/PostgreSQL qualification: unqualified AD CS onboarding and dispatch gates through real API.
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
test("unqualified AD CS onboarding and dispatch gates through real API", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires isolated real API and PostgreSQL
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl);
  const gate = createHostGate({ suite: "adcs-api-release-gates", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_ADCS_GATES_API_REPORT, evidenceLevel: "integration", requiredCapabilities: ["api", "postgres"], probeCapabilities: async () => ({ api: { available: true }, postgres: { available: true } }) });
  gate.report.fixtureSource = { file: "tests/e2e/certops-adcs-gates-api-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") };
  gate.report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  gate.report.fixtureTraffic = "Protocol identity declares Windows without enrollment capability; no real Windows or CA execution proof";
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  const agentId = crypto.randomUUID();
  let ready = false; let primaryError; let issuerId; let agentDbId; let credential;
  async function machine(route, type, body, token = credential) {
    const response = await fetch(new URL(`/api/v1/certops/agent/${route}`, baseUrl), { method: "POST", signal: AbortSignal.timeout(15000), headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify({ schemaVersion: 1, protocolVersion: "1.0.0", messageType: type, agentId, sentAt: new Date().toISOString(), body }) });
    return { status: response.status, body: await response.json() };
  }
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    await gate.scenario("adcs-api-unconfigured-issuer", async () => {
      const created = await fixture.request(`${prefix}/issuers`, "POST", { kind: "adcs", name: "Unqualified API gate fixture" }); assert.equal(created.status, 201); issuerId = created.body.issuer.id;
      assert.ok(!(await fixture.request(`${prefix}/issuers`)).body.items.some((row) => row.id === issuerId));
      assert.ok((await fixture.request(`${prefix}/issuers?includeUnconfigured=true`)).body.items.some((row) => row.id === issuerId));
      assert.equal((await fixture.pool.query("SELECT current_version FROM certificate_issuers WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, issuerId])).rows[0].current_version, 0);
    });
    await gate.scenario("adcs-api-unsafe-confirmation-refusal", async () => {
      const result = await fixture.request(`${prefix}/issuers/${issuerId}/confirm`, "POST", { caKeySha256: "ab".repeat(32), caConfig: "ca.invalid\\Qualification CA", template: "QualificationWebServer" });
      assert.equal(result.status, 400); assert.equal(result.body.code, "CERTOPS_SNAPSHOT_INVALID");
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_issuer_versions WHERE workspace_id=$1 AND issuer_id=$2", [fixture.workspaceId, issuerId])).rows[0].count, 0);
    });
    await gate.scenario("adcs-api-normal-preflight-dispatch", async () => {
      const bootstrap = await fixture.request(`${prefix}/agent-bootstrap-tokens`, "POST", { name: "Unqualified Windows protocol fixture", expiresAt: new Date(Date.now() + 3600000).toISOString() }); assert.equal(bootstrap.status, 201);
      const registered = await machine("register", "register", { bootstrapTokenId: bootstrap.body.token.id, registrationId: crypto.randomUUID(), hostname: "unqualified-identity", platform: "win32", agentVersion: "1.0.0", declaredCapabilities: [] }, bootstrap.body.plaintextToken); assert.equal(registered.status, 201, `Protocol registration rejected: ${registered.body.code || "unknown code"}`); credential = registered.body.credential;
      agentDbId = (await fixture.pool.query("SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [fixture.workspaceId, agentId])).rows[0].id;
      const queued = await fixture.request(`${prefix}/issuers/${issuerId}/preflight`, "POST", { agentId: agentDbId, caConfig: "ca.invalid\\Qualification CA", template: "QualificationWebServer" }); assert.equal(queued.status, 201);
      const claimed = await machine("jobs/claim", "claim", { maxJobs: 1, supportedActions: ["adcs-preflight"] }); assert.equal(claimed.status, 200); assert.equal(claimed.body.jobs.length, 1);
      assert.equal((await fixture.pool.query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, queued.body.job.id])).rows[0].status, "claimed");
      assert.equal((await fixture.pool.query("SELECT current_version FROM certificate_issuers WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, issuerId])).rows[0].current_version, 0);
    }, { oracle: "Read-only preflight dispatch is allowed without enrollment qualification; a claim is not a safe CA result or issuer confirmation" });
    await gate.scenario("adcs-api-unconfirmed-enrollment-refusal", async () => {
      const result = await fixture.request(`${prefix}/enrollments`, "POST", { issuerId, certificateId: crypto.randomUUID(), agentId: agentDbId, target: { type: "windows-iis", reference: "gate.example.test", store: "My", binding: { site: "Qualification", port: 443 } }, authorizedDnsNames: ["gate.example.test"], keyAlgorithm: "rsa", keySize: 2048 });
      assert.equal(result.status, 404); assert.equal(result.body.code, "CERTOPS_ISSUER_NOT_FOUND");
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_enrollments WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count, 0);
    });
    await gate.scenario("adcs-api-manual-continuation-bypass-refusal", async () => {
      const before = (await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_jobs WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count;
      for (const operation of ["adcs-preflight", "continue-enrollment"]) {
        const result = await fixture.request(`${prefix}/jobs`, "POST", { operation, allowIssuerPreflight: true, allowEnrollmentContinuation: true, source: "automation" });
        assert.equal(result.status, 400); assert.equal(result.body.code, "CERTOPS_JOB_OPERATION_INVALID");
      }
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_jobs WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count, before);
    }, { oracle: "Public manual job route cannot inject private service-only dispatch privileges" });
  } catch (error) { primaryError = error; throw error; }
  finally {
    try { if (ready) { await gate.scenario("adcs-api-gate-cleanup", fixture.cleanup); await gate.finish({ requiredScenarios: require("../../docs/certops/qualification-suites.json").suites["adcs-api-release-gates"] }); } else await fixture.cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "AD CS API gates and finalization failed"); throw error; }
  }
});
