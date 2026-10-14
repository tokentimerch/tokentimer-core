/**
 * Supporting API/PostgreSQL qualification: AD CS profile administration through real API.
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
test("AD CS profile administration through real API", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable feature-enabled API and PostgreSQL
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl);
  const gate = createHostGate({ suite: "profiles-api-policy", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_PROFILES_API_REPORT, evidenceLevel: "integration", requiredCapabilities: ["api", "postgres"], probeCapabilities: async () => ({ api: { available: true }, postgres: { available: true } }) });
  gate.report.fixtureSource = { file: "tests/e2e/certops-profiles-api-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") };
  gate.report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  gate.report.fixturePrerequisite = "Seeded confirmed issuer configuration for API policy only; no CA connectivity or issuance evidence";
  let ready = false; let primaryError; let profileId;
  const route = `/api/v1/workspaces/${fixture.workspaceId}/certops/profiles`;
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    const issuerId = (await fixture.pool.query("INSERT INTO certificate_issuers(workspace_id,kind,name,current_version,revalidation_required) VALUES ($1,'adcs','Policy fixture CA',1,false) RETURNING id", [fixture.workspaceId])).rows[0].id;
    await fixture.pool.query("INSERT INTO certificate_issuer_versions(workspace_id,issuer_id,version,ca_config,template,transport,ca_key_sha256,confirmed_at) VALUES($1,$2,1,$3,'QualificationWebServer','dcom',$4,NOW())", [fixture.workspaceId, issuerId, "ca.invalid\\Qualification CA", "ab".repeat(32)]);
    const input = { name: "Qualification AD CS profile", issuerId, target: { type: "windows-iis", reference: "policy.example.test", store: "WebHosting", binding: { site: "Qualification", port: 443, sniHost: "policy.example.test" } }, keyAlgorithm: "rsa", keySize: 2048, renewBeforeDays: 30 };
    await gate.scenario("profiles-api-create-policy", async () => {
      const created = await fixture.request(route, "POST", input); assert.equal(created.status, 201); profileId = created.body.id;
      assert.equal(created.body.issuerId, issuerId); assert.equal(created.body.keyMode, "os-store-managed");
      assert.equal((await fixture.request(`${route}/${profileId}`)).status, 200);
    });
    await gate.scenario("profiles-api-edit-allowed", async () => {
      const updated = await fixture.request(`${route}/${profileId}`, "PATCH", { description: "Updated via public API", renewBeforeDays: 45 });
      assert.equal(updated.status, 200); assert.equal(updated.body.renewBeforeDays, 45); assert.equal(updated.body.description, "Updated via public API");
    });
    await gate.scenario("profiles-api-immutable-target-refusal", async () => {
      const rejected = await fixture.request(`${route}/${profileId}`, "PATCH", { renewalProfile: { target: { ...input.target, store: "My" } } });
      assert.equal(rejected.status, 422); assert.equal(rejected.body.code, "CERTOPS_PROFILE_FIELD_IMMUTABLE");
      const current = await fixture.request(`${route}/${profileId}`); assert.equal(current.body.renewalProfile.target.store, "WebHosting");
    });
    await gate.scenario("profiles-api-invalid-create-atomic", async () => {
      const before = (await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_profiles WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count;
      for (const [invalid, status] of [[{ ...input, keySize: 123 }, 422], [{ ...input, target: { ...input.target, binding: { site: "Qualification", port: 70000 } } }, 422], [{ ...input, issuerId: crypto.randomUUID() }, 404]]) {
        const result = await fixture.request(route, "POST", invalid); assert.equal(result.status, status);
      }
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_profiles WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count, before);
    });
  } catch (error) { primaryError = error; throw error; }
  finally {
    try { if (ready) { await gate.scenario("profiles-api-cleanup", fixture.cleanup); await gate.finish({ requiredScenarios: require("../../docs/certops/qualification-suites.json").suites["profiles-api-policy"] }); } else await fixture.cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Profile policy and finalization failed"); throw error; }
  }
});
