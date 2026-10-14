"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const crypto = require("node:crypto");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("public renewal profile permissions and immutable execution policy", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable API and PostgreSQL
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl);
  let manager; let viewer; let ready = false; let primaryError;
  const route = `/api/v1/workspaces/${fixture.workspaceId}/certops/profiles`;
  const gate = createHostGate({ suite: "profile-permissions-api", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_PROFILE_PERMISSIONS_REPORT, requiredCapabilities: ["api", "postgres"], fixtureSource: { file: "tests/e2e/certops-profile-permissions-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true } }) });
  gate.report.fixturePrerequisite = "Seeded confirmed issuer metadata for API policy only; no CA validation, key custody or certificate execution evidence";
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    manager = await createApiFixture(baseUrl); viewer = await createApiFixture(baseUrl);
    for (const [identity, role] of [[manager, "workspace_manager"], [viewer, "viewer"]]) await fixture.pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,$3)", [fixture.workspaceId, identity.userId, role]);
    const issuerId = (await fixture.pool.query("INSERT INTO certificate_issuers(workspace_id,kind,name,current_version,revalidation_required) VALUES ($1,'adcs','Permission fixture issuer',1,false) RETURNING id", [fixture.workspaceId])).rows[0].id;
    await fixture.pool.query("INSERT INTO certificate_issuer_versions(workspace_id,issuer_id,version,ca_config,template,transport,ca_key_sha256,confirmed_at) VALUES($1,$2,1,$3,'QualificationWebServer','dcom',$4,NOW())", [fixture.workspaceId, issuerId, "ca.invalid\\Qualification CA", "ab".repeat(32)]);
    const input = { name: "Permission fixture profile", issuerId, target: { type: "windows-iis", reference: "permission.example.test", store: "WebHosting", binding: { site: "Qualification", port: 443, sniHost: "permission.example.test" } }, keyAlgorithm: "rsa", keySize: 2048, renewBeforeDays: 30 };
    const created = await fixture.request(route, "POST", input); assert.equal(created.status, 201); const profileId = created.body.id; const detail = `${route}/${profileId}`;
    await gate.scenario("profile-manager-read-write-fence", async () => {
      assert.equal((await manager.request(detail)).status, 200);
      assert.equal((await manager.request(detail, "PATCH", { renewBeforeDays: 45 })).status, 403);
      assert.equal((await manager.request(route, "POST", input)).status, 403);
      assert.equal((await fixture.request(detail)).body.renewBeforeDays, 30);
    });
    await gate.scenario("profile-viewer-topology-fence", async () => {
      for (const url of [route, detail]) assert.equal((await viewer.request(url)).status, 403);
      assert.equal((await viewer.request(detail, "PATCH", { status: "disabled" })).status, 403);
      assert.equal((await manager.request(`/api/v1/workspaces/${manager.workspaceId}/certops/profiles/${profileId}`)).status, 404);
    });
    await gate.scenario("profile-disable-resume-audit", async () => {
      for (const status of ["disabled", "active"]) { const result = await fixture.request(detail, "PATCH", { autoRenewEnabled: status === "active" }); assert.equal(result.status, 200); assert.equal(result.body.status, status); }
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_RENEWAL_PROFILE_UPDATED' AND metadata->>'profileId'=$2", [fixture.workspaceId, profileId])).rows[0].count, 2);
    }, { oracle: "Actual reversible profile status and attributable audit; no scheduler execution inferred" });
    await gate.scenario("profile-execution-selector-atomic-refusal", async () => {
      const before = (await fixture.request(detail)).body;
      for (const renewalProfile of [{ target: { ...input.target, store: "My" } }, { certPath: "unapproved/certificate.pem" }, { acme: { commandRef: "unapproved" } }, { dns: { provider: "unapproved" } }, { deploymentTargets: [{ reloadService: "unapproved" }] }]) {
        const result = await fixture.request(detail, "PATCH", { description: "Must not persist", renewalProfile }); assert.equal(result.status, 422); assert.equal(result.body.code, Object.hasOwn(renewalProfile, "certPath") ? "CERTOPS_PROFILE_INVALID" : "CERTOPS_PROFILE_FIELD_IMMUTABLE");
        const after = (await fixture.request(detail)).body; assert.equal(after.description, before.description); assert.deepEqual(after.renewalProfile, before.renewalProfile);
      }
    });
    await gate.scenario("profile-approved-key-edit-validation", async () => {
      const result = await fixture.request(detail, "PATCH", { renewalProfile: { keyAlgorithm: "rsa", keySize: 4096 } }); assert.equal(result.status, 200); assert.equal(result.body.renewalProfile.keySize, 4096);
      assert.equal((await fixture.request(detail, "PATCH", { renewalProfile: { keyAlgorithm: "ec", keySize: 4096 } })).status, 422);
      assert.equal((await fixture.request(detail)).body.renewalProfile.keySize, 4096);
      assert.equal((await fixture.request(detail, "PATCH", { status: "archived" })).status, 400); assert.equal((await fixture.request(detail)).body.status, "active");
    });
  } catch (error) { primaryError = error; throw error; }
  finally {
    const cleanup = async () => { const errors = []; for (const identity of [fixture, manager, viewer].filter(Boolean)) { try { await identity.cleanup(); } catch (error) { errors.push(error); } } if (errors.length) throw new AggregateError(errors, "Owned profile fixtures failed cleanup"); };
    try { if (ready) { await gate.scenario("profile-permissions-cleanup", cleanup); await gate.finish({ requiredScenarios: require("../../docs/certops/qualification-suites.json").suites["profile-permissions-api"] }); } else await cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Profile permission qualification and cleanup failed"); throw error; }
  }
});
