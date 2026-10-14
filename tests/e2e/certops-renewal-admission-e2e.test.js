/**
 * Supporting API/PostgreSQL qualification: renewal admission preserves monitored-only and terminal certificate policy.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * Public requests and persisted rows are the oracle; prerequisite state is isolated.
 * Native certificate deployment is qualified separately; strict reports and cleanup apply. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("renewal admission preserves monitored-only and terminal certificate policy", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable API PostgreSQL and OpenSSL
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "certops-admission-"));
  let viewer; let ready = false; let primaryError;
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  const gate = createHostGate({ suite: "renewal-admission-api", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_RENEWAL_ADMISSION_REPORT, requiredCapabilities: ["api", "postgres", "openssl"], fixtureSource: { file: "tests/e2e/certops-renewal-admission-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true }, openssl: { available: spawnSync("openssl", ["version"]).status === 0 } }) });
  const counts = async () => (await fixture.pool.query("SELECT (SELECT count(*)::int FROM certificate_jobs WHERE workspace_id=$1) AS jobs,(SELECT count(*)::int FROM certops_outbox WHERE workspace_id=$1) AS intents", [fixture.workspaceId])).rows[0];
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    const items = [];
    for (const name of ["monitored", "retired"]) {
      assert.equal(spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.crt`, "-days", "2", "-subj", `/CN=${name}.example.test`, "-addext", `subjectAltName=DNS:${name}.example.test`], { cwd: directory, timeout: 20000 }).status, 0, "Real public certificate fixture failed");
      const imported = await fixture.request(`${prefix}/certificates`, "POST", { certificatePem: fs.readFileSync(path.join(directory, `${name}.crt`), "utf8") }); assert.equal(imported.status, 201); items.push(imported.body.items[0]);
    }
    const [monitored, retired] = items;
    assert.equal((await fixture.request(`${prefix}/certificates/${retired.id}/retire`, "POST", { status: "revoked", expectedFingerprintSha256: retired.fingerprintSha256, reason: "Qualification terminal policy" })).status, 200);
    viewer = await createApiFixture(baseUrl); await fixture.pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'viewer')", [fixture.workspaceId, viewer.userId]);
    const input = { certificateIds: [monitored.id, retired.id, crypto.randomUUID()], idempotencyKey: crypto.randomUUID() };
    await gate.scenario("renewal-admission-monitored-only", async () => {
      const detail = await fixture.request(`${prefix}/certificates/${monitored.id}`); assert.equal(detail.status, 200); assert.equal(detail.body.certificate.renewal.state, "not-eligible");
      for (const dryRun of [false, true]) {
        const refusal = await fixture.request(`${prefix}/certificates/${monitored.id}/renewal-setup`, "POST", { dryRun }); assert.equal(refusal.status, 409); assert.equal(refusal.body.code, "CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE");
      }
      assert.deepEqual(await counts(), { jobs: 0, intents: 0 });
    }, { oracle: "Importing public material alone never proves host custody or arms automation; genuine API refuses both adoption and preflight" });
    await gate.scenario("renewal-admission-bulk-per-item", async () => {
      const result = await fixture.request(`${prefix}/jobs/bulk-renew`, "POST", input); assert.equal(result.status, 200);
      assert.deepEqual(result.body.summary, { requested: 3, succeeded: 0, failed: 3 });
      assert.deepEqual(result.body.results.map((item) => item.certificateId), input.certificateIds);
      assert.deepEqual(result.body.results.map((item) => item.errorCode), ["CERTOPS_RENEWAL_PROFILE_INCOMPLETE", "CERTOPS_CERTIFICATE_NOT_RENEWABLE", "CERTOPS_CERTIFICATE_NOT_FOUND"]);
      assert.deepEqual(await counts(), { jobs: 0, intents: 0 });
    }, { oracle: "Actual heterogeneous ineligible inputs retain independent reasons; no eligible native execution is claimed" });
    await gate.scenario("renewal-admission-dry-run-repeat", async () => {
      for (const extra of [{ dryRun: true }, {}, {}]) {
        const response = await fixture.request(`${prefix}/jobs/bulk-renew`, "POST", { ...input, ...extra }); assert.equal(response.status, 200); assert.equal(response.body.summary.failed, 3);
      }
      assert.deepEqual(await counts(), { jobs: 0, intents: 0 });
    });
    await gate.scenario("renewal-admission-override-pause-roles", async () => {
      const override = await fixture.request(`${prefix}/jobs/bulk-renew`, "POST", { ...input, payload: { commandRef: "unapproved" } }); assert.equal(override.status, 400); assert.equal(override.body.code, "CERTOPS_RENEWAL_OVERRIDE_INVALID");
      assert.equal((await viewer.request(`${prefix}/jobs/bulk-renew`, "POST", input)).status, 403);
      assert.equal((await fixture.request(`${prefix}/settings`, "PUT", { certOpsPaused: true })).status, 200);
      assert.equal((await fixture.request(`${prefix}/jobs/bulk-renew`, "POST", input)).status, 409);
      assert.equal((await fixture.request(`${prefix}/certificates/${monitored.id}/renewal-setup`, "POST", {})).status, 409);
      assert.equal((await fixture.request(`${prefix}/settings`, "PUT", { certOpsPaused: false })).status, 200);
      assert.deepEqual(await counts(), { jobs: 0, intents: 0 });
    });
    await gate.scenario("renewal-admission-retry-missing-role-boundary", async () => {
      const retry = `${prefix}/renewal-setup-intents/${crypto.randomUUID()}/retry`;
      assert.equal((await fixture.request(retry, "POST", {})).status, 404);
      assert.equal((await viewer.request(retry, "POST", {})).status, 403);
      assert.deepEqual(await counts(), { jobs: 0, intents: 0 });
    }, { oracle: "Missing intent cannot invent reconciliation or restart work; viewer cannot invoke the retry surface" });
  } catch (error) { primaryError = error; throw error; }
  finally {
    const cleanup = async () => { try { await fixture.cleanup(); } finally { try { if (viewer) await viewer.cleanup(); } finally { fs.rmSync(directory, { recursive: true, force: true }); } } };
    try { if (ready) { await gate.scenario("renewal-admission-cleanup", cleanup); await gate.finish({ requiredScenarios: require("../../docs/certops/qualification-suites.json").suites["renewal-admission-api"] }); } else await cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Renewal admission qualification and cleanup failed"); throw error; }
  }
});
