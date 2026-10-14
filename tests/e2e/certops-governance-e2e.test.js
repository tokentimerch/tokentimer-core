"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const https = require("node:https");
const { spawnSync } = require("node:child_process");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("observed certificate governance through public API", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - needs disposable real authenticated API and PostgreSQL
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl);
  const fixture = await createApiFixture(baseUrl);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "governance-tls-"));
  let server; let ready = false; let primaryError;
  const gate = createHostGate({ suite: "governance-api-lifecycle", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_GOVERNANCE_REPORT, evidenceLevel: "e2e", requiredCapabilities: ["openssl", "api", "postgres"], probeCapabilities: async () => ({ openssl: { available: spawnSync("openssl", ["version"]).status === 0 }, api: { available: true }, postgres: { available: true } }) });
  gate.report.fixtureSource = { file: "tests/e2e/certops-governance-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") };
  gate.report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    assert.equal(spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "private.key", "-out", "public.crt", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "2"], { cwd: directory, timeout: 20000 }).status, 0);
    const certificatePem = fs.readFileSync(path.join(directory, "public.crt"));
    const fingerprint = new crypto.X509Certificate(certificatePem).fingerprint256.replace(/:/g, "").toLowerCase();
    server = https.createServer({ key: fs.readFileSync(path.join(directory, "private.key")), cert: certificatePem }, (_request, response) => response.end("Governance fixture"));
    await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    const url = `https://127.0.0.1:${server.address().port}`;
    const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
    let managedId; let identityId; let periodId;
    await gate.scenario("governance-api-observed-source", async () => {
      const created = await fixture.request(`/api/v1/workspaces/${fixture.workspaceId}/domains`, "POST", { url, health_check_enabled: false, check_interval: "1min" }); assert.equal(created.status, 201);
      const identities = await fixture.request(`${prefix}/certificate-identities`); assert.equal(identities.status, 200);
      const identity = identities.body.items.find((row) => row.fingerprintSha256 === fingerprint || row.fingerprint_sha256 === fingerprint);
      assert.ok(identity, "Actual TLS scan must create public fingerprint identity"); identityId = identity.identityId;
      const managed = await fixture.pool.query("SELECT id FROM managed_certificates WHERE workspace_id=$1 AND source='endpoint_monitor'", [fixture.workspaceId]); managedId = managed.rows[0].id;
      const periods = await fixture.pool.query("SELECT id FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL", [fixture.workspaceId, managedId]);
      assert.equal(periods.rows.length, 1); periodId = periods.rows[0].id;
    });
    await gate.scenario("governance-api-retire-preconditions", async () => {
      assert.equal((await fixture.request(`${prefix}/certificate-identities/${identityId}/retire`, "POST", { status: "revoked" })).status, 428);
      assert.equal((await fixture.request(`${prefix}/certificate-identities/${identityId}/retire`, "POST", { status: "revoked", reason: "Qualification fixture", expectedFingerprintSha256: "f".repeat(64) })).status, 412);
    });
    await gate.scenario("governance-api-serving-decommission-refusal", async () => {
      const result = await fixture.request(`${prefix}/certificate-identities/${identityId}/retire`, "POST", { status: "decommissioned", expectedFingerprintSha256: fingerprint, reason: "Qualification fixture", acknowledgeUncertainty: true });
      assert.equal(result.status, 409); assert.equal(result.body.code, "CERTOPS_CERTIFICATE_STILL_SERVING");
    });
    await gate.scenario("governance-api-stop-readd", async () => {
      const stopped = await fixture.request(`${prefix}/management-periods/${periodId}/stop`, "POST", {}); assert.equal(stopped.status, 200);
      assert.equal((await fixture.request(`${prefix}/management-periods/${periodId}/stop`, "POST", {})).status, 200);
      assert.equal((await fixture.request(`${prefix}/sources/${managedId}/readd`, "POST", {})).status, 400);
      const readded = await fixture.request(`${prefix}/sources/${managedId}/readd`, "POST", { renewalProfileId: null, automationEnabled: false });
      assert.equal(readded.status, 201); assert.notEqual(readded.body.periodId, periodId);
      assert.equal((await fixture.request(`${prefix}/sources/${managedId}/readd`, "POST", { renewalProfileId: null, automationEnabled: false })).status, 409);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_instances WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count, 1);
    });
    await gate.scenario("governance-api-retired-visible", async () => {
      const retired = await fixture.request(`${prefix}/certificate-identities/${identityId}/retire`, "POST", { status: "revoked", expectedFingerprintSha256: fingerprint, reason: "Qualification fixture", acknowledgeUncertainty: true }); assert.equal(retired.status, 200);
      const active = await fixture.request(`${prefix}/certificate-identities?excludeRetired=true`); assert.ok(!active.body.items.some((row) => row.identityId === identityId));
      const history = await fixture.request(`${prefix}/certificate-identities/${identityId}`); assert.equal(history.status, 200);
      assert.ok(JSON.stringify(history.body).includes("revoked"));
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_instances WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count, 1);
    });
  } catch (error) { primaryError = error; throw error; }
  finally {
    const cleanup = async () => { try { if (server) await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); } finally { try { await fixture.cleanup(); } finally { fs.rmSync(directory, { recursive: true, force: true }); } } };
    try { if (ready) { await gate.scenario("governance-api-cleanup", cleanup); await gate.finish({ requiredScenarios: require("../../docs/certops/qualification-suites.json").suites["governance-api-lifecycle"] }); } else await cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Governance journey and finalization failed"); throw error; }
  }
});
