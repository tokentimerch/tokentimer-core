"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const https = require("node:https");
const tls = require("node:tls");
const { spawnSync } = require("node:child_process");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("fresh TLS observation cannot reactivate a retired identity", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires real TLS endpoint and disposable authenticated API
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "retired-tls-"));
  const gate = createHostGate({ suite: "retired-observation-lifecycle", strict: process.env.CERTOPS_E2E_REQUIRED === "1", evidenceLevel: "e2e", reportPath: process.env.CERTOPS_RETIRED_OBSERVATION_REPORT, requiredCapabilities: ["openssl", "api", "postgres"], probeCapabilities: async () => ({ openssl: { available: spawnSync("openssl", ["version"]).status === 0 }, api: { available: true }, postgres: { available: true } }) });
  gate.report.fixtureSource = { file: "tests/e2e/certops-retired-observation-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") };
  gate.report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  let server; let ready = false; let primaryError; let identityId;
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    assert.equal(spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "private.key", "-out", "public.crt", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "2"], { cwd: directory, timeout: 20000 }).status, 0);
    const cert = fs.readFileSync(path.join(directory, "public.crt")); const fingerprint = new crypto.X509Certificate(cert).fingerprint256.replace(/:/g, "").toLowerCase();
    server = https.createServer({ key: fs.readFileSync(path.join(directory, "private.key")), cert }, (_request, response) => response.end("Retired observation fixture"));
    await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    const route = `/api/v1/workspaces/${fixture.workspaceId}/domains`;
    const input = { url: `https://127.0.0.1:${server.address().port}`, health_check_enabled: false, check_interval: "1min" };
    await gate.scenario("retired-observation-real-source", async () => {
      assert.equal((await fixture.request(route, "POST", input)).status, 201);
      const list = await fixture.request(`${prefix}/certificate-identities`); assert.equal(list.body.items.length, 1); identityId = list.body.items[0].identityId;
      assert.equal(list.body.items[0].fingerprintSha256, fingerprint);
    });
    await gate.scenario("retired-observation-operator-retire", async () => {
      const result = await fixture.request(`${prefix}/certificate-identities/${identityId}/retire`, "POST", { status: "revoked", expectedFingerprintSha256: fingerprint, reason: "Qualification retirement", acknowledgeUncertainty: true }); assert.equal(result.status, 200);
    });
    await gate.scenario("retired-observation-rescan-stays-retired", async () => {
      const served = await new Promise((resolve, reject) => { const socket = tls.connect({ host: "127.0.0.1", port: server.address().port, rejectUnauthorized: false }, () => { const leaf = socket.getPeerCertificate().fingerprint256.replace(/:/g, "").toLowerCase(); socket.end(); resolve(leaf); }); socket.setTimeout(10000, () => socket.destroy(new Error("TLS oracle timeout"))); socket.once("error", reject); });
      assert.equal(served, fingerprint);
      assert.equal((await fixture.request(route, "POST", input)).status, 200);
      const result = await fixture.request(`${prefix}/certificate-identities/${identityId}`); assert.equal(result.status, 200); assert.equal(result.body.certificate.lifecycleStatus, "revoked"); assert.equal(result.body.certificate.stillObserved, true);
      const active = await fixture.request(`${prefix}/certificate-identities?excludeRetired=true`); assert.ok(!active.body.items.some((row) => row.identityId === identityId));
      const history = await fixture.request(`${prefix}/certificate-identities?status=revoked`); assert.ok(history.body.items.some((row) => row.identityId === identityId));
    }, { oracle: "Independent fresh served leaf and real public rescan preserve operator lifecycle and active-only filtering" });
  } catch (error) { primaryError = error; throw error; }
  finally {
    const cleanup = async () => { try { if (server) await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); } finally { try { await fixture.cleanup(); } finally { fs.rmSync(directory, { recursive: true, force: true }); } } };
    try { if (ready) { await gate.scenario("retired-observation-cleanup", cleanup); await gate.finish({ requiredScenarios: require("../../docs/certops/qualification-suites.json").suites["retired-observation-lifecycle"] }); } else await cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Retired observation and finalization failed"); throw error; }
  }
});
