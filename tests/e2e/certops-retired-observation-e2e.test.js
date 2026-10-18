/**
 * Supporting API/PostgreSQL qualification: fresh TLS observation cannot reactivate a retired identity.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * Public requests and persisted rows are the oracle; prerequisite state is isolated.
 * Native certificate deployment is qualified separately; strict reports and cleanup apply. */
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
  let server; let ready = false; let primaryError; let identityId; let monitorId; let retiredSnapshot; let retiredToken;
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    assert.equal(spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "private.key", "-out", "public.crt", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "2"], { cwd: directory, timeout: 20000 }).status, 0);
    const cert = fs.readFileSync(path.join(directory, "public.crt")); const fingerprint = new crypto.X509Certificate(cert).fingerprint256.replace(/:/g, "").toLowerCase();
    assert.equal(spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "replacement.key", "-out", "replacement.crt", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "3"], { cwd: directory, timeout: 20000 }).status, 0);
    const replacement = { key: fs.readFileSync(path.join(directory, "replacement.key")), cert: fs.readFileSync(path.join(directory, "replacement.crt")) };
    const replacementFingerprint = new crypto.X509Certificate(replacement.cert).fingerprint256.replace(/:/g, "").toLowerCase();
    server = https.createServer({ key: fs.readFileSync(path.join(directory, "private.key")), cert }, (_request, response) => response.end("Retired observation fixture"));
    await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    const route = `/api/v1/workspaces/${fixture.workspaceId}/domains`;
    const input = { url: `https://127.0.0.1:${server.address().port}`, health_check_enabled: false, check_interval: "1min" };
    const identity = async () => (await fixture.pool.query("SELECT id,fingerprint_sha256,lifecycle_status,lifecycle_reason,retired_at FROM certops_certificate_identities WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, identityId])).rows[0];
    const token = async () => (await fixture.pool.query("SELECT t.id,t.cert_lifecycle_status,t.expiration FROM tokens t JOIN managed_certificates mc ON mc.token_id=t.id WHERE mc.workspace_id=$1 AND mc.source='endpoint_monitor' ORDER BY mc.id LIMIT 1", [fixture.workspaceId])).rows[0];
    const retirementAudits = async () => (await fixture.pool.query("SELECT id,metadata FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_CERTIFICATE_RETIRED' AND metadata->>'identityId'=$2 ORDER BY id", [fixture.workspaceId, identityId])).rows;
    const capture = async () => (await fixture.pool.query("SELECT MAX(captured_at) AS latest FROM certificate_instances WHERE workspace_id=$1 AND domain_monitor_id=$2", [fixture.workspaceId, monitorId])).rows[0].latest;
    const scan = async () => { const result = await fixture.request(route, "POST", input); assert.equal(result.status, 200); };
    const peer = () => new Promise((resolve, reject) => { const socket = tls.connect({ host: "127.0.0.1", servername: "localhost", port: server.address().port, ca: [cert, replacement.cert], rejectUnauthorized: true }, () => { const leaf = socket.getPeerCertificate().fingerprint256.replace(/:/g, "").toLowerCase(); socket.end(); resolve(leaf); }); socket.setTimeout(10000, () => socket.destroy(new Error("TLS oracle timeout"))); socket.once("error", reject); });
    await gate.scenario("retired-observation-real-source", async () => {
      assert.equal(await peer(), fingerprint);
      const created = await fixture.request(route, "POST", input); assert.equal(created.status, 201); monitorId = created.body.id;
      const list = await fixture.request(`${prefix}/certificate-identities`); assert.equal(list.body.items.length, 1); identityId = list.body.items[0].identityId;
      assert.equal(list.body.items[0].fingerprintSha256, fingerprint);
    });
    await gate.scenario("retired-observation-invalid-retire-atomic", async () => {
      const before = await identity(); const audits = await retirementAudits();
      for (const reason of [undefined, "", "\u0000", "x".repeat(513)]) {
        const result = await fixture.request(`${prefix}/certificate-identities/${identityId}/retire`, "POST", { status: "revoked", expectedFingerprintSha256: fingerprint, ...(reason === undefined ? {} : { reason }) });
        assert.equal(result.status, 400);
        assert.deepEqual(await identity(), before); assert.deepEqual(await retirementAudits(), audits);
      }
    });
    await gate.scenario("retired-observation-operator-retire", async () => {
      const result = await fixture.request(`${prefix}/certificate-identities/${identityId}/retire`, "POST", { status: "revoked", expectedFingerprintSha256: fingerprint, reason: "Qualification retirement", acknowledgeUncertainty: true }); assert.equal(result.status, 200);
      retiredSnapshot = await identity(); assert.equal(retiredSnapshot.lifecycle_status, "revoked"); retiredToken = await token(); assert.equal(retiredToken.cert_lifecycle_status, "revoked");
    });
    await gate.scenario("retired-observation-rescan-stays-retired", async () => {
      const served = await peer();
      assert.equal(served, fingerprint);
      const before = await capture(); await scan(); assert.ok(new Date(await capture()).getTime() > new Date(before).getTime(), "A successful rescan must advance real observation freshness");
      const result = await fixture.request(`${prefix}/certificate-identities/${identityId}`); assert.equal(result.status, 200); assert.equal(result.body.certificate.lifecycleStatus, "revoked"); assert.equal(result.body.certificate.stillObserved, true);
      const active = await fixture.request(`${prefix}/certificate-identities?excludeRetired=true`); assert.ok(!active.body.items.some((row) => row.identityId === identityId));
      const history = await fixture.request(`${prefix}/certificate-identities?status=revoked`); assert.ok(history.body.items.some((row) => row.identityId === identityId));
    }, { oracle: "Independent fresh served leaf and real public rescan preserve operator lifecycle and active-only filtering" });
    await gate.scenario("retired-observation-concurrent-rescans", async () => {
      const audits = await retirementAudits(); const before = await capture();
      await Promise.all([scan(), scan(), scan()]);
      assert.ok(new Date(await capture()).getTime() > new Date(before).getTime()); assert.deepEqual(await identity(), retiredSnapshot); assert.deepEqual(await retirementAudits(), audits); assert.deepEqual(await token(), retiredToken);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS n FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2", [fixture.workspaceId, fingerprint])).rows[0].n, 1);
    });
    await gate.scenario("retired-observation-rotation-return", async () => {
      server.setSecureContext(replacement); assert.equal(await peer(), replacementFingerprint); await scan();
      const replacementIdentity = (await fixture.pool.query("SELECT id,lifecycle_status FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2", [fixture.workspaceId, replacementFingerprint])).rows[0];
      assert.ok(replacementIdentity); assert.notEqual(replacementIdentity.id, identityId); assert.equal(replacementIdentity.lifecycle_status, "active");
      assert.deepEqual(await identity(), retiredSnapshot);
      server.setSecureContext({ key: fs.readFileSync(path.join(directory, "private.key")), cert }); assert.equal(await peer(), fingerprint); await scan();
      assert.deepEqual(await identity(), retiredSnapshot); assert.deepEqual(await token(), retiredToken);
      const active = await fixture.request(`${prefix}/certificate-identities?excludeRetired=true`); assert.equal(active.status, 200); assert.ok(!active.body.items.some(item => item.identityId === identityId));
      assert.ok((await fixture.request(`${prefix}/certificate-identities/${identityId}`)).body.certificate.stillObserved);
      const fingerprints = (await fixture.pool.query("SELECT DISTINCT observed_fingerprint_sha256 FROM certificate_instances WHERE workspace_id=$1 AND domain_monitor_id=$2", [fixture.workspaceId, monitorId])).rows.map(item => item.observed_fingerprint_sha256);
      assert.ok(fingerprints.includes(fingerprint)); assert.ok(fingerprints.includes(replacementFingerprint));
    }, { oracle: "Actual served old/new/old trusted TLS observations conserve both fingerprint histories and never clear the original operator retirement" });
  } catch (error) { primaryError = error; throw error; }
  finally {
    const cleanup = async () => { try { if (server) await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); } finally { try { await fixture.cleanup(); } finally { fs.rmSync(directory, { recursive: true, force: true }); } } };
    try { if (ready) { await gate.scenario("retired-observation-cleanup", cleanup); await gate.finish({ requiredScenarios: require("../../scripts/certops-qualification-manifest").suites["retired-observation-lifecycle"] }); } else await cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Retired observation and finalization failed"); throw error; }
  }
});
