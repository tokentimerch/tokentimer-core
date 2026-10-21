/**
 * Qualification notes: CSR observation qualification
 * The authenticated API runner requires `csr-observation-api` and `csr-bound-observation-api`, using
 * real TLS endpoints and OpenSSL certificates. A matching observed leaf can complete a reviewed CSR; a
 * replacement observed during pending name review must preserve the selected identity and token expiry
 * until acknowledgement. Replay retains observation provenance; observation does not become manual
 * installation attestation.
 *
 * Shared execution and evidence policy: docs/certops/e2e-qualification.md.
 */
/**
 * Supporting API/PostgreSQL qualification: real TLS CSR observation preserves selected active identity and expiry until name review.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * Public requests and persisted rows are the oracle; prerequisite state is isolated.
 * Native certificate deployment is qualified separately; strict reports and cleanup apply. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), os = require("node:os"), crypto = require("node:crypto"), https = require("node:https"), tls = require("node:tls");
const { spawnSync } = require("node:child_process");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("real TLS CSR observation preserves selected active identity and expiry until name review", { timeout: 120000 }, async (t) => {
  const url = process.env.CERTOPS_CSR_API_URL;
  if (!url && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable API PostgreSQL and actual TLS endpoint
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(url); const fixture = await createApiFixture(url);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "csr-bound-observation-")); let server, ready = false, primaryError;
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}`;
  const scenarios = ["csr-bound-observation-public-target", "csr-bound-observation-signed-pending", "csr-bound-observation-name-review-defers", "csr-bound-observation-acknowledgement-promotes", "csr-bound-observation-replay", "csr-bound-observation-cleanup"];
  const gate = createHostGate({ suite: "csr-bound-observation-api", evidenceLevel: "e2e", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_CSR_BOUND_OBSERVATION_REPORT, requiredCapabilities: ["api", "postgres", "openssl"], fixtureSource: { file: "tests/e2e/certops-csr-bound-observation-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true }, openssl: { available: spawnSync("openssl", ["version"]).status === 0 } }) });
  const openssl = (args) => assert.equal(spawnSync("openssl", args, { cwd: root, timeout: 20000 }).status, 0, "Public TLS fixture generation failed");
  const peer = () => new Promise((resolve, reject) => { const socket = tls.connect({ host: "127.0.0.1", port: server.address().port, rejectUnauthorized: false }, () => { const fp = socket.getPeerCertificate().fingerprint256.replace(/:/g, "").toLowerCase(); socket.end(); resolve(fp); }); socket.setTimeout(10000, () => socket.destroy(new Error("TLS oracle timed out"))); socket.once("error", reject); });
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "old.key", "-out", "old.crt", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "2"]);
    openssl(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "new.key", "-out", "new.csr", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"]);
    fs.writeFileSync(path.join(root, "changed.ext"), "subjectAltName=DNS:changed.example.test,IP:127.0.0.1\n");
    openssl(["x509", "-req", "-in", "new.csr", "-signkey", "new.key", "-extfile", "changed.ext", "-days", "5", "-out", "new.crt"]);
    const material = (name) => ({ key: fs.readFileSync(path.join(root, `${name}.key`)), cert: fs.readFileSync(path.join(root, `${name}.crt`)) });
    const next = material("new"); const fingerprint = new crypto.X509Certificate(next.cert).fingerprint256.replace(/:/g, "").toLowerCase();
    server = https.createServer(material("old"), (_request, response) => response.end("Owned CSR observation fixture"));
    await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    let monitorId, workflowId, targetId, managedCertificateId, initialState;
    const activeState = async () => (await fixture.pool.query("SELECT mc.fingerprint_sha256,mc.token_id,t.expiration,identity.fingerprint_sha256 AS active_identity_fingerprint FROM managed_certificates mc JOIN tokens t ON t.id=mc.token_id JOIN certops_management_periods period ON period.managed_certificate_id=mc.id AND period.ended_at IS NULL JOIN certops_certificate_identities identity ON identity.id=period.current_identity_id WHERE mc.workspace_id=$1 AND mc.id=$2", [fixture.workspaceId,managedCertificateId])).rows[0];
    const workflow = () => fixture.request(`${prefix}/certops/csrs/${workflowId}`);
    const scan = () => fixture.request(`${prefix}/domains`, "POST", { url: `https://127.0.0.1:${server.address().port}`, health_check_enabled: false, check_interval: "1min" });
    await gate.scenario(scenarios[0], async () => {
      const response = await fixture.request(`${prefix}/domains`, "POST", { url: `https://127.0.0.1:${server.address().port}`, health_check_enabled: false, check_interval: "1min" }); assert.equal(response.status, 201); monitorId = response.body.id;
      targetId = (await fixture.pool.query("SELECT target_id FROM certificate_instances WHERE workspace_id=$1 AND domain_monitor_id=$2 ORDER BY observed_at DESC LIMIT 1", [fixture.workspaceId, monitorId])).rows[0].target_id;
      assert.ok(targetId);
      managedCertificateId = (await fixture.pool.query("SELECT managed_certificate_id FROM certificate_instances WHERE workspace_id=$1 AND domain_monitor_id=$2 ORDER BY observed_at DESC LIMIT 1", [fixture.workspaceId, monitorId])).rows[0].managed_certificate_id;
      initialState = await activeState(); assert.ok(initialState?.token_id);
    });
    await gate.scenario(scenarios[1], async () => {
      const created = await fixture.request(`${prefix}/certops/csrs`, "POST", { csrPem: fs.readFileSync(path.join(root, "new.csr"), "utf8"), targetId, existingCertificateId: managedCertificateId }); assert.equal(created.status, 201); workflowId = created.body.id;
      const imported = await fixture.request(`${prefix}/certops/csrs/${workflowId}/signed-certificate`, "POST", { certificatePem: next.cert.toString() }); assert.equal(imported.status, 200); assert.equal(imported.body.namesChanged, true); assert.equal(imported.body.status, "signed_pending_install");
    });
    await gate.scenario(scenarios[2], async () => {
      server.setSecureContext(next); assert.equal(await peer(), fingerprint); assert.equal((await scan()).status, 200);
      const observed = (await workflow()).body; assert.equal(observed.status, "signed_pending_install"); assert.ok(observed.observedInstanceId); assert.equal(observed.confirmedAt, null); assert.deepEqual(await activeState(), initialState, "Pending review must preserve selected active identity and token expiry despite factual new-leaf observation");
      assert.equal((await fixture.request(`${prefix}/certops/csrs/${workflowId}/confirm-installation`, "POST", {})).status, 409);
    }, { oracle: "Actual served leaf and monitor scan record observation; changed-name review remains required without manual installation attestation" });
    await gate.scenario(scenarios[3], async () => {
      const acknowledged = await fixture.request(`${prefix}/certops/csrs/${workflowId}/acknowledge-names`, "POST", {}); assert.equal(acknowledged.status, 200); assert.equal(acknowledged.body.status, "completed"); assert.equal(acknowledged.body.confirmationMethod, null); assert.equal(acknowledged.body.confirmedAt, null); assert.ok(acknowledged.body.observedInstanceId); assert.equal(acknowledged.body.signedFingerprintSha256, fingerprint);
      const current = await activeState(); assert.equal(current.fingerprint_sha256, fingerprint); assert.equal(current.active_identity_fingerprint, fingerprint); assert.equal(current.token_id, initialState.token_id); assert.notEqual(new Date(current.expiration).toISOString(), new Date(initialState.expiration).toISOString());
    });
    await gate.scenario(scenarios[4], async () => {
      const before = (await workflow()).body; assert.equal((await scan()).status, 200); const after = (await workflow()).body; assert.equal(after.status, "completed"); assert.equal(after.confirmedAt, before.confirmedAt); assert.equal(after.confirmationMethod, null); assert.equal(after.observedInstanceId, before.observedInstanceId);
    });
  } catch (error) { primaryError = error; throw error; }
  finally {
    const cleanup = async () => { try { if (server) { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); } } finally { try { await fixture.cleanup(); } finally { fs.rmSync(root, { recursive: true, force: true }); } } };
    try { if (ready) { await gate.scenario(scenarios.at(-1), cleanup); await gate.finish({ requiredScenarios: scenarios }); } else await cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "CSR observation and cleanup failed"); throw error; }
  }
});
