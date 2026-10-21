/**
 * Qualification notes: Decommission acknowledgement and factual rediscovery
 * `decommission-lifecycle-api` requires explicit uncertainty acknowledgement (`428
 * CERTOPS_VISIBILITY_ACK_REQUIRED`) before terminal decommissioning. Registered filesystem
 * observations and later real TLS rescans remain factual evidence without reactivation, duplicate
 * identities or additional retirement audits. No installed agent removal is claimed.
 *
 * Runner and report settings: `node --test tests/e2e/certops-decommission-e2e.test.js`,
 * `CERTOPS_DECOMMISSION_REPORT`.
 *
 * Run prerequisites: `CERTOPS_E2E_REQUIRED=1`, `CERTOPS_CSR_DISPOSABLE_STACK=1`.
 *
 * Shared execution and evidence policy: docs/certops/e2e-qualification.md.
 */
/**
 * Public decommission lifecycle through a disposable authenticated API/PostgreSQL stack.
 * Independent OpenSSL files, native discovery and trusted loopback TLS provide factual
 * observations. No observation rows are seeded and no Windows removal/CA claim is made.
 * Run with the API qualification runner and CERTOPS_DECOMMISSION_REPORT on an explicitly disposable stack.
 */
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
const { createRegisteredAgent } = require("./helpers/certops-registered-agent");
const { runDiscoveryScan } = require("../../packages/agent/src");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
const scenarios = ["decommission-public-import-no-observation", "decommission-uncertain-refusal-atomic", "decommission-explicit-acknowledgement", "decommission-stored-copy-acknowledgement", "decommission-real-tls-rediscovery", "decommission-concurrent-rescans-preserve-terminal", "decommission-owned-cleanup"];
module.exports = { scenarios };
test("decommission acknowledgement and factual rediscovery preserve operator lifecycle", { timeout: 120000 }, async t => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable authenticated API PostgreSQL OpenSSL and native files
    t.skip("Disposable API stack required"); return;
  }
  assert.ok(baseUrl);
  const fixture = await createApiFixture(baseUrl);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "certops-decommission-"));
  const publicDirectory = path.join(directory, "observed-public"); fs.mkdirSync(publicDirectory);
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  const gate = createHostGate({ suite: "decommission-lifecycle-api", evidenceLevel: "e2e", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_DECOMMISSION_REPORT, requiredCapabilities: ["api", "postgres", "openssl", "native-filesystem"], fixtureSource: { file: "tests/e2e/certops-decommission-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true }, openssl: { available: spawnSync("openssl", ["version"]).status === 0 }, "native-filesystem": { available: fs.statSync(publicDirectory).isDirectory() } }) });
  gate.report.fixtureSources = ["tests/e2e/helpers/certops-api-fixture.js", "tests/e2e/helpers/certops-registered-agent.js", "packages/agent/src/index.js"].map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname, "../..", file))).digest("hex") }));
  gate.report.executionScope = "Public decommission admission/audit and real native public-file/TLS observation; protocol registration supplies transport only, no native certificate removal or installation";
  let ready = false, primary, server, identityId, tokenId, fingerprint, retired, retiredToken, audits, monitorId;
  const identity = async id => (await fixture.pool.query("SELECT id,fingerprint_sha256,lifecycle_status,lifecycle_reason,retired_at FROM certops_certificate_identities WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, id])).rows[0];
  const token = async id => (await fixture.pool.query("SELECT id,cert_lifecycle_status,expiration FROM tokens WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, id])).rows[0];
  const retirementAudits = async id => (await fixture.pool.query("SELECT id,metadata FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_CERTIFICATE_RETIRED' AND metadata->>'identityId'=$2 ORDER BY id", [fixture.workspaceId, id])).rows;
  const retire = (id, hash, acknowledgeUncertainty) => fixture.request(`${prefix}/certificate-identities/${id}/retire`, "POST", { status: "decommissioned", expectedFingerprintSha256: hash, reason: "Owned fixture decommission", ...(acknowledgeUncertainty !== undefined ? { acknowledgeUncertainty } : {}) });
  const create = name => {
    assert.equal(spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.crt`, "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "2"], { cwd: directory, timeout: 20000, stdio: "ignore" }).status, 0);
    const pem = fs.readFileSync(path.join(directory, `${name}.crt`));
    return { pem, hash: new crypto.X509Certificate(pem).fingerprint256.replace(/:/g, "").toLowerCase() };
  };
  const importPublic = async cert => {
    const response = await fixture.request(`${prefix}/certificates`, "POST", { certificatePem: cert.pem.toString(), sourceRef: "Owned decommission public import" }); assert.equal(response.status, 201);
    const row = (await fixture.pool.query("SELECT id FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2", [fixture.workspaceId, cert.hash])).rows[0]; assert.ok(row);
    return { id: row.id, tokenId: response.body.items[0].tokenId };
  };
  try {
    await gate.preflight(); ready = true;
    const cert = create("unknown"); fingerprint = cert.hash;
    await gate.scenario(scenarios[0], async () => {
      const imported = await importPublic(cert); identityId = imported.id; tokenId = imported.tokenId;
      const detail = await fixture.request(`${prefix}/certificate-identities/${identityId}`); assert.equal(detail.status, 200);
      assert.equal((await identity(identityId)).lifecycle_status, "active");
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS n FROM certificate_instances WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].n, 0);
    });
    await gate.scenario(scenarios[1], async () => {
      const before = await identity(identityId), priorToken = await token(tokenId), priorAudits = await retirementAudits(identityId);
      for (const acknowledgement of [undefined, false]) { const response = await retire(identityId, fingerprint, acknowledgement); assert.equal(response.status, 428); assert.equal(response.body.code, "CERTOPS_VISIBILITY_ACK_REQUIRED"); }
      assert.deepEqual(await identity(identityId), before); assert.deepEqual(await token(tokenId), priorToken); assert.deepEqual(await retirementAudits(identityId), priorAudits);
    });
    await gate.scenario(scenarios[2], async () => {
      assert.equal((await retire(identityId, fingerprint, true)).status, 200);
      retired = await identity(identityId); retiredToken = await token(tokenId); audits = await retirementAudits(identityId);
      assert.equal(retired.lifecycle_status, "decommissioned"); assert.equal(retiredToken.cert_lifecycle_status, "decommissioned"); assert.equal(audits.length, 1);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS n FROM certificate_instances WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].n, 0);
    });
    await gate.scenario(scenarios[3], async () => {
      const stored = create("stored"), imported = await importPublic(stored);
      fs.writeFileSync(path.join(publicDirectory, "stored.crt"), stored.pem);
      const agent = await createRegisteredAgent(fixture, baseUrl, [], { platform: process.platform });
      const scan = await runDiscoveryScan({ directories: [publicDirectory], client: { async reportEvidence(body) { const result = await agent.machine("jobs/results", "evidence", { ...body, evidenceItems: body.evidenceItems.map(item => ({ ...item, evidenceId: crypto.randomUUID() })) }); assert.equal(result.status, 200); } } });
      assert.equal(scan.observed, 1); assert.equal(scan.warnings, 0);
      const observations = (await fixture.pool.query("SELECT location_kind,fingerprint_sha256 FROM certops_slot_observations WHERE workspace_id=$1 AND fingerprint_sha256=$2", [fixture.workspaceId, stored.hash])).rows;
      assert.equal(observations.length, 1); assert.equal(observations[0].location_kind, "filesystem");
      const before = await identity(imported.id), priorToken = await token(imported.tokenId), beforeAudits = await retirementAudits(imported.id);
      const refused = await retire(imported.id, stored.hash); assert.equal(refused.status, 428); assert.equal(refused.body.code, "CERTOPS_VISIBILITY_ACK_REQUIRED");
      assert.deepEqual(await identity(imported.id), before); assert.deepEqual(await token(imported.tokenId), priorToken); assert.deepEqual(await retirementAudits(imported.id), beforeAudits);
      assert.equal((await retire(imported.id, stored.hash, true)).status, 200); assert.equal((await identity(imported.id)).lifecycle_status, "decommissioned"); assert.equal((await retirementAudits(imported.id)).length, beforeAudits.length + 1);
      assert.deepEqual((await fixture.pool.query("SELECT location_kind,fingerprint_sha256 FROM certops_slot_observations WHERE workspace_id=$1 AND fingerprint_sha256=$2", [fixture.workspaceId, stored.hash])).rows, observations);
    });
    server = https.createServer({ key: fs.readFileSync(path.join(directory, "unknown.key")), cert: cert.pem }, (_request, response) => response.end("Owned decommission TLS"));
    await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    const route = `/api/v1/workspaces/${fixture.workspaceId}/domains`, input = { url: `https://127.0.0.1:${server.address().port}`, health_check_enabled: false, check_interval: "1min" };
    const peer = () => new Promise((resolve, reject) => { const socket = tls.connect({ host: "127.0.0.1", port: server.address().port, servername: "localhost", ca: cert.pem, rejectUnauthorized: true }, () => { try { assert.equal(socket.authorized, true); resolve(socket.getPeerCertificate().fingerprint256.replace(/:/g, "").toLowerCase()); } catch (error) { reject(error); } finally { socket.destroy(); } }); socket.once("error", reject); socket.setTimeout(10000, () => socket.destroy(new Error("Owned TLS oracle timeout"))); });
    await gate.scenario(scenarios[4], async () => {
      assert.equal(await peer(), fingerprint); const observed = await fixture.request(route, "POST", input); assert.equal(observed.status, 201); monitorId = observed.body.id;
      assert.deepEqual(await identity(identityId), retired); assert.deepEqual(await token(tokenId), retiredToken); assert.deepEqual(await retirementAudits(identityId), audits);
      const detail = await fixture.request(`${prefix}/certificate-identities/${identityId}`); assert.equal(detail.status, 200); assert.equal(detail.body.certificate.stillObserved, true);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS n FROM certificate_instances WHERE workspace_id=$1 AND domain_monitor_id=$2 AND observed_fingerprint_sha256=$3", [fixture.workspaceId, monitorId, fingerprint])).rows[0].n, 1);
    });
    await gate.scenario(scenarios[5], async () => {
      const captured = async () => (await fixture.pool.query("SELECT MAX(captured_at) AS latest FROM certificate_instances WHERE workspace_id=$1 AND domain_monitor_id=$2", [fixture.workspaceId, monitorId])).rows[0].latest;
      const priorCapture = await captured();
      await Promise.all(Array.from({ length: 3 }, async () => { const response = await fixture.request(route, "POST", input); assert.equal(response.status, 200); }));
      assert.ok(new Date(await captured()).getTime() > new Date(priorCapture).getTime());
      assert.equal(await peer(), fingerprint); assert.deepEqual(await identity(identityId), retired); assert.deepEqual(await token(tokenId), retiredToken); assert.deepEqual(await retirementAudits(identityId), audits);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS n FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2", [fixture.workspaceId, fingerprint])).rows[0].n, 1);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS n FROM certificate_instances WHERE workspace_id=$1 AND domain_monitor_id=$2 AND observed_fingerprint_sha256=$3", [fixture.workspaceId, monitorId, fingerprint])).rows[0].n, 1);
      const active = await fixture.request(`${prefix}/certificate-identities?excludeRetired=true`); assert.equal(active.status, 200); assert.ok(!active.body.items.some(item => item.identityId === identityId));
    });
  } catch (error) { primary = error; throw error; }
  finally {
    const cleanup = async () => { const failures = []; try { if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())); } catch (error) { failures.push(error); } try { await fixture.cleanup(); } catch (error) { failures.push(error); } try { fs.rmSync(directory, { recursive: true, force: true }); } catch (error) { failures.push(error); } if (failures.length) throw new AggregateError(failures, "Owned decommission fixture cleanup failed"); };
    try { if (ready) { await gate.scenario(scenarios[6], cleanup); await gate.finish({ requiredScenarios: scenarios }); } else await cleanup(); } catch (error) { if (primary) throw new AggregateError([primary, error], "Decommission journey and finalization failed"); throw error; }
  }
});
