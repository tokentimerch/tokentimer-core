/**
 * Qualification notes: Shared CSR ownership and truthful installation evidence
 * `csr-provisional-api` exercises shared provisional ownership, last-reference cancellation races,
 * manual confirmation without invented physical instances, and real TLS observation. A sibling
 * cancellation must preserve an active or observed identity. Conflicting ownership cannot transfer
 * identity, expiry or audit provenance. OpenSSL keys stay in the owned fixture; these controls do not
 * qualify native key custody.
 *
 * Scopes: `csr-provisional-api`.
 *
 * Runner and report settings: `CERTOPS_CSR_PROVISIONAL_REPORT`, `CERTOPS_CSR_API_URL`, `GITHUB_SHA`.
 *
 * $env:CERTOPS_CSR_PROVISIONAL_REPORT = "qualification-results/csr-provisional.json" node --test
 * tests/e2e/certops-csr-provisional-e2e.test.js node scripts/certops-qualification-report.js
 * $env:CERTOPS_CSR_PROVISIONAL_REPORT
 *
 * Run prerequisites: `CERTOPS_CSR_DISPOSABLE_STACK=1`, `CERTOPS_E2E_REQUIRED=1`,
 * `CERTOPS_QUALIFICATION_STRICT=1`.
 *
 * Shared execution and evidence policy: docs/certops/e2e-qualification.md.
 */
/**
 * Qualify shared CSR provisional ownership and truthful manual attestation through
 * a disposable authenticated API/PostgreSQL stack. OpenSSL owns the local keys;
 * only public requests create, import, cancel or complete workflows. An owned TLS
 * server supplies genuine observations for shared-identity rebinding. This does
 * not prove agent deployment, CA issuance, or custody on a Windows host. Strict
 * reports bind the current harness source; finally cleanup owns every fixture.
 */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const tls = require("node:tls");
const { spawnSync } = require("node:child_process");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");

const scenarios = [
  "csr-provisional-shared-public-import",
  "csr-provisional-cancel-one-preserves-sibling",
  "csr-provisional-last-cancel-releases-only-provisional",
  "csr-provisional-concurrent-last-cancellations",
  "csr-attestation-no-fabricated-observation",
  "csr-provisional-real-observation-rebinds-siblings",
  "csr-observed-foreign-owner-cannot-promote-selected-identity",
  "csr-provisional-owned-cleanup",
];

test("shared CSR ownership, cancellation and truthful installation evidence", { timeout: 150000 }, async (t) => {
  const base = process.env.CERTOPS_CSR_API_URL;
  if (!base && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable authenticated API, PostgreSQL and OpenSSL
    t.skip("Disposable API/PostgreSQL stack required"); return;
  }
  assert.ok(base);
  const fixture = await createApiFixture(base);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "certops-csr-provisional-"));
  const ownedTrust = new Map();
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}`;
  const route = `${prefix}/certops/csrs`;
  let server, foreignServer, observedAsset, ready = false, primaryError;
  const gate = createHostGate({
    suite: "csr-provisional-api", evidenceLevel: "integration",
    strict: process.env.CERTOPS_E2E_REQUIRED === "1",
    reportPath: process.env.CERTOPS_CSR_PROVISIONAL_REPORT,
    requiredCapabilities: ["api", "postgres", "openssl"],
    fixtureSource: { file: "tests/e2e/certops-csr-provisional-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") },
    probeCapabilities: () => ({ api: { available: true }, postgres: { available: true }, openssl: { available: spawnSync("openssl", ["version"]).status === 0 } }),
  });
  gate.report.executionScope = "Real public CSR requests, persisted ownership/audit oracles and owned loopback TLS observations. Public OpenSSL fixture signing is separate from native CA/agent execution; manual completion must not manufacture an observed deployment.";

  const query = (sql, args = []) => fixture.pool.query(sql, [fixture.workspaceId, ...args]);
  const digest = (buffer) => crypto.createHash("sha256").update(buffer).digest("hex");
  function openssl(args) {
    assert.equal(spawnSync("openssl", args, { cwd: directory, stdio: "ignore", timeout: 20000 }).status, 0, "Owned OpenSSL fixture operation failed");
  }
  function material(name) {
    openssl(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.csr`, "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"]);
    openssl(["req", "-verify", "-in", `${name}.csr`, "-noout"]);
    openssl(["x509", "-req", "-in", `${name}.csr`, "-signkey", `${name}.key`, "-copy_extensions", "copy", "-days", "2", "-out", `${name}.crt`]);
    const key = fs.readFileSync(path.join(directory, `${name}.key`));
    const cert = fs.readFileSync(path.join(directory, `${name}.crt`));
    return { name, key, keyDigest: digest(key), cert, csrPem: fs.readFileSync(path.join(directory, `${name}.csr`), "utf8"), fingerprint: new crypto.X509Certificate(cert).fingerprint256.replace(/:/g, "").toLowerCase() };
  }
  async function createSigned(input, target) {
    const created = await fixture.request(route, "POST", { csrPem: input.csrPem, ...target });
    assert.equal(created.status, 201, "Public CSR create must succeed");
    const signed = await fixture.request(`${route}/${created.body.id}/signed-certificate`, "POST", { certificatePem: input.cert.toString() });
    assert.equal(signed.status, 200, "Matching public signed leaf must import");
    assert.equal(signed.body.status, "signed_pending_install");
    assert.equal(signed.body.signedFingerprintSha256, input.fingerprint);
    return signed.body;
  }
  const manualTarget = (name) => ({ target: { name, type: "host" } });
  const workflow = async (id) => {
    const result = await fixture.request(`${route}/${id}`);
    assert.equal(result.status, 200); return result.body;
  };
  const certificate = async (id) => (await query("SELECT id,status,token_id,fingerprint_sha256 FROM managed_certificates WHERE workspace_id=$1 AND id=$2", [id])).rows[0];
  const instanceCount = async (id) => Number((await query("SELECT COUNT(*) FROM certificate_instances WHERE workspace_id=$1 AND managed_certificate_id=$2", [id])).rows[0].count);
  const auditCount = async (id, action) => Number((await query("SELECT COUNT(*) FROM audit_events WHERE workspace_id=$1 AND metadata->>'workflow_id'=$2 AND action=$3", [id, action])).rows[0].count);
  async function cancel(id) {
    const result = await fixture.request(`${route}/${id}/cancel`, "POST", {});
    assert.equal(result.status, 200); assert.equal(result.body.status, "cancelled");
    assert.equal(result.body.managedCertificateId, null); return result.body;
  }
  function unchangedKey(input) {
    assert.equal(digest(fs.readFileSync(path.join(directory, `${input.name}.key`))), input.keyDigest, "Public workflow must not mutate the independently owned local key");
  }
  const peer = (host = server) => new Promise((resolve, reject) => {
    const socket = tls.connect({ host: "127.0.0.1", port: host.address().port, ca: ownedTrust.get(host), rejectUnauthorized: true }, () => {
      const fingerprint = socket.getPeerCertificate().fingerprint256.replace(/:/g, "").toLowerCase(); socket.end(); resolve(fingerprint);
    });
    socket.setTimeout(10000, () => socket.destroy(new Error("Owned TLS observation timed out")));
    socket.once("error", reject);
  });

  try {
    assert.equal(await gate.preflight(), true); ready = true;
    const shared = material("shared");
    let first, second, provisionalId;
    await gate.scenario(scenarios[0], async () => {
      first = await createSigned(shared, manualTarget("Shared CSR target one"));
      second = await createSigned(shared, manualTarget("Shared CSR target two"));
      assert.notEqual(first.id, second.id); assert.notEqual(first.targetId, second.targetId);
      provisionalId = first.managedCertificateId;
      assert.equal(second.managedCertificateId, provisionalId);
      assert.equal((await certificate(provisionalId)).status, "provisioning");
      assert.equal((await certificate(provisionalId)).token_id, null);
      assert.equal(await instanceCount(provisionalId), 0);
      assert.equal(Number((await query("SELECT COUNT(*) FROM managed_certificates WHERE workspace_id=$1 AND fingerprint_sha256=$2", [shared.fingerprint])).rows[0].count), 1);
    });
    await gate.scenario(scenarios[1], async () => {
      await cancel(first.id);
      const survivor = await workflow(second.id);
      assert.equal(survivor.status, "signed_pending_install"); assert.equal(survivor.managedCertificateId, provisionalId);
      assert.equal(survivor.signedFingerprintSha256, shared.fingerprint);
      assert.equal((await certificate(provisionalId)).status, "provisioning");
      assert.equal(await instanceCount(provisionalId), 0); unchangedKey(shared);
    });
    await gate.scenario(scenarios[2], async () => {
      await cancel(second.id); await cancel(second.id); await cancel(first.id);
      assert.equal(await certificate(provisionalId), undefined);
      assert.equal(await instanceCount(provisionalId), 0);
      assert.equal(Number((await query("SELECT COUNT(*) FROM tokens WHERE workspace_id=$1")).rows[0].count), 0);
      for (const id of [first.id, second.id]) {
        assert.equal((await workflow(id)).signedFingerprintSha256, shared.fingerprint, "Cancellation retains public signed history");
        assert.equal(await auditCount(id, "CERTOPS_CSR_CANCELLED"), 1, "Repeated cancellation must not duplicate audit");
      }
      unchangedKey(shared);
    });
    await gate.scenario(scenarios[3], async () => {
      // Reuse public material only after the prior provisional owner was removed;
      // every pair gets distinct targets and genuinely concurrent HTTP requests.
      for (let index = 0; index < 3; index++) {
        const a = await createSigned(shared, manualTarget(`Concurrent CSR ${index} a`));
        const b = await createSigned(shared, manualTarget(`Concurrent CSR ${index} b`));
        assert.equal(a.managedCertificateId, b.managedCertificateId);
        await Promise.all([cancel(a.id), cancel(b.id)]);
        assert.equal(await certificate(a.managedCertificateId), undefined);
        for (const id of [a.id, b.id]) assert.equal(await auditCount(id, "CERTOPS_CSR_CANCELLED"), 1);
      }
      unchangedKey(shared);
    });
    await gate.scenario(scenarios[4], async () => {
      const a = await createSigned(shared, manualTarget("Manual attestation owner"));
      const b = await createSigned(shared, manualTarget("Manual attestation sibling"));
      assert.equal(a.managedCertificateId, b.managedCertificateId);
      const result = await fixture.request(`${route}/${a.id}/confirm-installation`, "POST", {});
      assert.equal(result.status, 200); assert.equal(result.body.status, "completed");
      assert.equal(result.body.confirmationMethod, "manual"); assert.ok(result.body.confirmedAt);
      assert.equal(result.body.observedInstanceId, null);
      const active = await certificate(a.managedCertificateId);
      assert.equal(active.status, "active"); assert.ok(active.token_id);
      assert.equal(await instanceCount(active.id), 0, "Manual attestation is not an observed deployment");
      const completion = (await query("SELECT metadata FROM audit_events WHERE workspace_id=$1 AND metadata->>'workflow_id'=$2 AND action='CERTOPS_CSR_COMPLETED'", [a.id])).rows;
      assert.equal(completion.length, 1); assert.equal(completion[0].metadata.method, "manual");
      assert.equal(completion[0].metadata.observed_instance_id, null);
      await cancel(b.id);
      assert.deepEqual(await certificate(active.id), active, "Cancelling a sibling must preserve active identity and token");
      assert.equal((await fixture.request(`${route}/${a.id}/confirm-installation`, "POST", {})).status, 409);
      assert.equal(await auditCount(a.id, "CERTOPS_CSR_COMPLETED"), 1);
      assert.equal(Number((await query("SELECT COUNT(*) FROM tokens WHERE workspace_id=$1")).rows[0].count), 1);
      unchangedKey(shared);
    });
    await gate.scenario(scenarios[5], async () => {
      const old = material("observed-old"), next = material("observed-next");
      server = https.createServer(old, (_request, response) => response.end("Owned CSR observation fixture"));
      ownedTrust.set(server, old.cert);
      await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
      const url = `https://127.0.0.1:${server.address().port}`;
      const scan = () => fixture.request(`${prefix}/domains`, "POST", { url, health_check_enabled: false, check_interval: "1min" });
      assert.equal(await peer(), old.fingerprint);
      const initial = await scan(); assert.equal(initial.status, 201);
      const observed = (await query("SELECT target_id,managed_certificate_id FROM certificate_instances WHERE workspace_id=$1 AND domain_monitor_id=$2 ORDER BY observed_at DESC LIMIT 1", [initial.body.id])).rows[0];
      assert.ok(observed?.target_id); assert.ok(observed.managed_certificate_id);
      observedAsset = { ...observed, monitorId: initial.body.id, url };
      const monitored = await createSigned(next, { targetId: observed.target_id });
      const sibling = await createSigned(next, manualTarget("Observed CSR sibling"));
      assert.equal(monitored.managedCertificateId, sibling.managedCertificateId);
      assert.notEqual(monitored.managedCertificateId, observed.managed_certificate_id);
      server.setSecureContext(next); ownedTrust.set(server, next.cert); assert.equal(await peer(), next.fingerprint);
      assert.equal((await scan()).status, 200);
      const completed = await workflow(monitored.id), retained = await workflow(sibling.id);
      assert.equal(completed.status, "completed"); assert.ok(completed.observedInstanceId);
      assert.equal(completed.confirmationMethod, null); assert.equal(completed.confirmedAt, null);
      assert.equal(completed.managedCertificateId, observed.managed_certificate_id);
      assert.equal(retained.managedCertificateId, observed.managed_certificate_id);
      assert.equal(retained.status, "signed_pending_install"); assert.equal(retained.observedInstanceId, null);
      assert.equal(await certificate(monitored.managedCertificateId), undefined, "Unobserved provisional owner must be released after all shared references rebind");
      const facts = (await query("SELECT managed_certificate_id,target_id,observed_fingerprint_sha256 FROM certificate_instances WHERE workspace_id=$1 AND id=$2", [completed.observedInstanceId])).rows[0];
      assert.equal(facts.managed_certificate_id, observed.managed_certificate_id);
      assert.equal(facts.target_id, monitored.targetId); assert.equal(facts.observed_fingerprint_sha256, next.fingerprint);
      await cancel(sibling.id);
      assert.ok(await certificate(observed.managed_certificate_id)); unchangedKey(old); unchangedKey(next);
    }, { oracle: "Independent served leaf fingerprint agrees with real monitor scan; shared workflows rebind to the observed logical asset without fabricating sibling observation" });
    await gate.scenario(scenarios[6], async () => {
      const next = material("conflicting-next");
      // A changed issued name makes the later acknowledgement meaningful. Both
      // served leaves use the genuine CSR key and independently parsed public DER.
      fs.writeFileSync(path.join(directory, "conflicting.ext"), "subjectAltName=DNS:changed.example.test,IP:127.0.0.1\n");
      openssl(["x509", "-req", "-in", "conflicting-next.csr", "-signkey", "conflicting-next.key", "-extfile", "conflicting.ext", "-days", "3", "-out", "conflicting-next.crt"]);
      next.cert = fs.readFileSync(path.join(directory, "conflicting-next.crt"));
      next.fingerprint = new crypto.X509Certificate(next.cert).fingerprint256.replace(/:/g, "").toLowerCase();
      const active = async () => (await query("SELECT cert.id,cert.fingerprint_sha256,cert.status,cert.token_id,token.expiration FROM managed_certificates cert JOIN tokens token ON token.id=cert.token_id WHERE cert.workspace_id=$1 AND cert.id=$2", [observedAsset.managed_certificate_id])).rows[0];
      const original = await active(); assert.ok(original?.token_id);
      const selected = await createSigned(next, { targetId: observedAsset.target_id, existingCertificateId: original.id });
      assert.equal(selected.managedCertificateId, original.id); assert.equal(selected.namesChanged, true);
      foreignServer = https.createServer(next, (_request, response) => response.end("Owned independent certificate owner"));
      ownedTrust.set(foreignServer, next.cert);
      await new Promise((resolve, reject) => { foreignServer.once("error", reject); foreignServer.listen(0, "127.0.0.1", resolve); });
      assert.equal(await peer(foreignServer), next.fingerprint);
      const foreignMonitor = await fixture.request(`${prefix}/domains`, "POST", { url: `https://127.0.0.1:${foreignServer.address().port}`, health_check_enabled: false, check_interval: "1min" });
      assert.equal(foreignMonitor.status, 201);
      const owner = (await query("SELECT id,managed_certificate_id FROM certificate_instances WHERE workspace_id=$1 AND domain_monitor_id=$2 AND observed_fingerprint_sha256=$3 ORDER BY observed_at DESC LIMIT 1", [foreignMonitor.body.id, next.fingerprint])).rows[0];
      assert.ok(owner?.id); assert.notEqual(owner.managed_certificate_id, original.id);
      server.setSecureContext(next); ownedTrust.set(server, next.cert); assert.equal(await peer(), next.fingerprint);
      const scan = () => fixture.request(`${prefix}/domains`, "POST", { url: observedAsset.url, health_check_enabled: false, check_interval: "1min" });
      assert.equal((await scan()).status, 200);
      const conflicted = await workflow(selected.id);
      assert.equal(conflicted.status, "signed_pending_install");
      assert.equal(conflicted.managedCertificateId, original.id);
      assert.equal(conflicted.identityConflict?.code, "CERTOPS_CSR_OBSERVED_IDENTITY_CONFLICT");
      assert.equal(conflicted.identityConflict.observedCertificateId, owner.managed_certificate_id);
      const factual = (await query("SELECT managed_certificate_id,target_id,observed_fingerprint_sha256 FROM certificate_instances WHERE workspace_id=$1 AND id=$2", [conflicted.identityConflict.observedInstanceId])).rows[0];
      assert.equal(factual.managed_certificate_id, owner.managed_certificate_id);
      assert.equal(factual.target_id, selected.targetId); assert.equal(factual.observed_fingerprint_sha256, next.fingerprint);
      const acknowledged = await fixture.request(`${route}/${selected.id}/acknowledge-names`, "POST", {});
      assert.equal(acknowledged.status, 200); assert.ok(acknowledged.body.namesAcknowledgedAt);
      assert.equal(acknowledged.body.status, "signed_pending_install"); assert.ok(acknowledged.body.identityConflict);
      const refused = await fixture.request(`${route}/${selected.id}/confirm-installation`, "POST", {});
      assert.equal(refused.status, 409); assert.equal(refused.body.code, "CERTOPS_CSR_IDENTITY_CONFLICT");
      assert.equal((await scan()).status, 200);
      assert.deepEqual(await active(), original, "Name acknowledgement and reobservation must preserve selected identity, token and expiry");
      assert.equal(await auditCount(selected.id, "CERTOPS_CSR_COMPLETED"), 0);
      assert.equal(await auditCount(selected.id, "CERTOPS_CSR_OBSERVED_IDENTITY_CONFLICT"), 1);
      unchangedKey(next);
    }, { oracle: "Two independently served TLS endpoints establish actual B-owned deployment; later A-target observation records conflict while acknowledgement cannot promote or transfer ownership" });
  } catch (error) { primaryError = error; throw error; }
  finally {
    const cleanup = async () => {
      const failures = [];
      for (const owned of [server, foreignServer]) {
        if (!owned) continue;
        try { owned.closeAllConnections(); } catch (error) { failures.push(error); }
        try { if (owned.listening) await new Promise((resolve, reject) => owned.close((error) => error ? reject(error) : resolve())); }
        catch (error) { failures.push(error); }
      }
      try { await fixture.cleanup(); } catch (error) { failures.push(error); }
      try { fs.rmSync(directory, { recursive: true, force: true }); } catch (error) { failures.push(error); }
      if (failures.length) throw new AggregateError(failures, "All owned CSR resources attempted cleanup");
    };
    try { if (ready) { await gate.scenario(scenarios.at(-1), cleanup); await gate.finish({ requiredScenarios: scenarios }); } else await cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "CSR ownership qualification and cleanup failed"); throw error; }
  }
});
module.exports = { scenarios };
