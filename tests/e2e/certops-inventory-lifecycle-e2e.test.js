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

test("real TLS endpoint certificate inventory lifecycle", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable real authenticated API and database
    t.skip("CERTOPS_CSR_API_URL required"); return;
  }
  assert.ok(baseUrl, "Strict inventory qualification requires API URL");
  const fixture = await createApiFixture(baseUrl);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "inventory-tls-"));
  let server;
  const gate = createHostGate({ suite: "inventory-api-lifecycle", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_INVENTORY_REPORT, evidenceLevel: "e2e", requiredCapabilities: ["openssl", "api", "postgres"], probeCapabilities: async () => ({ openssl: { available: spawnSync("openssl", ["version"]).status === 0 }, api: { available: true }, postgres: { available: true } }) });
  gate.report.fixtureSource = { file: "tests/e2e/certops-inventory-lifecycle-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") };
  gate.report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  const material = (name) => {
    const result = spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.crt`, "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "2"], { cwd: directory, timeout: 20000 });
    assert.equal(result.status, 0, "OpenSSL endpoint fixture failed");
    const cert = fs.readFileSync(path.join(directory, `${name}.crt`));
    return { key: fs.readFileSync(path.join(directory, `${name}.key`)), cert, fingerprint: new crypto.X509Certificate(cert).fingerprint256.replace(/:/g, "").toLowerCase() };
  };
  async function observedFingerprint() {
    return new Promise((resolve, reject) => {
      const socket = tls.connect({ host: "127.0.0.1", port: server.address().port, rejectUnauthorized: false }, () => {
        const publicCertificate = socket.getPeerCertificate(); socket.end();
        resolve(publicCertificate.fingerprint256.replace(/:/g, "").toLowerCase());
      });
      socket.setTimeout(10000, () => socket.destroy(new Error("TLS oracle timed out"))); socket.once("error", reject);
    });
  }
  let ready = false;
  let primaryError;
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    const first = material("first"); const second = material("second");
    server = https.createServer(first, (_request, response) => response.end("Certificate inventory fixture"));
    await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    const url = `https://127.0.0.1:${server.address().port}`;
    const route = `/api/v1/workspaces/${fixture.workspaceId}/domains`;
    let monitorId;
    let initialManagedId;
    const observations = () => fixture.pool.query("SELECT id,managed_certificate_id,observed_fingerprint_sha256 FROM certificate_instances WHERE workspace_id=$1 AND domain_monitor_id=$2 ORDER BY observed_at,id", [fixture.workspaceId, monitorId]);
    await gate.scenario("inventory-api-initial-tls", async () => {
      assert.equal(await observedFingerprint(), first.fingerprint);
      const created = await fixture.request(route, "POST", { url, health_check_enabled: false, check_interval: "1min" });
      assert.equal(created.status, 201); monitorId = created.body.id;
      const observed = await observations(); assert.ok(observed.rows.length > 0);
      assert.equal(observed.rows.at(-1).observed_fingerprint_sha256.replace(/:/g, "").toLowerCase(), first.fingerprint);
      initialManagedId = observed.rows.at(-1).managed_certificate_id;
    }, { oracle: "Independent served TLS fingerprint agrees with persisted real API scan" });
    await gate.scenario("inventory-api-monitor-idempotency", async () => {
      const duplicate = await fixture.request(route, "POST", { url, health_check_enabled: false, check_interval: "1min" });
      assert.ok([200, 201].includes(duplicate.status)); assert.equal(duplicate.body.id, monitorId);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM domain_monitors WHERE workspace_id=$1 AND url=$2", [fixture.workspaceId, url])).rows[0].count, 1);
    });
    await gate.scenario("inventory-api-tls-rotation", async () => {
      server.setSecureContext(second); assert.equal(await observedFingerprint(), second.fingerprint);
      const refreshed = await fixture.request(route, "POST", { url, health_check_enabled: false, check_interval: "1min" });
      assert.ok([200, 201].includes(refreshed.status));
      const observed = await observations(); const fingerprints = observed.rows.map((row) => row.observed_fingerprint_sha256.replace(/:/g, "").toLowerCase());
      assert.ok(fingerprints.includes(first.fingerprint)); assert.ok(fingerprints.includes(second.fingerprint));
      // The monitored logical asset remains stable across its certificate
      // versions; fingerprint identities and observation history distinguish leaves.
      assert.ok(observed.rows.every((row) => row.managed_certificate_id === initialManagedId));
      const identities = await fixture.pool.query("SELECT fingerprint_sha256 FROM certops_certificate_identities WHERE workspace_id=$1", [fixture.workspaceId]);
      assert.ok(identities.rows.some((row) => row.fingerprint_sha256 === first.fingerprint));
      assert.ok(identities.rows.some((row) => row.fingerprint_sha256 === second.fingerprint));
    }, { oracle: "Fresh served TLS replacement; historical certificate observation remains" });
    await gate.scenario("inventory-api-public-list", async () => {
      const result = await fixture.request(`/api/v1/workspaces/${fixture.workspaceId}/certops/certificates`);
      assert.equal(result.status, 200); assert.ok(JSON.stringify(result.body).toLowerCase().includes(second.fingerprint));
      assert.doesNotMatch(JSON.stringify(result.body), /BEGIN (?:RSA |EC )?PRIVATE KEY/);
    });
    await gate.scenario("inventory-api-unreachable-history", async () => {
      const previous = (await observations()).rows;
      await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
      server = null;
      const failedScan = await fixture.request(route, "POST", { url, health_check_enabled: false, check_interval: "1min" });
      assert.ok([200, 201].includes(failedScan.status));
      const after = (await observations()).rows;
      for (const observation of previous) assert.ok(after.some((row) => row.id === observation.id && row.observed_fingerprint_sha256 === observation.observed_fingerprint_sha256));
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certops_certificate_identities WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count, 2);
    }, { oracle: "Unreachable endpoint does not erase either previously observed public certificate identity" });
  } catch (error) { primaryError = error; throw error; }
  finally {
    const cleanup = async () => {
      try { if (server) await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); }
      finally { try { await fixture.cleanup(); } finally { fs.rmSync(directory, { recursive: true, force: true }); } }
    };
    try {
      if (ready) { await gate.scenario("inventory-api-cleanup", cleanup); await gate.finish({ requiredScenarios: require("../../docs/certops/qualification-suites.json").suites["inventory-api-lifecycle"] }); }
      else await cleanup();
    } catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Inventory journey and final qualification failed"); throw error; }
  }
});
