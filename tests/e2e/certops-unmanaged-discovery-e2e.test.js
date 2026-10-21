/**
 * Qualification notes: Unmanaged discovery qualification
 * `unmanaged-discovery-api` invokes the production filesystem collector against an actual temporary
 * public certificate file, then sends its observations through a registered protocol agent to the real
 * API and PostgreSQL database. OpenSSL generates the certificate; its public fingerprint is
 * independently calculated before collection. The private key lives outside the scanned directory, and
 * the fixture never advertises Windows CNG or machine-store custody.
 *
 * Shared execution and evidence policy: docs/certops/e2e-qualification.md.
 */
/**
 * Supporting API/PostgreSQL qualification: quota-blocked real filesystem discovery preserves unmanaged visibility.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * The registered fixture sends genuine machine-protocol requests; it does not run
 * an installed native agent. Named strict reports and owned cleanup are mandatory. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path"), crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createRegisteredAgent } = require("./helpers/certops-registered-agent");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
const { runDiscoveryScan } = require("../../packages/agent/src");
const scenarios = ["unmanaged-discovery-real-source", "unmanaged-discovery-admission-refusal", "unmanaged-discovery-fresh-repeat", "unmanaged-discovery-public-visibility", "unmanaged-discovery-admission-recovery", "unmanaged-discovery-cleanup", "unmanaged-discovery-malformed-scan-preserves"];
test("quota-blocked real filesystem discovery preserves unmanaged visibility", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable API PostgreSQL OpenSSL and native temporary certificate files
    t.skip("Disposable API and OpenSSL required"); return;
  }
  assert.ok(baseUrl);
  const fixture = await createApiFixture(baseUrl), root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-unmanaged-")), scanDirectory = path.join(root, "public");
  fs.mkdirSync(scanDirectory);
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  const gate = createHostGate({ suite: "unmanaged-discovery-api", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_UNMANAGED_DISCOVERY_REPORT, requiredCapabilities: ["api", "postgres", "openssl", "native-filesystem"], fixtureSource: { file: "tests/e2e/certops-unmanaged-discovery-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true }, openssl: { available: spawnSync("openssl", ["version"]).status === 0 }, "native-filesystem": { available: fs.statSync(scanDirectory).isDirectory() } }) });
  gate.report.executionScope = "Actual native public-file collector and authenticated protocol observation with a seeded workspace quota, real PostgreSQL admission and public inventory; no Windows certificate-store/CNG custody or SaaS plan transitions claimed";
  let ready = false, failure, agent, fingerprint, identityId, captured, transportPosts = 0;
  const client = { async reportEvidence(body) {
    transportPosts++;
    const response = await agent.machine("jobs/results", "evidence", { ...body, evidenceItems: body.evidenceItems.map(item => ({ ...item, evidenceId: crypto.randomUUID() })) }); assert.equal(response.status, 200);
  } };
  const scan = async () => { const result = await runDiscoveryScan({ directories: [scanDirectory], client }); assert.equal(result.observed, 1); assert.equal(result.warnings, 0); };
  const identity = async () => {
    const response = await fixture.request(`${prefix}/certificate-identities`); assert.equal(response.status, 200); assert.equal(response.body.items.length, 1); return response.body.items[0];
  };
  const counts = async () => (await fixture.pool.query("SELECT (SELECT count(*)::int FROM managed_certificates WHERE workspace_id=$1) AS managed,(SELECT count(*)::int FROM certops_management_periods WHERE workspace_id=$1 AND ended_at IS NULL) AS periods,(SELECT count(*)::int FROM certops_slot_observations WHERE workspace_id=$1) AS slots", [fixture.workspaceId])).rows[0];
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    await gate.scenario(scenarios[0], async () => {
      assert.equal(spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", path.join(root, "private.key"), "-out", path.join(scanDirectory, "public.crt"), "-subj", "/CN=unmanaged.example.test", "-addext", "subjectAltName=DNS:unmanaged.example.test", "-days", "2"], { timeout: 20000 }).status, 0);
      fingerprint = new crypto.X509Certificate(fs.readFileSync(path.join(scanDirectory, "public.crt"))).fingerprint256.replaceAll(":", "").toLowerCase();
      agent = await createRegisteredAgent(fixture, baseUrl, [], { platform: process.platform });
      await fixture.pool.query("UPDATE workspaces SET certops_managed_identity_limit=0 WHERE id=$1", [fixture.workspaceId]);
    });
    await gate.scenario(scenarios[1], async () => {
      await scan(); assert.deepEqual(await counts(), { managed: 0, periods: 0, slots: 1 });
      const row = await identity(); assert.equal(row.fingerprintSha256, fingerprint); identityId = row.identityId;
      captured = (await fixture.pool.query("SELECT captured_at FROM certops_slot_observations WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].captured_at;
    });
    await gate.scenario(scenarios[2], async () => {
      await new Promise(resolve => setTimeout(resolve, 50)); await scan(); assert.deepEqual(await counts(), { managed: 0, periods: 0, slots: 1 });
      const later = (await fixture.pool.query("SELECT captured_at FROM certops_slot_observations WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].captured_at;
      assert.ok(new Date(later) > new Date(captured)); assert.equal((await identity()).identityId, identityId);
    });
    await gate.scenario("unmanaged-discovery-malformed-scan-preserves", async () => {
      const file = path.join(scanDirectory, "public.crt"), original = fs.readFileSync(file), posts = transportPosts;
      const before = (await fixture.pool.query("SELECT captured_at FROM certops_slot_observations WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].captured_at;
      try {
        fs.writeFileSync(file, "malformed public certificate fixture");
        const result = await runDiscoveryScan({ directories: [scanDirectory], client }); assert.equal(result.observed, 0); assert.equal(transportPosts, posts);
        assert.deepEqual(await counts(), { managed: 0, periods: 0, slots: 1 }); assert.equal((await identity()).identityId, identityId);
        assert.deepEqual((await fixture.pool.query("SELECT captured_at FROM certops_slot_observations WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].captured_at, before);
      } finally { fs.writeFileSync(file, original); }
    }, { oracle: "Actual malformed native public file produces no fabricated observation or absence deletion; the retained identity and last genuine capture stay unchanged" });
    await gate.scenario(scenarios[3], async () => {
      const response = await fixture.request(`${prefix}/certificate-identities?unmanaged=true`); assert.equal(response.status, 200); assert.equal(response.body.items.length, 1); assert.equal(response.body.items[0].identityId, identityId);
      const detail = await fixture.request(`${prefix}/certificate-identities/${identityId}`); assert.equal(detail.status, 200); assert.ok(detail.body.certificate.locations.length >= 1);
      assert.ok(detail.body.certificate.locations.some(location => location.locationKind === "filesystem" && location.presenceState === "confirmed_present" && location.evidenceKind === "stored_copy"));
    });
    await gate.scenario(scenarios[4], async () => {
      await fixture.pool.query("UPDATE workspaces SET certops_managed_identity_limit=1 WHERE id=$1", [fixture.workspaceId]); await scan();
      assert.deepEqual(await counts(), { managed: 1, periods: 1, slots: 1 }); assert.equal((await identity()).identityId, identityId);
      const response = await fixture.request(`${prefix}/certificate-identities?unmanaged=true`); assert.equal(response.status, 200); assert.equal(response.body.items.length, 0);
    });
  } catch (error) { failure = error; }
  finally {
    const cleanup = async () => {
      const errors = [];
      try { await fixture.cleanup(); } catch (error) { errors.push(error); }
      try { assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir())); assert.ok(path.basename(root).startsWith("certops-unmanaged-")); fs.rmSync(root, { recursive: true, force: true }); assert.equal(fs.existsSync(root), false); } catch (error) { errors.push(error); }
      if (errors.length) throw new AggregateError(errors, "Unmanaged discovery cleanup failed");
    };
    try { if (ready) await gate.scenario(scenarios[5], cleanup); else await cleanup(); } catch (error) { failure = failure ? new AggregateError([failure, error], "Unmanaged discovery cleanup failed") : error; }
    try { if (ready) await gate.finish({ requiredScenarios: scenarios }); } catch (error) { failure = failure ? new AggregateError([failure, error], "Unmanaged discovery qualification incomplete") : error; }
  }
  if (failure) throw failure;
});
