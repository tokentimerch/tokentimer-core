/**
 * Qualification notes: Certificate-producing integration source qualification
 * The source inventory covers AWS ACM, Azure Key Vault, Google Certificate Manager/Compute SSL and
 * Vault KV/PKI. Production scanners use SDK/HTTP fixtures; real API/PostgreSQL tests enforce persisted
 * source provenance, authorization, incomplete-scan preservation and newer-observation fences. This
 * does not contact live providers or establish issuance, deployment or custody. Run `node
 * scripts/certops-integration-source-inventory.js` to check mappings.
 *
 * Runner and report settings: `CERTOPS_CSR_API_URL`, `CERTOPS_API_WORKER_FIXTURE_KEY`,
 * `CERTOPS_INTEGRATION_SOURCES_REPORT`, `node --test
 * tests/e2e/certops-integration-sources-e2e.test.js`, `node scripts/certops-qualification-report.js
 * <report.json>`.
 *
 * Run prerequisites: `CERTOPS_CSR_DISPOSABLE_STACK=1`, `DB_*`, `CERTOPS_E2E_REQUIRED=1`.
 *
 * Shared execution and evidence policy: docs/certops/e2e-qualification.md.
 */
/**
 * Supporting API/PostgreSQL qualification: certificate-producing integration source provenance survives authenticated import and replay.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * Public requests and persisted rows are the oracle; prerequisite state is isolated.
 * Native certificate deployment is qualified separately; strict reports and cleanup apply. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os"), path = require("node:path");
const { execFileSync, spawnSync } = require("node:child_process");
const { scanFixtureSources } = require("./helpers/certops-integration-scanners");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
const inventory = require("../../docs/certops/integration-source-inventory.json");
const scenarios = inventory.sources.map(source => `integration-source-${source.sourceKind}`).concat(["integration-source-provenance-authority", "integration-source-scanner-normalization", "integration-source-replay", "integration-source-role-fence", "integration-source-workspace-fence", "integration-source-owned-cleanup", "integration-source-unfenced-worker-cleanup", "integration-source-compute-malformed-absence", "integration-source-absence-malformed", "integration-source-absence-401", "integration-source-absence-429", "integration-source-absence-503", "integration-source-newer-observation-fence", "integration-source-complete-absence", "integration-source-cleanup-replay"]);
test("certificate-producing integration source provenance survives authenticated import and replay", { timeout: 150000 }, async t => {
  const base = process.env.CERTOPS_CSR_API_URL;
  if (!base && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable authenticated API and PostgreSQL
    t.skip("Disposable authenticated API required"); return;
  }
  assert.ok(base);
  const fixture = await createApiFixture(base);
  let foreign, ready = false, primary;
  const imported = [];
  let directory, normalized;
  const gate = createHostGate({ suite: "integration-certificate-sources-api", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_INTEGRATION_SOURCES_REPORT, requiredCapabilities: ["api", "postgres", "openssl", "workerFixtureKey"], fixtureSource: { file: "tests/e2e/certops-integration-sources-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true }, openssl: { available: spawnSync("openssl", ["version"]).status === 0 }, workerFixtureKey: { available: typeof process.env.CERTOPS_API_WORKER_FIXTURE_KEY === "string" && process.env.CERTOPS_API_WORKER_FIXTURE_KEY.length > 0 } }) });
  gate.report.executionScope = "Real authenticated import, production scan persistence and PostgreSQL provenance. Production scanners normalize upstream SDK/HTTP fixtures and fresh public X509 material before import; no live provider request, certificate issuance by a provider, key custody or live-provider qualification.";
  const scans = require("../../apps/api/services/integrationScans");
  function route(source, workspace = fixture.workspaceId) { return `/api/v1/integrations/${source.provider === "vault" ? "vault/" : ""}import?workspace_id=${workspace}`; }
  async function prepare(source, index) {
    const instance = source.provider === "vault" ? "https://vault.integration.invalid" : source.provider === "azure" ? "https://qualification.vault.azure.net" : source.provider === "gcp" ? "qualification-project" : "123456789012";
    const dimensions = source.provider === "vault" ? { mount: source.sourceKind === "vault-kv" ? "secret/" : "pki/", path: `certificate-${index}`, category: "cert" } : source.provider === "gcp" ? { location: "global", scope: "global" } : source.provider === "aws" ? { region: "us-east-1", service: "acm" } : {};
    const objectId = source.provider === "aws" ? `arn:aws:acm:us-east-1:123456789012:certificate/${crypto.randomUUID()}` : source.provider === "vault" ? `${dimensions.mount}certificate-${index}` : `qualification-certificate-${index}`;
    const item = { source: source.source, sourceKind: source.sourceKind, sourceObjectId: objectId, name: `Integration certificate ${index}`, category: "cert", type: "ssl_cert", expiration: "2030-01-01", domains: [`source-${index}.integration.invalid`], subject: `CN=source-${index}.integration.invalid`, issuer: "Qualification public metadata fixture", location: `${source.provider}:${instance}/${objectId}`, dimensions, mount: dimensions.mount, path: dimensions.path };
    Object.assign(item, normalized.outputs.flatMap(output => output.items).find(candidate => candidate.sourceKind === source.sourceKind));
    const scan = await scans.createScan({ workspaceId: fixture.workspaceId, provider: source.provider, instance, ownerKey: instance, createdBy: fixture.userId, client: fixture.pool });
    await scans.recordScanItems(scan.id, [item], { client: fixture.pool });
    await scans.finalizeScan(scan.id, [{ sourceKind: source.sourceKind, dimensions, complete: true }], { client: fixture.pool });
    return { source, item, scanId: scan.id };
  }
  async function send(entry, workspace) { return fixture.request(route(entry.source, workspace), "POST", { items: [entry.item], scan_id: entry.scanId, default_category: "cert", default_type: "ssl_cert" }); }
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    await gate.scenario("integration-source-scanner-normalization", async () => {
      directory = fs.mkdtempSync(path.join(os.tmpdir(), "certops-source-scanners-"));
      execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=scanner.integration.invalid", "-keyout", path.join(directory, "key.pem"), "-out", path.join(directory, "cert.pem")], { stdio: "ignore", timeout: 15000 });
      const privatePem = fs.readFileSync(path.join(directory, "key.pem"), "utf8");
      normalized = await scanFixtureSources(fs.readFileSync(path.join(directory, "cert.pem"), "utf8"), privatePem);
      const items = normalized.outputs.flatMap(output => output.items);
      assert.deepEqual(items.map(item => item.sourceKind).sort(), inventory.sources.map(source => source.sourceKind).sort());
      assert.equal(JSON.stringify(normalized.outputs).includes(privatePem), false);
      for (const item of items) assert.equal(item.expiration, normalized.expiry);
    }, { oracle: "Actual production scanners and public X509 parsers; only upstream SDK/HTTP transports replaced in isolated test process, restored before real API calls" });
    for (const [index, source] of inventory.sources.entries()) await gate.scenario(scenarios[index], async () => {
      const entry = await prepare(source, index);
      const response = await send(entry); assert.equal(response.status, 201); assert.equal(response.body.created_count, 1); assert.equal(response.body.error_count, 0);
      const rows = (await fixture.pool.query("SELECT id,source_provider,source_kind,source_instance,source_object_id,source_dimensions FROM tokens WHERE workspace_id=$1 AND source_kind=$2 AND source_object_id=$3", [fixture.workspaceId, source.sourceKind, entry.item.sourceObjectId])).rows;
      assert.equal(rows.length, 1); assert.equal(rows[0].source_provider, source.provider); assert.equal(rows[0].source_instance, source.provider === "aws" ? "123456789012" : source.provider === "gcp" ? "qualification-project" : source.provider === "azure" ? "https://qualification.vault.azure.net" : "https://vault.integration.invalid");
      const detail = await fixture.request(`/api/tokens/${rows[0].id}`); assert.equal(detail.status, 200);
      entry.tokenId = rows[0].id; imported.push(entry);
    }, { oracle: "Actual persisted server scan binds public certificate metadata to provider, source kind and object identity; production scanner input uses isolated upstream transport fixtures" });
    await gate.scenario("integration-source-replay", async () => {
      for (const entry of imported) { const response = await send(entry); assert.equal(response.status, 201); assert.equal(response.body.created_count, 0); assert.equal(response.body.updated_count, 1); }
      assert.equal(Number((await fixture.pool.query("SELECT COUNT(*) FROM tokens WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count), 6);
    });
    await gate.scenario("integration-source-provenance-authority", async () => {
      for (const entry of imported) {
        const original = (await fixture.pool.query("SELECT source_instance,source_owner_key,source_dimensions FROM tokens WHERE id=$1", [entry.tokenId])).rows[0];
        const response = await fixture.request(route(entry.source), "POST", { scan_id: entry.scanId, items: [{ ...entry.item, source_instance: "https://forged.invalid", source_owner_key: "forged-owner", dimensions: { forged: true } }] });
        assert.equal(response.status, 201); assert.equal(response.body.created_count, 0); assert.equal(response.body.updated_count, 1);
        const current = (await fixture.pool.query("SELECT source_instance,source_owner_key,source_dimensions FROM tokens WHERE id=$1", [entry.tokenId])).rows[0];
        assert.deepEqual(current, original);
      }
    }, { oracle: "Authenticated import cannot replace server-persisted provider instance, owner or dimensions with client provenance fields" });
    await gate.scenario("integration-source-role-fence", async () => {
      try { await fixture.pool.query("UPDATE workspace_memberships SET role='viewer' WHERE workspace_id=$1 AND user_id=$2", [fixture.workspaceId, fixture.userId]); for (const entry of imported) assert.equal((await send(entry)).status, 403); }
      finally { await fixture.pool.query("UPDATE workspace_memberships SET role='admin' WHERE workspace_id=$1 AND user_id=$2", [fixture.workspaceId, fixture.userId]); }
    });
    await gate.scenario("integration-source-workspace-fence", async () => { foreign = await createApiFixture(base); for (const entry of imported) assert.equal((await send(entry, foreign.workspaceId)).status, 403); assert.equal(Number((await foreign.pool.query("SELECT COUNT(*) FROM tokens WHERE workspace_id=$1", [foreign.workspaceId])).rows[0].count), 0); });
    const retained = imported.find(entry => entry.source.sourceKind === "gcp-certificate-manager-cert");
    async function absenceScan(subScopes, items = []) {
      const scan = await scans.createScan({ workspaceId: fixture.workspaceId, provider: "gcp", instance: "qualification-project", ownerKey: "qualification-project", createdBy: fixture.userId, client: fixture.pool });
      await scans.recordScanItems(scan.id, items, { client: fixture.pool, workspaceId: fixture.workspaceId, provider: "gcp", instance: "qualification-project", ownerKey: "qualification-project", observedAt: scan.startedAt });
      await scans.finalizeScan(scan.id, subScopes, { client: fixture.pool }); return scan;
    }
    async function cleanupScan(scan) { return fixture.request(route(retained.source), "POST", { items: [], cleanup: { enabled: true, provider: "gcp", scanId: scan.id } }); }
    async function exists() { return (await fixture.pool.query("SELECT id FROM tokens WHERE id=$1", [retained.tokenId])).rows.length === 1; }
    for (const status of [401, 429, 503, "malformed"]) await gate.scenario("integration-source-absence-" + status, async () => {
      const result = await scanFixtureSources(fs.readFileSync(path.join(directory, "cert.pem"), "utf8"), fs.readFileSync(path.join(directory, "key.pem"), "utf8"), status === "malformed" ? { gcpMalformed: true } : { gcpStatus: status });
      const scope = result.outputs.find(output => output.provider === "gcp").summary.find(scope => scope.sourceKind === "gcp-certificate-manager-cert");
      assert.equal(scope.complete, false);
      const response = await cleanupScan(await absenceScan([scope])); assert.equal(response.status, 201); assert.equal(response.body.deleted_count, 0); assert.equal(await exists(), true);
    }, { oracle: "Actual scanner failed scope is persisted, then real authenticated cleanup cannot delete a previously imported certificate token" });
    await gate.scenario("integration-source-compute-malformed-absence", async () => {
      const result = await scanFixtureSources(fs.readFileSync(path.join(directory, "cert.pem"), "utf8"), fs.readFileSync(path.join(directory, "key.pem"), "utf8"), { computeMalformed: { items: { global: { sslCertificates: "invalid" } } } });
      const scope = result.outputs.find(output => output.provider === "gcp").summary.find(scope => scope.sourceKind === "gcp-compute-ssl-cert");
      assert.equal(scope.complete, false);
      const response = await cleanupScan(await absenceScan([scope])); assert.equal(response.status, 201); assert.equal(response.body.deleted_count, 0);
      assert.equal(Number((await fixture.pool.query("SELECT COUNT(*) FROM tokens WHERE workspace_id=$1 AND source_kind='gcp-compute-ssl-cert'", [fixture.workspaceId])).rows[0].count), 1);
    });
    await gate.scenario("integration-source-newer-observation-fence", async () => {
      const old = await absenceScan([{ sourceKind: retained.item.sourceKind, dimensions: retained.item.dimensions, complete: true }]);
      await new Promise(resolve => setTimeout(resolve, 20));
      await absenceScan([{ sourceKind: retained.item.sourceKind, dimensions: retained.item.dimensions, complete: true }], [retained.item]);
      const response = await cleanupScan(old); assert.equal(response.status, 201); assert.equal(response.body.deleted_count, 0); assert.equal(await exists(), true);
    });
    let complete;
    await gate.scenario("integration-source-complete-absence", async () => {
      complete = await absenceScan([{ sourceKind: retained.item.sourceKind, dimensions: retained.item.dimensions, complete: true }]);
      const response = await cleanupScan(complete); assert.equal(response.status, 201); assert.equal(response.body.deleted_count, 1); assert.equal(await exists(), false);
      assert.equal(Number((await fixture.pool.query("SELECT COUNT(*) FROM tokens WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count), 5);
    }, { oracle: "A genuinely complete empty fixture scan removes only its exact owned source-kind token; other provider and Compute source tokens survive" });
    await gate.scenario("integration-source-unfenced-worker-cleanup", async () => {
      const compute = imported.find(entry => entry.source.sourceKind === "gcp-compute-ssl-cert");
      const scan = await absenceScan([{ sourceKind: compute.item.sourceKind, dimensions: compute.item.dimensions, complete: true }]);
      const response = await fixture.request(route(compute.source), "POST", { items: [], cleanup: { enabled: true, provider: "gcp", scanId: scan.id, reason: "auto_sync_cleanup" } }, { authorization: "Bearer " + process.env.CERTOPS_API_WORKER_FIXTURE_KEY });
      assert.equal(response.status, 201); assert.equal(response.body.deleted_count, 0);
      assert.equal((await fixture.pool.query("SELECT id FROM tokens WHERE id=$1", [compute.tokenId])).rows.length, 1);
      assert.equal((await fixture.pool.query("SELECT cleanup_consumed_at FROM integration_scans WHERE id=$1", [scan.id])).rows[0].cleanup_consumed_at, null);
    }, { oracle: "Actual configured disposable worker principal cannot perform destructive legacy import cleanup without activated auto-sync run fencing; no worker scheduler/process execution claim" });
    await gate.scenario("integration-source-cleanup-replay", async () => {
      const response = await cleanupScan(complete); assert.equal(response.status, 201); assert.equal(response.body.deleted_count, 0);
      assert.equal(Number((await fixture.pool.query("SELECT COUNT(*) FROM tokens WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count), 5);
    });
  } catch (error) { primary = error; throw error; }
  finally {
    const cleanup = async () => { const failures = []; for (const owned of [foreign, fixture]) if (owned) try { await owned.cleanup(); } catch (error) { failures.push(error); } if (directory) try { fs.rmSync(directory, { recursive: true, force: true }); } catch (error) { failures.push(error); } if (failures.length) throw new AggregateError(failures, "Owned integration source fixture cleanup failed"); };
    try { if (ready) { await gate.scenario("integration-source-owned-cleanup", cleanup); await gate.finish({ requiredScenarios: scenarios }); } else await cleanup(); }
    catch (error) { if (primary) throw new AggregateError([primary, error], "Integration import and cleanup failed"); throw error; }
  }
});
module.exports = { scenarios };
