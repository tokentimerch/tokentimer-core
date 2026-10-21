/**
 * Supporting API/PostgreSQL qualification: shared served fingerprint keeps source history and management accounting.
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
test("shared served fingerprint keeps source history and management accounting", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - needs disposable API, PostgreSQL and two real TLS endpoints
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "shared-tls-"));
  const servers = [];
  const gate = createHostGate({ suite: "shared-source-lifecycle", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_SHARED_SOURCES_REPORT, evidenceLevel: "e2e", requiredCapabilities: ["openssl", "api", "postgres"], probeCapabilities: async () => ({ openssl: { available: spawnSync("openssl", ["version"]).status === 0 }, api: { available: true }, postgres: { available: true } }) });
  gate.report.fixtureSource = { file: "tests/e2e/certops-shared-sources-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") };
  gate.report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  let ready = false; let primaryError; let identityId;
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  async function nativeFingerprint(server) {
    return new Promise((resolve, reject) => {
      const socket = tls.connect({ host: "127.0.0.1", port: server.address().port, rejectUnauthorized: false }, () => { const fingerprint = socket.getPeerCertificate().fingerprint256.replace(/:/g, "").toLowerCase(); socket.end(); resolve(fingerprint); });
      socket.setTimeout(10000, () => socket.destroy(new Error("TLS probe timeout"))); socket.once("error", reject);
    });
  }
  const identity = async () => (await fixture.request(`${prefix}/certificate-identities/${identityId}`)).body.certificate;
  const managementUsage = async () => (await fixture.pool.query("SELECT (count(DISTINCT current_identity_id) + count(*) FILTER (WHERE current_identity_id IS NULL))::int AS count FROM certops_management_periods WHERE workspace_id=$1 AND ended_at IS NULL", [fixture.workspaceId])).rows[0].count;
  let periods;
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    assert.equal(spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "private.key", "-out", "public.crt", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "2"], { cwd: directory, timeout: 20000 }).status, 0);
    const cert = fs.readFileSync(path.join(directory, "public.crt")); const key = fs.readFileSync(path.join(directory, "private.key"));
    const fingerprint = new crypto.X509Certificate(cert).fingerprint256.replace(/:/g, "").toLowerCase();
    await gate.scenario("shared-source-two-tls-observations", async () => {
      for (let index = 0; index < 2; index += 1) {
        const server = https.createServer({ key, cert }, (_request, response) => response.end("Shared fingerprint fixture")); servers.push(server);
        await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
        assert.equal(await nativeFingerprint(server), fingerprint);
        assert.equal((await fixture.request(`/api/v1/workspaces/${fixture.workspaceId}/domains`, "POST", { url: `https://127.0.0.1:${server.address().port}`, health_check_enabled: false, check_interval: "1min" })).status, 201);
      }
      const list = await fixture.request(`${prefix}/certificate-identities`); assert.equal(list.body.items.length, 1); identityId = list.body.items[0].identityId;
      assert.equal(list.body.items[0].sourceCount, 2); assert.equal(list.body.items[0].activeSourceCount, 2); assert.equal(list.body.items[0].locationCount, 2);
      assert.equal(await managementUsage(), 1);
      periods = (await fixture.pool.query("SELECT id,managed_certificate_id FROM certops_management_periods WHERE workspace_id=$1 AND ended_at IS NULL ORDER BY id", [fixture.workspaceId])).rows;
      assert.equal(periods.length, 2);
    });
    await gate.scenario("shared-source-stop-one-preserves-sibling", async () => {
      assert.equal((await fixture.request(`${prefix}/management-periods/${periods[0].id}/stop`, "POST", {})).status, 200);
      const current = await identity(); assert.equal(current.activeSourceCount, 1); assert.equal(current.stillObserved, true); assert.equal(await managementUsage(), 1);
      for (const server of servers) assert.equal(await nativeFingerprint(server), fingerprint);
    });
    await gate.scenario("shared-source-stop-all-preserves-observation", async () => {
      assert.equal((await fixture.request(`${prefix}/management-periods/${periods[1].id}/stop`, "POST", {})).status, 200);
      const current = await identity(); assert.equal(current.activeSourceCount, 0); assert.equal(current.managed, false); assert.equal(current.stillObserved, true); assert.equal(current.lifecycleStatus, "active"); assert.equal(await managementUsage(), 0);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_instances WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count, 2);
    });
    await gate.scenario("shared-source-readd-history", async () => {
      const added = await fixture.request(`${prefix}/sources/${periods[0].managed_certificate_id}/readd`, "POST", { renewalProfileId: null, automationEnabled: false }); assert.equal(added.status, 201); assert.ok(!periods.some((period) => period.id === added.body.periodId));
      const current = await identity(); assert.equal(current.activeSourceCount, 1); assert.equal(current.locationCount, 2); assert.equal(await managementUsage(), 1);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certops_management_periods WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count, 3);
    });
  } catch (error) { primaryError = error; throw error; }
  finally {
    const cleanup = async () => { const failures = []; for (const server of servers) { try { await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); } catch (error) { failures.push(error); } } try { await fixture.cleanup(); } catch (error) { failures.push(error); } finally { fs.rmSync(directory, { recursive: true, force: true }); } if (failures.length) throw new AggregateError(failures, "Shared source fixture cleanup failed"); };
    try { if (ready) { await gate.scenario("shared-source-cleanup", cleanup); await gate.finish({ requiredScenarios: require("../../scripts/certops-qualification-manifest").suites["shared-source-lifecycle"] }); } else await cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Shared source lifecycle and finalization failed"); throw error; }
  }
});
