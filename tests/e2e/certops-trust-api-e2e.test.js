"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("trust approval and workspace pause through real API", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires isolated authenticated feature-enabled API
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "trust-api-"));
  const gate = createHostGate({ suite: "trust-api-lifecycle", strict: process.env.CERTOPS_E2E_REQUIRED === "1", evidenceLevel: "integration", reportPath: process.env.CERTOPS_TRUST_API_REPORT, requiredCapabilities: ["openssl", "api", "postgres"], probeCapabilities: async () => ({ openssl: { available: spawnSync("openssl", ["version"]).status === 0 }, api: { available: true }, postgres: { available: true } }) });
  gate.report.fixtureSource = { file: "tests/e2e/certops-trust-api-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") };
  gate.report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  let ready = false; let primaryError;
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    assert.equal(spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "private.key", "-out", "public.crt", "-subj", "/CN=Qualification Trust CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-days", "2"], { cwd: directory, timeout: 20000 }).status, 0);
    const pem = fs.readFileSync(path.join(directory, "public.crt"), "utf8");
    let anchorId;
    await gate.scenario("trust-api-public-approval", async () => {
      const result = await fixture.request(`${prefix}/trust-anchors`, "POST", { name: "Qualification CA", anchorType: "root", pem }); assert.equal(result.status, 201);
      anchorId = result.body.trustAnchor.id;
      const fingerprint = new crypto.X509Certificate(pem).fingerprint256.replace(/:/g, "").toLowerCase();
      assert.equal(result.body.trustAnchor.fingerprintSha256.replace(/:/g, "").toLowerCase(), fingerprint);
      const list = await fixture.request(`${prefix}/trust-anchors`); assert.ok(list.body.items.some((anchor) => anchor.id === anchorId));
      assert.doesNotMatch(JSON.stringify(list.body), /BEGIN (?:RSA |EC )?PRIVATE KEY/);
    });
    await gate.scenario("trust-api-private-key-refusal", async () => {
      const result = await fixture.request(`${prefix}/trust-anchors`, "POST", { name: "Refused", anchorType: "root", pem: fs.readFileSync(path.join(directory, "private.key"), "utf8") }); assert.equal(result.status, 422);
    });
    await gate.scenario("trust-api-pause-gate", async () => {
      assert.equal((await fixture.request(`${prefix}/settings`, "PUT", { certOpsPaused: true, reason: "Qualification pause" })).status, 200);
      const blocked = await fixture.request(`${prefix}/trust-anchors`, "POST", { name: "Paused mutation", anchorType: "root", pem });
      assert.equal(blocked.status, 409);
      assert.equal((await fixture.request(`${prefix}/trust-anchors`)).status, 200);
      assert.equal((await fixture.request(`${prefix}/settings`, "PUT", { certOpsPaused: false, reason: "Qualification resume" })).status, 200);
    });
    await gate.scenario("trust-api-retire-idempotency", async () => {
      const first = await fixture.request(`${prefix}/trust-anchors/${anchorId}/retire`, "POST", { reason: "Qualification retirement" }); assert.equal(first.status, 200); assert.equal(first.body.retiredNow, true);
      const second = await fixture.request(`${prefix}/trust-anchors/${anchorId}/retire`, "POST", { reason: "Qualification repeated retirement" }); assert.equal(second.status, 200); assert.equal(second.body.retiredNow, false);
      const retired = await fixture.request(`${prefix}/trust-anchors?status=revoked`); assert.ok(retired.body.items.some((anchor) => anchor.id === anchorId));
    });
  } catch (error) { primaryError = error; throw error; }
  finally {
    const cleanup = async () => { try { await fixture.cleanup(); } finally { fs.rmSync(directory, { recursive: true, force: true }); } };
    try { if (ready) { await gate.scenario("trust-api-cleanup", cleanup); await gate.finish({ requiredScenarios: require("../../docs/certops/qualification-suites.json").suites["trust-api-lifecycle"] }); } else await cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Trust API journey and finalization failed"); throw error; }
  }
});
