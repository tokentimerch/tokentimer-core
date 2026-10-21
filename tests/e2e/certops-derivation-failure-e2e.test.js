/**
 * Supporting API/PostgreSQL qualification: missing renewal derivation fields preserve real public certificate state.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * Public requests and persisted rows are the oracle; prerequisite state is isolated.
 * Native certificate deployment is qualified separately; strict reports and cleanup apply. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path"), crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
const { ensureDerivedRenewalProfile, deriveRenewalProfileFromIssuedCertificate } = require("../../apps/api/services/certops/renewalProfileDerivation");
const scenarios = ["derivation-failure-public-material", "derivation-failure-issuer-command", "derivation-failure-dns-routing", "derivation-failure-deployment", "derivation-failure-truthful-state", "derivation-failure-cleanup"];
test("missing renewal derivation fields preserve real public certificate state", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable authenticated API PostgreSQL and OpenSSL
    t.skip("Disposable API and OpenSSL required"); return;
  }
  assert.ok(baseUrl);
  const fixture = await createApiFixture(baseUrl), directory = fs.mkdtempSync(path.join(os.tmpdir(), "certops-derivation-"));
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`, name = "derivation.example.test";
  const gate = createHostGate({ suite: "derivation-failure-api", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_DERIVATION_FAILURE_REPORT, requiredCapabilities: ["api", "postgres", "openssl"], fixtureSource: { file: "tests/e2e/certops-derivation-failure-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true }, openssl: { available: spawnSync("openssl", ["version"]).status === 0 } }) });
  gate.report.executionScope = "Actual public certificate import and production profile derivation against PostgreSQL using explicitly seeded historical active status and supplied issuance payload prerequisites; no issuer, host custody or successful issuance claimed";
  let ready = false, failure, certificate, fingerprint;
  const payload = { target: { type: "domain", reference: name }, sans: [name], caEndpoint: "https://qualification.invalid/directory", commandRef: "qualification-renewal", acmeKind: "certbot", dnsProvider: "cloudflare", dnsZone: "example.test", certPath: path.join(directory, "installed.pem"), keyPath: path.join(directory, "installed.key"), keyAlgorithm: "rsa", keySize: 2048 };
  const refuse = async (fields) => {
    for (const field of fields) {
      const incomplete = { ...payload }; delete incomplete[field];
      const result = await ensureDerivedRenewalProfile({ client: fixture.pool, workspaceId: fixture.workspaceId, certificateId: certificate.id, payload: incomplete, certificate: { commonName: name, subjectAltNames: [name] }, operation: "issue" });
      assert.equal(result.reason, "derivation_failed"); assert.equal(result.profileId, null); assert.equal(result.created, false); assert.ok(result.error.includes(field), "Refusal must name the missing prerequisite");
      const state = (await fixture.pool.query("SELECT status,profile_id,fingerprint_sha256 FROM managed_certificates WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, certificate.id])).rows[0];
      assert.equal(state.status, "active"); assert.equal(state.profile_id, null); assert.equal(state.fingerprint_sha256, fingerprint);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_profiles WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count, 0);
    }
  };
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    await gate.scenario(scenarios[0], async () => {
      assert.equal(spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "fixture.key", "-out", "fixture.crt", "-subj", `/CN=${name}`, "-addext", `subjectAltName=DNS:${name}`, "-days", "2"], { cwd: directory, timeout: 20000 }).status, 0);
      const pem = fs.readFileSync(path.join(directory, "fixture.crt"), "utf8"); fingerprint = new crypto.X509Certificate(pem).fingerprint256.replaceAll(":", "").toLowerCase();
      const response = await fixture.request(`${prefix}/certificates`, "POST", { certificatePem: pem }); assert.equal(response.status, 201); certificate = response.body.items[0]; assert.equal(certificate.fingerprintSha256, fingerprint);
      // Historical active status is an explicit prerequisite, not fabricated issuance evidence.
      await fixture.pool.query("UPDATE managed_certificates SET status='active' WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, certificate.id]);
      assert.ok(deriveRenewalProfileFromIssuedCertificate({ payload, certificate: { commonName: name, subjectAltNames: [name] } }).deploymentTargets.length === 1, "Complete control payload must actually derive");
    });
    await gate.scenario(scenarios[1], () => refuse(["caEndpoint", "commandRef"]));
    await gate.scenario(scenarios[2], () => refuse(["dnsProvider", "dnsZone"]));
    await gate.scenario(scenarios[3], () => refuse(["certPath"]));
    await gate.scenario(scenarios[4], async () => {
      const response = await fixture.request(`${prefix}/certificates/${certificate.id}`); assert.equal(response.status, 200); assert.equal(response.body.certificate.status, "active"); assert.equal(response.body.certificate.renewal.state, "not-eligible");
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_jobs WHERE workspace_id=$1", [fixture.workspaceId])).rows[0].count, 0);
    });
  } catch (error) { failure = error; }
  finally {
    const cleanup = async () => {
      const errors = [];
      try { await fixture.cleanup(); } catch (error) { errors.push(error); }
      try { assert.equal(path.dirname(path.resolve(directory)), path.resolve(os.tmpdir())); assert.ok(path.basename(directory).startsWith("certops-derivation-")); fs.rmSync(directory, { recursive: true, force: true }); assert.equal(fs.existsSync(directory), false); } catch (error) { errors.push(error); }
      if (errors.length) throw new AggregateError(errors, "Derivation fixture cleanup failed");
    };
    try { if (ready) await gate.scenario(scenarios[5], cleanup); else await cleanup(); } catch (error) { failure = failure ? new AggregateError([failure, error], "Derivation cleanup failed") : error; }
    try { if (ready) await gate.finish({ requiredScenarios: scenarios }); } catch (error) { failure = failure ? new AggregateError([failure, error], "Derivation qualification incomplete") : error; }
  }
  if (failure) throw failure;
});
