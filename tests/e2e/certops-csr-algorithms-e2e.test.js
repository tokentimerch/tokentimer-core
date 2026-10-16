/**
 * Supporting API/PostgreSQL qualification: external CSR algorithm compatibility through public API.
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
const { spawnSync } = require("node:child_process");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("external CSR algorithm compatibility through public API", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - needs disposable authenticated API and OpenSSL
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "csr-algorithms-"));
  let ready = false; let primaryError;
  const gate = createHostGate({ suite: "csr-api-algorithms", strict: process.env.CERTOPS_E2E_REQUIRED === "1", evidenceLevel: "integration", reportPath: process.env.CERTOPS_CSR_ALGORITHMS_REPORT, requiredCapabilities: ["openssl", "api", "postgres"], probeCapabilities: async () => ({ openssl: { available: spawnSync("openssl", ["version"]).status === 0 }, api: { available: true }, postgres: { available: true } }) });
  gate.report.fixtureSource = { file: "tests/e2e/certops-csr-algorithms-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") };
  gate.report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  const run = (args) => { const result = spawnSync("openssl", args, { cwd: directory, timeout: 20000 }); assert.equal(result.status, 0, "OpenSSL algorithm fixture failed"); };
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    for (const [name, options] of [["rsa2048", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]], ["ecp256", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]], ["ecp384", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"]]]) {
      await gate.scenario(`csr-api-${name}`, async () => {
        run(["genpkey", ...options, "-out", `${name}.key`]);
        run(["req", "-new", "-key", `${name}.key`, "-subj", `/CN=${name}.example.test`, "-addext", `subjectAltName=DNS:${name}.example.test`, "-out", `${name}.csr`]);
        run(["req", "-verify", "-in", `${name}.csr`, "-noout"]);
        run(["x509", "-req", "-in", `${name}.csr`, "-signkey", `${name}.key`, "-copy_extensions", "copy", "-days", "2", "-out", `${name}.crt`]);
        const csrPem = fs.readFileSync(path.join(directory, `${name}.csr`), "utf8");
        const certificatePem = fs.readFileSync(path.join(directory, `${name}.crt`), "utf8");
        const route = `/api/v1/workspaces/${fixture.workspaceId}/certops/csrs`;
        const created = await fixture.request(route, "POST", { csrPem, target: { name: `${name} fixture`, type: "host" } }); assert.equal(created.status, 201);
        const signed = await fixture.request(`${route}/${created.body.id}/signed-certificate`, "POST", { certificatePem }); assert.equal(signed.status, 200);
        assert.equal(signed.body.signedFingerprintSha256, new crypto.X509Certificate(certificatePem).fingerprint256.replace(/:/g, "").toLowerCase());
        assert.equal((await fixture.request(`${route}/${created.body.id}/confirm-installation`, "POST", {})).body.status, "completed");
      }, { oracle: "Independent OpenSSL PKCS10 signature verification and public X509 fingerprint" });
    }
  } catch (error) { primaryError = error; throw error; }
  finally {
    const cleanup = async () => { try { await fixture.cleanup(); } finally { fs.rmSync(directory, { recursive: true, force: true }); } };
    try { if (ready) { await gate.scenario("csr-algorithms-cleanup", cleanup); await gate.finish({ requiredScenarios: require("../../docs/certops/qualification-suites.json").suites["csr-api-algorithms"] }); } else await cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "CSR algorithms and finalization failed"); throw error; }
  }
});
