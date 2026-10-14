/**
 * Supporting API/PostgreSQL qualification: external signing chain lifecycle through public CSR API.
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
test("external signing chain lifecycle through public CSR API", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable authenticated API and OpenSSL
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "csr-chain-"));
  let ready = false; let primaryError;
  const gate = createHostGate({ suite: "csr-api-chain", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_CSR_CHAIN_REPORT, evidenceLevel: "integration", requiredCapabilities: ["openssl", "api", "postgres"], probeCapabilities: async () => ({ openssl: { available: spawnSync("openssl", ["version"]).status === 0 }, api: { available: true }, postgres: { available: true } }) });
  gate.report.fixtureSource = { file: "tests/e2e/certops-csr-chain-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") };
  gate.report.artifactQualification = process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout-source" : "local-worktree-source-baseline-sha-only";
  const run = (args) => assert.equal(spawnSync("openssl", args, { cwd: directory, timeout: 20000 }).status, 0, "Independent OpenSSL chain operation failed");
  const read = (name) => fs.readFileSync(path.join(directory, name), "utf8");
  const route = `/api/v1/workspaces/${fixture.workspaceId}/certops/csrs`;
  let workflowId;
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    run(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "root.key", "-out", "root.crt", "-subj", "/CN=Qualification Root", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-days", "2"]);
    for (const name of ["intermediate", "leaf"]) run(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.csr`, "-subj", name === "leaf" ? "/CN=chain.example.test" : "/CN=Qualification Intermediate", ...(name === "leaf" ? ["-addext", "subjectAltName=DNS:chain.example.test"] : [])]);
    fs.writeFileSync(path.join(directory, "intermediate.ext"), "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n");
    run(["x509", "-req", "-in", "intermediate.csr", "-CA", "root.crt", "-CAkey", "root.key", "-CAcreateserial", "-extfile", "intermediate.ext", "-out", "intermediate.crt", "-days", "2"]);
    fs.writeFileSync(path.join(directory, "leaf.ext"), "basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:chain.example.test\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n");
    run(["x509", "-req", "-in", "leaf.csr", "-CA", "intermediate.crt", "-CAkey", "intermediate.key", "-CAcreateserial", "-extfile", "leaf.ext", "-out", "leaf.crt", "-days", "2"]);
    run(["verify", "-CAfile", "root.crt", "-untrusted", "intermediate.crt", "-verify_hostname", "chain.example.test", "leaf.crt"]);
    const input = { csrPem: read("leaf.csr"), target: { name: "CSR chain fixture", type: "host" } };
    const created = await fixture.request(route, "POST", input); assert.equal(created.status, 201); workflowId = created.body.id;
    await gate.scenario("csr-chain-wrong-first-leaf-refusal", async () => {
      const rejected = await fixture.request(`${route}/${workflowId}/signed-certificate`, "POST", { certificatePem: read("root.crt") + read("intermediate.crt") + read("leaf.crt") });
      assert.equal(rejected.status, 422); assert.equal(rejected.body.code, "CERTOPS_CSR_PUBLIC_KEY_MISMATCH");
      assert.equal((await fixture.request(`${route}/${workflowId}`)).body.status, "pending_signature");
    });
    await gate.scenario("csr-chain-signed-import", async () => {
      const signed = await fixture.request(`${route}/${workflowId}/signed-certificate`, "POST", { certificatePem: read("leaf.crt") + read("intermediate.crt") + read("root.crt") });
      assert.equal(signed.status, 200); assert.equal(signed.body.status, "signed_pending_install");
      assert.equal(signed.body.signedFingerprintSha256, new crypto.X509Certificate(read("leaf.crt")).fingerprint256.replace(/:/g, "").toLowerCase());
    }, { oracle: "Independent two-tier OpenSSL certificate signature and hostname verification" });
    await gate.scenario("csr-chain-public-export", async () => {
      const exported = await fixture.request(`${route}/${workflowId}`); assert.equal(exported.status, 200);
      assert.equal((exported.body.signedChainPem.match(/BEGIN CERTIFICATE/g) || []).length, 2);
      assert.doesNotMatch(JSON.stringify(exported.body), /BEGIN (?:RSA |EC )?PRIVATE KEY/);
      fs.writeFileSync(path.join(directory, "exported-leaf.crt"), exported.body.signedLeafPem);
      fs.writeFileSync(path.join(directory, "exported-chain.crt"), exported.body.signedChainPem);
      run(["verify", "-CAfile", "root.crt", "-untrusted", "exported-chain.crt", "-verify_hostname", "chain.example.test", "exported-leaf.crt"]);
    });
  } catch (error) { primaryError = error; throw error; }
  finally {
    const cleanup = async () => { try { await fixture.cleanup(); } finally { fs.rmSync(directory, { recursive: true, force: true }); } };
    try { if (ready) { await gate.scenario("csr-chain-cleanup", cleanup); await gate.finish({ requiredScenarios: require("../../docs/certops/qualification-suites.json").suites["csr-api-chain"] }); } else await cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "CSR chain lifecycle and finalization failed"); throw error; }
  }
});
