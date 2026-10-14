/**
 * Supporting API/PostgreSQL qualification: signed CSR material freezes review until explicit cancel and restart.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * Public requests and persisted rows are the oracle; prerequisite state is isolated.
 * Native certificate deployment is qualified separately; strict reports and cleanup apply. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), os = require("node:os"), crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("signed CSR material freezes review until explicit cancel and restart", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable API PostgreSQL and OpenSSL
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl); let ready = false, primaryError;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "csr-frozen-"));
  const scenarios = ["csr-frozen-import-review", "csr-frozen-same-leaf-idempotence", "csr-frozen-replacement-refused", "csr-frozen-cancel-restart-clears-review", "csr-frozen-cleanup"];
  const gate = createHostGate({ suite: "csr-frozen-api", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_CSR_FROZEN_REPORT, requiredCapabilities: ["api", "postgres", "openssl"], fixtureSource: { file: "tests/e2e/certops-csr-frozen-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true }, openssl: { available: spawnSync("openssl", ["version"]).status === 0 } }) });
  const openssl = (args) => assert.equal(spawnSync("openssl", args, { cwd: root, timeout: 20000 }).status, 0, "Public CSR fixture failed");
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    openssl(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "key.pem", "-out", "public.csr", "-subj", "/CN=requested.example.test", "-addext", "subjectAltName=DNS:requested.example.test"]);
    const leaves = [];
    for (const name of ["first", "second"]) { fs.writeFileSync(path.join(root, `${name}.ext`), `subjectAltName=DNS:${name}.example.test\n`); openssl(["x509", "-req", "-in", "public.csr", "-signkey", "key.pem", "-extfile", `${name}.ext`, "-set_serial", name === "first" ? "101" : "102", "-days", "2", "-out", `${name}.crt`]); leaves.push(fs.readFileSync(path.join(root, `${name}.crt`), "utf8")); }
    const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops/csrs`; const input = { csrPem: fs.readFileSync(path.join(root, "public.csr"), "utf8"), target: { name: "Frozen signed review", type: "host" } };
    const created = await fixture.request(prefix, "POST", input); assert.equal(created.status, 201); const route = `${prefix}/${created.body.id}`;
    let initial;
    await gate.scenario(scenarios[0], async () => { const signed = await fixture.request(`${route}/signed-certificate`, "POST", { certificatePem: leaves[0] }); assert.equal(signed.status, 200); assert.equal(signed.body.namesChanged, true); const ack = await fixture.request(`${route}/acknowledge-names`, "POST", {}); assert.equal(ack.status, 200); assert.equal(ack.body.status, "signed_pending_install"); assert.ok(ack.body.namesAcknowledgedAt); initial = ack.body; });
    await gate.scenario(scenarios[1], async () => { const repeated = await fixture.request(`${route}/signed-certificate`, "POST", { certificatePem: leaves[0] }); assert.equal(repeated.status, 200); assert.equal(repeated.body.namesAcknowledgedAt, initial.namesAcknowledgedAt); assert.equal(repeated.body.signedFingerprintSha256, initial.signedFingerprintSha256); });
    await gate.scenario(scenarios[2], async () => { const refused = await fixture.request(`${route}/signed-certificate`, "POST", { certificatePem: leaves[1] }); assert.equal(refused.status, 409); assert.equal(refused.body.code, "CERTOPS_CSR_STATE_CONFLICT"); const current = (await fixture.request(route)).body; assert.equal(current.signedFingerprintSha256, initial.signedFingerprintSha256); assert.deepEqual(current.issuedNames, initial.issuedNames); assert.equal(current.namesAcknowledgedAt, initial.namesAcknowledgedAt); });
    await gate.scenario(scenarios[3], async () => { assert.equal((await fixture.request(`${route}/cancel`, "POST", {})).status, 200); const restarted = await fixture.request(prefix, "POST", input); assert.equal(restarted.status, 201); assert.equal(restarted.body.id, initial.id); assert.equal(restarted.body.status, "pending_signature"); assert.equal(restarted.body.namesAcknowledgedAt, null); assert.equal(restarted.body.signedFingerprintSha256, null); const next = await fixture.request(`${route}/signed-certificate`, "POST", { certificatePem: leaves[1] }); assert.equal(next.status, 200); assert.equal(next.body.signedFingerprintSha256, new crypto.X509Certificate(leaves[1]).fingerprint256.replace(/:/g, "").toLowerCase()); assert.equal(next.body.namesAcknowledgedAt, null); assert.equal((await fixture.request(`${route}/confirm-installation`, "POST", {})).status, 409); }, { oracle: "Actual signed-public-material snapshot rejects redirection; explicit restart clears prior acknowledgement and requires review of the new leaf. No deployment is claimed" });
  } catch (error) { primaryError = error; throw error; }
  finally { const cleanup = async () => { try { await fixture.cleanup(); } finally { fs.rmSync(root, { recursive: true, force: true }); } }; try { if (ready) { await gate.scenario(scenarios.at(-1), cleanup); await gate.finish({ requiredScenarios: scenarios }); } else await cleanup(); } catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "CSR snapshot qualification and cleanup failed"); throw error; } }
});
