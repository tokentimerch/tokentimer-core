/**
 * Supporting API/PostgreSQL qualification: public certificate import parsing, refusal and identity conservation.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * Public requests and persisted rows are the oracle; prerequisite state is isolated.
 * Native certificate deployment is qualified separately; strict reports and cleanup apply. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const zlib = require("node:zlib");
const { spawnSync } = require("node:child_process");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("public certificate import parsing, refusal and identity conservation", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable API PostgreSQL and OpenSSL
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "certops-import-"));
  let ready = false; let primaryError;
  const gate = createHostGate({ suite: "public-import-api", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_PUBLIC_IMPORT_REPORT, requiredCapabilities: ["api", "postgres", "openssl"], fixtureSource: { file: "tests/e2e/certops-public-import-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true }, openssl: { available: spawnSync("openssl", ["version"]).status === 0 } }) });
  const run = (args) => { const result = spawnSync("openssl", args, { cwd: directory, timeout: 20000, encoding: "utf8" }); assert.equal(result.status, 0, "Independent public certificate fixture operation failed"); return result.stdout; };
  const read = (name) => fs.readFileSync(path.join(directory, name), "utf8");
  const route = `/api/v1/workspaces/${fixture.workspaceId}/certops/certificates`;
  const counts = async () => (await fixture.pool.query("SELECT (SELECT count(*)::int FROM managed_certificates WHERE workspace_id=$1) AS managed,(SELECT count(*)::int FROM tokens WHERE workspace_id=$1 AND type='ssl_cert') AS tokens,(SELECT count(*)::int FROM certops_certificate_identities WHERE workspace_id=$1) AS identities", [fixture.workspaceId])).rows[0];
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    for (const name of ["public", "bundle", "race"]) run(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.crt`, "-days", "2", "-subj", `/CN=${name}.example.test`, "-addext", `subjectAltName=DNS:${name}.example.test,IP:127.0.0.1,URI:https://${name}.example.test, email:certificate@example.test`]);
    const certificatePem = read("public.crt"); const independent = new crypto.X509Certificate(certificatePem);
    let initial;
    await gate.scenario("public-import-pem-facts", async () => {
      const result = await fixture.request(route, "POST", { certificatePem, sourceRef: "qualification-public-leaf" }); assert.equal(result.status, 201); assert.equal(result.body.count, 1); initial = result.body.items[0];
      assert.equal(initial.fingerprintSha256, independent.fingerprint256.replace(/:/g, "").toLowerCase());
      assert.equal(initial.spkiFingerprintSha256, crypto.createHash("sha256").update(independent.publicKey.export({ type: "spki", format: "der" })).digest("hex"));
      assert.equal(initial.serialNumber, run(["x509", "-in", "public.crt", "-noout", "-serial"]).trim().split("=")[1]);
      assert.equal(initial.issuer, independent.issuer); assert.equal(initial.publicKeyAlgorithm, "rsa"); assert.equal(initial.publicKeySize, 2048);
      for (const san of ["public.example.test", "127.0.0.1", "https://public.example.test", "certificate@example.test"]) assert.ok(initial.subjectAltNames.includes(san));
      assert.equal(initial.source, "api"); assert.equal(initial.sourceRef, "qualification-public-leaf");
    }, { oracle: "Independent OpenSSL serial and X509 DER/SPKI hashes, typed SAN values and actual API-persisted import provenance" });
    await gate.scenario("public-import-repeat-preserves-identity", async () => {
      const before = await counts();
      const repeated = await fixture.request(route, "POST", { certificatePem, sourceRef: "attempted-provenance-replacement" }); assert.equal(repeated.status, 201);
      assert.equal(repeated.body.items[0].id, initial.id); assert.equal(repeated.body.items[0].tokenId, initial.tokenId); assert.equal(repeated.body.items[0].sourceRef, initial.sourceRef); assert.deepEqual(await counts(), before);
    });
    await gate.scenario("public-import-bundle", async () => {
      const result = await fixture.request(`/api/v1/workspaces/${fixture.workspaceId}/certops/imports`, "POST", { certificates: [certificatePem, read("bundle.crt")] }); assert.equal(result.status, 202); assert.equal(result.body.count, 2);
      assert.equal(result.body.items[0].id, initial.id);
      assert.equal(result.body.items[1].fingerprintSha256, new crypto.X509Certificate(read("bundle.crt")).fingerprint256.replace(/:/g, "").toLowerCase());
      assert.deepEqual(await counts(), { managed: 2, tokens: 2, identities: 2 });
    }, { oracle: "Public PEM bundle imports two actual certificates; first certificate remains the existing identity/token" });
    await gate.scenario("public-import-malformed-atomic", async () => {
      const before = await counts();
      for (const certificatePem of ["invalid certificate", read("race.crt") + "\n-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----", read("public.crt") + "trailing unexpected text"]) {
        const result = await fixture.request(route, "POST", { certificatePem }); assert.equal(result.status, 400); assert.equal(result.body.code, "CERTOPS_CERTIFICATE_PARSE_FAILED");
      }
      assert.deepEqual(await counts(), before);
    });
    await gate.scenario("public-import-size-source-ref-refusal", async () => {
      const before = await counts();
      const oversized = await fixture.request(route, "POST", { certificatePem: certificatePem.repeat(70) }); assert.equal(oversized.status, 400); assert.equal(oversized.body.code, "CERTOPS_CERTIFICATE_TOO_LARGE");
      for (const sourceRef of ["password=qualification-secret", "invalid\nreference", "x".repeat(513)]) assert.equal((await fixture.request(route, "POST", { certificatePem, sourceRef })).status, 400);
      assert.deepEqual(await counts(), before);
    });
    await gate.scenario("public-import-private-input-refusal", async () => {
      const before = await counts(); const privateKey = read("public.key");
      const encoded = Buffer.from(privateKey).toString("base64"); const compressed = zlib.gzipSync(Buffer.from(privateKey)).toString("base64");
      for (const body of [{ certificatePem: privateKey }, { certificatePem: encoded }, { certificatePem, metadata: { nested: { material: compressed } } }]) {
        const rejected = await fixture.request(route, "POST", body); assert.equal(rejected.status, 422); assert.equal(rejected.body.code, "PRIVATE_KEY_MATERIAL_REJECTED");
        assert.ok(!JSON.stringify(rejected.body).includes(privateKey) && !JSON.stringify(rejected.body).includes(encoded));
      }
      assert.deepEqual(await counts(), before);
    });
    await gate.scenario("public-import-exact-der-parser", async () => {
      run(["x509", "-in", "public.crt", "-outform", "DER", "-out", "public.der"]);
      const der = fs.readFileSync(path.join(directory, "public.der"));
      const { parsePublicCertificateMaterial } = require("../../apps/api/services/certops/parser");
      assert.equal(parsePublicCertificateMaterial(der)[0].fingerprintSha256, initial.fingerprintSha256);
      assert.deepEqual(parsePublicCertificateMaterial(der)[0].subjectAltNameEntries.map((entry) => entry.type), ["dns", "ip", "uri", "email"]);
      assert.throws(() => parsePublicCertificateMaterial(Buffer.concat([der, Buffer.from([0])])), { code: "CERTOPS_CERTIFICATE_PARSE_FAILED" });
      assert.throws(() => parsePublicCertificateMaterial(Buffer.concat([der, der])), { code: "CERTOPS_CERTIFICATE_PARSE_FAILED" });
      assert.equal((await fixture.request(route, "POST", { certificatePem: der })).status, 400);
    }, { evidenceLevel: "unit", oracle: "Real OpenSSL DER bytes exercise the production parser directly; the public JSON API accepts PEM, and DER JSON objects are explicitly refused" });
    await gate.scenario("public-import-concurrent-conservation", async () => {
      const results = await Promise.all(Array.from({ length: 4 }, () => fixture.request(route, "POST", { certificatePem: read("race.crt"), sourceRef: "qualification-concurrent-import" })));
      for (const result of results) assert.equal(result.status, 201);
      assert.equal(new Set(results.map((result) => result.body.items[0].id)).size, 1);
      assert.equal(new Set(results.map((result) => result.body.items[0].tokenId)).size, 1);
      assert.deepEqual(await counts(), { managed: 3, tokens: 3, identities: 3 });
    }, { oracle: "Four concurrent public imports of previously unseen real certificate conserve one identity, managed asset and token" });
  } catch (error) { primaryError = error; throw error; }
  finally {
    const cleanup = async () => { try { await fixture.cleanup(); } finally { fs.rmSync(directory, { recursive: true, force: true }); } };
    try { if (ready) { await gate.scenario("public-import-cleanup", cleanup); await gate.finish({ requiredScenarios: require("../../docs/certops/qualification-suites.json").suites["public-import-api"] }); } else await cleanup(); }
    catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Public import qualification and cleanup failed"); throw error; }
  }
});
