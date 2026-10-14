"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), os = require("node:os"), crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
test("public certificate token transfer preserves workspace authority and atomic identity conflicts", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable API PostgreSQL and OpenSSL
    t.skip("Disposable API URL required"); return;
  }
  assert.ok(baseUrl); const fixture = await createApiFixture(baseUrl); let destination, ready = false, primaryError;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certificate-transfer-"));
  const scenarios = ["transfer-api-dual-role-required", "transfer-api-identity-conflict-atomic", "transfer-api-owned-certificate-move", "transfer-api-replay-source-fence", "transfer-api-cleanup"];
  const gate = createHostGate({ suite: "certificate-transfer-api", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_TRANSFER_REPORT, requiredCapabilities: ["api", "postgres", "openssl"], fixtureSource: { file: "tests/e2e/certops-certificate-transfer-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true }, openssl: { available: spawnSync("openssl", ["version"]).status === 0 } }) });
  try {
    assert.equal(await gate.preflight(), true); ready = true; destination = await createApiFixture(baseUrl);
    const imported = [];
    for (const name of ["conflict", "unique"]) { assert.equal(spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.crt`, "-subj", `/CN=${name}.example.test`, "-days", "2"], { cwd: root, timeout: 20000 }).status, 0, "Public certificate fixture failed"); const response = await fixture.request(`/api/v1/workspaces/${fixture.workspaceId}/certops/certificates`, "POST", { certificatePem: fs.readFileSync(path.join(root, `${name}.crt`), "utf8") }); assert.equal(response.status, 201); imported.push(response.body.items[0]); }
    const route = `/api/v1/workspaces/${destination.workspaceId}/transfer-tokens`;
    const transfer = (ids) => fixture.request(route, "POST", { from_workspace_id: fixture.workspaceId, token_ids: ids });
    const ownership = async (item) => (await fixture.pool.query("SELECT workspace_id,token_id FROM managed_certificates WHERE id=$1", [item.id])).rows[0];
    await gate.scenario(scenarios[0], async () => { assert.equal((await transfer([imported[1].tokenId])).status, 403); assert.equal(String((await ownership(imported[1])).workspace_id), String(fixture.workspaceId)); });
    await fixture.pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'workspace_manager')", [destination.workspaceId, fixture.userId]);
    const duplicate = await destination.request(`/api/v1/workspaces/${destination.workspaceId}/certops/certificates`, "POST", { certificatePem: fs.readFileSync(path.join(root, "conflict.crt"), "utf8") }); assert.equal(duplicate.status, 201);
    await gate.scenario(scenarios[1], async () => { const response = await transfer(imported.map((item) => item.tokenId)); assert.equal(response.status, 409); assert.equal(response.body.code, "TRANSFER_CONFLICT"); for (const item of imported) assert.equal(String((await ownership(item)).workspace_id), String(fixture.workspaceId)); });
    await gate.scenario(scenarios[2], async () => { const response = await transfer([imported[1].tokenId]); assert.equal(response.status, 200); assert.equal(response.body.moved, 1); assert.equal(String((await ownership(imported[1])).workspace_id), String(destination.workspaceId)); const detail = await destination.request(`/api/v1/workspaces/${destination.workspaceId}/certops/certificates/${imported[1].id}`); assert.equal(detail.status, 200); assert.equal(detail.body.certificate.fingerprintSha256, imported[1].fingerprintSha256); assert.equal((await fixture.request(`/api/v1/workspaces/${fixture.workspaceId}/certops/certificates/${imported[1].id}`)).status, 404); });
    await gate.scenario(scenarios[3], async () => { const repeated = await transfer([imported[1].tokenId]); assert.equal(repeated.status, 200); assert.equal(repeated.body.moved, 0); assert.equal(String((await ownership(imported[1])).workspace_id), String(destination.workspaceId)); assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM managed_certificates WHERE id=$1", [imported[1].id])).rows[0].count, 1); }, { oracle: "Actual token transfer and certificate inventory move together; foreign and colliding identities remain untouched, no host key custody is claimed" });
  } catch (error) { primaryError = error; throw error; }
  finally { const cleanup = async () => { try { if (destination) await destination.cleanup(); } finally { try { await fixture.cleanup(); } finally { fs.rmSync(root, { recursive: true, force: true }); } } }; try { if (ready) { await gate.scenario(scenarios.at(-1), cleanup); await gate.finish({ requiredScenarios: scenarios }); } else await cleanup(); } catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Certificate transfer qualification and cleanup failed"); throw error; } }
});
