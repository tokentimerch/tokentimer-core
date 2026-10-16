/**
 * Supporting API/PostgreSQL qualification: public token transfer preserves certificate/CSR lineage, target association, immutable audit history and workspace authority.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * Public requests and persisted rows are the oracle; prerequisite state is isolated.
 * Native certificate deployment is qualified separately; strict reports and cleanup apply. */
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
  const scenarios = ["transfer-api-dual-role-required", "transfer-api-identity-conflict-atomic", "transfer-api-owned-certificate-move", "transfer-api-replay-source-fence", "transfer-api-viewer-refusal", "transfer-api-csr-lineage-created", "transfer-api-csr-lineage-move", "transfer-api-audit-history", "transfer-api-csr-outside-token-refusal", "transfer-api-cleanup"];
  const gate = createHostGate({ suite: "certificate-transfer-api", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_TRANSFER_REPORT, requiredCapabilities: ["api", "postgres", "openssl"], fixtureSource: { file: "tests/e2e/certops-certificate-transfer-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true }, openssl: { available: spawnSync("openssl", ["version"]).status === 0 } }) });
  try {
    assert.equal(await gate.preflight(), true); ready = true; destination = await createApiFixture(baseUrl);
    const imported = [];
    for (const name of ["conflict", "unique", "outside"]) { assert.equal(spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.crt`, "-subj", `/CN=${name}.example.test`, "-days", "2"], { cwd: root, timeout: 20000 }).status, 0, "Public certificate fixture failed"); const response = await fixture.request(`/api/v1/workspaces/${fixture.workspaceId}/certops/certificates`, "POST", { certificatePem: fs.readFileSync(path.join(root, `${name}.crt`), "utf8") }); assert.equal(response.status, 201); imported.push(response.body.items[0]); }
    const route = `/api/v1/workspaces/${destination.workspaceId}/transfer-tokens`;
    const transfer = (ids) => fixture.request(route, "POST", { from_workspace_id: fixture.workspaceId, token_ids: ids });
    const ownership = async (item) => (await fixture.pool.query("SELECT workspace_id,token_id FROM managed_certificates WHERE id=$1", [item.id])).rows[0];
    await gate.scenario(scenarios[0], async () => { assert.equal((await transfer([imported[1].tokenId])).status, 403); assert.equal(String((await ownership(imported[1])).workspace_id), String(fixture.workspaceId)); });
    await gate.scenario("transfer-api-viewer-refusal", async () => {
      await fixture.pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'viewer')", [destination.workspaceId, fixture.userId]);
      assert.equal((await transfer([imported[1].tokenId])).status, 403);
      assert.equal(String((await ownership(imported[1])).workspace_id), String(fixture.workspaceId));
      await fixture.pool.query("DELETE FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2", [destination.workspaceId,fixture.userId]);
    });
    await fixture.pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'workspace_manager')", [destination.workspaceId, fixture.userId]);
    const duplicate = await destination.request(`/api/v1/workspaces/${destination.workspaceId}/certops/certificates`, "POST", { certificatePem: fs.readFileSync(path.join(root, "conflict.crt"), "utf8") }); assert.equal(duplicate.status, 201);
    await gate.scenario(scenarios[1], async () => { const response = await transfer(imported.map((item) => item.tokenId)); assert.equal(response.status, 409); assert.equal(response.body.code, "TRANSFER_CONFLICT"); for (const item of imported) assert.equal(String((await ownership(item)).workspace_id), String(fixture.workspaceId)); });
    const csrRoute = `/api/v1/workspaces/${fixture.workspaceId}/certops/csrs`;
    let lineage, originalAudit;
    await gate.scenario("transfer-api-csr-lineage-created", async () => {
      assert.equal(spawnSync("openssl", ["req","-new","-key","unique.key","-out","unique.csr","-subj","/CN=unique.example.test"], {cwd:root,timeout:20000}).status,0);
      const created=await fixture.request(csrRoute,"POST",{csrPem:fs.readFileSync(path.join(root,"unique.csr"),"utf8"),existingCertificateId:imported[1].id,target:{name:"Transfer manual CSR target",type:"host"}});
      assert.equal(created.status,201);const signed=await fixture.request(`${csrRoute}/${created.body.id}/signed-certificate`,"POST",{certificatePem:fs.readFileSync(path.join(root,"unique.crt"),"utf8")});assert.equal(signed.status,200);
      const confirmed=await fixture.request(`${csrRoute}/${created.body.id}/confirm-installation`,"POST",{});assert.equal(confirmed.status,200);assert.equal(confirmed.body.confirmationMethod,"manual");lineage=confirmed.body;
      assert.equal(lineage.existingCertificateId,imported[1].id);assert.equal(lineage.managedCertificateId,imported[1].id);
      originalAudit=(await fixture.pool.query("SELECT id,workspace_id,action,metadata FROM audit_events WHERE workspace_id=$1 AND metadata->>'workflow_id'=$2 ORDER BY id",[fixture.workspaceId,lineage.id])).rows;
      // Manual attestation is a control-plane record, not physical deployment proof.
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_instances WHERE workspace_id=$1 AND target_id=$2",[fixture.workspaceId,lineage.targetId])).rows[0].count,0);
    });
    await gate.scenario(scenarios[2], async () => { const response = await transfer([imported[1].tokenId]); assert.equal(response.status, 200); assert.equal(response.body.moved, 1); assert.equal(String((await ownership(imported[1])).workspace_id), String(destination.workspaceId)); const detail = await destination.request(`/api/v1/workspaces/${destination.workspaceId}/certops/certificates/${imported[1].id}`); assert.equal(detail.status, 200); assert.equal(detail.body.certificate.fingerprintSha256, imported[1].fingerprintSha256); assert.equal((await fixture.request(`/api/v1/workspaces/${fixture.workspaceId}/certops/certificates/${imported[1].id}`)).status, 404); });
    await gate.scenario(scenarios[3], async () => { const repeated = await transfer([imported[1].tokenId]); assert.equal(repeated.status, 200); assert.equal(repeated.body.moved, 0); assert.equal(String((await ownership(imported[1])).workspace_id), String(destination.workspaceId)); assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM managed_certificates WHERE id=$1", [imported[1].id])).rows[0].count, 1); }, { oracle: "Actual token transfer and certificate inventory move together; foreign and colliding identities remain untouched, no host key custody is claimed" });
    await gate.scenario("transfer-api-csr-lineage-move", async () => {
      const moved=await destination.request(`/api/v1/workspaces/${destination.workspaceId}/certops/csrs/${lineage.id}`);assert.equal(moved.status,200);assert.equal(moved.body.workspaceId,destination.workspaceId);
      for(const field of ["id","targetId","existingCertificateId","managedCertificateId","csrPem","signedLeafPem","signedChainPem","requestedNames","issuedNames","csrDerSha256","spkiFingerprintSha256","signedFingerprintSha256","status","confirmationMethod","confirmedAt","confirmedBy"])assert.deepEqual(moved.body[field],lineage[field],field);
      assert.equal((await fixture.request(`${csrRoute}/${lineage.id}`)).status,404);
      const target=(await fixture.pool.query("SELECT workspace_id,name,source FROM certificate_targets WHERE id=$1",[lineage.targetId])).rows[0];assert.equal(target.workspace_id,destination.workspaceId);assert.equal(target.name,"Transfer manual CSR target");assert.equal(target.source,"api");
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_csr_workflows WHERE id=$1",[lineage.id])).rows[0].count,1);
    });
    await gate.scenario("transfer-api-audit-history", async () => {
      const previous=(await fixture.pool.query("SELECT id,workspace_id,action,metadata FROM audit_events WHERE workspace_id=$1 AND metadata->>'workflow_id'=$2 ORDER BY id",[fixture.workspaceId,lineage.id])).rows;assert.ok(previous.length>=3);assert.deepEqual(previous,originalAudit,"Historical CSR audit stays immutable in its original workspace");
      const listed=await destination.request(`/api/v1/workspaces/${destination.workspaceId}/audit-events?action=TOKENS_TRANSFERRED_BETWEEN_WORKSPACES`);assert.equal(listed.status,200);
      const moved=listed.body.find(row=>row.metadata.from_workspace_id===fixture.workspaceId&&row.metadata.moved===1);assert.ok(moved);assert.equal(moved.metadata.to_workspace_id,destination.workspaceId);assert.equal(moved.actor_user_id,fixture.userId);
      assert.ok(!listed.body.some(row=>previous.some(old=>String(old.id)===String(row.id))));
    });
    await gate.scenario("transfer-api-csr-outside-token-refusal", async () => {
      const created=await fixture.request(csrRoute,"POST",{csrPem:fs.readFileSync(path.join(root,"unique.csr"),"utf8"),existingCertificateId:imported[2].id,target:{name:"Transfer linked target prerequisite",type:"host"}});assert.equal(created.status,201);
      // Seed only a supported target association prerequisite; the transfer and
      // its transaction refusal use the real public API and PostgreSQL service.
      await fixture.pool.query("UPDATE certificate_targets SET token_id=$1 WHERE workspace_id=$2 AND id=$3",[imported[0].tokenId,fixture.workspaceId,created.body.targetId]);
      const before=(await fixture.pool.query("SELECT * FROM certificate_csr_workflows WHERE id=$1",[created.body.id])).rows[0];const response=await transfer([imported[2].tokenId]);assert.equal(response.status,409);assert.equal(response.body.code,"TRANSFER_CONFLICT");assert.match(response.body.error,/CSR workflow target.*outside this transfer/);
      assert.equal(String((await ownership(imported[2])).workspace_id),String(fixture.workspaceId));assert.deepEqual((await fixture.pool.query("SELECT * FROM certificate_csr_workflows WHERE id=$1",[created.body.id])).rows[0],before);
      assert.equal((await fixture.pool.query("SELECT workspace_id,token_id FROM certificate_targets WHERE id=$1",[created.body.targetId])).rows[0].workspace_id,fixture.workspaceId);
    });
  } catch (error) { primaryError = error; throw error; }
  finally { const cleanup = async () => { try { if (destination) await destination.cleanup(); } finally { try { await fixture.cleanup(); } finally { fs.rmSync(root, { recursive: true, force: true }); } } }; try { if (ready) { await gate.scenario(scenarios.at(-1), cleanup); await gate.finish({ requiredScenarios: scenarios }); } else await cleanup(); } catch (error) { if (primaryError) throw new AggregateError([primaryError, error], "Certificate transfer qualification and cleanup failed"); throw error; } }
});
