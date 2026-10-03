"use strict";

const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { Pool, Client } = require("pg");
const { migrations, applyMigrationSql } = require("../../apps/api/migrations/migrate");
const { listCertificateIdentities, stopManagingSource } = require("../../apps/api/services/certops/certificateIdentity");
const config = {
  host: process.env.DB_HOST || "localhost", port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || "tokentimer", password: process.env.DB_PASSWORD || "password",
};
const dbName = `certops_details_${process.pid}_${Date.now()}`;
const A = "a".repeat(64), B = "b".repeat(64);

describe("Certificate details survive management and token history changes", function () {
  this.timeout(90000);
  let db, userId;
  before(async () => {
    const admin = new Client({ ...config, database: process.env.DB_NAME || "tokentimer" });
    await admin.connect();
    await admin.query(`CREATE DATABASE ${dbName}`);
    await admin.end();
    db = new Pool({ ...config, database: dbName });
    const client = await db.connect();
    try {
      for (const migration of migrations) {
        await client.query("BEGIN");
        await applyMigrationSql(client, migration);
        await client.query("COMMIT");
      }
    } finally { client.release(); }
    userId = (await db.query(`INSERT INTO users(email,email_original,display_name,password_hash,auth_method)
      VALUES('details@example.test','details@example.test','Identity Details','x','local') RETURNING id`)).rows[0].id;
  });
  after(async () => {
    if (db) await db.end();
    const admin = new Client({ ...config, database: process.env.DB_NAME || "tokentimer" });
    await admin.connect();
    await admin.query(`DROP DATABASE IF EXISTS ${dbName}`);
    await admin.end();
  });
  async function workspace() {
    return (await db.query(`INSERT INTO workspaces(id,name,plan,created_by)
      VALUES(gen_random_uuid(),'Details history','oss',$1) RETURNING id`, [userId])).rows[0].id;
  }
  async function fixture() {
    const ws = await workspace();
    const tid = (await db.query(`INSERT INTO tokens(workspace_id,user_id,name,type,expiration,serial_number,notes)
      VALUES($1,$2,'Certificate A','ssl_cert','2027-01-01','AA','Notes for A') RETURNING id`, [ws, userId])).rows[0].id;
    const mc = (await db.query(`INSERT INTO managed_certificates(workspace_id,source,source_ref,fingerprint_sha256,
      name,token_id,serial_number,not_before,not_after,identity_observed_at)
      VALUES($1,'agent_filesystem',$2,$3,'Certificate A',$4,'AA','2026-01-01','2027-01-01',NOW()-INTERVAL '1 minute') RETURNING *`,
    [ws, randomUUID(), A, tid])).rows[0];
    return { ws, tid, mc };
  }
  async function detail(ws, fp) {
    const id = (await db.query("SELECT id FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2", [ws, fp])).rows[0].id;
    return (await listCertificateIdentities({ workspaceId: ws, identityId: id, client: db })).items[0];
  }
  async function updateSource(mc) {
    await db.query(`UPDATE managed_certificates SET fingerprint_sha256=$2,serial_number='BB',not_after='2028-01-01',
      identity_observed_at=NOW(),name='Certificate B' WHERE id=$1`, [mc.id, B]);
  }
  async function updateToken(tid) {
    await db.query(`UPDATE tokens SET name='Certificate B',serial_number='BB',expiration='2028-01-01',notes='Notes for B' WHERE id=$1`, [tid]);
  }
  it("keeps full token and X.509 details after closing the final management period", async () => {
    const { ws, tid, mc } = await fixture();
    const p = (await db.query("SELECT id FROM certops_management_periods WHERE managed_certificate_id=$1 AND ended_at IS NULL", [mc.id])).rows[0];
    await stopManagingSource({ workspaceId: ws, periodId: p.id, client: db });
    const result = await detail(ws, A);
    assert.equal(result.managed, false);
    assert.equal(result.activeSourceCount, 0);
    assert.equal(result.tokenId, tid);
    assert.equal(result.tokenSnapshot.notes, "Notes for A");
    assert.equal(result.certificateSnapshot.serialNumber, "AA");
    assert.equal(result.certificateSnapshot.notBefore, "2026-01-01T00:00:00+00:00");
    await db.query("UPDATE tokens SET notes='Edited after stop' WHERE id=$1", [tid]);
    assert.equal((await detail(ws, A)).tokenSnapshot.notes, "Edited after stop");
  });
  for (const order of ["token-first", "source-first"]) {
    it(`retains independent A/B public details during ${order} rotation`, async () => {
      const { ws, tid, mc } = await fixture();
      if (order === "token-first") { await updateToken(tid); await updateSource(mc); }
      else {
        await updateSource(mc);
        const intermediate = await detail(ws, B);
        assert.equal(intermediate.tokenId, null);
        assert.equal(intermediate.tokenSnapshot, null);
        await updateToken(tid);
      }
      const a = await detail(ws, A), b = await detail(ws, B);
      assert.equal(a.tokenId, null);
      assert.equal(a.tokenSnapshot.name, "Certificate A");
      assert.equal(a.tokenSnapshot.notes, "Notes for A");
      assert.equal(a.certificateSnapshot.serialNumber, "AA");
      assert.equal(b.tokenId, tid);
      assert.equal(b.tokenSnapshot.notes, "Notes for B");
      assert.equal(b.certificateSnapshot.serialNumber, "BB");
      assert(a.sources.every(s => s.tokenId === null));
      await db.query("UPDATE tokens SET notes='Later B edit' WHERE id=$1", [tid]);
      assert.equal((await detail(ws, A)).tokenSnapshot.notes, "Notes for A");
      assert.equal((await detail(ws, B)).tokenSnapshot.notes, "Later B edit");
    });
  }
  it("keeps original public history without exposing moved token or destination edits", async () => {
    const { ws, tid } = await fixture(), to = await workspace();
    await db.query("UPDATE tokens SET workspace_id=$2,notes='Destination secret note' WHERE id=$1", [tid, to]);
    const original = await detail(ws, A);
    assert.equal(original.tokenId, null);
    assert.equal(original.tokenSnapshot.notes, "Notes for A");
    assert(original.sources.every(s => s.tokenId === null));
    assert(!JSON.stringify(original).includes("Destination secret note"));
    assert.equal((await listCertificateIdentities({ workspaceId: to, identityId: original.identityId, client: db })).items.length, 0);
  });
  it("retains read-only public fields after token deletion and excludes arbitrary/private metadata", async () => {
    const { ws, tid, mc } = await fixture();
    await db.query("UPDATE managed_certificates SET public_metadata=$2::jsonb WHERE id=$1", [mc.id, JSON.stringify({ privateKey: "DO NOT EXPOSE", subject: "" })]);
    await db.query("DELETE FROM tokens WHERE id=$1", [tid]);
    const result = await detail(ws, A);
    assert.equal(result.tokenId, null);
    assert.equal(result.tokenSnapshot.notes, "Notes for A");
    assert(!JSON.stringify(result).includes("DO NOT EXPOSE"));
    assert(!Object.hasOwn(result.tokenSnapshot, "id"));
  });
  it("idempotent backfill cannot invent token fields for an already rotated identity", async () => {
    const { ws, tid, mc } = await fixture();
    await updateToken(tid); await updateSource(mc);
    await db.query("DELETE FROM certops_identity_detail_history WHERE workspace_id=$1", [ws]);
    await db.query(migrations.find(m => m.name === "certops_identity_detail_history").sql);
    const a = await detail(ws, A), b = await detail(ws, B);
    assert.equal(a.tokenSnapshot, null);
    assert.equal(a.certificateSnapshot, null);
    assert.equal(b.tokenSnapshot.notes, "Notes for B");
    await db.query(migrations.find(m => m.name === "certops_identity_detail_history").sql);
    assert.equal((await detail(ws, B)).tokenSnapshot.notes, "Notes for B");
  });
  it("keeps one canonical token and its notes when multiple sources have distinct tokens for A", async () => {
    const { ws, tid } = await fixture();
    const secondary = (await db.query(`INSERT INTO tokens(workspace_id,user_id,name,type,expiration,serial_number,notes)
      VALUES($1,$2,'Secondary token A','ssl_cert','2027-01-01','AA','Secondary A notes') RETURNING id`, [ws, userId])).rows[0].id;
    await db.query(`INSERT INTO managed_certificates(workspace_id,source,source_ref,fingerprint_sha256,
      name,token_id,serial_number,not_after,identity_observed_at)
      VALUES($1,'agent_filesystem',$2,$3,'Secondary A',$4,'AA','2027-01-01',NOW())`, [ws, randomUUID(), A, secondary]);
    await db.query("UPDATE tokens SET notes='Edited secondary notes' WHERE id=$1", [secondary]);
    const result = await detail(ws, A);
    assert.equal(result.tokenId, tid);
    assert.equal(result.tokenSnapshot.name, "Certificate A");
    assert.equal(result.tokenSnapshot.notes, "Notes for A");
    assert.equal(result.sourceCount, 2);
    await db.query("UPDATE tokens SET notes='Edited canonical notes' WHERE id=$1", [result.tokenId]);
    assert.equal((await detail(ws, A)).tokenSnapshot.notes, "Edited canonical notes");
    assert.equal((await db.query("SELECT notes FROM tokens WHERE id=$1", [secondary])).rows[0].notes, "Edited secondary notes");
    await updateToken(tid);
    const historical = await detail(ws, A);
    assert.equal(historical.tokenId, null);
    assert.equal(historical.tokenSnapshot.notes, "Edited canonical notes");
  });
  it("a less complete second source cannot erase retained X.509 facts for the same fingerprint", async () => {
    const { ws } = await fixture();
    await db.query(`INSERT INTO managed_certificates(workspace_id,source,source_ref,fingerprint_sha256,name,identity_observed_at)
      VALUES($1,'agent_filesystem',$2,$3,'Sparse A',NOW())`, [ws, randomUUID(), A]);
    const result = await detail(ws, A);
    assert.equal(result.certificateSnapshot.serialNumber, "AA");
    assert.equal(result.certificateSnapshot.notBefore, "2026-01-01T00:00:00+00:00");
    assert.equal(result.certificateSnapshot.notAfter, "2027-01-01T00:00:00+00:00");
    assert.equal(result.tokenSnapshot.notes, "Notes for A");
  });
  it("source-then-token workspace transfer seeds only destination details while retaining original history", async () => {
    const { ws, tid, mc } = await fixture(), to = await workspace();
    await db.query("SELECT certops_transfer_management_sources($1,$2,$3::uuid[])", [ws, to, [mc.id]]);
    await db.query("UPDATE tokens SET workspace_id=$2,notes='Destination notes' WHERE id=$1", [tid, to]);
    const old = await detail(ws, A), current = await detail(to, A);
    assert.equal(old.tokenId, null);
    assert.equal(old.tokenSnapshot.notes, "Notes for A");
    assert.equal(current.tokenId, tid);
    assert.equal(current.tokenSnapshot.notes, "Destination notes");
  });
  it("backfill prefers the oldest verified token over an older divergent token and safely fills missing details on rerun", async () => {
    const { ws, tid } = await fixture();
    await db.query(`INSERT INTO managed_certificates(workspace_id,source,source_ref,fingerprint_sha256,name,
      token_id,serial_number,not_after,identity_observed_at)
      VALUES($1,'agent_filesystem',$2,$3,'Shared-token B',$4,'BB','2028-01-01',NOW())`, [ws, randomUUID(), B, tid]);
    const incompleteToken = (await db.query(`INSERT INTO tokens(workspace_id,user_id,name,type,expiration,notes)
      VALUES($1,$2,'Unverified older A','ssl_cert','2027-01-01','Unverified notes') RETURNING id`, [ws, userId])).rows[0].id;
    await db.query(`INSERT INTO managed_certificates(workspace_id,source,source_ref,fingerprint_sha256,name,
      token_id,serial_number,not_after,identity_observed_at)
      VALUES($1,'agent_filesystem',$2,$3,'Incomplete-token A',$4,'AA','2027-01-01',NOW())`, [ws, randomUUID(), A, incompleteToken]);
    const endpointToken = (await db.query(`INSERT INTO tokens(workspace_id,user_id,name,type,expiration,serial_number,notes)
      VALUES($1,$2,'Verified endpoint A','ssl_cert','2027-01-01','AA','Verified endpoint notes') RETURNING id`, [ws, userId])).rows[0].id;
    const monitor = (await db.query(`INSERT INTO domain_monitors(workspace_id,created_by,url)
      VALUES($1,$2,$3) RETURNING id`, [ws, userId, `https://${randomUUID()}.example.test`])).rows[0].id;
    await db.query(`INSERT INTO managed_certificates(workspace_id,source,source_ref,fingerprint_sha256,name,
      token_id,serial_number,not_after,identity_observed_at,public_metadata)
      VALUES($1,'endpoint_monitor',$2,$3,'Endpoint A',$4,'AA','2027-01-01',NOW(),$5::jsonb)`,
    [ws, monitor, A, endpointToken, JSON.stringify({domainMonitorId:monitor})]);
    await db.query("DELETE FROM certops_identity_detail_history WHERE workspace_id=$1", [ws]);
    const backfill = migrations.find(m => m.name === "certops_identity_detail_history").sql;
    await db.query(backfill);
    assert.equal((await detail(ws, A)).tokenId, endpointToken);
    assert.equal((await detail(ws, A)).tokenSnapshot.notes, "Verified endpoint notes");
    assert.equal((await detail(ws, B)).tokenSnapshot, null);
    await db.query(`UPDATE certops_identity_detail_history SET token_id=NULL,token_details=NULL
      WHERE workspace_id=$1 AND identity_id=(SELECT id FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2)`, [ws, A]);
    await db.query(backfill);
    assert.equal((await detail(ws, A)).tokenId, endpointToken);
    assert.equal((await detail(ws, A)).tokenSnapshot.notes, "Verified endpoint notes");
    await db.query("UPDATE tokens SET notes='Canonical notes survive rerun' WHERE id=$1", [endpointToken]);
    await db.query(backfill);
    assert.equal((await detail(ws, A)).tokenSnapshot.notes, "Canonical notes survive rerun");
    assert.equal((await detail(ws, B)).tokenSnapshot, null);
  });
});
