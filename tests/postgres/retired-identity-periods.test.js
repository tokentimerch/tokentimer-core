"use strict";
const { test, after } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.match(process.env.DB_NAME || "", /^pr329_.*_test$/);
assert.equal(process.env.NODE_ENV, "test");
const { pool } = require("../../apps/api/db/database");
const { retireCertificateIdentity, readdManagingSource } = require("../../apps/api/services/certops/certificateIdentity");
after(() => pool.end());

for (const status of ["revoked", "decommissioned"]) {
  for (const legacy of [false, true]) {
  test(`${status}, legacy=${legacy}: closes current source periods and retains history`, async () => {
    const workspaceId = crypto.randomUUID();
    const fingerprint = crypto.randomBytes(32).toString("hex");
    const user = (await pool.query(`INSERT INTO users(email,display_name,password_hash,auth_method)
      VALUES($1,'Retirement test','synthetic-fixture','local') RETURNING id`, [`retire-${workspaceId}@example.test`])).rows[0].id;
    await pool.query("INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'Retirement fixture',$2,'team')", [workspaceId, user]);
    for (let i = 0; i < 2; i++) {
      await pool.query(`INSERT INTO managed_certificates(workspace_id,name,status,source,fingerprint_sha256)
        VALUES($1,$2,'active','agent_filesystem',$3)`, [workspaceId, `source-${i}`, fingerprint]);
    }
    const identityId = (await pool.query("SELECT id FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2", [workspaceId, fingerprint])).rows[0].id;
    const rotated = (await pool.query(`INSERT INTO managed_certificates(workspace_id,name,status,source,fingerprint_sha256)
      VALUES($1,'rotated','active','agent_filesystem',$2) RETURNING id`, [workspaceId, fingerprint])).rows[0].id;
    await pool.query("UPDATE managed_certificates SET fingerprint_sha256=$2,identity_observed_at=clock_timestamp() WHERE id=$1", [rotated, crypto.randomBytes(32).toString("hex")]);
    await pool.query(`INSERT INTO managed_certificates(workspace_id,name,status,source,fingerprint_sha256)
      VALUES($1,'other','active','agent_filesystem',$2)`, [workspaceId, crypto.randomBytes(32).toString("hex")]);
    const before = (await pool.query("SELECT id FROM certops_management_periods WHERE workspace_id=$1 AND current_identity_id=$2 AND ended_at IS NULL", [workspaceId, identityId])).rows;
    assert.equal(before.length, 2);
    if (legacy) await pool.query("UPDATE certops_certificate_identities SET lifecycle_status=$3 WHERE workspace_id=$1 AND id=$2", [workspaceId, identityId, status]);
    const result = await retireCertificateIdentity({ workspaceId, identityId, expectedFingerprintSha256: fingerprint,
      status, reason: "Certificate intentionally retired", acknowledgeUncertainty: true, actorUserId: user });
    assert.equal(result.managed, false);
    const rows = (await pool.query("SELECT * FROM certops_management_periods WHERE workspace_id=$1 AND current_identity_id=$2", [workspaceId, identityId])).rows;
    assert.equal(rows.length, 2);
    for (const row of rows) {
      assert.ok(row.ended_at);
      assert.equal(row.ended_reason, `certificate_${status}`);
      assert.equal(row.automation_enabled, false);
    }
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM certops_management_associations WHERE workspace_id=$1 AND identity_id=$2", [workspaceId, identityId])).rows[0].n, 3);
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM certops_management_periods WHERE workspace_id=$1 AND ended_at IS NULL", [workspaceId])).rows[0].n, 2);
    // Repeating retirement is idempotent and repairs open periods left by older builds.
    await retireCertificateIdentity({ workspaceId, identityId, expectedFingerprintSha256: fingerprint, status,
      reason: "Repeat retirement", acknowledgeUncertainty: true, actorUserId: user });
    assert.equal((await pool.query("SELECT ended_at FROM certops_management_periods WHERE id=$1", [rows[0].id])).rows[0].ended_at.toISOString(), rows[0].ended_at.toISOString());
    const sourceId = rows[0].managed_certificate_id;
    const readd = () => readdManagingSource({ workspaceId, managedCertificateId: sourceId,
      renewalProfileId: null, automationEnabled: false });
    await assert.rejects(readd(), { code: "CERTOPS_CERTIFICATE_RETIRED" });
    const replacement = crypto.randomBytes(32).toString("hex");
    await pool.query("UPDATE managed_certificates SET fingerprint_sha256=$2,identity_observed_at=clock_timestamp(),status='active' WHERE id=$1", [sourceId, replacement]);
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM certops_management_periods WHERE managed_certificate_id=$1 AND ended_at IS NULL", [sourceId])).rows[0].n, 0,
      "a fresh observation does not implicitly resume management");
    const started = await readd();
    assert.notEqual(started.periodId, rows[0].id);
    assert.equal((await pool.query("SELECT current_identity_id FROM certops_management_periods WHERE id=$1", [started.periodId])).rows[0].current_identity_id,
      (await pool.query("SELECT id FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2", [workspaceId, replacement])).rows[0].id);
  });
  }
}
