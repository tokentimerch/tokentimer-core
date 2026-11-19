"use strict";
const {test,after}=require("node:test"),assert=require("node:assert/strict");
assert.equal(process.env.DB_HOST,"127.0.0.1");
assert.match(process.env.DB_NAME||"",/^distribution_lifecycle_[a-f0-9]+_test$/);
const {pool}=require("../../apps/api/db/database");
const {migrations,runMigrations}=require("../../apps/api/migrations/migrate");
after(()=>pool.end());
test("retirement preview upgrades through PagerDuty recovery and survives restart",async()=>{
  const registry=migrations.splice(0);
  try {
    const retirement=registry.find(entry=>entry.name==="certops_retirement_dossiers");
    assert.ok(retirement);
    migrations.push(...registry.filter(entry=>entry.version<=108),{...retirement,version:109});
    await runMigrations();
    const before=(await pool.query("SELECT version,name FROM migrations ORDER BY version")).rows;
    assert.equal(before.at(-1).version,109);assert.equal(before.at(-1).name,"certops_retirement_dossiers");
    migrations.splice(0,migrations.length,...registry);
    await runMigrations();
    const upgraded=(await pool.query("SELECT version,name FROM migrations ORDER BY version")).rows;
    assert.deepEqual(upgraded.slice(0,before.length),before);
    assert.deepEqual(upgraded.slice(-6).map(row=>row.name),["certops_period_creator_delete","recipient_member_verification","auto_sync_owner_username","certops_material_reconciliation","distribution_pagerduty_recovery","auto_sync_creation_expiration"]);
    await runMigrations();
    assert.deepEqual((await pool.query("SELECT version,name FROM migrations ORDER BY version")).rows,upgraded);
  } finally { migrations.splice(0,migrations.length,...registry); }
});
