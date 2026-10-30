"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {migrations,validateMigrationHistory}=require("../../apps/api/migrations/migrate");
const {composeMigrations}=require("../../apps/api/migrations/compose-migrations");
const histories=require("../helpers/distribution-migration-histories.cjs");
for(const [history,names] of Object.entries(histories))test(`preserves ${history} identities and moves only unapplied migrations`,()=>{
  const rows=[...migrations.filter(m=>m.version<=77).map(({version,name})=>({version,name})),...names.map((name,index)=>({version:78+index,name}))];
  const snapshot=structuredClone(rows),plan=composeMigrations(migrations,rows);
  validateMigrationHistory(rows);
  assert.deepEqual(rows,snapshot);assert.equal(plan.length,migrations.length);
  assert.equal(new Set(plan.map(m=>m.version)).size,plan.length);
  assert.equal(new Set(plan.map(m=>m.name)).size,plan.length);
  for(const row of rows)assert.equal(plan.find(m=>m.version===row.version).name,row.name);
  for(const m of plan)assert.equal(m.sql,migrations.find(original=>original.name===m.name).sql);
  const repeated=composeMigrations(migrations,plan.map(({version,name})=>({version,name})));
  assert.deepEqual(repeated,plan);
});
test("unknown, duplicate and dependency-incomplete migration histories fail closed",()=>{
  const prefix=migrations.filter(m=>m.version<=80).map(({version,name})=>({version,name}));
  for(const tail of [
    [{version:81,name:"unknown_extension"}],
    [{version:81,name:"weekly_digest_recipient_claim_token"}],
    [{version:81,name:"auto_sync_run_metrics"}],
    [{version:82,name:"recipient_channel_verification"}],
  ])assert.throws(()=>composeMigrations(migrations,[...prefix,...tail]));
});
