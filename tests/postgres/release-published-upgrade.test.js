"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { randomUUID } = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { seedCertOpsUpgrade, snapshotCertOpsUpgrade, assertCertOpsUpgradePreserved } = require("../helpers/release-upgrade-certops.cjs");

test("published Core 0.18.2 CertOps rows and full ledger survive candidate migration and replay", {timeout:240000}, async () => {
  assert.equal(process.env.TT_RELEASE_UPGRADE_DISPOSABLE,"1","Explicit disposable database required");
  assert.match(process.env.DB_NAME || "",/^core_published_upgrade.*_test$/,"Owned release-upgrade database required");
  const { Client } = require("pg");
  const root = path.resolve(__dirname,"../..");
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(),"tt-core-published-upgrade-"));
  const client = new Client();
  const container = process.env.TT_RELEASE_UPGRADE_PG_CONTAINER;
  assert.match(container || "",/^(?:[0-9a-f]{64}|tt-release-accept-pg-[a-z0-9-]+)$/,"Owned PostgreSQL service container required");
  const restoreDatabase=`core_published_restore_${randomUUID().replaceAll('-','')}_test`;
  let restoreCreated=false;
  const execute = (command,args) => {
    const result=spawnSync(command,args,{cwd:root,env:{...process.env,NODE_ENV:"test"},encoding:"utf8",timeout:120000,maxBuffer:16*1024*1024});
    assert.equal(result.status,0,`${command} failed: ${(result.stderr || result.stdout || String(result.error)).slice(-3000)}`);
  };
  const migrate = (directory) => execute(process.execPath,[path.join(directory,"apps/api/migrations/migrate.js")]);
  try {
    await client.connect();
    assert.equal((await client.query("SELECT to_regclass('migrations') AS relation")).rows[0].relation,null,"Use a fresh owned database");
    execute("git",["archive","--format=tar",`--output=${path.join(temporary,"published.tar")}`,"v0.18.2","apps/api"]);
    execute("tar",["-xf",path.join(temporary,"published.tar"),"-C",temporary]);
    migrate(temporary);
    const prior = (await client.query("SELECT to_jsonb(m) AS value FROM migrations m ORDER BY version")).rows.map(row=>row.value);
    assert.ok(prior.length>0,"Published migration ledger absent");
    const fixture = await seedCertOpsUpgrade(client);
    const before = await snapshotCertOpsUpgrade(client,fixture);
    const dump=spawnSync("docker",["exec",container,"pg_dump","--username",process.env.DB_USER,"--format=custom",process.env.DB_NAME],{timeout:60000,maxBuffer:32*1024*1024});
    assert.equal(dump.status,0,"Preupgrade disposable database backup failed");
    assert.ok(dump.stdout.length>0,"Preupgrade backup was empty");
    migrate(root);
    const preserved = await assertCertOpsUpgradePreserved(client,fixture,before);
    const versions=prior.map(row=>row.version);
    assert.deepEqual((await client.query("SELECT to_jsonb(m) AS value FROM migrations m WHERE version=ANY($1::int[]) ORDER BY version",[versions])).rows.map(row=>row.value),prior,"Published ledger entries or timestamps changed");
    const upgraded=(await client.query("SELECT to_jsonb(m) AS value FROM migrations m ORDER BY version")).rows.map(row=>row.value);
    assert.ok(upgraded.length>=prior.length);
    migrate(root);
    await assertCertOpsUpgradePreserved(client,fixture,before);
    assert.deepEqual((await client.query("SELECT to_jsonb(m) AS value FROM migrations m ORDER BY version")).rows.map(row=>row.value),upgraded,"Migration replay changed ledger");
    await client.query(`CREATE DATABASE "${restoreDatabase}"`);restoreCreated=true;
    const restore=spawnSync("docker",["exec","-i",container,"pg_restore","--username",process.env.DB_USER,"--dbname",restoreDatabase,"--single-transaction","--no-owner","--no-privileges"],{input:dump.stdout,timeout:120000,maxBuffer:8*1024*1024});
    assert.equal(restore.status,0,"Preupgrade backup restore failed");
    const restored=new Client({database:restoreDatabase});
    try{
      await restored.connect();
      await assertCertOpsUpgradePreserved(restored,fixture,before);
      assert.deepEqual((await restored.query("SELECT to_jsonb(m) AS value FROM migrations m ORDER BY version")).rows.map(row=>row.value),prior,"Restored backup does not retain exact published ledger");
    }finally{await restored.end();}
    console.log(JSON.stringify({scope:"published Core migration source to candidate; synthetic persisted CertOps data",previous:"v0.18.2",priorMigrations:prior.length,currentMigrations:upgraded.length,...preserved,replay:"passed",preupgradeBackupRestore:"passed"}));
  } finally {
    if(restoreCreated){
      await client.query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()",[restoreDatabase]);
      await client.query(`DROP DATABASE "${restoreDatabase}"`);
    }
    await client.end();
    assert.equal(path.dirname(temporary),path.resolve(os.tmpdir()));
    assert.ok(path.basename(temporary).startsWith("tt-core-published-upgrade-"));
    fs.rmSync(temporary,{recursive:true,force:true});
  }
});
