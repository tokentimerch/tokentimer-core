"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto"),path=require("node:path");
const {spawnSync,spawn}=require("node:child_process"),{Client}=require("pg");
const histories=require("../helpers/distribution-migration-histories.cjs");
describe("Independent PR migration and preview compatibility",function(){
  this.timeout(120000);
  for(const [history,names] of Object.entries(histories))it(`upgrades ${history} without rewriting applied rows or replaying SQL`,async()=>{
    assert.equal(process.env.DB_HOST,"127.0.0.1");assert.equal(process.env.NODE_ENV,"test");
    const config={host:process.env.DB_HOST,port:Number(process.env.DB_PORT),user:process.env.DB_USER,password:process.env.DB_PASSWORD,database:process.env.DB_NAME};
    const admin=new Client(config);await admin.connect();const database=`distribution_compat_${crypto.randomBytes(8).toString("hex")}_test`;
    let client;
    try{
      await admin.query(`CREATE DATABASE ${database}`);client=new Client({...config,database});await client.connect();
      const cwd=path.resolve(__dirname,"../../apps/api"),env={...process.env,DB_NAME:database};
      const execute=script=>{
        const r=spawnSync(process.execPath,["-e",script],{cwd,env,encoding:"utf8",windowsHide:true,timeout:60000,maxBuffer:8*1024*1024});
        assert.equal(r.status,0,`${r.error || ""}\n${r.stderr}\n${r.stdout.slice(-2500)}`);
      };
      execute(`const c=require('./migrations/migrate');const names=${JSON.stringify(names)};const list=[...c.migrations.filter(m=>m.version<=77),...names.map((entry,i)=>{const [version,name]=Array.isArray(entry)?entry:[78+i,entry];return {...c.migrations.find(m=>m.name===name),version};})];c.migrations.splice(0,c.migrations.length,...list);c.runMigrations().then(()=>process.exit(0));`);
      const before=(await client.query("SELECT * FROM migrations ORDER BY version")).rows;
      const labelsExist=(await client.query("SELECT to_regclass('auto_sync_kind_stats') AS name")).rows[0].name;
      if(labelsExist)await client.query("INSERT INTO auto_sync_kind_stats(provider,kind,items_created_total) VALUES('compat_fixture','certificate',7)");
      const upgrade="require('./migrations/migrate').runMigrations().then(()=>process.exit(0))";
      let preserved = before;
      if (history === "pagerduty-81" || history === "pagerduty-preview-79") {
        const rejected = spawnSync(process.execPath,["-e",upgrade],{cwd,env,encoding:"utf8",windowsHide:true,timeout:60000});
        assert.equal(rejected.status,1,"A colliding preview must stop before automatic upgrade");
        assert.deepEqual((await client.query("SELECT * FROM migrations ORDER BY version")).rows,before);
        execute("const {pool}=require('./db/database');const {reconcilePagerDutyV79}=require('../../scripts/reconcile-pagerduty-v79.cjs');(async()=>{const c=await pool.connect();try{await reconcilePagerDutyV79(c,{apply:true})}finally{c.release();await pool.end()}})().catch(()=>process.exit(1));");
        preserved=(await client.query("SELECT * FROM migrations ORDER BY version")).rows;
      }
      if(history==="main-81"){
        await Promise.all([1,2].map(()=>new Promise((resolve,reject)=>{
          const child=spawn(process.execPath,["-e",upgrade],{cwd,env,windowsHide:true});let output="";
          child.stdout.on("data",chunk=>output+=chunk);child.stderr.on("data",chunk=>output+=chunk);
          child.on("error",reject);child.on("exit",code=>code===0?resolve():reject(new Error(output.slice(-3000))));
        })));
      }else execute(upgrade);
      const after=(await client.query("SELECT * FROM migrations ORDER BY version")).rows;
      assert.deepEqual(after.filter(row=>preserved.some(original=>original.version===row.version)),preserved);assert.equal(after.length,112);
      assert.equal(after.filter(row=>row.name==="certops_retirement_dossiers").length,1);
      const canonicalTail=["pagerduty_resolution_reason","pagerduty_operator_actions","remove_pagerduty_rest_lookup","certops_consumer_staging","certops_review_authority_epochs","certops_manual_rollout_authority"];
      const previewTails={
        "lifecycle-81-85":["weekly_digest_recipient_claim_token","pagerduty_incident_lifecycle","pagerduty_resolution_reason","pagerduty_operator_actions","remove_pagerduty_rest_lookup","certops_manual_rollout_authority"],
        "providers-81":["certops_stable_consumer_discovery","certops_material_cleanup","certops_consumer_verification_failures","certops_distribution_resolution_delivery","pagerduty_operator_actions","remove_pagerduty_rest_lookup"],
      };
      assert.deepEqual(after.filter(({version})=>version>=93 && version<=98).map(({name})=>name),previewTails[history] || canonicalTail);
      for(const name of ["certops_consumer_staging","certops_review_authority_epochs","certops_manual_rollout_authority"])
        assert.equal(after.filter(row=>row.name===name).length,1,"Authority migration "+name+" is present once");
      for(const name of ["operator_connections","operator_enrollment_grants","operator_action_requests","operator_oauth","operator_connection_lifetimes","operator_inventory","operator_oauth_retention","operator_issuance","certops_issuance_job_identity","certops_issuance_identity_transfer"])
        assert.equal(after.filter(row=>row.name===name).length,1,"Released MCP migration "+name+" is present once");
      for(const table of ["certops_material_cleanups","certops_consumer_verification_outcomes","contact_channel_verifications","pagerduty_incidents","certops_material_retirement_dossiers"])
        assert.equal((await client.query("SELECT to_regclass($1)::text AS name",[table])).rows[0].name,table);
      assert.equal((await client.query("SELECT resolution_delivery_pending FROM certops_distribution_incidents LIMIT 0")).rowCount,0);
      if(labelsExist)assert.equal(Number((await client.query("SELECT items_created_total FROM auto_sync_kind_stats WHERE provider='compat_fixture'")).rows[0].items_created_total),7);
      execute(upgrade);assert.deepEqual((await client.query("SELECT * FROM migrations ORDER BY version")).rows,after);
    }finally{
      if(client)await client.end();await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);await admin.end();
    }
  });
});
