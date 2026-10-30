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
      execute(`const c=require('./migrations/migrate');const names=${JSON.stringify(names)};const list=[...c.migrations.filter(m=>m.version<=77),...names.map((name,i)=>({...c.migrations.find(m=>m.name===name),version:78+i}))];c.migrations.splice(0,c.migrations.length,...list);c.runMigrations().then(()=>process.exit(0));`);
      const before=(await client.query("SELECT * FROM migrations ORDER BY version")).rows;
      const labelsExist=(await client.query("SELECT to_regclass('auto_sync_kind_stats') AS name")).rows[0].name;
      if(labelsExist)await client.query("INSERT INTO auto_sync_kind_stats(provider,kind,items_created_total) VALUES('compat_fixture','certificate',7)");
      const upgrade="require('./migrations/migrate').runMigrations().then(()=>process.exit(0))";
      if(history==="main-81"){
        await Promise.all([1,2].map(()=>new Promise((resolve,reject)=>{
          const child=spawn(process.execPath,["-e",upgrade],{cwd,env,windowsHide:true});let output="";
          child.stdout.on("data",chunk=>output+=chunk);child.stderr.on("data",chunk=>output+=chunk);
          child.on("error",reject);child.on("exit",code=>code===0?resolve():reject(new Error(output.slice(-3000))));
        })));
      }else execute(upgrade);
      const after=(await client.query("SELECT * FROM migrations ORDER BY version")).rows;
      assert.deepEqual(after.slice(0,before.length),before);assert.equal(after.length,91);
      for(const table of ["certops_material_cleanups","certops_consumer_verification_outcomes","contact_channel_verifications","pagerduty_incidents"])
        assert.equal((await client.query("SELECT to_regclass($1)::text AS name",[table])).rows[0].name,table);
      assert.equal((await client.query("SELECT resolution_delivery_pending FROM certops_distribution_incidents LIMIT 0")).rowCount,0);
      if(labelsExist)assert.equal(Number((await client.query("SELECT items_created_total FROM auto_sync_kind_stats WHERE provider='compat_fixture'")).rows[0].items_created_total),7);
      execute(upgrade);assert.deepEqual((await client.query("SELECT * FROM migrations ORDER BY version")).rows,after);
    }finally{
      if(client)await client.end();await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);await admin.end();
    }
  });
});
