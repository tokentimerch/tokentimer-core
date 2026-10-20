"use strict";
// Exercise the controller through Docker's temporary socket-only startup phase.
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),vm=require('node:vm');
test('PostgreSQL controller waits for final TCP server before creating databases',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'distribution-ready-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 let polls=0,ready=false;const owner='a'.repeat(32);
 const spawnSync=(cmd,args)=>{
  if(cmd==='git')return {status:0,stdout:'b'.repeat(40)};
  if(cmd==='docker'&&args.includes('pg_isready')){
   assert.ok(args.includes('-h'),'socket readiness accepts the temporary init server');
   assert.equal(args[args.indexOf('-h')+1],'127.0.0.1');
   ready=++polls===2;return {status:ready?0:1};
  }
  if(cmd==='docker'&&args.includes('createdb'))assert.ok(ready,'database creation preceded final startup');
  if(args[0]==='port')return {status:0,stdout:'127.0.0.1:54321'};
  if(args[0]==='inspect')return {status:0,stdout:owner};
  if(cmd===process.execPath&&args.some(a=>a.startsWith('--test-reporter-destination='))){const file=args.find(a=>a.endsWith('.jsonl')).split('=')[1];fs.writeFileSync(file,'{}');}
  return {status:0,stdout:''};
 };
 const localRequire=name=>{
  if(name==='node:child_process')return {spawnSync};
  if(name==='node:crypto')return {randomBytes:()=>({toString:()=>owner})};
  if(name==='./certops-stack-report')return {verify:()=>{}};
  if(name==='./certops-distribution-functional-summary')return {sourceInventory:()=>[]};
  if(name.includes('qualification-suites'))return {slots:['postgres','pr329-review','transfer'].map(s=>({id:'distribution-postgres-'+s,requiredTests:[],suite:s}))};
  return require(name);
 };
 localRequire.main=null;const context={require:localRequire,module:{exports:{}},__dirname:path.join(dir,'scripts'),process,console:{log:()=>{}},setTimeout};
 vm.runInNewContext(fs.readFileSync(path.join(__dirname,'certops-distribution-postgres.js'),'utf8'),context);
 await context.module.exports.main();assert.equal(polls,2);
});
