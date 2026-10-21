/**
 * Check the owned ACME command barrier used to measure cancellation of an actual child.
 * These local fixtures test barrier identity and release behavior; the full native
 * ACME lease-loss journey separately proves public cancellation and certificate custody. */
"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),crypto=require("node:crypto"),{spawn}=require("node:child_process");
const wrapper=path.resolve(__dirname,"../e2e/helpers/certops-acme-command-barrier.js");
async function until(check){const end=Date.now()+5000;while(Date.now()<end){if(check())return;await new Promise(resolve=>setTimeout(resolve,10));}throw new Error("Owned command fixture timed out");}
for(const armed of [false,true])test(`native command wrapper ${armed?"blocks until terminated without executing its command":"transparently executes its actual command"}`,{timeout:10000},async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),"certops-command-test-")),marker=path.join(directory,"mutation.txt"),receipt=path.join(directory,"process.json");let child;
 try{
  const token=crypto.randomUUID();if(armed)fs.writeFileSync(path.join(directory,"armed.json"),JSON.stringify({token}));
  child=spawn(process.execPath,[wrapper,directory,process.execPath,"-e","require('fs').writeFileSync(process.argv[1],'actual-command')",marker],{stdio:"ignore"});
  const exited=new Promise((resolve,reject)=>{child.once("exit",resolve);child.once("error",reject);});
  if(armed){await until(()=>fs.existsSync(receipt));assert.equal(JSON.parse(fs.readFileSync(receipt)).token,token);assert.equal(JSON.parse(fs.readFileSync(receipt)).pid,child.pid);assert.equal(fs.existsSync(marker),false);child.kill("SIGTERM");}
  await exited;assert.equal(fs.existsSync(marker),!armed);if(!armed)assert.equal(fs.readFileSync(marker,"utf8"),"actual-command");
 }finally{if(child&&child.exitCode===null&&child.signalCode===null){child.kill("SIGKILL");await until(()=>child.exitCode!==null||child.signalCode!==null);}fs.rmSync(directory,{recursive:true});}
});

test("command barrier publishes its receipt only after all bytes are written", {timeout:15000}, async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),"certops-command-publication-"));
 const receipt=path.join(directory,"process.json"),started=path.join(directory,"write-started"),release=path.join(directory,"write-release"),preload=path.join(directory,"preload.cjs"),marker=path.join(directory,"mutation.txt");
 const token=crypto.randomUUID();let child;
 fs.writeFileSync(path.join(directory,"armed.json"),JSON.stringify({token}));
 // Pause the actual child's receipt write after creation, making the publication
 // race deterministic without replacing the wrapper or its process behavior.
 fs.writeFileSync(preload,`
  const fs=require("node:fs"),path=require("node:path"),write=fs.writeFileSync;
  fs.writeFileSync=function(file,data,options){
   if(typeof file!=="string"||!path.basename(file).startsWith("process.json"))return write.apply(this,arguments);
   const descriptor=fs.openSync(file,options.flag,options.mode);
   try{
    write(${JSON.stringify(started)},"started");
    const deadline=Date.now()+10000;
    while(!fs.existsSync(${JSON.stringify(release)})){
     if(Date.now()>deadline)throw new Error("Receipt write release timed out");
     Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,5);
    }
    fs.writeFileSync=write;write(descriptor,data);
   }finally{fs.closeSync(descriptor);}
  };
 `);
 try{
  child=spawn(process.execPath,["--require",preload,wrapper,directory,process.execPath,"-e","require('fs').writeFileSync(process.argv[1],'unexpected-command')",marker],{stdio:"ignore"});
  const exited=new Promise((resolve,reject)=>{child.once("exit",resolve);child.once("error",reject);});
  await until(()=>fs.existsSync(started));
  assert.equal(fs.existsSync(receipt),false,"An unfinished receipt must not be visible to readers");
  fs.writeFileSync(release,"release");await until(()=>fs.existsSync(receipt));
  const proof=JSON.parse(fs.readFileSync(receipt,"utf8"));
  assert.equal(proof.token,token);assert.equal(proof.pid,child.pid);
  assert.equal(fs.existsSync(marker),false);
  child.kill("SIGTERM");await exited;
  assert.equal(fs.existsSync(marker),false);
  assert.equal(fs.readdirSync(directory).some(name=>/^process\.json\..*\.tmp$/.test(name)),false);
 }finally{
  if(child&&child.exitCode===null&&child.signalCode===null){child.kill("SIGKILL");await until(()=>child.exitCode!==null||child.signalCode!==null);}
  fs.rmSync(directory,{recursive:true});
 }
});

test("command barrier refuses an existing receipt without clobbering it", {timeout:10000}, async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),"certops-command-existing-"));
 const receipt=path.join(directory,"process.json"),marker=path.join(directory,"mutation.txt");let child;
 try{
  fs.writeFileSync(path.join(directory,"armed.json"),JSON.stringify({token:crypto.randomUUID()}));
  fs.writeFileSync(receipt,"existing-receipt");
  child=spawn(process.execPath,[wrapper,directory,process.execPath,"-e","require('fs').writeFileSync(process.argv[1],'unexpected-command')",marker],{stdio:"ignore"});
  const code=await new Promise((resolve,reject)=>{child.once("exit",resolve);child.once("error",reject);});
  assert.notEqual(code,0);assert.equal(fs.readFileSync(receipt,"utf8"),"existing-receipt");
  assert.equal(fs.existsSync(marker),false);
  assert.equal(fs.readdirSync(directory).some(name=>/^process\.json\..*\.tmp$/.test(name)),false);
 }finally{
  if(child&&child.exitCode===null&&child.signalCode===null){child.kill("SIGKILL");await until(()=>child.exitCode!==null||child.signalCode!==null);}
  fs.rmSync(directory,{recursive:true});
 }
});
