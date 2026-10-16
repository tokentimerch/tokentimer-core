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
