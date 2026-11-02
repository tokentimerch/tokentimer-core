"use strict";
// Shared bounded commands, polling and owned-child teardown for the two Kubernetes journeys.
const assert=require("node:assert/strict");
const {spawnSync}=require("node:child_process");
function run(binary,args,input){
  const result=spawnSync(binary,args,{input,encoding:"utf8",timeout:180000,maxBuffer:1024*1024});
  if(result.error||result.status!==0)throw new Error("Disposable controller fixture operation failed");
  return result.stdout;
}
function kube(args,input){return run("kubectl",["--context",process.env.CERTOPS_KUBE_CONTEXT,...args],input);}
async function eventually(check){
  const until=Date.now()+180000;
  while(Date.now()<until){const result=await check();if(result)return result;await new Promise(resolve=>setTimeout(resolve,1000));}
  throw new Error("Actual controller journey exceeded deadline");
}
async function stopChild(child){
  if(!child?.pid||child.exitCode!==null||child.signalCode!==null)return;
  const exited=new Promise(resolve=>child.once("exit",resolve));
  child.kill("SIGCONT");child.kill("SIGTERM");
  let timeout;
  await Promise.race([exited,new Promise(resolve=>{timeout=setTimeout(resolve,5000);})]);clearTimeout(timeout);
  if(child.exitCode===null&&child.signalCode===null){
    child.kill("SIGKILL");
    await Promise.race([exited,new Promise(resolve=>{timeout=setTimeout(resolve,5000);})]);clearTimeout(timeout);
    assert.ok(child.exitCode!==null||child.signalCode!==null,"Owned child must terminate during cleanup");
  }
}
module.exports={run,kube,eventually,stopChild};
