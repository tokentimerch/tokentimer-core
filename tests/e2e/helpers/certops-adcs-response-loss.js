"use strict";
/* Opt-in lost-submit-response experiment using an actual owned CA side effect and verified
 * certreq process interruption. Public reconciliation must preserve request/key ownership and
 * cannot silently resubmit uncertainty. Called only by the protected disposable-forest AD CS
 * harness; native qualification requires that workflow to execute.
 */
const path=require("node:path");
const {spawn}=require("node:child_process");
// This opt-in experiment never substitutes CLI output or edits the enrollment journal.
module.exports=function startResponseLoss({commonName,ownedDirectory}){
  const child=spawn("powershell.exe",["-NoProfile","-NonInteractive","-File",path.resolve(__dirname,"../../../infra/certops-adcs/response-loss.ps1"),"-CommonName",commonName,"-OwnedDirectory",ownedDirectory],{env:process.env,stdio:["ignore","pipe","pipe"]});
  let output="";
  let readyResolve;let readyReject;let observedReady=false;
  const ready=new Promise((resolve,reject)=>{readyResolve=resolve;readyReject=reject;});ready.catch(()=>{});
  child.stdout.on("data",chunk=>{output+=chunk.toString();if(output.includes("CERTOPS_FAULT_READY")){observedReady=true;readyResolve();}if(output.length>8192)child.kill();});
  // Do not persist native errors, command lines or credential-bearing environment values.
  child.stderr.resume();
  const timer=setTimeout(()=>child.kill(),110000);
  const result=new Promise((resolve,reject)=>{
    child.once("error",error=>{clearTimeout(timer);readyReject(error);reject(error);});
    child.once("exit",code=>{clearTimeout(timer);if(!observedReady)readyReject(new Error("Native CA observation controller did not start"));if(code!==0)return reject(new Error("Experimental response-loss fault window was not independently proven"));try{const evidence=JSON.parse(output.replace("CERTOPS_FAULT_READY","").trim());if(!evidence.caRequestObserved || !evidence.ownedServiceTree || !Number.isInteger(evidence.requestId))throw new Error("Missing native fault evidence");resolve(evidence);}catch(error){reject(error);}});
  });
  // Attach a handler before the caller awaits real API dispatch, so early failures are not unhandled.
  result.catch(()=>{});
  return {ready,result,stop:()=>{clearTimeout(timer);if(child.exitCode===null)child.kill();}};
};
