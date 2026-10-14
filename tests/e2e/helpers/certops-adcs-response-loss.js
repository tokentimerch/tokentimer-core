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
  const child=spawn("powershell.exe",["-NoProfile","-NonInteractive","-File",path.resolve(__dirname,"../../../infra/certops-adcs/response-loss.ps1"),"-CommonName",commonName,"-OwnedDirectory",ownedDirectory],{env:process.env,stdio:["ignore","pipe","pipe"],windowsHide:true});
  let output="",overflow=false,drained=false;
  const closed=new Promise(resolve=>child.once("close",()=>{drained=true;resolve();}));
  let readyResolve;let readyReject;let observedReady=false;
  const ready=new Promise((resolve,reject)=>{readyResolve=resolve;readyReject=reject;});ready.catch(()=>{});
  child.stdout.on("data",chunk=>{if(overflow)return;if(Buffer.byteLength(output)+chunk.length>8192){overflow=true;child.kill();return;}output+=chunk.toString();if(output.includes("CERTOPS_FAULT_READY")){observedReady=true;readyResolve();}});
  // Do not persist native errors, command lines or credential-bearing environment values.
  child.stderr.resume();
  const timer=setTimeout(()=>child.kill(),110000);
  const result=new Promise((resolve,reject)=>{
    child.once("error",()=>{clearTimeout(timer);const error=new Error("Native CA observation controller could not start");readyReject(error);reject(error);});
    // Final receipt bytes can arrive after exit. Only close proves that both
    // the owned process and its stdio have drained before parsing or cleanup.
    child.once("close",code=>{clearTimeout(timer);if(!observedReady)readyReject(new Error("Native CA observation controller did not start"));if(code!==0||overflow)return reject(new Error("Experimental response-loss fault window was not independently proven"));try{const evidence=JSON.parse(output.replace("CERTOPS_FAULT_READY","").trim());if(evidence.caRequestObserved!==true || evidence.ownedServiceTree!==true || !Number.isInteger(evidence.requestId)||evidence.requestId<1||evidence.requestId>4294967295)throw new Error("Missing native fault evidence");resolve(evidence);}catch{reject(new Error("Native response-loss evidence invalid"));}});
  });
  // Attach a handler before the caller awaits real API dispatch, so early failures are not unhandled.
  result.catch(()=>{});
  const stop=()=>{clearTimeout(timer);if(child.exitCode===null)child.kill();};
  return {ready,result,stop,hasLiveChild(){return !drained;},async stopAndDrain(){stop();let deadline;try{await Promise.race([closed,new Promise((_,reject)=>{deadline=setTimeout(()=>reject(new Error("Owned native response observer did not drain")),30000);})]);}finally{clearTimeout(deadline);}}};
};
