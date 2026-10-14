"use strict";
/* Observed native journal-phase fault helper for the dedicated experiment. Exact owned
 * process/phase receipts fence termination; durable records are observed rather than rewritten to
 * manufacture a crash state. Called only by the protected disposable-forest AD CS harness; native
 * qualification requires that workflow to execute.
 */
const path=require("node:path");
const {spawn}=require("node:child_process");
module.exports=function startJournalPhaseFault({ownedDirectory,configDirectory,repositoryRoot,phase}){
  const env=Object.fromEntries(["SYSTEMROOT","WINDIR","TEMP","TMP","PATH","PSModulePath","CERTOPS_ADCS_DISPOSABLE_LAB"].filter(key=>process.env[key]!==undefined).map(key=>[key,process.env[key]]));
  const child=spawn("powershell.exe",["-NoProfile","-NonInteractive","-File",path.resolve(__dirname,"../../../infra/certops-adcs/journal-phase-fault.ps1"),
    "-OwnedDirectory",ownedDirectory,"-ConfigDirectory",configDirectory,"-RepositoryRoot",repositoryRoot,"-NodeExecutable",process.execPath,"-Phase",phase],{env,stdio:["ignore","pipe","pipe"],windowsHide:true});
  let output="",readyResolve,readyReject,seenReady=false;
  const ready=new Promise((resolve,reject)=>{readyResolve=resolve;readyReject=reject;});ready.catch(()=>{});
  child.stdout.on("data",chunk=>{output+=chunk.toString();if(output.includes("CERTOPS_JOURNAL_FAULT_READY")){seenReady=true;readyResolve();}if(output.length>8192)child.kill();});
  child.stderr.resume();
  const timer=setTimeout(()=>child.kill(),195000);
  const result=new Promise((resolve,reject)=>{
    child.once("error",()=>{clearTimeout(timer);readyReject(new Error("Native phase observer could not start"));reject(new Error("Native phase observer could not start"));});
    child.once("exit",code=>{clearTimeout(timer);if(!seenReady)readyReject(new Error("Native phase ownership preflight failed"));if(code!==0)return reject(new Error("Experimental native phase window was not independently proven"));
      try{const evidence=JSON.parse(output.replace("CERTOPS_JOURNAL_FAULT_READY","").trim());if(evidence.phase!==phase||evidence.observedDurablePhase!==true||evidence.unchangedAfterTermination!==true||evidence.ownedServiceTree!==true||evidence.nativeIdentity!=="LocalSystem")throw new Error("Native phase evidence incomplete");resolve(evidence);}catch{reject(new Error("Native phase evidence invalid"));}
    });
  });result.catch(()=>{});
  return {ready,result,stop(){clearTimeout(timer);if(child.exitCode===null)child.kill();}};
};
