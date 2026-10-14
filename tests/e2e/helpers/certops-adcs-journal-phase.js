"use strict";
/* Observed native journal-phase fault helper for protected qualification and opt-in experiments. Exact owned
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
  // Keep the original synchronous stop API for existing experiment callers.
  // Qualification callers additionally await close, including stdio drainage,
  // before removing this exact child's ownership receipt or fixture directory.
  let drained=false;
  const closed=new Promise(resolve=>child.once("close",()=>{drained=true;resolve();}));
  let output="",readyResolve,readyReject,seenReady=false;
  const ready=new Promise((resolve,reject)=>{readyResolve=resolve;readyReject=reject;});ready.catch(()=>{});
  child.stdout.on("data",chunk=>{output+=chunk.toString();if(output.includes("CERTOPS_JOURNAL_FAULT_READY")){seenReady=true;readyResolve();}if(output.length>8192)child.kill();});
  child.stderr.resume();
  const timer=setTimeout(()=>child.kill(),195000);
  const result=new Promise((resolve,reject)=>{
    child.once("error",()=>{clearTimeout(timer);readyReject(new Error("Native phase observer could not start"));reject(new Error("Native phase observer could not start"));});
    // close follows both process exit and drained stdio; exit alone can precede
    // the final JSON bytes produced by the owned observer.
    child.once("close",code=>{clearTimeout(timer);if(!seenReady)readyReject(new Error("Native phase ownership preflight failed"));if(code!==0)return reject(new Error("Native phase window was not independently proven"));
      try{const evidence=JSON.parse(output.replace("CERTOPS_JOURNAL_FAULT_READY","").trim());if(evidence.phase!==phase||evidence.observedDurablePhase!==true||evidence.unchangedAfterTermination!==true||evidence.ownedServiceTree!==true||evidence.nativeIdentity!=="LocalSystem")throw new Error("Native phase evidence incomplete");resolve(evidence);}catch{reject(new Error("Native phase evidence invalid"));}
    });
  });result.catch(()=>{});
  const stop=()=>{clearTimeout(timer);if(child.exitCode===null)child.kill();};
  return {ready,result,stop,hasLiveChild(){return !drained;},async stopAndDrain(){stop();let deadline;try{await Promise.race([closed,new Promise((_,reject)=>{deadline=setTimeout(()=>reject(new Error("Owned native phase observer did not drain")),30000);})]);}finally{clearTimeout(deadline);}}};
};
