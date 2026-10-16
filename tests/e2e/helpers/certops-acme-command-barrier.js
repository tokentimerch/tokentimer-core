"use strict";
// Transparent qualification command wrapper. Only an explicitly armed,
// run-owned fixture directory enables the pre-execution process barrier.
const fs=require("node:fs"),path=require("node:path"),{spawn}=require("node:child_process");
const [directory,binary,...args]=process.argv.slice(2);
if(!path.isAbsolute(directory)||!binary)throw new Error("Owned command fixture arguments required");
const arm=path.join(directory,"armed.json"),receipt=path.join(directory,"process.json");
let child,timer,deadline;
function stop(signal){clearInterval(timer);clearTimeout(deadline);if(child)child.kill(signal);else process.exit(signal==="SIGTERM"?143:130);}
process.on("SIGTERM",()=>stop("SIGTERM"));process.on("SIGINT",()=>stop("SIGINT"));
function execute(){clearInterval(timer);clearTimeout(deadline);child=spawn(binary,args,{stdio:"inherit",env:process.env});child.on("error",()=>{process.exitCode=1;});child.on("exit",(code,signal)=>{process.exitCode=signal?1:code;});}
if(fs.existsSync(arm)){
 const item=fs.lstatSync(arm);if(!item.isFile()||item.isSymbolicLink())throw new Error("Unsafe command barrier");
 const proof=JSON.parse(fs.readFileSync(arm,"utf8"));if(!/^[a-f0-9-]{36}$/.test(proof.token))throw new Error("Invalid owned barrier token");
 const native=process.platform==="linux"?fs.readFileSync("/proc/self/stat","utf8").slice(fs.readFileSync("/proc/self/stat","utf8").lastIndexOf(")")+2).trim().split(/\s+/):null;
 fs.writeFileSync(receipt,JSON.stringify({token:proof.token,pid:process.pid,parentPid:process.ppid,binary,...(native?{processGroup:Number(native[2]),startTicks:native[19]}:{})}),{flag:"wx",mode:0o600});
 timer=setInterval(()=>{if(!fs.existsSync(arm))execute();},100);
 deadline=setTimeout(()=>{throw new Error("Native command barrier deadline exceeded");},120000);deadline.unref();
}else execute();
