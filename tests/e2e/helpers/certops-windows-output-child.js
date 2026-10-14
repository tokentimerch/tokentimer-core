"use strict";
/* Qualification-only command-profile launcher for the installed Windows
 * journey. Emits synthetic secrets into real captured stdout/stderr, records
 * bounded emission/identity/exit facts, then delegates the unchanged real ACME
 * executable/argv/environment. It never supplies a fake certificate or result.
 * The parent owns the recipe/receipt directory and never uploads raw streams. */
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto"),{spawn,spawnSync}=require("node:child_process");
async function main(){
 const [recipePath,program,...args]=process.argv.slice(2);if(!recipePath||!program)throw new Error("Owned output recipe and real command required");
 const recipe=JSON.parse(fs.readFileSync(recipePath,"utf8"));if(!/^[a-f0-9]{32}$/.test(recipe.runId)||path.resolve(recipe.receiptDirectory)!==path.join(path.dirname(path.resolve(recipePath)),"native-output-receipts"))throw new Error("Invalid owned output fixture");
 let sid=null;
 if(process.platform==="win32"){
  const measured=spawnSync("powershell.exe",["-NoProfile","-NonInteractive","-Command","[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"],{encoding:"utf8",timeout:15000,env:{SystemRoot:process.env.SystemRoot,WINDIR:process.env.WINDIR,PATH:process.env.PATH}});
  if(measured.error||measured.status!==0||!/^S-1-\d+(?:-\d+)+$/.test(measured.stdout.trim()))throw new Error("Native output identity measurement failed");sid=measured.stdout.trim();
 }
 const receipt={schemaVersion:1,runId:recipe.runId,pid:process.pid,parentPid:process.ppid,platform:process.platform,nativeSid:sid,stdoutEmitted:false,stderrEmitted:false,delegatedExit:null};
 const receiptPath=path.join(recipe.receiptDirectory,`${process.pid}-${crypto.randomUUID()}.json`);fs.writeFileSync(receiptPath,JSON.stringify(receipt),{flag:"wx",mode:0o600});
 const text=`Authorization: Bearer ${recipe.bearer}\npassword=${recipe.password}\n-----BEGIN PRIVATE KEY-----\n${recipe.pemPayload}\n-----END PRIVATE KEY-----\n`;
 const write=(stream,label)=>new Promise((resolve,reject)=>stream.write(text,error=>{if(error){reject(error);return;}receipt[label]=true;resolve();}));
 await Promise.all([write(process.stdout,"stdoutEmitted"),write(process.stderr,"stderrEmitted")]);fs.writeFileSync(receiptPath,JSON.stringify(receipt));
 const child=spawn(program,args,{env:process.env,stdio:"inherit",windowsHide:true});
 const exit=await new Promise((resolve,reject)=>{child.once("error",reject);child.once("close",(code,signal)=>resolve({code,signal}));});
 receipt.delegatedExit=exit.code;receipt.delegatedSignal=exit.signal;fs.writeFileSync(receiptPath,JSON.stringify(receipt));
 if(exit.signal){process.exitCode=1;return;}process.exitCode=Number.isInteger(exit.code)?exit.code:1;
}
if(require.main===module)main().catch(()=>{process.stderr.write("Owned output qualification launcher failed\n");process.exitCode=1;});
module.exports={main};
