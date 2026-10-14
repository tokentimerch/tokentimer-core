"use strict";
/** Pinned EDB x64 PostgreSQL dependency on the disposable ARM64 desktop.
 * The database runs under Windows x64 emulation. It is never represented as
 * native ARM64 PostgreSQL. No installer/service or arbitrary URL is accepted. */
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),https=require("node:https"),crypto=require("node:crypto"),{spawnSync}=require("node:child_process");
const lock=require("./certops-arm64-postgres-lock.json");
const sha=bytes=>crypto.createHash("sha256").update(bytes).digest("hex");
function run(file,args){const r=spawnSync(file,args,{encoding:"utf8",windowsHide:true,timeout:180000,maxBuffer:131072});assert.ifError(r.error);assert.equal(r.status,0,"Owned PostgreSQL operation failed; raw output withheld");return r.stdout.trim();}
function identity(file){const s=fs.lstatSync(file,{bigint:true});assert.equal(s.isSymbolicLink(),false);assert.ok(s.ino>0n,"Persistent native file identity required");return{dev:String(s.dev),ino:String(s.ino),birth:String(s.birthtimeNs)};}
function validateReceipt(r,file){
 assert.equal(process.env.CERTOPS_ARM64_PG_RECEIPT_IDENTITY_SHA256,sha(Buffer.from(JSON.stringify(identity(file)))),"Original PostgreSQL receipt file identity required");assert.ok(fs.lstatSync(file).size<=65536);
 assert.equal(r.schemaVersion,1);assert.match(r.nonce,/^[a-f0-9]{32}$/);assert.equal(path.dirname(file),r.root);assert.equal(path.dirname(r.root),path.resolve(process.env.RUNNER_TEMP));assert.equal(path.basename(r.root),`certops-arm64-pg-${r.nonce}`);
 assert.deepEqual(identity(r.root),r.rootIdentity);assert.deepEqual(identity(path.join(r.root,".owner")),r.markerIdentity);assert.equal(fs.readFileSync(path.join(r.root,".owner"),"utf8"),r.nonce);assert.equal(fs.realpathSync(r.root).toLowerCase(),r.root.toLowerCase());
 assert.equal(process.env.CERTOPS_ARM64_PG_IDENTITY_SHA256,sha(Buffer.from(JSON.stringify([r.root,r.nonce,r.rootIdentity,r.markerIdentity]))),"Original independently recorded PostgreSQL root identity required");
 assert.equal(r.archiveSha256,lock.sha256);assert.equal(r.bin,path.join(r.root,"extract","pgsql","bin"));assert.equal(r.data,path.join(r.root,"data"));assert.equal(r.port,55432);
 if(r.phase==="preparing")return true;
 for(const [file,id]of [[path.dirname(path.dirname(r.bin)),r.extractionRootIdentity],[path.dirname(r.bin),r.extractIdentity],[r.bin,r.binIdentity],[r.data,r.dataIdentity]])assert.deepEqual(identity(file),id);
 for(const name of ["postgres","initdb","pg_ctl","psql","createdb"]){const file=path.join(r.bin,`${name}.exe`);require("../packages/agent/scripts/host/package-fixture").verifyPeArchitecture(file,0x8664);assert.equal(sha(fs.readFileSync(file)),r.binarySha256[name]);}
 return true;
}
async function download(file){
 await new Promise((resolve,reject)=>{const out=fs.createWriteStream(file,{flags:"wx"});let bytes=0;const hash=crypto.createHash("sha256");const request=https.get(lock.url,{timeout:30000},response=>{
  if(response.statusCode!==200){response.resume();out.destroy();reject(new Error("Pinned official PostgreSQL archive unavailable"));return;}
  response.on("data",chunk=>{bytes+=chunk.length;if(bytes>lock.bytes){request.destroy(new Error("Pinned PostgreSQL download exceeds reviewed bound"));return;}hash.update(chunk);});response.pipe(out);response.on("error",reject);out.on("finish",()=>{try{assert.equal(bytes,lock.bytes);assert.equal(hash.digest("hex"),lock.sha256);resolve();}catch(e){reject(e);}});
 });request.on("timeout",()=>request.destroy(new Error("Pinned PostgreSQL download timed out")));request.on("error",reject);out.on("error",reject);const timer=setTimeout(()=>request.destroy(new Error("PostgreSQL total download deadline exceeded")),180000);timer.unref();out.once("close",()=>clearTimeout(timer));});
}
function currentProcess(r){
 const pid=Number(fs.readFileSync(path.join(r.data,"postmaster.pid"),"utf8").split(/\r?\n/)[0]);assert.ok(Number.isSafeInteger(pid)&&pid>0);
 return JSON.parse(run(process.env.CERTOPS_ARM64_AGENT_PWSH,["-NoProfile","-NonInteractive","-Command",`$ErrorActionPreference='Stop';$p=Get-CimInstance Win32_Process -Filter 'ProcessId=${pid}';if(!$p){throw 'Owned database process missing'};@{pid=[int]$p.ProcessId;created=$p.CreationDate.ToUniversalTime().ToString('o');exe=$p.ExecutablePath;command=$p.CommandLine}|ConvertTo-Json -Compress`]));
}
async function setup(){
 assert.equal(process.platform,"win32");assert.equal(process.arch,"arm64");assert.equal(process.env.GITHUB_ACTIONS,"true");assert.equal(process.env.RUNNER_ENVIRONMENT,"github-hosted");assert.equal(process.env.CERTOPS_ARM64_AGENT_REQUIRED,"1");
 const nonce=crypto.randomBytes(16).toString("hex"),root=path.join(path.resolve(process.env.RUNNER_TEMP),`certops-arm64-pg-${nonce}`);assert.equal(fs.existsSync(root),false);fs.mkdirSync(root);fs.writeFileSync(path.join(root,".owner"),nonce,{flag:"wx"});
 const archive=path.join(root,"postgres.zip"),extract=path.join(root,"extract"),rootIdentity=identity(root),markerIdentity=identity(path.join(root,".owner"));
 const r={schemaVersion:1,phase:"preparing",nonce,root,rootIdentity,markerIdentity,archiveSha256:lock.sha256,bin:path.join(extract,"pgsql","bin"),data:path.join(root,"data"),port:55432,binarySha256:{}};
 const receipt=path.join(root,"ownership.json"),seal=sha(Buffer.from(JSON.stringify([root,nonce,rootIdentity,markerIdentity])));process.env.CERTOPS_ARM64_PG_IDENTITY_SHA256=seal;
 fs.writeFileSync(receipt,JSON.stringify(r),{flag:"wx"});const receiptSeal=sha(Buffer.from(JSON.stringify(identity(receipt))));process.env.CERTOPS_ARM64_PG_RECEIPT_IDENTITY_SHA256=receiptSeal;fs.appendFileSync(process.env.GITHUB_ENV,`CERTOPS_ARM64_PG_RECEIPT_IDENTITY_SHA256=${receiptSeal}\nCERTOPS_ARM64_PG_RECEIPT=${receipt}\nCERTOPS_ARM64_PG_IDENTITY_SHA256=${seal}\n`);
 fs.mkdirSync(extract);const extractRootIdentity=identity(extract);await download(archive);validateReceipt(r,receipt);assert.deepEqual(identity(extract),extractRootIdentity);run(path.join(process.env.SystemRoot,"System32","tar.exe"),["-xf",archive,"-C",extract]);validateReceipt(r,receipt);assert.deepEqual(identity(extract),extractRootIdentity);fs.mkdirSync(r.data);r.extractionRootIdentity=extractRootIdentity;r.extractIdentity=identity(path.dirname(r.bin));r.binIdentity=identity(r.bin);r.dataIdentity=identity(r.data);r.phase="prepared";
 for(const name of ["postgres","initdb","pg_ctl","psql","createdb"])r.binarySha256[name]=sha(fs.readFileSync(path.join(r.bin,`${name}.exe`)));
 validateReceipt(r,receipt);fs.writeFileSync(receipt,JSON.stringify(r));
 run(path.join(r.bin,"initdb.exe"),["-D",r.data,"-U","postgres","-A","trust","--encoding=UTF8"]);
 // There is no permissive adoption path: pg_ctl refuses an occupied port or
 // another cluster. A failed start retains its data and receipt for diagnosis.
 r.phase="starting";fs.writeFileSync(receipt,JSON.stringify(r));
 run(path.join(r.bin,"pg_ctl.exe"),["-D",r.data,"-l",path.join(root,"private-pg.log"),"-o","-h 127.0.0.1 -p 55432","-w","start"]);
 const actual=currentProcess(r);assert.equal(actual.exe.toLowerCase(),path.join(r.bin,"postgres.exe").toLowerCase());
 const directory=run(path.join(r.bin,"psql.exe"),["-h","127.0.0.1","-p","55432","-U","postgres","-d","postgres","-Atc","SHOW data_directory"]);assert.equal(path.win32.resolve(directory).toLowerCase(),path.win32.resolve(r.data).toLowerCase(),"Actual connected cluster must use exact owned data directory");
 const listeners=JSON.parse(run(process.env.CERTOPS_ARM64_AGENT_PWSH,["-NoProfile","-NonInteractive","-Command","@{rows=@(Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort 55432 -State Listen|ForEach-Object {[int]$_.OwningProcess})}|ConvertTo-Json -Compress"])).rows;assert.deepEqual(listeners,[actual.pid],"Actual loopback listener must belong to exact owned PostgreSQL process");
 r.phase="running";r.process=actual;fs.writeFileSync(receipt,JSON.stringify(r));
 run(path.join(r.bin,"createdb.exe"),["-h","127.0.0.1","-p","55432","-U","postgres","certops_arm64_qualification"]);
 const version=run(path.join(r.bin,"psql.exe"),["-h","127.0.0.1","-p","55432","-U","postgres","-d","certops_arm64_qualification","-Atc","SELECT version()"]);assert.match(version,/^PostgreSQL 17\.11\b.*64-bit/);
 fs.writeFileSync(path.join(root,"public-dependency.json"),JSON.stringify({version:lock.version,architecture:"x64",execution:"windows11-x64-emulation",archiveSha256:lock.sha256,actualSqlVersion:version}));
 fs.appendFileSync(process.env.GITHUB_ENV,`CERTOPS_ARM64_PG_PROOF=${path.join(root,"public-dependency.json")}\n`);
}
function ownedProcesses(r){
 const prefix=r.root.replace(/'/g,"''")+"\\";
 const value=JSON.parse(run(process.env.CERTOPS_ARM64_AGENT_PWSH,["-NoProfile","-NonInteractive","-Command",`$ErrorActionPreference='Stop';@{rows=@(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -and $_.ExecutablePath.StartsWith('${prefix}',[StringComparison]::OrdinalIgnoreCase)}|ForEach-Object {@{pid=[int]$_.ProcessId;parent=[int]$_.ParentProcessId;created=$_.CreationDate.ToUniversalTime().ToString('o')}})}|ConvertTo-Json -Depth 4 -Compress`]));assert.ok(Array.isArray(value.rows)&&value.rows.length<=256);return value.rows;
}
function cleanup(file,{preserve=false}={}){
 if(!file)return;assert.equal(fs.lstatSync(file).isSymbolicLink(),false);assert.ok(fs.lstatSync(file).size<=65536);const r=JSON.parse(fs.readFileSync(file,"utf8"));validateReceipt(r,file);
 if(r.phase==="preparing"){assert.equal(ownedProcesses(r).length,0,"Unexpected native process preserves preparation root");validateReceipt(r,file);if(!preserve)fs.rmSync(r.root,{recursive:true});return;}
 assert.notEqual(r.phase,"starting","Unknown native startup preserves PostgreSQL root");const captured=ownedProcesses(r);
 if(fs.existsSync(path.join(r.data,"postmaster.pid"))){assert.ok(r.process,"Unconfirmed startup preserves database state");assert.deepEqual(currentProcess(r),r.process,"Foreign replacement database process preserved");run(path.join(r.bin,"pg_ctl.exe"),["-D",r.data,"-m","fast","-w","stop"]);}
 assert.equal(fs.existsSync(path.join(r.data,"postmaster.pid")),false);assert.equal(ownedProcesses(r).length,0,"Owned PostgreSQL descendants remain");
 const all=JSON.parse(run(process.env.CERTOPS_ARM64_AGENT_PWSH,["-NoProfile","-NonInteractive","-Command","@{rows=@(Get-CimInstance Win32_Process|ForEach-Object {@{pid=[int]$_.ProcessId;parent=[int]$_.ParentProcessId;created=$_.CreationDate.ToUniversalTime().ToString('o')}})}|ConvertTo-Json -Depth 4 -Compress"])).rows;
 require("../tests/e2e/helpers/certops-adcs-webhosting-renewal").assertDrainAbsent({processes:captured},all);validateReceipt(r,file);if(!preserve)fs.rmSync(r.root,{recursive:true});
}
if(require.main===module)(process.argv[2]==="--cleanup"?Promise.resolve().then(()=>cleanup(process.env.CERTOPS_ARM64_PG_RECEIPT,{preserve:process.env.CERTOPS_ARM64_AGENT_NATIVE_COMPLETED!=="1"})):setup()).catch(()=>{console.error("Pinned owned PostgreSQL dependency failed; private state retained");process.exitCode=1;});
module.exports={identity,validateReceipt,download,setup,cleanup};
