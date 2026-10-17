"use strict";
/** Native two-process receipt conflict integration on the existing disposable
 * Linux trust host. The first refresh is genuine but its return is held behind
 * an owned barrier. A second writer finalizes first; the loser must report its
 * real receipt conflict. This does not claim cross-process serialization,
 * installed-service dispatch, or recovery from a partial receipt write. */
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const {spawn,spawnSync}=require("node:child_process");
const trust=require("../packages/agent/src/trust-store"),receipts=require("../packages/agent/src/trust-store/receipt");
const SCENARIO="linux-trust-native-receipt-conflict-recovery";
const SCOPE="native-linux-two-process-fixture-wrapped-refresh-receipt-conflict-recovery";
const PREFIX=".preserve-trust-receipt-conflict-";
const FLAGS=["actualSeparateWriterProcesses","firstNativeRefreshCompleted","secondActualRefreshFinalized","actualNativeRefreshesNoOverride","wrapperReleaseConsumed","losingWriterConflictReported","freshDefaultProcessReplay","freshDefaultProcessRevoke","unrelatedRootSourceAndReceiptUnchanged","unrelatedDefaultLeafTrustPreserved","ownedRootFinallyUntrusted","ownedWorkersClosed","ownedInheritedProcessGroupsDrained","ownershipGuardReleased"];
const REQUIRED_SOURCES=["scripts/certops-linux-trust-receipt-conflict.js","scripts/certops-linux-trust.js","packages/agent/src/trust-store/index.js","packages/agent/src/trust-store/receipt.js","packages/agent/src/platform/index.js","packages/agent/src/platform/durability.js"];
const hash=bytes=>crypto.createHash("sha256").update(bytes).digest("hex");
function identity(file,directory=false){const s=fs.lstatSync(file,{bigint:true});assert.ok(!s.isSymbolicLink()&&(directory?s.isDirectory():s.isFile())&&s.ino>0n);assert.equal(fs.realpathSync.native(file),file);return `${s.dev}:${s.ino}`;}
function snapshot(file){const s=fs.lstatSync(file,{bigint:true});return {identity:identity(file),hash:hash(fs.readFileSync(file)),mode:String(s.mode),uid:String(s.uid),gid:String(s.gid)};}
function publish(file,value){
  const temporary=`${file}.${crypto.randomBytes(16).toString("hex")}.tmp`,bytes=Buffer.from(JSON.stringify(value));
  const fd=fs.openSync(temporary,"wx",0o600);try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  const before=identity(temporary);fs.linkSync(temporary,file);assert.equal(identity(file),before);assert.equal(identity(temporary),before);assert.deepEqual(fs.readFileSync(file),bytes);fs.unlinkSync(temporary);
}
function read(file){const s=fs.lstatSync(file);assert.ok(s.isFile()&&!s.isSymbolicLink()&&s.nlink>=1&&s.nlink<=2&&s.size<=65536);return JSON.parse(fs.readFileSync(file,"utf8"));}
function guard(){assert.equal(process.platform,"linux");assert.equal(process.getuid(),0);assert.equal(process.env.CERTOPS_LINUX_TRUST_DISPOSABLE_HOST,"1");}
async function until(check,limit=150000){const deadline=performance.now()+limit;while(performance.now()<deadline){const value=await check();if(value)return value;await new Promise(resolve=>setTimeout(resolve,100));}throw new Error("Owned trust conflict handshake exceeded deadline");}
function verifyProof(value){
  assert.ok(value&&typeof value==="object"&&!Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(),["schemaVersion","scope","family","writerCount","losingFailureCategory","firstJobId","secondJobId","fingerprints","serializationQualified","partialWriteRecoveryQualified","detachedDescendantContainmentQualified",...FLAGS].sort());
  assert.equal(value.schemaVersion,1);assert.equal(value.scope,SCOPE);assert.ok(["debian","rhel"].includes(value.family));assert.equal(value.writerCount,2);assert.equal(value.losingFailureCategory,"receipt_finalize_conflict");
  for(const name of ["firstJobId","secondJobId"])assert.match(value[name],/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  assert.notEqual(value.firstJobId,value.secondJobId);
  assert.ok(Array.isArray(value.fingerprints)&&value.fingerprints.length===2&&value.fingerprints.every(v=>typeof v==="string"&&/^[a-f0-9]{64}$/.test(v))&&new Set(value.fingerprints).size===2);
  assert.equal(value.serializationQualified,false);assert.equal(value.partialWriteRecoveryQualified,false);assert.equal(value.detachedDescendantContainmentQualified,false);
  for(const flag of FLAGS)assert.equal(value[flag],true,flag);return true;
}
function assertCleanupSafe(workDir){assert.equal(fs.readdirSync(workDir).some(name=>name.startsWith(PREFIX)),false,"Unresolved native trust writers preserve fixture and receipts");}
function assertCleanNativeResult(result){assert.ok(!(result.metadata||[]).some(item=>["post_condition_override_applied","refresh_command_exit_code"].includes(item.name)),"A refresh failure/timeout override cannot qualify native writer completion");}
function parseProcess(pid,raw){
  assert.ok(Number.isSafeInteger(pid)&&pid>0);assert.ok(typeof raw==="string"&&raw.startsWith(`${pid} (`));
  const end=raw.lastIndexOf(") ");assert.ok(end>0);const fields=raw.slice(end+2).trim().split(/\s+/);assert.ok(fields.length>=20);
  const value={pid,parent:Number(fields[1]),group:Number(fields[2]),session:Number(fields[3]),birth:fields[19]};
  for(const name of ["parent","group","session"])assert.ok(Number.isSafeInteger(value[name])&&value[name]>=0);assert.match(value.birth,/^[0-9]+$/);return value;
}
function groupMembers(group){
  assert.ok(Number.isSafeInteger(group)&&group>0);const members=[];
  for(const name of fs.readdirSync("/proc"))if(/^[1-9][0-9]*$/.test(name)){
    let raw;try{raw=fs.readFileSync(`/proc/${name}/stat`,"utf8");}catch(error){if(["ENOENT","ESRCH"].includes(error.code))continue;throw error;}
    if(parseProcess(Number(name),raw).group===group)members.push(Number(name));
  }
  return members;
}
async function worker(manifestFile){
  guard();const manifest=read(manifestFile);assert.match(manifest.token,/^[a-f0-9]{32}$/);assert.equal(manifest.ownerPid,process.ppid);
  const observed=parseProcess(process.pid,fs.readFileSync("/proc/self/stat","utf8"));assert.equal(observed.group,process.pid);assert.equal(observed.session,process.pid);
  publish(manifestFile+".started",{token:manifest.token,...observed,executable:fs.realpathSync("/proc/self/exe")});
  const input=manifest.input;
  if(manifest.hold){
    const refreshFile=path.join(path.dirname(manifestFile),"refresh.json");
    publish(refreshFile,{token:manifest.token,family:input.family,ownerPid:process.pid});
    input.seams={...input.seams,updateCommandArgv:[process.execPath,__filename,"--refresh",refreshFile]};
  }
  const result=await (manifest.action==="revoke"?trust.revokeTrust(input):trust.distributeTrust(input));
  publish(manifest.resultFile,{token:manifest.token,workerPid:process.pid,result});
}
async function refresh(manifestFile){
  guard();const manifest=read(manifestFile);assert.equal(manifest.ownerPid,process.ppid);assert.match(manifest.token,/^[a-f0-9]{32}$/);assert.ok(["debian","rhel"].includes(manifest.family));
  const binary=manifest.family==="debian"?"update-ca-certificates":"update-ca-trust",args=manifest.family==="debian"?[]:["extract"];
  const actual=spawnSync(binary,args,{encoding:"utf8",timeout:120000,maxBuffer:512*1024});
  assert.ok(!actual.error&&actual.signal===null&&Number.isInteger(actual.status));
  if(actual.status!==0){process.exitCode=actual.status;return;}
  const directory=path.dirname(manifestFile);
  publish(path.join(directory,"refresh-ready.json"),{token:manifest.token,nativeExitCode:actual.status});
  await until(()=>{const file=path.join(directory,"release.json");if(!fs.existsSync(file))return false;assert.equal(read(file).token,manifest.token);return true;},180000);
  publish(path.join(directory,"release-consumed.json"),{token:manifest.token,nativeExitCode:actual.status});
  process.exitCode=actual.status;
}
async function qualifyReceiptConflict({family,workDir,receiptDir,certificate,protectedRoot,protectedLeaf,input,job,sourcePath,ownedPaths,ownedAnchors,native}){
  guard();assert.ok(["debian","rhel"].includes(family));
  for(const name of Object.keys(process.env))assert.ok(!["SSL_CERT_FILE","SSL_CERT_DIR","OPENSSL_CONF","OPENSSL_MODULES","NODE_EXTRA_CA_CERTS"].includes(name.toUpperCase()),"Default native trust oracle refuses environment overrides");
  const root=fs.realpathSync.native(workDir),rootId=identity(root,true),directory=fs.mkdtempSync(path.join(root,"receipt-conflict-")),directoryId=identity(directory,true),token=crypto.randomBytes(16).toString("hex");
  const marker=path.join(root,PREFIX+token+".json");publish(marker,{token,directory});const markerBefore=snapshot(marker);
  const owned=()=>{assert.equal(identity(root,true),rootId);assert.equal(identity(directory,true),directoryId);assert.deepEqual(snapshot(marker),markerBefore);};
  const store=family==="debian"?"debian-ca-certificates":"rhel-ca-trust";
  const protectedSource=sourcePath(protectedRoot),protectedReceipt=receipts.receiptRowPath(receiptDir,store,protectedRoot.fingerprint),sourceBefore=snapshot(protectedSource),receiptBefore=snapshot(protectedReceipt);
  let targetTrusted=false;
  const preserve=()=>{owned();assert.deepEqual(snapshot(protectedSource),sourceBefore);assert.deepEqual(snapshot(protectedReceipt),receiptBefore);native("openssl",["verify",protectedLeaf.pem]);if(targetTrusted)native("openssl",["verify",certificate.pem]);};
  const row=()=>receipts.readReceipt(receiptDir,store,certificate.fingerprint).row;
  assert.equal(fs.existsSync(sourcePath(certificate)),false);ownedPaths.add(sourcePath(certificate));ownedAnchors.push(certificate);
  const workers=[];
  const launch=(name,payload,hold=false,action="distribute")=>{
    owned();const manifestFile=path.join(directory,name+".json"),resultFile=path.join(directory,name+"-result.json");publish(manifestFile,{token,ownerPid:process.pid,input:input(payload),resultFile,hold,action});
    const child=spawn(process.execPath,[__filename,"--worker",manifestFile],{stdio:["ignore","ignore","ignore"],detached:true});
    const entry={child,closed:false,error:null,groupDrained:false};entry.promise=new Promise(resolve=>{child.once("error",error=>{entry.error=error;});child.once("close",(code,signal)=>{entry.closed=true;resolve({code,signal});});});workers.push(entry);
    entry.ready=()=>until(()=>{
      assert.equal(entry.error,null);const started=manifestFile+".started";if(!fs.existsSync(started)){assert.equal(entry.closed,false,"Writer closed before owned process-group readiness");return false;}
      const actual=read(started);assert.equal(actual.token,token);assert.equal(actual.pid,child.pid);assert.equal(actual.parent,process.pid);assert.equal(actual.group,child.pid);assert.equal(actual.session,child.pid);assert.match(actual.birth,/^[1-9][0-9]*$/);assert.equal(actual.executable,fs.realpathSync(process.execPath));
      if(!entry.closed){let live;try{live=parseProcess(child.pid,fs.readFileSync(`/proc/${child.pid}/stat`,"utf8"));}catch(error){if(["ENOENT","ESRCH"].includes(error.code))return false;throw error;}for(const key of ["pid","parent","group","session","birth"])assert.equal(live[key],actual[key]);}
      return actual;
    },15000);
    entry.result=async()=>{await entry.ready();await until(()=>entry.closed,320000);const exited=await entry.promise;assert.equal(entry.error,null);assert.equal(exited.code,0);assert.equal(exited.signal,null);await until(()=>groupMembers(child.pid).length===0,10000);entry.groupDrained=true;const value=read(resultFile);assert.equal(value.token,token);assert.equal(value.workerPid,child.pid);return value.result;};return entry;
  };
  let completed=false,proof;
  try{
    preserve();
    const initiallyUntrusted=native("openssl",["verify",certificate.pem],false);assert.ok(!initiallyUntrusted.error&&Number.isInteger(initiallyUntrusted.status)&&initiallyUntrusted.status!==0);
    const firstJob=job(certificate,"root"),secondJob={...firstJob,jobId:crypto.randomUUID(),transitionGeneration:firstJob.transitionGeneration+1};
    const first=launch("first",firstJob,true);
    await first.ready();
    await until(()=>{assert.equal(first.error,null);assert.equal(first.closed,false,"First writer closed before genuine refresh readiness");const file=path.join(directory,"refresh-ready.json");if(!fs.existsSync(file))return false;const value=read(file);assert.equal(value.token,token);assert.equal(value.nativeExitCode,0);return true;});
    assert.equal(first.closed,false);assert.equal(row().state,"pending_install");assert.equal(row().jobId,firstJob.jobId);targetTrusted=true;preserve();
    const second=launch("second",secondJob);assert.notEqual(second.child.pid,first.child.pid);
    const winner=await second.result();assertCleanNativeResult(winner);assert.equal(winner.jobId,secondJob.jobId);assert.equal(winner.transitionGeneration,secondJob.transitionGeneration);assert.equal(winner.observedFingerprintAfter,certificate.fingerprint);assert.equal(winner.failureCategory,null);assert.equal(winner.receipt.state,"finalized");assert.equal(winner.mutationPerformed,true);assert.equal(row().state,"installed");assert.equal(row().jobId,secondJob.jobId);preserve();
    assert.equal(first.closed,false,"First writer must remain retained until barrier release");
    publish(path.join(directory,"release.json"),{token});
    const loser=await first.result();assertCleanNativeResult(loser);const consumed=read(path.join(directory,"release-consumed.json"));assert.equal(consumed.token,token);assert.equal(consumed.nativeExitCode,0);assert.equal(loser.jobId,firstJob.jobId);assert.equal(loser.transitionGeneration,firstJob.transitionGeneration);assert.equal(loser.observedFingerprintAfter,certificate.fingerprint);assert.equal(loser.failureCategory,"receipt_finalize_conflict");assert.equal(loser.receipt.state,"intent_written");assert.equal(loser.outcome,"installed");assert.equal(loser.mutationPerformed,true);assert.equal(row().jobId,secondJob.jobId);assert.equal(row().state,"installed");preserve();
    const replay=await launch("replay",{...secondJob,jobId:crypto.randomUUID()}).result();assert.equal(replay.failureCategory,null);assert.equal(replay.outcome,"preexisting");assert.equal(replay.mutationPerformed,false);assert.equal(replay.receipt.state,"finalized");assert.equal(row().jobId,secondJob.jobId);preserve();
    const revoked=await launch("revoke",job(certificate,"root","revoke-trust"),false,"revoke").result();assert.equal(revoked.failureCategory,null);assert.equal(revoked.outcome,"removed");assert.equal(revoked.receipt.state,"finalized");assert.equal(revoked.mutationPerformed,true);assert.equal(row().state,"removed");assert.equal(fs.existsSync(sourcePath(certificate)),false);targetTrusted=false;
    const untrusted=native("openssl",["verify",certificate.pem],false);assert.ok(!untrusted.error&&Number.isInteger(untrusted.status)&&untrusted.status!==0);preserve();
    assert.ok(workers.every(value=>value.closed&&value.groupDrained));
    // This proves inherited groups are empty. It does not claim containment of
    // arbitrary hooks which deliberately detach into another session/group.
    proof={schemaVersion:1,scope:SCOPE,family,writerCount:2,serializationQualified:false,partialWriteRecoveryQualified:false,detachedDescendantContainmentQualified:false,losingFailureCategory:loser.failureCategory,firstJobId:firstJob.jobId,secondJobId:secondJob.jobId,fingerprints:[certificate.fingerprint,protectedRoot.fingerprint],...Object.fromEntries(FLAGS.map(name=>[name,true]))};
    owned();fs.unlinkSync(marker);completed=true;verifyProof(proof);return proof;
  }finally{
    // No PID kill or unproven cleanup: unresolved writers/refreshes retain the
    // marker and all original receipts for the disposable environment teardown.
    if(!completed)assert.equal(fs.existsSync(marker),true);
  }
}
module.exports={SCENARIO,SCOPE,FLAGS,REQUIRED_SOURCES,verifyProof,assertCleanupSafe,assertCleanNativeResult,parseProcess,publish,qualifyReceiptConflict};
if(require.main===module){const action=process.argv[2];(action==="--worker"?worker(process.argv[3]):action==="--refresh"?refresh(process.argv[3]):Promise.reject(new Error("Explicit native trust fixture mode required"))).catch(()=>{console.error("Native trust receipt conflict fixture failed; preserve owned state");process.exitCode=1;});}
