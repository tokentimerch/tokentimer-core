"use strict";
/** SYSTEM ScheduledTask entry point for the same-VM resident collector window.
 * Protected workflow source; native execution remains a separate qualification.
 * Preparation must supply real
 * AD CS cutover receipts, its untouched production ledger and controller-owned
 * config digest; no CA request/key/ledger fixture is constructed here. */
const assert = require("node:assert/strict"), crypto = require("node:crypto"), fs = require("node:fs"), path = require("node:path"), tls = require("node:tls");
const { spawnSync } = require("node:child_process");
const {performance}=require("node:perf_hooks");
const contract = require("./certops-retention24h-contract");
const retention = require("../packages/agent/src/windows-retention");
const { runResidentWindow } = require("../tests/e2e/helpers/certops-retention24h-keeper");
const REQUIRED_SOURCES=require("./certops-retention24h-sources").REQUIRED_SOURCES;
function digest(file) { return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex"); }
function verifyConfig(config, configPath) {
  contract.verifyLease(config.lease); assert.equal(config.lease.phase, "preparing");
  const directory = `C:\\ttqualification\\retention24h\\${config.lease.nonce}`;
  assert.equal(configPath, path.win32.join(directory, "keeper-config.json")); assert.equal(config.stateDir, path.win32.join(directory, "agent"));
  assert.equal(config.retentionHours, 24);
  assert.ok(Array.isArray(config.drainedTree) && config.drainedTree.length > 0 && config.drainedTree.length <= 64);const drainedPids=new Set();for(const item of config.drainedTree){assert.ok(Number.isInteger(item.pid)&&item.pid>0&&!drainedPids.has(item.pid));drainedPids.add(item.pid);assert.ok(Number.isFinite(Date.parse(item.createdAt)));}
  assert.ok(Array.isArray(config.requiredSources) && config.requiredSources.length >= 5 && config.requiredSources.length <= 64);
  const sources = new Set();
  for (const item of config.requiredSources) {
    assert.equal(typeof item.file, "string"); assert.match(item.file, /^(?:scripts|tests|packages|infra|apps|\.github)\/[a-zA-Z0-9_./-]+$/); assert.ok(!item.file.split("/").includes("..")); assert.match(item.sha256, /^[a-f0-9]{64}$/); assert.equal(sources.has(item.file), false); sources.add(item.file);
  }
  for (const file of REQUIRED_SOURCES) assert.ok(sources.has(file));
  assert.match(config.collectorHelper?.file, /^(?:packages\/agent\/bin\/tokentimer-adcs-chain-amd64.exe|packages\/agent\/reference\/adcs-chain\/dist\/tokentimer-adcs-chain-windows-amd64.exe)$/); assert.match(config.collectorHelper.sha256,/^[a-f0-9]{64}$/);
  for (const item of [config.predecessor, config.replacement]) {
    assert.match(item.thumbprint, /^[A-F0-9]{40}$/); assert.match(item.containerName, /^tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
    assert.equal(typeof item.certificateDerB64,"string"); assert.ok(item.certificateDerB64.length <= 32768);
    const leaf = new crypto.X509Certificate(Buffer.from(item.certificateDerB64, "base64")); assert.equal(leaf.fingerprint.replace(/:/g, ""), item.thumbprint);
  }
  assert.notEqual(config.predecessor.thumbprint, config.replacement.thumbprint); assert.notEqual(config.predecessor.containerName, config.replacement.containerName);
  assert.equal(config.site,`TTADCS-${config.domain?.split("-")[2]?.split(".")[0]}-retention24h`);
  assert.match(config.domain, /^certops-adcs-[a-f0-9]{10}-retention24h\.example\.test$/); assert.ok(Number.isInteger(config.port) && config.port > 0 && config.port <= 65535);
  assert.equal(typeof config.caPem, "string"); assert.ok(config.caPem.length <= 65536); new crypto.X509Certificate(config.caPem);
  const row = retention.validateLedgerRow(config.originalLedgerRow);
  assert.equal(row.oldThumbprint, config.predecessor.thumbprint); assert.equal(row.replacementThumbprint, config.replacement.thumbprint); assert.equal(row.cngKeyContainerId, config.predecessor.containerName); assert.equal(row.ownershipProvenance, "tokentimer_installed"); assert.ok(["pending_retention", "deferred"].includes(row.lifecycleState)); if (row.lifecycleState === "deferred") assert.equal(row.deferralReason, "deadline_not_reached");
  assert.equal(Date.parse(row.oldNotAfter),Date.parse(new crypto.X509Certificate(Buffer.from(config.predecessor.certificateDerB64,"base64")).validTo));
  assert.equal(Date.parse(config.cleanupDeadline), Date.parse(row.verifiedCutoverAt) + contract.DAY);
  assert.ok(Date.parse(row.oldNotAfter) > Date.parse(config.cleanupDeadline) + contract.HOUR);
  return true;
}
function assertOwnedLedgerInventory(stateDir, thumbprint) {
  assert.match(thumbprint,/^[A-F0-9]{40}$/);
  // Fresh protected fixture state and a drained sole agent bound this workload.
  // This is not a transaction against a malicious privileged actor racing us.
  assert.deepEqual(retention.listLedgerThumbprints(path.join(stateDir,"windows-retention")).sort(),[thumbprint]);
}
function assertOwnedSweepSummary(summary, thumbprint, expected) {
  assert.ok(["kept-before-deadline","removed-after-real-day"].includes(expected));
  assert.ok(summary&&typeof summary==="object");
  const removed=expected==="removed-after-real-day";
  assert.deepEqual(summary.removed,removed?[thumbprint]:[]);
  assert.deepEqual(summary.deferred,removed?[]:[{oldThumbprint:thumbprint,reason:"deadline_not_reached"}]);
  assert.deepEqual(summary.deferredCountByReason,Object.fromEntries(retention.DEFERRAL_REASONS.map(reason=>[reason,!removed&&reason==="deadline_not_reached"?1:0])));
}
async function trustedPeer(config) {
  const binding=await require("../packages/agent/src/windows-iis").queryCurrentBinding({binding:{site:config.site,port:config.port,sniHost:config.domain}});assert.equal(binding.ok,true);assert.equal(binding.thumbprint?.toUpperCase(),config.replacement.thumbprint);
  await new Promise((resolve, reject) => {
    const socket = tls.connect({host:"127.0.0.1",port:config.port,servername:config.domain,ca:config.caPem,rejectUnauthorized:true},()=>{try {assert.equal(socket.authorized,true);assert.equal(new crypto.X509Certificate(socket.getPeerCertificate().raw).fingerprint.replace(/:/g,""),config.replacement.thumbprint);resolve();}catch(error){reject(error);}finally{socket.destroy();}});
    socket.once("error",reject);socket.setTimeout(10000,()=>socket.destroy(new Error("Resident trusted TLS deadline")));
  });
}
async function inspectNative(configPath, configSha256, expected) {
  assert.equal(process.platform,"win32");assert.match(configSha256,/^[a-f0-9]{64}$/);assert.equal(digest(configPath),configSha256);assert.ok(fs.statSync(configPath).size<=262144);
  const config=JSON.parse(fs.readFileSync(configPath,"utf8"));verifyConfig(config,configPath);assert.equal(digest(process.execPath),config.lease.nodeSha256);assert.equal(digest(__filename),config.lease.keeperSha256);
  for(const item of config.requiredSources)assert.equal(digest(path.resolve(__dirname,"..",item.file)),item.sha256);
  const helper=require("../packages/agent/src/issuers/chain-helper").resolveAdcsChainHelperPath();assert.equal(helper.error,undefined);assert.equal(path.resolve(helper.path),path.resolve(__dirname,"..",config.collectorHelper.file));assert.equal(digest(helper.path),config.collectorHelper.sha256);
  process.env.CERTOPS_ADCS_DISPOSABLE_LAB="1";
  const result=spawnSync("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(__dirname,"certops-retention24h-native.ps1"),"-ConfigPath",configPath,"-ConfigSha256",configSha256,"-Expected",expected],{encoding:"utf8",timeout:30000,windowsHide:true,maxBuffer:8192});assert.ifError(result.error);assert.equal(result.status,0,"Independent current native oracle failed");
  const observed=JSON.parse(result.stdout);assert.equal(observed.soleAgentStopped,true);assert.equal(observed.replacementCustodyVerified,true);assert.equal(observed.expected,expected);assert.equal(observed.predecessorPresent,expected==="kept-before-deadline");assert.equal(observed.predecessorKeyPresent,expected==="kept-before-deadline");
  assertOwnedLedgerInventory(config.stateDir,config.predecessor.thumbprint);
  const row=retention.readLedgerRow(path.join(config.stateDir,"windows-retention"),config.predecessor.thumbprint);assert.ok(row);for(const[key,value]of Object.entries(config.originalLedgerRow))if(!["lifecycleState","deferralReason"].includes(key))assert.deepEqual(row[key],value);
  if(expected==="removed-after-real-day")assert.equal(row.lifecycleState,"removed");else {assert.ok(["pending_retention","deferred"].includes(row.lifecycleState));if(row.lifecycleState==="deferred")assert.equal(row.deferralReason,"deadline_not_reached");}
  await trustedPeer(config);
  return {nativeCustodyVerified:true,trustedTlsVerified:true,soleAgentStoppedAndDrained:true,productionCutoverVerified:true,ledgerUnmodified:true,verifiedCutoverAt:row.verifiedCutoverAt,oldNotAfter:row.oldNotAfter,cleanupDeadline:config.cleanupDeadline,bootTime:observed.bootTime,actualPredecessorCertificateAbsent:observed.predecessorPresent===false,actualPredecessorKeyAbsent:observed.predecessorKeyPresent===false,replacementCngCustodyVerified:true,replacementIisSniBindingVerified:true};
}
async function main(configPath, configSha256) {
  assert.equal(process.platform, "win32"); assert.match(configSha256, /^[a-f0-9]{64}$/); assert.equal(digest(configPath),configSha256);
  assert.ok(fs.statSync(configPath).size <= 262144);
  const config=JSON.parse(fs.readFileSync(configPath,"utf8"));verifyConfig(config,configPath);assert.equal(digest(process.execPath),config.lease.nodeSha256);
  const readinessStart=performance.now();
  process.env.CERTOPS_ADCS_DISPOSABLE_LAB="1"; // Dedicated validated keeper entry point; native oracle independently verifies actual domain/IMDS.
  const root=path.resolve(__dirname,".."),directory=path.dirname(configPath);
  const checkSources=()=>{assert.equal(digest(configPath),configSha256);assert.equal(digest(__filename),config.lease.keeperSha256);const actualHelper=require("../packages/agent/src/issuers/chain-helper").resolveAdcsChainHelperPath();assert.equal(actualHelper.error,undefined);assert.equal(path.resolve(actualHelper.path),path.resolve(root,config.collectorHelper.file));assert.equal(digest(actualHelper.path),config.collectorHelper.sha256);for(const item of config.requiredSources)assert.equal(digest(path.join(root,item.file)),item.sha256);};
  let bootTime, processCreatedAt;
  const native=expected=>{
    checkSources(); const result=spawnSync("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(__dirname,"certops-retention24h-native.ps1"),"-ConfigPath",configPath,"-ConfigSha256",configSha256,"-Expected",expected],{encoding:"utf8",timeout:30000,windowsHide:true,maxBuffer:8192});
    assert.ifError(result.error);assert.equal(result.status,0,"Resident exact native custody oracle failed");const observed=JSON.parse(result.stdout);
    assert.equal(observed.processId,process.pid);if(processCreatedAt)assert.equal(observed.processCreatedAt,processCreatedAt);else processCreatedAt=observed.processCreatedAt;
    assert.equal(observed.principalSid,"S-1-5-18");assert.equal(observed.soleAgentStopped,true);assert.equal(observed.replacementCustodyVerified,true);assert.equal(observed.expected,expected);
    if(bootTime)assert.equal(observed.bootTime,bootTime,"Resident VM boot identity changed");else bootTime=observed.bootTime;
    assert.equal(observed.predecessorPresent,expected==="kept-before-deadline");assert.equal(observed.predecessorKeyPresent,expected==="kept-before-deadline");return observed;
  };
  const ledger=expected=>{
    assertOwnedLedgerInventory(config.stateDir,config.predecessor.thumbprint);
  const row=retention.readLedgerRow(path.join(config.stateDir,"windows-retention"),config.predecessor.thumbprint);assert.ok(row);
    for(const [key,value]of Object.entries(config.originalLedgerRow))if(!["lifecycleState","deferralReason"].includes(key))assert.deepEqual(row[key],value);
    if(expected==="removed-after-real-day") assert.equal(row.lifecycleState,"removed"); else {assert.ok(["pending_retention","deferred"].includes(row.lifecycleState));if(row.lifecycleState==="deferred")assert.equal(row.deferralReason,"deadline_not_reached");}return row;
  };
  native("kept-before-deadline");ledger("kept-before-deadline");await trustedPeer(config);
  // Exclusive ready file makes a task restart fail rather than claim elapsed
  // time from a previous process. Finalizer independently checks this PID/task.
  fs.writeFileSync(path.join(directory,"resident-ready.json"),JSON.stringify({candidateSha:config.lease.candidateSha,nonce:config.lease.nonce,pid:process.pid,processCreatedAt,bootTime,configSha256,nodeSha256:digest(process.execPath),readinessMonotonicElapsedMs:Math.floor(performance.now()-readinessStart)}),{flag:"wx",mode:0o600});
  const result=await runResidentWindow({stateDir:config.stateDir,cleanupDeadline:config.cleanupDeadline,
    verifySoleAgentStopped:()=>{native("kept-before-deadline");},
    beforeSweep:async()=>{assertOwnedLedgerInventory(config.stateDir,config.predecessor.thumbprint);native("kept-before-deadline");ledger("kept-before-deadline");await trustedPeer(config);assertOwnedLedgerInventory(config.stateDir,config.predecessor.thumbprint);},
    afterSweep:async(expected,summary)=>{native(expected);ledger(expected);await trustedPeer(config);assertOwnedSweepSummary(summary,config.predecessor.thumbprint,expected);}});
  fs.writeFileSync(path.join(directory,"resident-result.json"),JSON.stringify({...result,candidateSha:config.lease.candidateSha,nonce:config.lease.nonce,pid:process.pid,processCreatedAt,bootTime,configSha256,nativeCustodyVerified:true,trustedTlsVerified:true,actualProductionLedgerVerified:true}),{flag:"wx",mode:0o600});
}
module.exports={REQUIRED_SOURCES,verifyConfig,assertOwnedLedgerInventory,assertOwnedSweepSummary,inspectNative,main};
if(require.main===module){
 const operation=process.argv[2]==="--observe"||process.argv[2]==="--final-observe" ? inspectNative(process.argv[3],process.argv[4],process.argv[2]==="--observe"?"kept-before-deadline":"removed-after-real-day").then(value=>process.stdout.write(JSON.stringify(value))) : main(process.argv[2],process.argv[3]);
 operation.catch(()=>{process.stderr.write("Resident native retention qualification failed; preserve owned state for independent cleanup.\n");process.exitCode=1;});
}
