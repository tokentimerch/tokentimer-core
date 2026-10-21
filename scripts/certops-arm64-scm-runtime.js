/*
 * Qualification notes: arm64-packaged-scm
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * On fresh elevated Windows11 ARM64 with native Node/PowerShell, require canonical service/registry
 * absent and verify actual candidate archive checksum/PE/digests. Run the packaged SYSTEM host with
 * controlled mock child: start/stop/fresh restart, exit17 recovery and exit86 no-respawn for>=5
 * monotonic seconds. Capture native process creation/executable/argv/SID and original
 * volume/inode/birth identities for every owned root/file. Durable receipt updates preserve inode;
 * copied bytes/nonce do not transfer ownership. Read-only digest-bound validator checks each
 * mutation/cleanup; require absent captured descendants and exact service/registry absence before
 * deleting the root. Do not adopt/kill a PID or clean while original owner lives. This proves packaged
 * SCM behavior, not installed product registration, installer CLI, certificates/IIS/Server or full
 * ARM64 host qualification.
 */
"use strict";
/** Native-only packaged ARM64 SCM/mock-child qualification. Merely importing
 * this module performs no native mutation. Persistent receipts refuse cleanup
 * while the exact PowerShell owner is live or any service/process is uncertain. */
const assert=require("node:assert/strict"), fs=require("node:fs"), path=require("node:path"), os=require("node:os"), crypto=require("node:crypto"), cp=require("node:child_process");
const proof=require("./certops-arm64-scm-proof"), root=path.resolve(__dirname,".."), native=path.join(__dirname,"certops-arm64-scm-native.ps1");
const REQUIRED_SOURCES=Object.freeze(["scripts/certops-arm64-scm-runtime.js","scripts/certops-arm64-scm-proof.js","scripts/certops-arm64-scm-native.ps1",".github/workflows/certops-windows-arm64-scm.yml","packages/agent/scripts/pack-release.js","packages/agent/scripts/build-windows-service-host.js","packages/agent/scripts/build-windows-chain-helper.js","packages/agent/windows-service-host/go.mod","packages/agent/windows-service-host/go.sum","packages/agent/windows-service-host/main.go","packages/agent/windows-service-host/service_windows.go","packages/agent/windows-service-host/console_windows.go","packages/agent/windows-service-host/host.go","packages/agent/windows-service-host/testdata/mock-agent.js","packages/agent/scripts/host/package-fixture.js","packages/agent/scripts/host-gate.js"]);
const sha=bytes=>crypto.createHash("sha256").update(bytes).digest("hex");
function run(file,args,options={}){const result=cp.spawnSync(file,args,{encoding:"utf8",timeout:180000,...options});assert.ifError(result.error);assert.equal(result.status,0,`${file} failed: ${result.stderr}`);return result.stdout.trim();}
function fileIdentity(file, mutable = false) {
 const value=fs.lstatSync(file,{bigint:true}); assert.equal(value.isSymbolicLink(),false); assert.ok(value.ino>0n,"Stable file identity required");
 return {dev:String(value.dev),ino:String(value.ino),birthtimeNs:String(value.birthtimeNs),...(!value.isDirectory()&&!mutable?{size:String(value.size)}:{})};
}
function identityPaths(receipt,receiptPath){return {root:receipt.workDir,marker:path.join(receipt.workDir,".owner"),candidate:path.join(receipt.workDir,"candidate"),package:path.join(receipt.workDir,"candidate","package"),bin:path.join(receipt.workDir,"candidate","package","bin"),host:receipt.hostPath,mock:receipt.mockPath,node:receipt.nodePath,receipt:receiptPath};}
function initializeReceipt(receipt,receiptPath){
 // The original receipt inode is retained through all later updates. A torn
 // in-place write intentionally fails closed rather than authorizing cleanup.
 const fd=fs.openSync(receiptPath,"wx");
 try{fs.writeSync(fd,JSON.stringify(receipt));receipt.fileIdentities=Object.fromEntries(Object.entries(identityPaths(receipt,receiptPath)).map(([key,file])=>[key,fileIdentity(file,key==="receipt")]));const bytes=Buffer.from(JSON.stringify(receipt));fs.writeSync(fd,bytes,0,bytes.length,0);fs.ftruncateSync(fd,bytes.length);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
}
function validateReceipt(receipt,receiptPath){
 assert.ok(fs.lstatSync(receiptPath).size<=65536,"Bounded ownership receipt required");
 assert.equal(receipt.schemaVersion,1);assert.equal(receipt.suite,proof.suite);assert.match(receipt.runId,/^[a-f0-9-]{36}$/);
 const expected=path.join(os.tmpdir(),`certops-arm64-scm-${receipt.runId}`);assert.equal(path.resolve(receipt.workDir),path.resolve(expected));assert.equal(path.resolve(receiptPath),path.join(expected,"ownership.json"));
 for(const file of [expected,receiptPath]){assert.equal(fs.lstatSync(file).isSymbolicLink(),false);assert.equal(fs.realpathSync(file).toLowerCase(),path.resolve(file).toLowerCase());}
 assert.deepEqual(Object.keys(receipt.fileIdentities).sort(),Object.keys(identityPaths(receipt,receiptPath)).sort());
 for(const [key,file]of Object.entries(identityPaths(receipt,receiptPath)))assert.deepEqual(fileIdentity(file,key==="receipt"),receipt.fileIdentities[key],`Foreign replacement preserved: ${key}`);
 assert.equal(fs.readFileSync(path.join(expected,".owner"),"utf8"),receipt.runId);assert.equal(receipt.hostPath,path.join(expected,"candidate","package","bin","tokentimer-agent-host-arm64.exe"));assert.equal(receipt.mockPath,path.join(expected,"mock-agent.js"));assert.equal(receipt.nodePath,process.execPath);assert.equal(receipt.serviceName,"TokenTimerAgent");assert.equal(receipt.initialServiceAbsent,true);assert.equal(receipt.binPath,`"${receipt.hostPath}" "${receipt.nodePath}" "${receipt.mockPath}"`);
 const validationFiles=["scripts/certops-arm64-scm-runtime.js","scripts/certops-arm64-scm-proof.js","scripts/certops-arm64-scm-native.ps1"];assert.deepEqual(receipt.validationSources.map(row=>row.file),validationFiles);for(const row of receipt.validationSources)assert.equal(sha(fs.readFileSync(path.join(root,row.file))),row.sha256,"Original ownership validator source changed");
 for(const [file,digest]of [[receipt.hostPath,receipt.hostSha256],[receipt.mockPath,receipt.mockSha256],[receipt.nodePath,receipt.nodeSha256]]){assert.equal(fs.lstatSync(file).isSymbolicLink(),false);assert.equal(sha(fs.readFileSync(file)),digest);}
 return true;
}
function cleanup(receiptPath,pwsh){
 assert.ok(typeof receiptPath==="string"&&path.isAbsolute(receiptPath),"Exact owned cleanup receipt path required");
 if(!fs.existsSync(receiptPath))return;
 assert.ok(fs.lstatSync(receiptPath).size<=65536,"Bounded ownership receipt required");
 const receipt=JSON.parse(fs.readFileSync(receiptPath,"utf8").replace(/^\uFEFF/,""));validateReceipt(receipt,receiptPath);
 const result=JSON.parse(run(pwsh,["-NoProfile","-NonInteractive","-File",native,"-Mode","Cleanup","-Receipt",receiptPath]));assert.equal(result.cleanupVerified,true);
 assert.ok(fs.lstatSync(receiptPath).size<=65536,"Bounded ownership receipt required");const fresh=JSON.parse(fs.readFileSync(receiptPath,"utf8"));assert.deepEqual(fresh.fileIdentities,receipt.fileIdentities,"Original ownership identities changed during cleanup");assert.deepEqual(fresh.validationSources,receipt.validationSources);validateReceipt(receipt,receiptPath);validateReceipt(fresh,receiptPath);assert.equal(fresh.cleanupVerified,true);
 // Native adapter proved exact service/registry/process absence before files
 // are erased; re-read the same guarded receipt immediately before removal.
 fs.rmSync(receipt.workDir,{recursive:true});assert.equal(fs.existsSync(receipt.workDir),false);
}
async function main(){
 assert.equal(process.platform,"win32");assert.equal(process.arch,"arm64");assert.equal(process.env.CERTOPS_ARM64_SCM_REQUIRED,"1");
 const pwsh=process.env.CERTOPS_ARM64_SCM_PWSH;assert.ok(pwsh&&path.isAbsolute(pwsh));
 if(process.argv[2]==="--cleanup"){cleanup(process.env.CERTOPS_ARM64_SCM_RECEIPT,pwsh);return;}
 const {createHostGate}=require("../packages/agent/scripts/host-gate");
 const gate=createHostGate({suite:proof.suite,fixtureSource:{file:"scripts/certops-arm64-scm-runtime.js",sha256:sha(fs.readFileSync(__filename))},requiredCapabilities:["windows","native-arm64","optIn"],probeCapabilities:()=>({windows:{available:process.platform==="win32"},"native-arm64":{available:process.arch==="arm64"},optIn:{available:process.env.CERTOPS_ARM64_SCM_REQUIRED==="1"}})});
 assert.equal(await gate.preflight(),true);gate.report.qualificationEnvironment.architecture=process.arch;
 const runId=crypto.randomUUID(),workDir=path.join(os.tmpdir(),`certops-arm64-scm-${runId}`),receiptPath=path.join(workDir,"ownership.json");
 assert.equal(fs.existsSync(workDir),false);fs.mkdirSync(workDir);fs.writeFileSync(path.join(workDir,".owner"),runId,{flag:"wx"});const originalRootIdentity=fileIdentity(workDir),originalMarkerIdentity=fileIdentity(path.join(workDir,".owner"));
 // Publish the exact independently guarded cleanup path before any service work.
 assert.ok(process.env.GITHUB_ENV);fs.appendFileSync(process.env.GITHUB_ENV,`CERTOPS_ARM64_SCM_RECEIPT=${receiptPath}\n`);
 let primary, nativeResult, hostSha256, archiveSha256;
 try{
 await gate.scenario(proof.REQUIRED_SCENARIOS[0],()=>{
 const observation=JSON.parse(run(pwsh,["-NoProfile","-NonInteractive","-Command","$ErrorActionPreference='Stop';$o=Get-CimInstance Win32_OperatingSystem;@{productType=[int]$o.ProductType;build=[string]$o.BuildNumber;architecture=[string][Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture;cpus=@((Get-CimInstance Win32_Processor).Architecture);serviceAbsent=($null-eq(Get-Service TokenTimerAgent -ErrorAction SilentlyContinue));registryAbsent=!(Test-Path -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent')}|ConvertTo-Json -Compress"]));
 assert.equal(observation.productType,1);assert.ok(Number(observation.build)>=22000);assert.equal(observation.architecture,"Arm64");assert.ok(observation.cpus.length&&observation.cpus.every(value=>value===12));assert.equal(observation.serviceAbsent,true);assert.equal(observation.registryAbsent,true);
 const artifact=require("../packages/agent/scripts/pack-release").main(["--out-dir",path.join(workDir,"archive")]);const packageProof=require("../packages/agent/scripts/host/package-fixture");archiveSha256=packageProof.verifyArchiveDigest(artifact.tarballPath,artifact.checksumPath);
 fs.mkdirSync(path.join(workDir,"candidate"));run("tar.exe",["-xzf",artifact.tarballPath,"-C",path.join(workDir,"candidate")]);
 const hostPath=path.join(workDir,"candidate","package","bin","tokentimer-agent-host-arm64.exe");packageProof.verifyPeArchitecture(hostPath,0xaa64);hostSha256=sha(fs.readFileSync(hostPath));assert.equal(hostSha256,sha(fs.readFileSync(path.join(root,"packages/agent/bin/tokentimer-agent-host-arm64.exe"))));packageProof.verifyPeArchitecture(process.execPath,0xaa64);packageProof.verifyPeArchitecture(pwsh,0xaa64);
 const mockPath=path.join(workDir,"mock-agent.js");fs.copyFileSync(path.join(root,"packages/agent/windows-service-host/testdata/mock-agent.js"),mockPath,fs.constants.COPYFILE_EXCL);
 const receipt={validationSources:["scripts/certops-arm64-scm-runtime.js","scripts/certops-arm64-scm-proof.js","scripts/certops-arm64-scm-native.ps1"].map(file=>({file,sha256:sha(fs.readFileSync(path.join(root,file)))})),schemaVersion:1,suite:proof.suite,runId,workDir,hostPath,hostSha256,mockPath,mockSha256:sha(fs.readFileSync(mockPath)),nodePath:process.execPath,nodeSha256:sha(fs.readFileSync(process.execPath)),serviceName:"TokenTimerAgent",initialServiceAbsent:true,binPath:`"${hostPath}" "${process.execPath}" "${mockPath}"`,processes:[],serviceOwned:false,operationPid:null,operationCreated:null,cleanupVerified:false,result:null};
 assert.deepEqual(fileIdentity(workDir),originalRootIdentity);assert.deepEqual(fileIdentity(path.join(workDir,".owner")),originalMarkerIdentity);initializeReceipt(receipt,receiptPath);validateReceipt(receipt,receiptPath);
 },{evidenceLevel:"real-host",oracle:"Actual native ARM64 desktop/Node/PowerShell, initially absent canonical SCM identity and freshly packed exact candidate ARM64 host PE/digest; no source-renamed host"});
 await gate.scenario(proof.REQUIRED_SCENARIOS[1],()=>{
 nativeResult=JSON.parse(run(pwsh,["-NoProfile","-NonInteractive","-File",native,"-Mode","Run","-Receipt",receiptPath],{timeout:180000}));
 },{evidenceLevel:"real-host",oracle:"Actual canonical LocalSystem service running owned mock child, stopped exact process drainage and fresh restart"});
 await gate.scenario(proof.REQUIRED_SCENARIOS[2],()=>{
 assert.equal(nativeResult.generations.length,3);assert.ok(nativeResult.retirementObservationMs>=5000);
 },{evidenceLevel:"real-host",oracle:"Actual mock exit17 triggers configured SCM recovery with fresh processes; exit86 stops successfully and no respawn during bounded real monotonic observation"});
 }catch(error){primary=error;}
 try{await gate.scenario(proof.REQUIRED_SCENARIOS[3],()=>{if(fs.existsSync(receiptPath))cleanup(receiptPath,pwsh);else{assert.ok(!nativeResult,"Native execution requires durable receipt");assert.deepEqual(fileIdentity(workDir),originalRootIdentity);assert.deepEqual(fileIdentity(path.join(workDir,".owner")),originalMarkerIdentity);assert.equal(fs.lstatSync(workDir).isSymbolicLink(),false);assert.equal(fs.realpathSync(workDir).toLowerCase(),path.resolve(workDir).toLowerCase());assert.equal(fs.readFileSync(path.join(workDir,".owner"),"utf8"),runId);fs.rmSync(workDir,{recursive:true});}assert.equal(fs.existsSync(workDir),false);},{evidenceLevel:"real-host",oracle:"Exact owned service/registry absent and all captured process identities drained before guarded owned root erasure"});}catch(error){throw new AggregateError([...(primary?[primary]:[]),error],"SCM fixture failed; unresolved service/process/files preserved");}
 if(primary)throw primary;
 const result={scope:proof.SCOPE,architecture:"arm64",productType:nativeResult.productType,build:nativeResult.build,hostSha256,archiveSha256,realAgentQualified:false,apiQualified:false,fullInstallerQualified:false,iisQualified:false,serverQualified:false,retirementObservationMs:nativeResult.retirementObservationMs,generations:nativeResult.generations,...Object.fromEntries(proof.FLAGS.map(flag=>[flag,true]))};proof.verifyProof(result);gate.report.nativeArm64Scm=result;
 gate.report.fixtureSources=REQUIRED_SOURCES.map(file=>({file,sha256:sha(fs.readFileSync(path.join(root,file)))}));gate.report.cleanup={status:"passed"};proof.verifyRuntimeReport(gate.report);await gate.finish({requiredScenarios:proof.REQUIRED_SCENARIOS,cleanup:{status:"passed",summary:"Exact service/registry and captured descendants absent; owned root removed"}});
}
module.exports={REQUIRED_SOURCES,fileIdentity,initializeReceipt,validateReceipt,cleanup,main};
if(require.main===module)main().catch(error=>{console.error(error.message);process.exitCode=1;});
