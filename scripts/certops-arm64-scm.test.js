"use strict";
// Pure proof adversaries only; native SCM/service-host execution is deferred.
const test = require("node:test"), assert = require("node:assert/strict");
const h = require("./certops-arm64-scm-proof");
function proof() { return { scope: h.SCOPE, architecture: "arm64", productType: 1, build: "26100", hostSha256: "a".repeat(64), archiveSha256: "b".repeat(64), realAgentQualified: false, apiQualified: false, fullInstallerQualified: false, iisQualified: false, serverQualified: false, retirementObservationMs: 5001, generations: [0,1,2].map(i=>({hostPid:100+i,childPid:200+i,hostCreated:`2026-10-14T10:00:0${i}.0000000Z`,childCreated:`2026-10-14T10:00:0${i}.1000000Z`})), ...Object.fromEntries(h.FLAGS.map(flag=>[flag,true])) }; }
test("ARM64 packaged SCM proof cannot promote mock child lifecycle into real agent or Server", () => {
  assert.equal(h.verifyProof(proof()), true);
  for (const key of Object.keys(proof())) { const missing=proof(); delete missing[key]; assert.throws(()=>h.verifyProof(missing)); const bad=proof(); bad[key]=typeof bad[key]==="boolean"?!bad[key]:"invalid"; assert.throws(()=>h.verifyProof(bad)); }
  for (const patch of [{retirementObservationMs:4999},{retirementObservationMs:20001},{retirementObservationMs:true},{productType:3},{architecture:"x64"},{rawCommandLine:"private"},{generations:[proof().generations[0],proof().generations[0],proof().generations[2]]}]) assert.throws(()=>h.verifyProof({...proof(),...patch}));
});

test("ARM64 SCM source inventory and manual runner remain narrowly scoped", () => {
 const fs=require("node:fs"), path=require("node:path"), runtime=require("./certops-arm64-scm-runtime");
 assert.equal(new Set(runtime.REQUIRED_SOURCES).size,runtime.REQUIRED_SOURCES.length);
 for(const file of runtime.REQUIRED_SOURCES)assert.ok(fs.statSync(path.resolve(__dirname,"..",file)).isFile(),file);
 const native=fs.readFileSync(path.join(__dirname,"certops-arm64-scm-native.ps1"),"utf8");
 for(const expected of ["function Assert-Drained", "CreationDate.ToUniversalTime().ToString('o')", "GetOwnerSid", "S-1-5-18", "Actual child failure17", "Actual retirement86", "while($watch.ElapsedMilliseconds-lt 5000)", "Native owner still live", "Native owner descendant still live", "Unexpected late descendant preserved", "Retirement created an unexpected additional mock child"])assert.ok(native.includes(expected),expected);
 assert.doesNotMatch(native,/Stop-Process|taskkill/i);
 const workflow=fs.readFileSync(path.resolve(__dirname,"../.github/workflows/certops-windows-arm64-scm.yml"),"utf8");assert.match(workflow,/runs-on: windows-11-arm/);assert.match(workflow,/workflow_dispatch:/);assert.doesNotMatch(workflow,/pull_request:|schedule:|Enable-WindowsOptionalFeature/);
});

test("SCM cleanup receipt refuses changed public files and foreign root/service command", () => {
 const fs=require("node:fs"),os=require("node:os"),path=require("node:path"),crypto=require("node:crypto"),runtime=require("./certops-arm64-scm-runtime");
 const runId=crypto.randomUUID(),workDir=path.join(os.tmpdir(),`certops-arm64-scm-${runId}`),receiptPath=path.join(workDir,"ownership.json");
 const hash=bytes=>crypto.createHash("sha256").update(bytes).digest("hex");
 fs.mkdirSync(path.join(workDir,"candidate/package/bin"),{recursive:true});
 const hostPath=path.join(workDir,"candidate/package/bin/tokentimer-agent-host-arm64.exe"),mockPath=path.join(workDir,"mock-agent.js");
 fs.writeFileSync(path.join(workDir,".owner"),runId);fs.writeFileSync(hostPath,"public placeholder; never executed");fs.writeFileSync(mockPath,"public mock placeholder; never executed");
 const receipt={validationSources:["scripts/certops-arm64-scm-runtime.js","scripts/certops-arm64-scm-proof.js","scripts/certops-arm64-scm-native.ps1"].map(file=>({file,sha256:hash(fs.readFileSync(path.resolve(__dirname,"..",file)))})),schemaVersion:1,suite:h.suite,runId,workDir,hostPath,mockPath,nodePath:process.execPath,hostSha256:hash(fs.readFileSync(hostPath)),mockSha256:hash(fs.readFileSync(mockPath)),nodeSha256:hash(fs.readFileSync(process.execPath)),serviceName:"TokenTimerAgent",initialServiceAbsent:true,binPath:`"${hostPath}" "${process.execPath}" "${mockPath}"`};runtime.initializeReceipt(receipt,receiptPath);
 try{
  assert.equal(runtime.validateReceipt(receipt,receiptPath),true);
  for(const patch of [{workDir:path.dirname(workDir)},{hostPath:mockPath},{serviceName:"ForeignService"},{initialServiceAbsent:false},{binPath:"foreign command"},{hostSha256:"a".repeat(64)}])assert.throws(()=>runtime.validateReceipt({...receipt,...patch},receiptPath));
  // Identical bytes/nonce at a replacement inode never inherit ownership.
  for(const file of [hostPath,mockPath,path.join(workDir,".owner"),receiptPath]){
   const backup=file+".original",bytes=fs.readFileSync(file);fs.renameSync(file,backup);fs.writeFileSync(file,bytes,{flag:"wx"});
   assert.throws(()=>runtime.validateReceipt(receipt,receiptPath),/Foreign replacement preserved/);
   assert.deepEqual(fs.readFileSync(file),bytes);fs.rmSync(file);fs.renameSync(backup,file);assert.equal(runtime.validateReceipt(receipt,receiptPath),true);
  }
  const originalRoot=workDir+"-original";fs.renameSync(workDir,originalRoot);fs.cpSync(originalRoot,workDir,{recursive:true});
  assert.throws(()=>runtime.validateReceipt(receipt,receiptPath),/Foreign replacement preserved/);assert.equal(fs.readFileSync(path.join(workDir,".owner"),"utf8"),runId);
  fs.rmSync(workDir,{recursive:true});fs.renameSync(originalRoot,workDir);assert.equal(runtime.validateReceipt(receipt,receiptPath),true);
  fs.writeFileSync(hostPath,"foreign changed bytes");assert.throws(()=>runtime.validateReceipt(receipt,receiptPath));assert.equal(fs.readFileSync(hostPath,"utf8"),"foreign changed bytes");
 }finally{assert.equal(path.dirname(workDir),os.tmpdir());assert.equal(fs.readFileSync(path.join(workDir,".owner"),"utf8"),runId);fs.rmSync(workDir,{recursive:true});}
});

test("ARM64 SCM report requires native desktop scope, cleanup and every exact current source", () => {
 const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto"),sources=require("./certops-arm64-scm-runtime").REQUIRED_SOURCES;
 const report={platform:"win32",architecture:"arm64",nativeArm64Scm:proof(),qualificationEnvironment:{osFamily:"windows",productType:1,architecture:"arm64",osVersion:"desktop-26100",measurement:"native"},cleanup:{status:"passed"},fixtureSources:sources.map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"..",file))).digest("hex")}))};report.fixtureSource=report.fixtureSources.find(row=>row.file==="scripts/certops-arm64-scm-runtime.js");assert.equal(h.verifyRuntimeReport(report),true);
 for(const change of [r=>r.architecture="x64",r=>r.qualificationEnvironment.productType=3,r=>r.qualificationEnvironment.osVersion="2025",r=>r.qualificationEnvironment.measurement="declared",r=>r.cleanup.status="not-run",r=>r.fixtureSources.pop(),r=>r.fixtureSources.push(r.fixtureSources[0]),r=>r.fixtureSource={file:"foreign",sha256:"a".repeat(64)}]){const bad=structuredClone(report);change(bad);assert.throws(()=>h.verifyRuntimeReport(bad));}
 for(const file of sources){const bad=structuredClone(report);bad.fixtureSources.find(row=>row.file===file).sha256="f".repeat(64);assert.throws(()=>h.verifyRuntimeReport(bad),file);}
});
