"use strict";
// Portable proof and observer-finalization regressions, not native qualification.
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),crypto=require("node:crypto"),vm=require("node:vm");
const experiment=require("../tests/e2e/certops-adcs-focused-experiment.cjs");
const root=path.resolve(__dirname,"..");
const fingerprint=file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")});
function proof(){
 const phase="issued",candidate="a".repeat(40);
 return {schemaVersion:1,startedAt:"2026-10-19T00:00:00Z",finishedAt:"2026-10-19T00:01:00Z",requiredCapabilities:["api"],capabilities:{api:{available:true}},suite:"adcs-focused-journal-experiment",strict:true,status:"passed",candidateSha:candidate,phase,qualificationStatus:"not-qualified",experimental:true,baselineQualificationSatisfied:false,releaseQualificationSatisfied:false,
  requiredScenarios:[...experiment.SCENARIOS],missingScenarios:[],missingCapabilities:[],scenarios:experiment.SCENARIOS.map(id=>({id,status:"passed"})),fixtureSources:experiment.SOURCES.map(fingerprint),actualOSBuild:"20348",systemLocale:"en-US",qualificationEnvironment:{osFamily:"windows",osVersion:"2022",nativeLanguage:"en-US",identity:"LocalSystem",measurement:"native"},
  buildProvenance:{buildMode:"qualification-only-not-release",nodeArchiveSha256:"1".repeat(64),goArchiveSha256:"2".repeat(64),sourceArchiveSha256:"3".repeat(64),qualifiedModuleSha256:"4".repeat(64)},cleanup:{status:"passed"},ownedCleanup:{scope:"owned-process-drain-only",status:"passed",nativeCustody:"preserved-for-owned-lab-teardown",databaseOwnership:"preserved-for-owned-lab-teardown",serviceRemoved:true,ownedProcessesDrained:true},
  journalExperiment:{qualificationEnvironment:{osFamily:"windows",osVersion:"2022",nativeLanguage:"en-US",identity:"LocalSystem",measurement:"native"},schemaVersion:1,scope:"enterprise-adcs-journal-phase-experimental",qualificationStatus:"not-qualified",status:"passed",candidateSha:candidate,fixtureSource:fingerprint("tests/e2e/helpers/certops-adcs-journal-phase-experiment.js"),phase,
   fault:{phase,observedDurablePhase:true,unchangedAfterTermination:true,ownedServiceTree:true,nativeIdentity:"LocalSystem"},actualRenewedLeaseObserved:true,actualOrphanedJobObserved:true,ownedScmRecoveryTemporarilyDisabled:true,ownedScmRecoveryRestored:true,operatorRecoveryAuditObserved:true,originalUnknownEffectEvidencePreserved:true,sameKeyAndCsrIdentityPreserved:true,leaseSeconds:60,hardGraceMs:60000,clocks:"actual-host-and-database",databasePhaseRewritten:false,journalRewritten:false,outcome:"same-key-installation-recovered",caRequestsAtFault:1,caRequestsAfterRecovery:1,trustedNativeTls:true,issuedRequestIdentityPreserved:true,nativeRequestIdAtFault:17,nativeRequestIdAfterRecovery:17}};
}
test("a repeatable experiment cannot claim clean-forest or release qualification",()=>{
 assert.equal(experiment.verifyReport(proof(),"a".repeat(40)),true);
 for(const patch of [{suite:"enterprise-adcs-real"},{baselineQualificationSatisfied:true},{releaseQualificationSatisfied:true},{qualificationStatus:"qualified"},{strict:false},{phase:"keygen_intent"},{candidateSha:"b".repeat(40)},{actualOSBuild:"17763"},{systemLocale:"de-DE"}])assert.throws(()=>experiment.verifyReport({...proof(),...patch},"a".repeat(40)));
});
test("source fingerprints, actual native outcomes and owned drainage are mandatory",()=>{
 for(const mutate of [p=>p.fixtureSources.pop(),p=>p.requiredCapabilities=[],p=>p.capabilities.api.available=false,p=>p.startedAt="missing",p=>p.finishedAt="2025-01-01",p=>p.journalExperiment.qualificationEnvironment.osVersion="2019",p=>p.fixtureSources[0].sha256="0".repeat(64),p=>p.scenarios.pop(),p=>p.scenarios[0].status="skipped",p=>p.ownedCleanup.ownedProcessesDrained=false,p=>p.ownedCleanup.nativeCustody="deleted",p=>p.cleanup.status="failed",p=>p.ownedCleanup.status="failed",p=>p.buildProvenance.sourceArchiveSha256="missing",p=>p.journalExperiment.nativeRequestIdAfterRecovery=18,p=>p.journalExperiment.fixtureSource.sha256="0".repeat(64)]){
  const p=proof();mutate(p);assert.throws(()=>experiment.verifyReport(p,"a".repeat(40)));
 }
});
for(const drainFails of [false,true])test(drainFails?"failed observer drainage prevents SCM recovery and service restart":"journal finalization waits for the exact observer's drained close before writing evidence",async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),"journal-finalize-drain-")),report=path.join(directory,"report.json");
 let releaseDrain,drainStarted=false;const serviceActions=[];let serviceStarts=0;
 const drained=new Promise(resolve=>{releaseDrain=resolve;});
 const module={exports:{}};
 const sourceFile=path.join(root,"tests/e2e/helpers/certops-adcs-journal-phase-experiment.js");
 const actualRequire=require("node:module").createRequire(sourceFile);
 vm.runInNewContext(fs.readFileSync(sourceFile,"utf8"),{module,__filename:sourceFile,__dirname:path.dirname(sourceFile),Buffer,console,
  process:{platform:"win32",env:{CERTOPS_ADCS_JOURNAL_PHASE_EXPERIMENT:"issued",CERTOPS_ADCS_DISPOSABLE_LAB:"1",CERTOPS_JOB_LEASE_SECONDS:"60",CERTOPS_LEASE_HARD_GRACE_MS:"60000",CERTOPS_ADCS_JOURNAL_PHASE_REPORT:report,GITHUB_SHA:"a".repeat(40)}},
  require(name){
   if(name==="./certops-adcs-journal-phase")return ()=>({ready:Promise.resolve(),async stopAndDrain(){drainStarted=true;await drained;if(drainFails)throw new Error("Expected observer drain failure");}});
   if(name==="./certops-adcs-local-rules")return {async provisionSurvivorSource(){throw new Error("Expected fixture failure");}};
   return actualRequire(name);
  }});
 const result=module.exports({serviceOwned:true,fixture:{async request(){return {status:200};}},api:"/owned",agentRowId:"owned",configDir:path.join(directory,"agent"),workDir:directory,run:"a".repeat(10),
  preflight:async()=>({issuerId:"owned",result:{templateCheck:{verdict:"safe"},caCheck:{verdict:"safe"},caCertificates:[{keySha256:"b".repeat(64)}]}}),
  ps:script=>{if(script.includes("Start-Service"))serviceStarts++;return script.includes("Get-Service TokenTimerAgent")?(drainFails?"Stopped":"Running"):JSON.stringify({actions:"AA==",nonCrash:1});},
  command:(file,args)=>{if(file==="sc.exe")serviceActions.push(args);return file==="powershell.exe"?JSON.stringify({subjectRequestCount:0}):"";},ownedSites:[],ownedCertificateIds:[],ownedEnrollmentIds:[],ownedThumbprints:new Set(),gate:{report:{qualificationEnvironment:{}}}});
 const outcome=result.then(()=>null,error=>error);
 try{
  for(let i=0;i<50&&!drainStarted;i++)await new Promise(resolve=>setTimeout(resolve,5));
  assert.equal(drainStarted,true);assert.equal(fs.existsSync(report),false,"Report must not precede observer drainage");
  releaseDrain();const error=await outcome;
  if(drainFails){assert.match(error.message,/finalization failed/);assert.equal(serviceActions.length,1,"Unproven drain must not restore SCM recovery");assert.equal(serviceStarts,0,"Unproven drain must not restart the agent");}
  else assert.match(error.message,/Expected fixture failure/);
  const saved=JSON.parse(fs.readFileSync(report,"utf8"));assert.equal(saved.status,"failed");
  if(drainFails){assert.equal(saved.ownedObserverDrainFailed,true);assert.equal(saved.cleanupFailed,true);assert.equal(saved.ownedScmRecoveryRestored,undefined);}
 }finally{releaseDrain();await outcome;fs.rmSync(directory,{recursive:true,force:true});}
});

test("canonical guest entrypoint isolates experimental phase selection and verifies its report",()=>{
 const source=fs.readFileSync(path.join(root,"infra/certops-adcs/run-windows-tests.ps1"),"utf8");
 assert.match(source,/ValidateSet\('acceptance','focused','experiment'\)/);
 assert.match(source,/Standalone experiments require exactly one supported fault mode/);
 assert.match(source,/elseif\(\$Scope -eq 'acceptance'\).*certops-adcs-package-acceptance/);
 assert.match(source,/certops-adcs-focused-experiment\.cjs verify \$experimentReport/);
 assert.match(source,/focused-journal-experiment-passed-not-qualified/);
});
test("sanitized report collection selects only the standalone experiment report",()=>{
 const source=fs.readFileSync(path.join(root,"infra/certops-adcs/read-report.ps1"),"utf8");
 assert.match(source,/\$ReportKind -eq 'focused-journal-experiment'\)\{'focused-journal-experiment\.json'\}/);
 assert.match(source,/\$ReportKind -eq 'focused-journal-experiment'\)\{'enterprise-adcs-focused-journal-experiment\.json'\}/);
 assert.match(source,/Reconstructed guest evidence checksum mismatch/);
});

test("an actual non-Windows early guard writes a bounded failed preflight receipt",async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),"focused-preflight-failure-")),reportPath=path.join(directory,"failed.json");
 const sourceFile=path.join(root,"tests/e2e/certops-adcs-focused-experiment.cjs"),module={exports:{}};
 const actualRequire=require("node:module").createRequire(sourceFile);
 vm.runInNewContext(fs.readFileSync(sourceFile,"utf8"),{module,__filename:sourceFile,__dirname:path.dirname(sourceFile),Buffer,console,
  process:{platform:"linux",arch:"x64",env:{GITHUB_SHA:"a".repeat(40),PRIVATE_TOKEN:"SECRET_DO_NOT_EXPORT"}},require:actualRequire});
 try{
  await assert.rejects(module.exports.run({reportPath}),/inspect bounded report/);
  const report=JSON.parse(fs.readFileSync(reportPath,"utf8"));
  assert.equal(report.status,"failed");assert.equal(report.nativeExecutionStarted,false);
  assert.deepEqual(report.preflightFailure,{step:"platform",errorClass:"AssertionError"});
  assert.equal(report.qualificationStatus,"not-qualified");assert.equal(report.releaseQualificationSatisfied,false);assert.equal(report.baselineQualificationSatisfied,false);
  assert.deepEqual(report.scenarios,[]);assert.deepEqual(report.missingScenarios,[...experiment.SCENARIOS]);
  assert.throws(()=>experiment.verifyReport(report,"a".repeat(40)));
  assert.doesNotMatch(JSON.stringify(report),/SECRET_DO_NOT_EXPORT|PRIVATE_TOKEN|message|argv|stack|linux/);
 }finally{fs.rmSync(directory,{recursive:true});}
});

// Execute run's actual preflight through module call seams; these fixtures are
// deliberately not native evidence and always stop before API fixture creation.
for (const [name,step,change] of [
 ["architecture","platform",s=>s.process.arch="arm64"],
 ["disposable opt-in","profile",s=>s.process.env.CERTOPS_ADCS_DISPOSABLE_LAB="0"],
 ["phase","profile",s=>s.process.env.CERTOPS_ADCS_JOURNAL_PHASE_EXPERIMENT="installing"],
 ["lease","profile",s=>s.process.env.CERTOPS_JOB_LEASE_SECONDS="300"],
 ["grace","profile",s=>s.process.env.CERTOPS_LEASE_HARD_GRACE_MS="0"],
 ["domain","native-identity",s=>s.domain="other.test"],
 ["identity","native-identity",s=>s.identity="S-1-5-21-1"],
 ["existing service","service-absence",s=>s.serviceStatus=0],
 ["unavailable SCM query","service-absence",s=>s.serviceStatus=null],
 ["SCM access denied","service-absence",s=>s.serviceStatus=5],
 ["agent descendant","service-absence",s=>s.agents="1"],
 ["candidate","runtime-candidate",s=>s.runtime.candidateSha="b".repeat(40)],
 ["build mode","runtime-candidate",s=>s.runtime.buildMode="release"],
 ["Node version","runtime-candidate",s=>s.runtime.nodeVersion="v0.0.0"],
 ["archive hash","runtime-candidate",s=>s.runtime.sourceArchiveSha256="invalid"],
 ["qualified module hash","runtime-candidate",s=>s.runtime.qualifiedModuleSha256="0".repeat(64)],
 ["capability","native-helper-tools",s=>s.qualified=[]],
 ["chain helper","native-helper-tools",s=>s.chain={error:"missing"}],
 ["CMC helper","native-helper-tools",s=>s.cmc={error:"missing"}],
 ["API protocol","api-url",s=>s.process.env.CERTOPS_ADCS_API_URL="http://10.64.0.6"],
 ["API host","api-url",s=>s.process.env.CERTOPS_ADCS_API_URL="https://example.test"],
 ["valid bootstrap reaches API","api-preflight",()=>{}],
]) test(`standalone preflight call seam: ${name}`,async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),"focused-guard-seam-")),reportPath=path.join(directory,"failed.json");
 const sourceFile=path.join(root,"tests/e2e/certops-adcs-focused-experiment.cjs"),module={exports:{}},actualRequire=require("node:module").createRequire(sourceFile);
 const state={process:{platform:"win32",arch:"x64",version:process.version,env:{GITHUB_SHA:"a".repeat(40),CERTOPS_ADCS_DISPOSABLE_LAB:"1",CERTOPS_ADCS_JOURNAL_PHASE_EXPERIMENT:"issued",CERTOPS_JOB_LEASE_SECONDS:"60",CERTOPS_LEASE_HARD_GRACE_MS:"60000",CERTOPS_ADCS_API_URL:"https://10.64.0.6"}},domain:"lab.certops.test",identity:"S-1-5-18",serviceStatus:1060,agents:"0",qualified:["adcs-enroll-v1"],chain:{path:"owned.exe"},cmc:{path:"owned.exe"},runtime:{candidateSha:"a".repeat(40),buildMode:"qualification-only-not-release",nodeVersion:process.version,nodeArchiveSha256:"1".repeat(64),goArchiveSha256:"2".repeat(64),sourceArchiveSha256:"3".repeat(64),qualifiedModuleSha256:fingerprint("packages/agent/src/capabilities/qualified-capabilities.generated.js").sha256}};
 change(state);
 vm.runInNewContext(fs.readFileSync(sourceFile,"utf8"),{module,__filename:sourceFile,__dirname:path.dirname(sourceFile),Buffer,URL,console,process:state.process,
 require(name){
  if(name==="node:fs")return {...fs,readFileSync(file,...args){return file==="C:\\ttqualification\\runtime.json"?JSON.stringify(state.runtime):fs.readFileSync(file,...args);}};
  if(name==="node:child_process")return {spawnSync(file,args){if(file==="sc.exe")return {status:state.serviceStatus};const script=args.at(-1);return {status:0,stdout:script.includes("Win32_ComputerSystem")?state.domain:script.includes("WindowsIdentity")?state.identity:state.agents};}};
  if(name.endsWith("/capabilities/qualified-capabilities.generated"))return {qualified:state.qualified};
  if(name.endsWith("/issuers/chain-helper"))return {resolveAdcsChainHelperPath:()=>state.chain};
  if(name.endsWith("/issuers/adcs-enrollment"))return {resolveAdcsCmcHelperPath:()=>state.cmc};
  if(name.endsWith("/host-gate"))return {createHostGate(){throw new Error("Bounded local API stop");}};
  return actualRequire(name);
 }});
 try{await assert.rejects(module.exports.run({reportPath}),/inspect bounded report/);const report=JSON.parse(fs.readFileSync(reportPath,"utf8"));assert.equal(report.preflightFailure.step,step);assert.equal(report.nativeExecutionStarted,false);assert.equal(report.status,"failed");assert.equal(report.releaseQualificationSatisfied,false);}
 finally{fs.rmSync(directory,{recursive:true});}
});

test("agent-absence probe excludes its own PowerShell command but refuses a real matching process",()=>{
 const source=fs.readFileSync(path.join(root,"tests/e2e/certops-adcs-focused-experiment.cjs"),"utf8");
 const script=source.match(/ps\("(@\(Get-CimInstance Win32_Process[^"\n]+)"\)/)[1];
 const {spawnSync}=require("node:child_process");
 for(const other of [false,true]){
  const setup=`function Get-CimInstance { @([pscustomobject]@{ProcessId=$PID;CommandLine='powershell tokentimer-agent.js'}${other?",[pscustomobject]@{ProcessId=($PID+1);CommandLine='node tokentimer-agent.js'}":""}) };`;
  const result=spawnSync("powershell.exe",["-NoProfile","-NonInteractive","-Command",setup+script],{encoding:"utf8",windowsHide:true,timeout:10000});
  assert.equal(result.status,0);assert.equal(result.stdout.trim(),other?"1":"0");
 }
});

function responseProof(){
 const p=proof();p.suite="adcs-focused-response-loss-experiment";p.phase="response-loss";p.requiredScenarios=[...experiment.RESPONSE_SCENARIOS];p.scenarios=p.requiredScenarios.map(id=>({id,status:"passed"}));delete p.journalExperiment;
 p.responseLossExperiment={schemaVersion:1,scope:"enterprise-adcs-response-loss-experimental",qualificationStatus:"not-qualified",status:"passed",candidateSha:"a".repeat(40),fixtureSource:fingerprint("tests/e2e/helpers/certops-adcs-response-loss-experiment.js"),qualificationEnvironment:{...p.qualificationEnvironment},foreignRequestRefused:true,recoveredOwnedKey:true,candidateSearch:{origin:"real-response-loss-with-one-explicit-operator-duplicate",outcomes:["unresolved","unique_candidate","ambiguous"],requestIds:["12","13"],caRequestCounts:[1,1,2],originalCsrSha256:"a".repeat(64),originalSpkiSha256:"b".repeat(64),journalAndKeyPreserved:true,operatorDuplicateRevoked:true,agentSubmissionCount:1,operatorInjectedSubmissionCount:1},fault:{requestId:12,killedProcessId:123,caRequestObserved:true,ownedServiceTree:true,fault:"real-native-certreq-termination-after-CA-observation"}};
 return p;
}
test("scoped response-loss proof requires all frozen-key and candidate oracles without promoting qualification",()=>{
 assert.equal(experiment.verifyReport(responseProof(),"a".repeat(40)),true);
 for(const mutate of [p=>p.responseLossExperiment.foreignRequestRefused=false,p=>p.responseLossExperiment.recoveredOwnedKey=false,p=>p.responseLossExperiment.candidateSearch.outcomes.pop(),p=>p.responseLossExperiment.candidateSearch.agentSubmissionCount=2,p=>p.responseLossExperiment.candidateSearch.operatorDuplicateRevoked=false,p=>p.responseLossExperiment.fixtureSource.sha256="0".repeat(64),p=>p.responseLossExperiment.qualificationEnvironment.osVersion="2019",p=>p.releaseQualificationSatisfied=true,p=>p.phase="issued",p=>p.requiredScenarios=[...experiment.SCENARIOS]]){const p=responseProof();mutate(p);assert.throws(()=>experiment.verifyReport(p,"a".repeat(40)));}
});

for(const valid of [true,false])test(`scoped D foreign RequestId comes from an owned installed enrollment: ${valid}`,async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),"focused-foreign-request-")),sourceFile=path.join(root,"tests/e2e/helpers/certops-adcs-response-loss-experiment.js"),module={exports:{}},events=[];
 const actualRequire=require("node:module").createRequire(sourceFile);
 vm.runInNewContext(fs.readFileSync(sourceFile,"utf8"),{module,__filename:sourceFile,__dirname:path.dirname(sourceFile),Buffer,process:{platform:"win32",env:{CERTOPS_ADCS_DISPOSABLE_LAB:"1"}},require(name){if(name==="./certops-adcs-local-rules")return {async provisionSurvivorSource(){events.push("eligible-source");return "owned-source";}};return actualRequire(name);}});
 const ownedSites=[],ownedCertificateIds=[],ownedEnrollmentIds=[];
 const fixture={workspaceId:"owned-workspace",async request(url,method,body){if(url.endsWith("/confirm"))return {status:200};assert.equal(body.certificateId,"owned-source");events.push("enroll");return {status:201,body:{enrollmentId:"owned-enrollment",jobId:"owned-job"}};},pool:{async query(sql,args){assert.deepEqual([...args],["owned-workspace","owned-enrollment"]);events.push("database-owned-request");return {rows:[{state:valid?"installed":"pending_issuance",request_id:17}]};}}};
 try{
  const operation=module.exports.provisionForeignRequest({fixture,api:"/owned",agentRowId:"owned-agent",caConfig:"owned-ca",workDir:directory,run:"abcdef",serviceOwned:true,
   preflight:async template=>{assert.equal(template,"TTQualificationRSAShort");return {issuerId:"owned-issuer",result:{templateCheck:{verdict:"safe"},caCheck:{verdict:"safe"},caCertificates:[{keySha256:"a".repeat(64)}]}};},jobFinished:async id=>{assert.equal(id,"owned-job");events.push("job-succeeded");},ps:()=>"",freePort:async()=>8443,ownedSites,ownedCertificateIds,ownedEnrollmentIds,ownedThumbprints:new Set(),
   command(file,args){assert.equal(file,"powershell.exe");assert.equal(args.at(-1),"17");assert.ok(args.includes("certops-adcs-abcdef-faultforeign.example.test"));events.push("native-owned-request");return JSON.stringify({disposition:20,subjectRequestCount:1,requestId:17});}});
  if(valid){assert.equal(await operation,17);assert.deepEqual(events,["eligible-source","enroll","job-succeeded","database-owned-request","native-owned-request"]);assert.deepEqual(ownedEnrollmentIds,["owned-enrollment"]);}
  else{await assert.rejects(operation);assert.equal(events.includes("native-owned-request"),false);}
 }finally{fs.rmSync(directory,{recursive:true});}
});
