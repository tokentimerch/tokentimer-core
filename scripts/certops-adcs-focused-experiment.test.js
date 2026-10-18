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
 assert.match(source,/\$Scope -eq 'experiment' -and \(\$ResponseLossExperiment -ne '0' -or \$JournalPhaseExperiment -notin @\('submitting','issued'\)\)/);
 assert.match(source,/elseif\(\$Scope -eq 'acceptance'\).*certops-adcs-package-acceptance/);
 assert.match(source,/certops-adcs-focused-experiment\.cjs verify 'C:\\ttqualification\\focused-journal-experiment\.json'/);
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
