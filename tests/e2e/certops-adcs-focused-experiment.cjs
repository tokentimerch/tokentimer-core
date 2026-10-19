"use strict";
// A repeatable observed crash experiment on an already qualified disposable
// forest. This is deliberately separate from the clean-forest baseline suite.
// Only its own service is removed; native custody and database ownership remain
// available until the enclosing owned lab is destroyed.
const assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),crypto=require("node:crypto");
const {spawnSync}=require("node:child_process");
const {createHostGate}=require("../../packages/agent/scripts/host-gate");
const {createApiFixture}=require("./helpers/certops-api-fixture");
const {applyRestrictivePermissions}=require("../../packages/agent/src/platform");
const {hostBinaryName}=require("../../packages/agent/scripts/build-windows-service-host");
const journalExperiment=require("./helpers/certops-adcs-journal-phase-experiment");
const {captureServiceDrain,assertDrainAbsent}=require("./helpers/certops-adcs-webhosting-renewal");
const SOURCES=Object.freeze(["scripts/certops-adcs-journal-phase-report.js","tests/e2e/helpers/certops-adcs-response-loss-experiment.js","tests/e2e/helpers/certops-adcs-response-loss.js","tests/e2e/helpers/certops-adcs-response-loss-candidates.js","infra/certops-adcs/response-loss.ps1","scripts/certops-adcs-response-loss-report.js","tests/e2e/certops-adcs-focused-experiment.cjs","infra/certops-adcs/run-windows-tests.ps1","infra/certops-adcs/read-report.ps1","tests/e2e/helpers/certops-adcs-journal-phase-experiment.js","infra/certops-adcs/journal-phase-fault.ps1","tests/e2e/helpers/certops-adcs-journal-phase.js","tests/e2e/helpers/certops-adcs-local-rules.js","tests/e2e/helpers/certops-adcs-webhosting-renewal.js","tests/e2e/helpers/certops-adcs-live-enroll-acl.js","infra/certops-adcs/owned-request-observation.ps1","packages/agent/scripts/host-gate.js","packages/agent/src/issuers/adcs-enrollment-journal.js","packages/agent/src/adcs-windows-iis.js","packages/agent/src/issuers/adcs-enrollment.js","packages/agent/src/issuers/adcs-enrollment-reconcile.js","packages/agent/src/issuers/chain-helper.js","packages/agent/src/windows-key-survivors/index.js","packages/agent/src/windows-cert-store/index.js","apps/api/services/certops/certificateEnrollments.js","apps/worker/src/certops-worker.js"]);
const RESPONSE_SCENARIOS=Object.freeze(["adcs-experiment-native-environment","adcs-experiment-owned-system-registration","adcs-experiment-observed-response-loss-recovery","adcs-experiment-owned-process-drain-state-preserved"]);
const SCENARIOS=Object.freeze(["adcs-experiment-native-environment","adcs-experiment-owned-system-registration","adcs-experiment-observed-journal-recovery","adcs-experiment-owned-process-drain-state-preserved"]);
const ROOT=path.resolve(__dirname,"../..");
const fingerprint=file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(ROOT,file))).digest("hex")});
function verifyReport(report,candidate){
 const response=report.suite==="adcs-focused-response-loss-experiment",scenarios=response?RESPONSE_SCENARIOS:SCENARIOS;
 assert.equal(report.suite,response?"adcs-focused-response-loss-experiment":"adcs-focused-journal-experiment");assert.equal(report.strict,true);assert.equal(report.status,"passed");
 assert.equal(report.schemaVersion,1);assert.deepEqual(report.requiredCapabilities,["api"]);assert.equal(report.capabilities?.api?.available,true);
 assert.ok(typeof report.startedAt==="string" && Number.isFinite(Date.parse(report.startedAt)));assert.ok(typeof report.finishedAt==="string" && Date.parse(report.finishedAt)>=Date.parse(report.startedAt));
 assert.match(candidate,/^[a-f0-9]{40}$/);assert.equal(report.candidateSha,candidate);
 assert.equal(report.qualificationStatus,"not-qualified");assert.equal(report.experimental,true);assert.equal(report.baselineQualificationSatisfied,false);assert.equal(report.releaseQualificationSatisfied,false);
 assert.ok((response?["response-loss"]:["issued","submitting"]).includes(report.phase));
 assert.deepEqual(report.requiredScenarios,scenarios);assert.deepEqual(report.missingScenarios,[]);assert.deepEqual(report.missingCapabilities,[]);
 for(const id of scenarios){const rows=report.scenarios.filter(row=>row.id===id);assert.equal(rows.length,1);assert.equal(rows[0].status,"passed");}
 assert.deepEqual(report.fixtureSources,SOURCES.map(fingerprint));
 if(!response)assert.deepEqual(report.journalExperiment.fixtureSource,fingerprint("tests/e2e/helpers/certops-adcs-journal-phase-experiment.js"));
 assert.equal(report.buildProvenance?.buildMode,"qualification-only-not-release");
 for(const key of ["nodeArchiveSha256","goArchiveSha256","sourceArchiveSha256","qualifiedModuleSha256"])assert.match(report.buildProvenance[key],/^[a-f0-9]{64}$/i);
 const env=report.qualificationEnvironment;assert.ok(["2019","2022","2025"].includes(env.osVersion));assert.equal(env.osFamily,"windows");assert.equal(env.identity,"LocalSystem");assert.equal(env.measurement,"native");
 assert.equal(report.actualOSBuild,{"2019":"17763","2022":"20348","2025":"26100"}[env.osVersion]);
 assert.ok(["en-US","de-DE","fr-FR"].includes(env.nativeLanguage));assert.equal(report.systemLocale,env.nativeLanguage);
 assert.equal(report.ownedCleanup?.status,"passed");
 assert.equal(report.ownedCleanup?.scope,"owned-process-drain-only");assert.equal(report.cleanup?.status,"passed");
 assert.equal(report.ownedCleanup?.nativeCustody,"preserved-for-owned-lab-teardown");assert.equal(report.ownedCleanup?.databaseOwnership,"preserved-for-owned-lab-teardown");
 assert.equal(report.ownedCleanup?.serviceRemoved,true);assert.equal(report.ownedCleanup?.ownedProcessesDrained,true);
 if(response){
  require("../../scripts/certops-adcs-response-loss-report").verify(report.responseLossExperiment,candidate);
  assert.deepEqual(report.responseLossExperiment.fixtureSource,fingerprint("tests/e2e/helpers/certops-adcs-response-loss-experiment.js"));
  assert.deepEqual(report.responseLossExperiment.qualificationEnvironment,report.qualificationEnvironment);
 }else{
 require("../../scripts/certops-adcs-journal-phase-report").verify(report.journalExperiment);
 assert.equal(report.journalExperiment.phase,report.phase);assert.equal(report.journalExperiment.candidateSha,candidate);
 assert.deepEqual(report.journalExperiment.qualificationEnvironment,report.qualificationEnvironment);
 }
 return true;
}
function command(file,args){
 const env={...process.env};if(path.basename(file).toLowerCase()==="powershell.exe")for(const key of Object.keys(env))if(key.toLowerCase()==="psmodulepath")delete env[key];
 const result=spawnSync(file,args,{encoding:"utf8",windowsHide:true,timeout:180000,env});
 assert.ok(!result.error&&result.status===0,"Owned native experiment command failed; private output withheld");return result.stdout.trim();
}
const ps=script=>command("powershell.exe",["-NoProfile","-NonInteractive","-Command",`$ErrorActionPreference='Stop';${script}`]);
async function until(check,timeout=180000){const deadline=Date.now()+timeout;while(Date.now()<deadline){const value=await check();if(value)return value;await new Promise(resolve=>setTimeout(resolve,500));}throw new Error("Owned journal experiment exceeded its deadline");}
async function run({reportPath}={}){
 const response=process.env.CERTOPS_ADCS_RESPONSE_LOSS_EXPERIMENT==="1",scenarios=response?RESPONSE_SCENARIOS:SCENARIOS;
 reportPath??=response?"C:\\ttqualification\\focused-response-loss-experiment.json":"C:\\ttqualification\\focused-journal-experiment.json";
 let gate;let preflightStep="platform";const startedAt=new Date().toISOString();
 try{
 assert.equal(process.platform,"win32");assert.equal(process.arch,"x64");
 preflightStep="profile";assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB,"1");
 const journalPhase=process.env.CERTOPS_ADCS_JOURNAL_PHASE_EXPERIMENT;
 const phase=response?"response-loss":journalPhase;assert.ok(response?(!journalPhase||journalPhase==="none"):["issued","submitting"].includes(phase));
 if(!response){assert.equal(process.env.CERTOPS_JOB_LEASE_SECONDS,"60");assert.equal(process.env.CERTOPS_LEASE_HARD_GRACE_MS,"60000");}
 preflightStep="native-identity";
 assert.equal(ps("(Get-CimInstance Win32_ComputerSystem).Domain"),"lab.certops.test");assert.equal(ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),"S-1-5-18");
 preflightStep="service-absence";
 assert.equal(spawnSync("sc.exe",["query","TokenTimerAgent"]).status,1060,"Require a confirmed absent service");
 assert.equal(ps("@(Get-CimInstance Win32_Process|Where-Object {$_.ProcessId -ne $PID -and $_.CommandLine -like '*tokentimer-agent.js*'}).Count"),"0","Refuse existing agent descendants");
 preflightStep="runtime-candidate";
 const runtime=JSON.parse(fs.readFileSync("C:\\ttqualification\\runtime.json","utf8"));assert.equal(runtime.candidateSha,process.env.GITHUB_SHA);assert.equal(runtime.buildMode,"qualification-only-not-release");assert.equal(runtime.nodeVersion,process.version);
 for(const key of ["nodeArchiveSha256","goArchiveSha256","sourceArchiveSha256","qualifiedModuleSha256"])assert.match(runtime[key],/^[a-f0-9]{64}$/i);
 assert.equal(runtime.qualifiedModuleSha256.toLowerCase(),crypto.createHash("sha256").update(fs.readFileSync(path.join(ROOT,"packages/agent/src/capabilities/qualified-capabilities.generated.js"))).digest("hex"));
 preflightStep="native-helper-tools";
 assert.ok(require("../../packages/agent/src/capabilities/qualified-capabilities.generated").qualified.includes("adcs-enroll-v1"));
 assert.equal(require("../../packages/agent/src/issuers/chain-helper").resolveAdcsChainHelperPath().error,undefined);
 assert.equal(require("../../packages/agent/src/issuers/adcs-enrollment").resolveAdcsCmcHelperPath().error,undefined);
 preflightStep="api-url";
 const url=new URL(process.env.CERTOPS_ADCS_API_URL);assert.equal(url.protocol,"https:");assert.equal(url.hostname,"10.64.0.6");
 preflightStep="api-preflight";
 gate=createHostGate({suite:response?"adcs-focused-response-loss-experiment":"adcs-focused-journal-experiment",strict:true,reportPath,requiredCapabilities:["api"],probeCapabilities:async()=>({api:{available:(await fetch(new URL("/health",url),{signal:AbortSignal.timeout(10000)})).ok}})});
 Object.assign(gate.report,{phase,qualificationStatus:"not-qualified",experimental:true,baselineQualificationSatisfied:false,releaseQualificationSatisfied:false,fixtureSources:SOURCES.map(fingerprint)});
 gate.report.fixtureSource=fingerprint(SOURCES[0]);
 gate.report.buildProvenance=Object.fromEntries(["buildMode","nodeVersion","goVersion","nodeArchiveSha256","goArchiveSha256","sourceArchiveSha256","qualifiedModuleSha256"].map(key=>[key,runtime[key]]));
 await gate.preflight();
 preflightStep="fixture-setup";
 const fixture=await createApiFixture(url.href),api=`/api/v1/workspaces/${fixture.workspaceId}/certops`;
 const workDir=fs.mkdtempSync(path.join(os.tmpdir(),"certops-domain-adcs-"));applyRestrictivePermissions(workDir,{kind:"directory"});
 const configDir=path.join(workDir,"agent");fs.mkdirSync(configDir);applyRestrictivePermissions(configDir,{kind:"directory"});
 const run=crypto.randomBytes(5).toString("hex"),agentId=`experiment-${crypto.randomUUID()}`,caConfig="tt-ca.lab.certops.test\\TTQualificationRoot";
 const ownedSites=[],ownedCertificateIds=[],ownedEnrollmentIds=[],ownedThumbprints=new Set();let agentRowId,serviceOwned=false,primary,servicePath;
 const jobFinished=id=>until(async()=>{const row=(await fixture.pool.query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,id])).rows[0];assert.ok(!["failed","rejected","cancelled"].includes(row?.status),"Owned native job did not succeed");return row?.status==="succeeded";});
 const preflight=async template=>{
  const created=await fixture.request(`${api}/issuers`,"POST",{kind:"adcs",name:`experiment-${run}`});assert.equal(created.status,201);const issuerId=created.body.issuer.id;
  const dispatched=await fixture.request(`${api}/issuers/${issuerId}/preflight`,"POST",{agentId:agentRowId,caConfig,template});assert.equal(dispatched.status,201);await jobFinished(dispatched.body.job.id);
  const result=(await fixture.pool.query("SELECT last_preflight FROM certificate_issuers WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,issuerId])).rows[0].last_preflight;assert.ok(result);return {issuerId,result};
 };
 try{
  await gate.scenario(scenarios[0],async()=>{
   const version=runtime.windowsVersion,language=process.env.CERTOPS_WINDOWS_LANGUAGE||"en-US",build=ps("(Get-CimInstance Win32_OperatingSystem).BuildNumber");
   assert.equal(ps("(Get-CimInstance Win32_OperatingSystem).ProductType"),"3");assert.equal(build,{"2019":"17763","2022":"20348","2025":"26100"}[version]);assert.equal(ps("(Get-UICulture).Name"),language);assert.equal(ps("(Get-WinSystemLocale).Name"),language);
   assert.equal(ps(`Test-Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\MUI\\UILanguages\\${language}'`),"True");
   gate.report.actualOSBuild=build;gate.report.systemLocale=language;gate.report.qualificationEnvironment={osFamily:"windows",osVersion:version,nativeLanguage:language,identity:"LocalSystem",measurement:"native"};
  });
  await gate.scenario(scenarios[1],async()=>{
   const bootstrap=await fixture.request(`${api}/agent-bootstrap-tokens`,"POST",{name:`journal-${run}`,expiresAt:new Date(Date.now()+3600000).toISOString()});assert.equal(bootstrap.status,201);
   const settings={serverUrl:url.href,caBundlePath:process.env.NODE_EXTRA_CA_CERTS,agentId,heartbeatIntervalMs:5000,pollIntervalMs:2000,declaredTargetSelectors:response?[`certops-adcs-${run}-fault.example.test`,`certops-adcs-${run}-faultforeign.example.test`]:[`certops-adcs-${run}-journal.example.test`],execution:{enabled:true,dryRun:false},policy:{allowedPaths:[workDir],allowedCommands:{},allowedCaEndpoints:[],allowedDnsZones:[],allowedDnsProviders:[]},adcs:{enrollmentRules:(response?["TTQualificationRSAShort","TTQualificationPending"]:["TTQualificationRSAShort"]).map(template=>({caConfig,template,dnsScopes:["example.test"],keyAlgorithms:["rsa"],operatorAttested:false}))}};
   fs.writeFileSync(path.join(configDir,"config.json"),JSON.stringify(settings));applyRestrictivePermissions(path.join(configDir,"config.json"));
   const host=path.join(ROOT,"packages/agent/bin",hostBinaryName("amd64"));assert.ok(fs.existsSync(host));servicePath=`"${host}" "${process.execPath}" "${path.join(ROOT,"packages/agent/bin/tokentimer-agent.js")}"`;
   command("sc.exe",["create","TokenTimerAgent","type=","own","start=","demand","obj=","LocalSystem","binPath=",servicePath]);serviceOwned=true;
   command("reg.exe",["add","HKLM\\SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent","/v","Environment","/t","REG_MULTI_SZ","/d",`TOKENTIMER_AGENT_CONFIG_DIR=${configDir}\\0TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=${bootstrap.body.plaintextToken}\\0TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID=${bootstrap.body.token.id}\\0NODE_EXTRA_CA_CERTS=${process.env.NODE_EXTRA_CA_CERTS}\\0PATH=${process.env.PATH}`,"/f"]);
   command("sc.exe",["failureflag","TokenTimerAgent","1"]);command("sc.exe",["failure","TokenTimerAgent","reset=","86400","actions=","restart/5000"]);command("sc.exe",["start","TokenTimerAgent"]);
   agentRowId=await until(async()=>(await fixture.pool.query("SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",[fixture.workspaceId,agentId])).rows[0]?.id);
   await until(()=>fs.existsSync(path.join(configDir,"credential"))&&!/TOKENTIMER_AGENT_BOOTSTRAP_TOKEN/.test(command("reg.exe",["query","HKLM\\SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent","/v","Environment"])));
   captureServiceDrain(ps,{configDir,expectedServicePath:servicePath});
  });
  await gate.scenario(scenarios[2],async()=>{
   if(response){
    const helper=require("./helpers/certops-adcs-response-loss-experiment");
    const freePort=()=>new Promise((resolve,reject)=>{const server=require("node:net").createServer();server.once("error",reject);server.listen(0,"127.0.0.1",()=>{const port=server.address().port;server.close(error=>error?reject(error):resolve(port));});});
    const context={fixture,api,caConfig,agentRowId,configDir,workDir,run,preflight,jobFinished,until,ps,command,ownedSites,ownedCertificateIds,ownedEnrollmentIds,ownedThumbprints,gate,serviceOwned,freePort,ownedPhaseObservers:[]};
    const foreignRequestId=await helper.provisionForeignRequest(context);
    gate.report.responseLossExperiment=await helper({...context,foreignRequestId,faultDomain:`certops-adcs-${run}-fault.example.test`});
    gate.report.fixtureSources=SOURCES.map(fingerprint);
   }else{
   process.env.CERTOPS_ADCS_JOURNAL_PHASE_REPORT="C:\\ttqualification\\focused-journal-phase.json";
   await journalExperiment({fixture,api,caConfig,agentRowId,configDir,workDir,run,preflight,jobFinished,until,ps,command,ownedSites,ownedCertificateIds,ownedEnrollmentIds,ownedThumbprints,serviceOwned,gate,allowOperatorReconciliationOutcome:true,tlsAuthority:authority=>new crypto.X509Certificate(Buffer.from(authority.certificateB64,"base64")).toString()});
   gate.report.journalExperiment=JSON.parse(fs.readFileSync(process.env.CERTOPS_ADCS_JOURNAL_PHASE_REPORT,"utf8"));
   require("../../scripts/certops-adcs-journal-phase-report").verify(gate.report.journalExperiment);
   }
  });
 }catch(error){primary=error;gate.report.failure={errorClass:error?.constructor?.name||"Error",...(/^(?:ADCS|CERTOPS)_[A-Z0-9_]{1,80}$/.test(error?.code||"")?{errorCode:error.code}:{})};}
 finally{
  try{await gate.scenario(scenarios[3],async()=>{
   if(serviceOwned){
    const drain=captureServiceDrain(ps,{configDir,expectedServicePath:servicePath});command("sc.exe",["stop","TokenTimerAgent"]);await until(()=>ps("(Get-Service TokenTimerAgent).Status")==="Stopped",30000);
    const processes=JSON.parse(ps("@(Get-CimInstance Win32_Process|ForEach-Object {@{pid=[int]$_.ProcessId;parent=[int]$_.ParentProcessId;created=$_.CreationDate.ToUniversalTime().ToString('o')}})|ConvertTo-Json -Compress"));assertDrainAbsent(drain,processes);
    if(!primary){command("sc.exe",["delete","TokenTimerAgent"]);await until(()=>spawnSync("sc.exe",["query","TokenTimerAgent"]).status!==0,30000);}
   }
   gate.report.cleanup={scope:"owned-process-drain-only",status:primary?"failed":"passed",nativeCustody:"preserved-for-owned-lab-teardown",databaseOwnership:"preserved-for-owned-lab-teardown",serviceRemoved:serviceOwned&&!primary,ownedProcessesDrained:true};
  });}catch(error){gate.report.cleanup={scope:"owned-process-drain-only",status:"failed",nativeCustody:"preserved-for-owned-lab-teardown",databaseOwnership:"preserved-for-owned-lab-teardown"};primary=primary||error;}
  // Preserve enrollment/job/audit rows and their corresponding durable key
  // ownership. Deleting a workspace here would discard reconciliation proof.
  await fixture.pool.end();
  gate.report.ownedCleanup={...gate.report.cleanup};
  await gate.finish({cleanup:{status:gate.report.cleanup.status},requiredScenarios:scenarios});
 }
 if(primary)throw primary;
 verifyReport(gate.report,runtime.candidateSha);
 return gate.report;
 }catch(error){
  // Guards can fail before HostGate exists. Persist a failed, explicitly
  // unexecuted receipt rather than leaving collection with no diagnosis.
  if(!gate?.report?.scenarios?.length){
   const knownClasses=new Set(["Error","AssertionError","TypeError","RangeError","SyntaxError"]);
   const report=gate?.report || {schemaVersion:1,suite:response?"adcs-focused-response-loss-experiment":"adcs-focused-journal-experiment",strict:true,startedAt,
    candidateSha:/^[a-f0-9]{40}$/.test(process.env.GITHUB_SHA||"")?process.env.GITHUB_SHA:null,
    requiredCapabilities:["api"],capabilities:{},missingCapabilities:["api"],scenarios:[]};
   Object.assign(report,{status:"failed",finishedAt:new Date().toISOString(),qualificationStatus:"not-qualified",experimental:true,
    baselineQualificationSatisfied:false,releaseQualificationSatisfied:false,nativeExecutionStarted:false,
    requiredScenarios:[...scenarios],missingScenarios:[...scenarios],
    preflightFailure:{step:preflightStep,errorClass:knownClasses.has(error?.constructor?.name)?error.constructor.name:"Error"}});
   fs.mkdirSync(path.dirname(reportPath),{recursive:true});fs.writeFileSync(reportPath,JSON.stringify(report,null,2));
  }
  throw new Error("Focused journal experiment failed; inspect bounded report");
 }
}
module.exports={run,verifyReport,SOURCES,SCENARIOS,RESPONSE_SCENARIOS};
if(require.main===module){
 if(process.argv[2]==="verify"){
  try{verifyReport(JSON.parse(fs.readFileSync(process.argv[3],"utf8")),process.env.GITHUB_SHA);console.log("Focused journal experiment passed; clean-forest and release qualification remain unchanged");}
  catch{console.error("Focused journal experiment evidence incomplete or invalid");process.exitCode=1;}
 }else run().catch(()=>{console.error("Focused journal experiment failed; inspect its bounded report");process.exitCode=1;});
}
