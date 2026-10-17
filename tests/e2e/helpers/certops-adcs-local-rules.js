"use strict";
/* Whole local enrollment-rule negative cases with genuine signed jobs, unchanged CA request count
 * and trusted outgoing TLS; tighter policy continuation checks exact unaccepted-key cleanup.
 * Called only by the protected disposable-forest AD CS harness; native qualification requires
 * that workflow to execute.
 */
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const {buildEnrollmentContainerName}=require("../../../packages/agent/src/windows-cert-store");
const REQUIRED_SOURCES=Object.freeze(["tests/e2e/helpers/certops-adcs-local-rules.js","packages/agent/src/issuers/adcs-enrollment-rules.js","packages/agent/src/issuers/adcs-enrollment-journal.js","tests/e2e/helpers/certops-adcs-result-service.js","tests/e2e/helpers/certops-windows-stop-observer.js","tests/e2e/helpers/certops-windows-stop-observer-process.js","tests/e2e/helpers/certops-windows-stop-observer.ps1","tests/e2e/helpers/certops-windows-installed-paths.js","tests/e2e/helpers/certops-native-issuer-reassignment.js"]);
const SURVIVOR_SOURCES=Object.freeze(["infra/certops-adcs/owned-ca-request-certificate.ps1","infra/certops-adcs/officer-action.ps1","infra/certops-adcs/owned-request-observation.ps1","infra/certops-adcs/owned-ca-checkpoint.ps1","packages/agent/src/windows-key-survivors/index.js","packages/agent/src/windows-cert-store/index.js","packages/agent/src/adcs-windows-iis.js","tests/e2e/helpers/certops-adcs-issued-revocation.js"]);
const pairCases=Object.freeze(["ca-host-mismatch","ca-authority-mismatch","template-pair-mismatch","empty-allowlist"]);
const pairFlags=Object.freeze(["actualSignedJobRefused","claimBoundOutcome","noCaRequestAllocated","noKeyGenerated","noAcceptedLeafOrJournal","originalNativeCustodyPreserved","outgoingTrustedTlsPreserved","configurationAndCredentialRestored"]);
const survivorScenario="adcs-real-pending-key-survivor-protects-local-policy-cleanup";
const survivorScope="native-pending-key-policy-refusal-then-public-cancellation";
const survivorError="Local policy refusal could not free the protected enrollment key; retry required";
const survivorMarker=".preserve-adcs-pending-key-survivor.json",activeSurvivors=new Set();
const survivorFlags=Object.freeze(["actualOwnedPendingRequest","actualOwnedCaLeafSameCsrSpki","exactWebHostingAssociationAndProtectedKey","nativeSurvivorReferenceObserved","signedCleanupRefusedWhileReferenced","pendingJournalAndKeyPreserved","noAdditionalCaRequest","exactPublicAssociationOnlyRemoved","publicCancellationAcknowledged","signedTerminalCleanupCompleted","predecessorCustodyIisTlsPreserved","configurationCredentialRestored","ownedCaLeafRevoked","ownershipGuardReleased"]);
function assertCleanupSafe(workDir){assert.equal(activeSurvivors.has(path.resolve(workDir)),false,"Preserve unresolved AD CS key survivor association");assert.equal(fs.existsSync(path.join(workDir,survivorMarker)),false,"Preserve durable AD CS key survivor ownership");}
function verifySurvivorProof(value){
 assert.deepEqual(Object.keys(value).sort(),["scope","store","recovery","firstError","enrollmentId","requestId","failedJobId","cleanupJobId","fingerprint","csrSpkiSha256","caRequestCounts","automaticRetryQualified","schedulerDefaultClockQualified",...survivorFlags].sort());
 assert.equal(value.scope,survivorScope);assert.equal(value.store,"WebHosting");assert.equal(value.recovery,"public-cancel-then-terminal-cleanup");assert.equal(value.firstError,survivorError);assert.equal(value.automaticRetryQualified,false);assert.equal(value.schedulerDefaultClockQualified,false);
 for(const field of ["enrollmentId","failedJobId","cleanupJobId"])assert.match(value[field],/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
 assert.notEqual(value.failedJobId,value.cleanupJobId);assert.match(value.requestId,/^[1-9][0-9]{0,9}$/);assert.ok(Number(value.requestId)<=0xffffffff);
 for(const field of ["fingerprint","csrSpkiSha256"])assert.match(value[field],/^[a-f0-9]{64}$/);
 assert.ok(Array.isArray(value.caRequestCounts)&&value.caRequestCounts.length===3&&value.caRequestCounts.every(n=>Number.isSafeInteger(n)&&n>0&&n===value.caRequestCounts[0]));
 for(const flag of survivorFlags)assert.equal(value[flag],true,flag);return true;
}
function pairRules(caseId,allowed){
 assert.ok(pairCases.includes(caseId));
 if(caseId==="empty-allowlist")return [];
 const split=allowed.caConfig.indexOf("\\");assert.ok(split>0);
 if(caseId==="ca-host-mismatch")return [{...allowed,caConfig:`other-ca.lab.certops.test${allowed.caConfig.slice(split)}`}];
 if(caseId==="ca-authority-mismatch")return [{...allowed,caConfig:`${allowed.caConfig.slice(0,split)}\\OtherQualificationAuthority`}];
 return [{...allowed,template:"TTQualificationRSA3072"}];
}
function verifyPairProof(rows){
 assert.ok(Array.isArray(rows));assert.equal(rows.length,pairCases.length);assert.deepEqual(rows.map(row=>row.caseId).sort(),[...pairCases].sort());
 for(const row of rows){assert.deepEqual(Object.keys(row).sort(),["caseId",...pairFlags].sort());for(const flag of pairFlags)assert.equal(row[flag],true,flag);}return true;
}
async function qualifyLocalRules({gate,fixture,api,agentRowId,renewalFixture,configDir,run,preflight,command,ps,until,ownedEnrollmentIds,tlsAuthority,workDir,ownedResultResources,ownedTlsProbes}){
 const root=path.resolve(__dirname,"../../.."),file=path.join(configDir,"config.json"),original=fs.readFileSync(file),credential=fs.readFileSync(path.join(configDir,"credential"));
 const {item,issuerId,certificateId,site,port,authority,observed}=renewalFixture;const caConfig="tt-ca.lab.certops.test\\TTQualificationRoot";
 assert.equal(process.platform,"win32");assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB,"1");assert.equal(ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),"S-1-5-18");
 gate.report.fixtureSources??=[];for(const source of [...REQUIRED_SOURCES,...SURVIVOR_SOURCES]){const sha256=crypto.createHash("sha256").update(fs.readFileSync(path.join(root,source))).digest("hex");const prior=gate.report.fixtureSources.find(row=>row.file===source);if(prior)assert.equal(prior.sha256,sha256);else gate.report.fixtureSources.push({file:source,sha256});}
 const checkpoint=()=>JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(root,"infra/certops-adcs/owned-ca-checkpoint.ps1"),"-RunId",run]));
 assert.ok(Array.isArray(ownedTlsProbes));
 const probes=require("./certops-native-issuer-reassignment").createOwnedTlsProbes();ownedTlsProbes.push(probes);
 const served=()=>probes.observe({host:"127.0.0.1",port,servername:item.domain,ca:tlsAuthority(authority),rejectUnauthorized:true},socket=>{assert.equal(socket.authorized,true);return socket.getPeerCertificate().fingerprint256;});
 const observedPredecessor=observed;
 let retainedController,pendingSafetyIssuer,retainedStopped=false;
 const controller=()=>retainedController??=require("./certops-adcs-result-service").createServiceController({workDir,configDir,ps,command,until,onCreated:resource=>ownedResultResources.push(resource)});
 const retainedStop=async()=>{assert.ok(Array.isArray(ownedResultResources));if(!retainedStopped){await controller().stop();retainedStopped=true;}controller().assertStopped();};
 const retainedStart=async()=>{const marker=(await fixture.pool.query("SELECT now() AS marker")).rows[0].marker;await controller().start();retainedStopped=false;await until(async()=>Date.parse((await fixture.pool.query("SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,agentRowId])).rows[0].last_seen_at)>Date.parse(marker),45000);assert.deepEqual(fs.readFileSync(path.join(configDir,"credential")),credential);};
 const restart=async(bytes,retained=false)=>{if(retained){await retainedStop();if(bytes)fs.writeFileSync(file,bytes);await retainedStart();return; }if(ps("(Get-Service TokenTimerAgent).Status")!=="Stopped")command("sc.exe",["stop","TokenTimerAgent"]);await until(async()=>ps("(Get-Service TokenTimerAgent).Status")==="Stopped",30000);const before=(await fixture.pool.query("SELECT now() AS marker")).rows[0].marker;if(bytes)fs.writeFileSync(file,bytes);command("sc.exe",["start","TokenTimerAgent"]);await until(async()=>Date.parse((await fixture.pool.query("SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,agentRowId])).rows[0].last_seen_at)>Date.parse(before),45000);assert.ok(fs.readFileSync(path.join(configDir,"credential")).equals(credential));};
 const configure=async(template,rules)=>{const config=JSON.parse(original);config.adcs.enrollmentRules=config.adcs.enrollmentRules.filter(rule=>rule.caConfig!==caConfig||rule.template!==template).concat(rules);await restart(Buffer.from(JSON.stringify(config)));};
 const custody=()=>{const thumbprint=crypto.createHash("sha1").update(observed.raw).digest("hex").toUpperCase();return JSON.parse(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumbprint}';$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);try{@{der=[Convert]::ToBase64String($c.RawData);thumbprint=$c.Thumbprint;container=$k.Key.KeyName;provider=$k.Key.Provider.Provider;machine=$k.Key.IsMachineKey;exportPolicy=[int]$k.Key.ExportPolicy;usage=[int]$k.Key.KeyUsage;bits=$k.KeySize}|ConvertTo-Json -Compress}finally{$k.Dispose();$c.Dispose()}`));};
 const admittedInput=(selectedIssuer=issuerId)=>({issuerId:selectedIssuer,certificateId,agentId:agentRowId,target:{type:"windows-iis",reference:item.domain,store:"My",binding:{site,port,sniHost:item.domain}},authorizedDnsNames:[item.domain],keyAlgorithm:"rsa",keySize:2048});
 const refused=async jobId=>{const outcome=await until(async()=>{const row=(await fixture.pool.query("SELECT status,result_metadata FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,jobId])).rows[0];if(row.status==="succeeded")throw new Error("Out-of-rule signed enrollment succeeded");return ["failed","rejected"].includes(row.status)?row:null;});assert.equal(outcome.result_metadata.enrollmentResult.state,"refused");assert.equal(outcome.result_metadata.enrollmentResult.errorCode,"ADCS_CA_CONFIG_UNSAFE");return outcome;};
 for(const selected of ["missing-constraints","dns-dot-boundary","key-algorithm","cross-product","extra-san",...pairCases])await gate.scenario(`adcs-real-local-rule-${selected}-refused`,async()=>{
  const before=checkpoint(),isPair=pairCases.includes(selected),allowed={caConfig,template:item.template,dnsScopes:[item.domain],keyAlgorithms:["rsa"]};let primaryError,pairProof;const originalCustody=isPair?custody():null;const cleanupErrors=[];
  try{
   let rules=[allowed];if(selected==="missing-constraints")rules=[{caConfig,template:item.template}];if(selected==="dns-dot-boundary")rules=[{...allowed,dnsScopes:["ample.test"]}];if(selected==="key-algorithm")rules=[{...allowed,keyAlgorithms:["ecdsa"]}];if(selected==="cross-product")rules=[{...allowed,dnsScopes:["other.test"]},{...allowed,keyAlgorithms:["ecdsa"]}];if(isPair)rules=pairRules(selected,allowed);
   if(selected==="empty-allowlist"){const denied=JSON.parse(original);denied.adcs.enrollmentRules=[];await restart(Buffer.from(JSON.stringify(denied)),true);assert.deepEqual(JSON.parse(fs.readFileSync(file,"utf8")).adcs.enrollmentRules,[]);}else await configure(item.template,rules);
   const input=admittedInput();if(selected==="extra-san")input.authorizedDnsNames.push(`certops-adcs-${run}-outside.example.test`);
   const created=await fixture.request(`${api}/enrollments`,"POST",input);assert.equal(created.status,201);ownedEnrollmentIds.push(created.body.enrollmentId);await refused(created.body.jobId);
   assert.deepEqual(checkpoint(),before);assert.ok(!command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(buildEnrollmentContainerName(created.body.enrollmentId)));assert.equal(await served(),observed.fingerprint256);
   if(isPair){
    const job=(await fixture.pool.query("SELECT assigned_agent_id,claim_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,created.body.jobId])).rows[0];assert.equal(job.assigned_agent_id,agentRowId);assert.ok(job.claim_id);
    const journal=require("../../../packages/agent/src/issuers/adcs-enrollment-journal").readEnrollmentJournal(configDir,created.body.enrollmentId);assert.equal(journal.kind,"not_found");
    assert.equal(require("../../../packages/agent/src/windows-cert-store").readIssuedContainerRecord({stateDir:configDir,containerName:buildEnrollmentContainerName(created.body.enrollmentId)}),null);
    const state=(await fixture.pool.query("SELECT state,request_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,created.body.enrollmentId])).rows[0];assert.equal(state.state,"refused");assert.equal(state.request_id,null);assert.deepEqual(custody(),originalCustody);
    pairProof={caseId:selected,...Object.fromEntries(pairFlags.filter(flag=>flag!=="configurationAndCredentialRestored").map(flag=>[flag,true]))};
   }else {gate.report.nativeLocalRules??=[];gate.report.nativeLocalRules.push({caseId:selected,actualSignedJobRefused:true,noCaRequestAllocated:true,noKeyGenerated:true,outgoingTrustedTlsPreserved:true,immutableSnapshotCannotOverrideLocalPolicy:true});}
  }catch(error){primaryError=error;}finally{try{await restart(original,selected==="empty-allowlist");assert.ok(fs.readFileSync(file).equals(original));}catch(error){cleanupErrors.push(error);}}
  if(cleanupErrors.length)throw new AggregateError([...(primaryError?[primaryError]:[]),...cleanupErrors],"Local rule fixture restoration failed");if(primaryError)throw primaryError;
  if(pairProof){assert.deepEqual(custody(),originalCustody);assert.equal(await served(),observed.fingerprint256);assert.deepEqual(checkpoint(),before);pairProof.configurationAndCredentialRestored=true;gate.report.nativeLocalRulePairs??=[];gate.report.nativeLocalRulePairs.push(pairProof);}
 });
 verifyPairProof(gate.report.nativeLocalRulePairs);
 await gate.scenario("adcs-real-local-rule-tightening-frees-pending-key",async()=>{
  const checked=await preflight("TTQualificationPending");pendingSafetyIssuer=checked.issuerId;assert.equal((await fixture.request(`${api}/issuers/${checked.issuerId}/confirm`,"POST",{caKeySha256:authority.keySha256,caConfig,template:"TTQualificationPending"})).status,200);
  let primaryError,pending;const cleanupErrors=[];
  try{
   const created=await fixture.request(`${api}/enrollments`,"POST",admittedInput(checked.issuerId));assert.equal(created.status,201);ownedEnrollmentIds.push(created.body.enrollmentId);
   pending=await until(async()=>{const row=(await fixture.pool.query("SELECT id,state,request_id,next_poll_at,snapshot_sha256 FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,created.body.enrollmentId])).rows[0];return row.state==="pending_issuance"&&row.next_poll_at&&row.request_id?row:null;});const before=checkpoint();const container=buildEnrollmentContainerName(pending.id);assert.ok(command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(container));
   await configure("TTQualificationPending",[{caConfig,template:"TTQualificationPending",dnsScopes:["outside.test"],keyAlgorithms:["rsa"]}]);
   const dispatch=(await require("../../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments({client:fixture.pool,now:new Date(Date.parse(pending.next_poll_at)+1000)})).find(value=>value.enrollmentId===pending.id);assert.ok(dispatch);await refused(dispatch.jobId);
   const after=(await fixture.pool.query("SELECT state,snapshot_sha256,request_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,pending.id])).rows[0];assert.equal(after.state,"refused");assert.equal(after.snapshot_sha256,pending.snapshot_sha256);assert.equal(String(after.request_id),String(pending.request_id));assert.deepEqual(checkpoint(),before);assert.ok(!command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(container));assert.equal(await served(),observed.fingerprint256);
   gate.report.nativeLocalRuleTightening={actualPendingRequestId:String(pending.request_id),snapshotSha256:pending.snapshot_sha256,actualSignedContinuationRefused:true,exactUnacceptedKeyFreed:true,noAdditionalCaRequest:true,outgoingTrustedTlsPreserved:true};
  }catch(error){primaryError=error;}finally{
   try{await restart(original);assert.ok(fs.readFileSync(file).equals(original));}catch(error){cleanupErrors.push(error);}
   if(pending)try{command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(root,"infra/certops-adcs/officer-action.ps1"),"-RequestId",String(pending.request_id),"-Action","deny","-CommonName",item.domain]);}catch(error){cleanupErrors.push(error);}
  }
  if(cleanupErrors.length)throw new AggregateError([...(primaryError?[primaryError]:[]),...cleanupErrors],"Pending local rule fixture restoration failed");if(primaryError)throw primaryError;
 },{evidenceLevel:"real-host",oracle:"actual pending CA request and CNG key; supported configuration tightening plus real SYSTEM restart and signed continuation frees only its original unaccepted key, preserves frozen request identity and live trusted TLS without CA resubmission"});
 // A secondary store association is a real native key reference, never permission
 // to delete the key. Any unresolved phase keeps the parent cleanup barrier armed.
 await gate.scenario(survivorScenario,async()=>{
  assert.ok(pendingSafetyIssuer);assertCleanupSafe(workDir);
  const root=path.resolve(workDir),rootIdentity=fs.lstatSync(root,{bigint:true}),marker=path.join(root,survivorMarker),nonce=crypto.randomBytes(32),baselineCustody=custody();
  const invoke=(script,args)=>JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(rootPath,script),...args]));
  const rootPath=path.join(path.resolve(__dirname,"../../.."),"infra/certops-adcs");
  const created=await fixture.request(`${api}/enrollments`,"POST",admittedInput(pendingSafetyIssuer));assert.equal(created.status,201);const id=created.body.enrollmentId;ownedEnrollmentIds.push(id);
  const row=async()=>(await fixture.pool.query("SELECT state,request_id,next_poll_at,snapshot_sha256 FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,id])).rows[0];
  const pending=await until(async()=>{const r=await row();return r.state==="pending_issuance"&&r.request_id&&r.next_poll_at?r:null;});
  const journals=require("../../../packages/agent/src/issuers/adcs-enrollment-journal"),originalJournal=journals.readEnrollmentJournal(configDir,id);assert.equal(originalJournal.kind,"valid");assert.equal(originalJournal.journal.state,"pending");
  const container=buildEnrollmentContainerName(id),requestId=String(pending.request_id);assert.equal(originalJournal.journal.containerName,container);assert.equal(String(originalJournal.journal.requestId),requestId);assert.equal(originalJournal.artifacts.leafPem,null);
  const bytes=Buffer.from(JSON.stringify({enrollmentId:id,requestId,container})),fd=fs.openSync(marker,"wx",0o600);try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}activeSurvivors.add(root);
  const markerIdentity=fs.lstatSync(marker,{bigint:true});const ownedGuard=()=>{const directory=fs.lstatSync(root,{bigint:true});assert.ok(directory.isDirectory()&&!directory.isSymbolicLink()&&directory.dev===rootIdentity.dev&&directory.ino===rootIdentity.ino);const current=fs.lstatSync(marker,{bigint:true});assert.ok(current.isFile()&&!current.isSymbolicLink()&&current.dev===markerIdentity.dev&&current.ino===markerIdentity.ino);assert.deepEqual(fs.readFileSync(marker),bytes);};
  let proof,complete=false;
  try{
   ownedGuard();await retainedStop();
   command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(rootPath,"officer-action.ps1"),"-RequestId",requestId,"-Action","approve","-CommonName",item.domain]);
   const observed=invoke("owned-ca-request-certificate.ps1",["-CommonName",item.domain,"-RequestId",requestId]);
   const leaf=require("./certops-adcs-issued-revocation").verifyIssuedLeaf({native:observed,authority,journal:originalJournal.journal,domain:item.domain}),fingerprint=crypto.createHash("sha256").update(leaf.raw).digest("hex"),thumbprint=leaf.fingerprint.replace(/:/g,"").toUpperCase();
   assert.notEqual(leaf.fingerprint256,observedPredecessor.fingerprint256);
   const publicFile=path.join(workDir,"pending-key-survivor-public.cer");fs.writeFileSync(publicFile,leaf.raw,{flag:"wx"});
   const association=()=>JSON.parse(ps(`$c=Get-Item 'Cert:\\LocalMachine\\WebHosting\\${thumbprint}' -ErrorAction Stop;$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);if(!$k-or$k.Key.KeyName-ne'${container}'-or!$k.Key.IsMachineKey-or$k.Key.Provider.Provider-ne'Microsoft Software Key Storage Provider'-or[int]$k.Key.ExportPolicy-ne 0){throw 'Exact protected pending key association absent'};@{der=[Convert]::ToBase64String($c.RawData);container=$k.Key.KeyName;signature=[Convert]::ToBase64String($k.SignData([Convert]::FromBase64String('${nonce.toString("base64")}'),[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1))}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`));
   assert.equal(ps(`[bool](Test-Path -LiteralPath 'Cert:\\LocalMachine\\WebHosting\\${thumbprint}')`),"False");
   command("certutil.exe",["-addstore","WebHosting",publicFile]);command("certutil.exe",["-repairstore","WebHosting",thumbprint]);
   const reference=association();assert.equal(reference.der,leaf.raw.toString("base64"));assert.equal(crypto.verify("sha256",nonce,leaf.publicKey,Buffer.from(reference.signature,"base64")),true);
   const survivors=await require("../../../packages/agent/src/windows-key-survivors").inspectMachineKeySurvivors({containerName:container});assert.equal(survivors.ok,true);assert.equal(survivors.shared,true);
   const before=invoke("owned-request-observation.ps1",["-CommonName",item.domain,"-RequestId",requestId]);assert.equal(before.disposition,20);const nativeBefore=checkpoint();
   const denied=JSON.parse(original);denied.adcs.enrollmentRules=[];fs.writeFileSync(file,JSON.stringify(denied));await retainedStart();
   const first=(await require("../../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments({client:fixture.pool,now:new Date(Date.parse(pending.next_poll_at)+1000)})).find(r=>r.enrollmentId===id);assert.ok(first);
   const failed=await until(async()=>{const j=(await fixture.pool.query("SELECT status,error_message,claim_id,assigned_agent_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,first.jobId])).rows[0];assert.notEqual(j.status,"succeeded");return j.status==="failed"?j:null;});assert.equal(failed.error_message,survivorError);assert.ok(failed.claim_id);assert.equal(failed.assigned_agent_id,agentRowId);
   assert.deepEqual(journals.readEnrollmentJournal(configDir,id),originalJournal);assert.deepEqual(association(),reference);assert.equal((await row()).state,"pending_issuance");assert.equal(String((await row()).request_id),requestId);assert.deepEqual(custody(),baselineCustody);assert.equal(await served(),observedPredecessor.fingerprint256);assert.deepEqual(checkpoint(),nativeBefore);
   const after=invoke("owned-request-observation.ps1",["-CommonName",item.domain,"-RequestId",requestId]);assert.equal(after.subjectRequestCount,before.subjectRequestCount);
   ownedGuard();await retainedStop();assert.deepEqual(association(),reference);command("certutil.exe",["-delstore","WebHosting",thumbprint]);assert.equal(ps(`[bool](Test-Path -LiteralPath 'Cert:\\LocalMachine\\WebHosting\\${thumbprint}')`),"False");
   const unreferenced=await require("../../../packages/agent/src/windows-key-survivors").inspectMachineKeySurvivors({containerName:container});assert.equal(unreferenced.ok,true);assert.equal(unreferenced.shared,false);
   assert.ok(command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).split(/\r?\n/).map(s=>s.trim()).includes(container));
   await retainedStart();assert.equal((await fixture.request(`${api}/enrollments/${id}/cancel`,"POST",{})).status,204);
   const cleanupJob=(await require("../../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments({client:fixture.pool})).find(r=>r.enrollmentId===id);assert.ok(cleanupJob);
   await until(async()=>{const j=(await fixture.pool.query("SELECT status,claim_id,assigned_agent_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,cleanupJob.jobId])).rows[0];assert.ok(!["failed","rejected"].includes(j.status));if(j.status!=="succeeded")return false;assert.ok(j.claim_id);assert.equal(j.assigned_agent_id,agentRowId);return true;});
   const final=journals.readEnrollmentJournal(configDir,id);assert.equal(final.kind,"valid");assert.equal(final.journal.state,"cancelled");for(const key of ["containerName","csrSha256","csrSpkiSha256","snapshotSha256","requestId"])assert.equal(final.journal[key],originalJournal.journal[key]);assert.equal((await row()).state,"cancelled");
   assert.ok(!command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).split(/\r?\n/).map(s=>s.trim()).includes(container));
   const absent=await require("../../../packages/agent/src/windows-cert-store").removeAbandonedKeyContainer({containerName:container,requireAlreadyAbsent:true});assert.equal(absent.ok,true);assert.equal(absent.alreadyAbsent,true);
   const last=invoke("owned-request-observation.ps1",["-CommonName",item.domain,"-RequestId",requestId]);assert.equal(last.subjectRequestCount,before.subjectRequestCount);assert.deepEqual(checkpoint(),nativeBefore);
   command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(rootPath,"officer-action.ps1"),"-RequestId",requestId,"-Action","revoke","-CommonName",item.domain]);assert.equal(invoke("owned-request-observation.ps1",["-CommonName",item.domain,"-RequestId",requestId]).disposition,21);
   proof={scope:survivorScope,store:"WebHosting",recovery:"public-cancel-then-terminal-cleanup",firstError:survivorError,enrollmentId:id,requestId,failedJobId:first.jobId,cleanupJobId:cleanupJob.jobId,fingerprint,csrSpkiSha256:originalJournal.journal.csrSpkiSha256,caRequestCounts:[before.subjectRequestCount,after.subjectRequestCount,last.subjectRequestCount],automaticRetryQualified:false,schedulerDefaultClockQualified:false,...Object.fromEntries(survivorFlags.map(flag=>[flag,true]))};
   complete=true;
  }finally{
   // Association ownership stays armed on every failure. Configuration restore
   // still requires the exact original service tree to stop and close first.
   await restart(original,true);assert.deepEqual(fs.readFileSync(file),original);assert.deepEqual(fs.readFileSync(path.join(configDir,"credential")),credential);
  }
  assert.equal(complete,true);assert.deepEqual(custody(),baselineCustody);assert.equal(await served(),observedPredecessor.fingerprint256);verifySurvivorProof(proof);ownedGuard();fs.unlinkSync(marker);activeSurvivors.delete(root);gate.report.nativePendingKeySurvivor=proof;
 },{evidenceLevel:"real-host",oracle:"Actual same-CSR CA public leaf bound to pending CNG in WebHosting blocks signed local-policy key cleanup; exact public association removal followed by public cancel permits genuine terminal cleanup without any in-use key deletion or resubmission"});

}
module.exports={assertCleanupSafe,survivorScenario,survivorScope,survivorError,survivorFlags,verifySurvivorProof,SURVIVOR_SOURCES,REQUIRED_SOURCES,qualifyLocalRules,pairCases,pairFlags,pairRules,verifyPairProof};
