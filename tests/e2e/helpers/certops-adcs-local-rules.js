"use strict";
/* Whole local enrollment-rule negative cases with genuine signed jobs, unchanged CA request count
 * and trusted outgoing TLS; tighter policy continuation checks exact unaccepted-key cleanup.
 * Called only by the protected disposable-forest AD CS harness; native qualification requires
 * that workflow to execute.
 */
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto"),tls=require("node:tls");
const {buildEnrollmentContainerName}=require("../../../packages/agent/src/windows-cert-store");
const pairCases=Object.freeze(["ca-host-mismatch","ca-authority-mismatch","template-pair-mismatch"]);
const pairFlags=Object.freeze(["actualSignedJobRefused","claimBoundOutcome","noCaRequestAllocated","noKeyGenerated","noAcceptedLeafOrJournal","originalNativeCustodyPreserved","outgoingTrustedTlsPreserved","configurationAndCredentialRestored"]);
function pairRules(caseId,allowed){
 assert.ok(pairCases.includes(caseId));
 const split=allowed.caConfig.indexOf("\\");assert.ok(split>0);
 if(caseId==="ca-host-mismatch")return [{...allowed,caConfig:`other-ca.lab.certops.test${allowed.caConfig.slice(split)}`}];
 if(caseId==="ca-authority-mismatch")return [{...allowed,caConfig:`${allowed.caConfig.slice(0,split)}\\OtherQualificationAuthority`}];
 return [{...allowed,template:"TTQualificationRSA3072"}];
}
function verifyPairProof(rows){
 assert.ok(Array.isArray(rows));assert.equal(rows.length,pairCases.length);assert.deepEqual(rows.map(row=>row.caseId).sort(),[...pairCases].sort());
 for(const row of rows){assert.deepEqual(Object.keys(row).sort(),["caseId",...pairFlags].sort());for(const flag of pairFlags)assert.equal(row[flag],true,flag);}return true;
}
async function qualifyLocalRules({gate,fixture,api,agentRowId,renewalFixture,configDir,run,preflight,command,ps,until,ownedEnrollmentIds,tlsAuthority}){
 const root=path.resolve(__dirname,"../../.."),file=path.join(configDir,"config.json"),original=fs.readFileSync(file),credential=fs.readFileSync(path.join(configDir,"credential"));
 const {item,issuerId,certificateId,site,port,authority,observed}=renewalFixture;const caConfig="tt-ca.lab.certops.test\\TTQualificationRoot";
 assert.equal(process.platform,"win32");assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB,"1");assert.equal(ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),"S-1-5-18");
 gate.report.fixtureSources??=[];for(const source of ["tests/e2e/helpers/certops-adcs-local-rules.js","packages/agent/src/issuers/adcs-enrollment-rules.js","packages/agent/src/issuers/adcs-enrollment-journal.js"]){const sha256=crypto.createHash("sha256").update(fs.readFileSync(path.join(root,source))).digest("hex");const prior=gate.report.fixtureSources.find(row=>row.file===source);if(prior)assert.equal(prior.sha256,sha256);else gate.report.fixtureSources.push({file:source,sha256});}
 const checkpoint=()=>JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(root,"infra/certops-adcs/owned-ca-checkpoint.ps1"),"-RunId",run]));
 const served=()=>new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:item.domain,ca:tlsAuthority(authority),rejectUnauthorized:true},()=>{try{assert.equal(socket.authorized,true);resolve(socket.getPeerCertificate().fingerprint256);}catch(error){reject(error);}finally{socket.destroy();}});socket.once("error",reject);socket.setTimeout(10000,()=>socket.destroy(new Error("Local rule TLS oracle timed out")));});
 const restart=async(bytes)=>{if(ps("(Get-Service TokenTimerAgent).Status")!=="Stopped")command("sc.exe",["stop","TokenTimerAgent"]);await until(async()=>ps("(Get-Service TokenTimerAgent).Status")==="Stopped",30000);const before=(await fixture.pool.query("SELECT now() AS marker")).rows[0].marker;if(bytes)fs.writeFileSync(file,bytes);command("sc.exe",["start","TokenTimerAgent"]);await until(async()=>Date.parse((await fixture.pool.query("SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,agentRowId])).rows[0].last_seen_at)>Date.parse(before),45000);assert.ok(fs.readFileSync(path.join(configDir,"credential")).equals(credential));};
 const configure=async(template,rules)=>{const config=JSON.parse(original);config.adcs.enrollmentRules=config.adcs.enrollmentRules.filter(rule=>rule.caConfig!==caConfig||rule.template!==template).concat(rules);await restart(Buffer.from(JSON.stringify(config)));};
 const custody=()=>{const thumbprint=crypto.createHash("sha1").update(observed.raw).digest("hex").toUpperCase();return JSON.parse(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumbprint}';$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);try{@{der=[Convert]::ToBase64String($c.RawData);thumbprint=$c.Thumbprint;container=$k.Key.KeyName;provider=$k.Key.Provider.Provider;machine=$k.Key.IsMachineKey;exportPolicy=[int]$k.Key.ExportPolicy;usage=[int]$k.Key.KeyUsage;bits=$k.KeySize}|ConvertTo-Json -Compress}finally{$k.Dispose();$c.Dispose()}`));};
 const admittedInput=(selectedIssuer=issuerId)=>({issuerId:selectedIssuer,certificateId,agentId:agentRowId,target:{type:"windows-iis",reference:item.domain,store:"My",binding:{site,port,sniHost:item.domain}},authorizedDnsNames:[item.domain],keyAlgorithm:"rsa",keySize:2048});
 const refused=async jobId=>{const outcome=await until(async()=>{const row=(await fixture.pool.query("SELECT status,result_metadata FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,jobId])).rows[0];if(row.status==="succeeded")throw new Error("Out-of-rule signed enrollment succeeded");return ["failed","rejected"].includes(row.status)?row:null;});assert.equal(outcome.result_metadata.enrollmentResult.state,"refused");assert.equal(outcome.result_metadata.enrollmentResult.errorCode,"ADCS_CA_CONFIG_UNSAFE");return outcome;};
 for(const selected of ["missing-constraints","dns-dot-boundary","key-algorithm","cross-product","extra-san",...pairCases])await gate.scenario(`adcs-real-local-rule-${selected}-refused`,async()=>{
  const before=checkpoint(),isPair=pairCases.includes(selected),allowed={caConfig,template:item.template,dnsScopes:[item.domain],keyAlgorithms:["rsa"]};let primaryError,pairProof;const originalCustody=isPair?custody():null;const cleanupErrors=[];
  try{
   let rules=[allowed];if(selected==="missing-constraints")rules=[{caConfig,template:item.template}];if(selected==="dns-dot-boundary")rules=[{...allowed,dnsScopes:["ample.test"]}];if(selected==="key-algorithm")rules=[{...allowed,keyAlgorithms:["ecdsa"]}];if(selected==="cross-product")rules=[{...allowed,dnsScopes:["other.test"]},{...allowed,keyAlgorithms:["ecdsa"]}];if(isPair)rules=pairRules(selected,allowed);await configure(item.template,rules);
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
  }catch(error){primaryError=error;}finally{try{await restart(original);assert.ok(fs.readFileSync(file).equals(original));}catch(error){cleanupErrors.push(error);}}
  if(cleanupErrors.length)throw new AggregateError([...(primaryError?[primaryError]:[]),...cleanupErrors],"Local rule fixture restoration failed");if(primaryError)throw primaryError;
  if(pairProof){assert.deepEqual(custody(),originalCustody);assert.equal(await served(),observed.fingerprint256);assert.deepEqual(checkpoint(),before);pairProof.configurationAndCredentialRestored=true;gate.report.nativeLocalRulePairs??=[];gate.report.nativeLocalRulePairs.push(pairProof);}
 });
 verifyPairProof(gate.report.nativeLocalRulePairs);
 await gate.scenario("adcs-real-local-rule-tightening-frees-pending-key",async()=>{
  const checked=await preflight("TTQualificationPending");assert.equal((await fixture.request(`${api}/issuers/${checked.issuerId}/confirm`,"POST",{caKeySha256:authority.keySha256,caConfig,template:"TTQualificationPending"})).status,200);
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
}
module.exports={qualifyLocalRules,pairCases,pairFlags,pairRules,verifyPairProof};
