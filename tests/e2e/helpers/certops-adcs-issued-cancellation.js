"use strict";
/* CA-issued / not-yet-accepted cancellation boundary, invoked by the protected
 * disposable-forest AD CS main/hierarchy harness. The public enrollment, real
 * pending key, officer issuance and signed cleanup are genuine. No poll clock,
 * database date, journal state or successful outcome is synthesized. The parent
 * owns the IIS fixture/enrollment; this helper always revokes its unused issued
 * CA leaf. Native execution is required; portable verifier tests are supporting. */
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto"),tls=require("node:tls");
const {readEnrollmentJournal}=require("../../../packages/agent/src/issuers/adcs-enrollment");
const {buildEnrollmentContainerName,readIssuedContainerRecord}=require("../../../packages/agent/src/windows-cert-store");
const ID="adcs-real-cancel-ca-issued-unaccepted-key";
function verifyIssuedCancellationFacts(facts){
 assert.ok(typeof facts.requestId==="string"&&/^[1-9][0-9]{0,9}$/.test(facts.requestId)&&Number(facts.requestId)<=0xffffffff);assert.match(facts.snapshotSha256,/^[a-f0-9]{64}$/i);assert.equal(facts.pollIntervalSeconds,900);assert.equal(facts.schedulerClock,"default-real-now");
 for(const field of ["actualCaIssuedBeforeCancel","caLeafSignatureAndCsrSpkiVerified","controlPlaneStillPendingBeforeCancel","nonExportableKeyPresentBeforeCancel","signedTerminalCleanupSucceeded","exactUnacceptedKeyAbsent","certificateNeverAccepted","sameRequestSnapshotAndCsrPreserved","noAdditionalCaRequest","outgoingTrustedTlsUnchanged","terminalReconcileRefused","unusedIssuedLeafRevoked"])assert.equal(facts[field],true);
 assert.equal(facts.databaseDatesRewritten,false);assert.equal(facts.journalRewritten,false);return true;
}
async function qualifyIssuedCancellation({gate,fixture,api,agentRowId,renewalFixture,configDir,preflight,command,ps,until,jobFinished,ownedEnrollmentIds,tlsAuthority,caConfig}){
 await gate.scenario(ID,async()=>{
  assert.equal(process.platform,"win32");assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB,"1");assert.equal(ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),"S-1-5-18");
  const root=path.resolve(__dirname,"../../.."),{item,certificateId,site,port,authority,observed}=renewalFixture,binding={site,port,sniHost:item.domain};
  const native=(script,requestId,extra=[])=>JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(root,`infra/certops-adcs/${script}.ps1`),"-CommonName",item.domain,"-RequestId",String(requestId),...extra]));
  const observe=requestId=>native("owned-request-observation",requestId);
  const officer=(requestId,action)=>command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(root,"infra/certops-adcs/officer-action.ps1"),"-CommonName",item.domain,"-RequestId",String(requestId),"-Action",action]);
  const served=()=>new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:item.domain,ca:tlsAuthority(authority)},()=>{try{assert.equal(socket.authorized,true);resolve(socket.getPeerCertificate().fingerprint256);}catch(error){reject(error);}finally{socket.destroy();}});socket.once("error",reject);socket.setTimeout(10000,()=>socket.destroy(new Error("Issued cancellation TLS oracle timed out")));});
  const checked=await preflight("TTQualificationPending");assert.equal(checked.result.templateCheck.verdict,"safe");assert.equal(checked.result.caCheck.verdict,"safe");assert.equal((await fixture.request(`${api}/issuers/${checked.issuerId}/confirm`,"POST",{caKeySha256:checked.result.caCertificates[0].keySha256,caConfig,template:"TTQualificationPending"})).status,200);
  assert.equal(await served(),observed.fingerprint256);
  const admitted=await fixture.request(`${api}/enrollments`,"POST",{issuerId:checked.issuerId,certificateId,agentId:agentRowId,target:{type:"windows-iis",reference:item.domain,store:"My",binding},authorizedDnsNames:[item.domain],keyAlgorithm:"rsa",keySize:2048});assert.equal(admitted.status,201);
  const id=admitted.body.enrollmentId;ownedEnrollmentIds.push(id);const container=buildEnrollmentContainerName(id);
  const row=async()=>(await fixture.pool.query("SELECT state,request_id,next_poll_at,snapshot_bytes,snapshot_sha256,current_job_id,NOW() AS database_now FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,id])).rows[0];
  const pending=await until(async()=>{const value=await row();return value.state==="pending_issuance"&&value.request_id&&value.next_poll_at?value:null;});
  const snapshot=JSON.parse(Buffer.from(pending.snapshot_bytes).toString("utf8"));assert.equal(snapshot.pollInterval,900);
  const original=readEnrollmentJournal(configDir,id);assert.equal(original.kind,"valid");assert.equal(original.journal.state,"pending_issuance");assert.equal(original.journal.containerName,container);
  assert.equal(ps(`$key=[Security.Cryptography.CngKey]::Open('${container}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey);try{if($key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None){throw 'Owned pending key is exportable'};'nonexportable'}finally{$key.Dispose()}`),"nonexportable");
  const before=observe(pending.request_id);assert.equal(before.disposition,9);let approvalAttempted=false,revoked=false,primary;
  try{
   approvalAttempted=true;officer(pending.request_id,"approve");await until(()=>observe(pending.request_id).disposition===20);
   const publicLeaf=native("owned-ca-request-certificate",pending.request_id),leaf=new crypto.X509Certificate(Buffer.from(publicLeaf.certificateB64,"base64"));
   assert.equal(leaf.verify(new crypto.X509Certificate(Buffer.from(authority.certificateB64,"base64")).publicKey),true);assert.equal(leaf.checkHost(item.domain),item.domain);assert.equal(crypto.createHash("sha256").update(leaf.publicKey.export({type:"spki",format:"der"})).digest("hex"),original.journal.csrSpkiSha256);
   const leafThumbprint=leaf.fingerprint.replace(/:/g,"");
   const noAcceptance=()=>assert.equal(ps(`$found=@();foreach($store in @('My','WebHosting')){$location='Cert:\\LocalMachine\\'+$store;if(Test-Path -LiteralPath $location){$found+=@(Get-ChildItem -LiteralPath $location|Where-Object Thumbprint -eq '${leafThumbprint}')}};$found.Count`),"0");noAcceptance();
   const beforeCancel=await row();assert.equal(beforeCancel.state,"pending_issuance");assert.ok(new Date(beforeCancel.database_now).getTime()<new Date(beforeCancel.next_poll_at).getTime(),"The real normal poll must not already be due");assert.equal(readEnrollmentJournal(configDir,id).journal.state,"pending_issuance");
   assert.equal((await fixture.request(`${api}/enrollments/${id}/cancel`,"POST",{})).status,204);
   const dispatched=(await require("../../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments({client:fixture.pool})).filter(value=>value.enrollmentId===id);assert.equal(dispatched.length,1);await jobFinished(dispatched[0].jobId);
   const cancelled=await row();assert.equal(cancelled.state,"cancelled");assert.equal(String(cancelled.request_id),String(pending.request_id));assert.equal(cancelled.snapshot_sha256,pending.snapshot_sha256);assert.ok(cancelled.snapshot_bytes.equals(pending.snapshot_bytes));
   const terminal=readEnrollmentJournal(configDir,id);assert.equal(terminal.kind,"valid");assert.equal(terminal.journal.state,"cancelled");for(const field of ["containerName","csrSha256","csrSpkiSha256","snapshotSha256","requestId"])assert.equal(terminal.journal[field],original.journal[field]);
   assert.ok(!command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(container));assert.ok(!readIssuedContainerRecord({stateDir:configDir,containerName:container}));noAcceptance();
   assert.equal((await require("../../../packages/agent/src/windows-iis").queryCurrentBinding({binding})).thumbprint.toUpperCase(),observed.fingerprint.replace(/:/g,"").toUpperCase());assert.equal(await served(),observed.fingerprint256);assert.equal(observe(pending.request_id).subjectRequestCount,before.subjectRequestCount);
   const refused=await fixture.request(`${api}/enrollments/${id}/reconcile`,"POST",{requestId:Number(pending.request_id)});assert.equal(refused.status,400);assert.equal(refused.body.code,"CERTOPS_ENROLLMENT_TRANSITION_INVALID");
   assert.equal((await require("../../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments({client:fixture.pool})).filter(value=>value.enrollmentId===id).length,0);noAcceptance();
  }catch(error){primary=error;throw error;}finally{
   if(approvalAttempted){try{if(observe(pending.request_id).disposition===20){officer(pending.request_id,"revoke");assert.equal(observe(pending.request_id).disposition,21);revoked=true;}}catch(error){if(primary)throw new AggregateError([primary,error],"Issued cancellation and exact unused leaf revocation failed");throw error;}}
  }
  assert.equal(revoked,true);
  gate.report.nativeIssuedCancellation={requestId:String(pending.request_id),snapshotSha256:pending.snapshot_sha256,pollIntervalSeconds:900,schedulerClock:"default-real-now",actualCaIssuedBeforeCancel:true,caLeafSignatureAndCsrSpkiVerified:true,controlPlaneStillPendingBeforeCancel:true,nonExportableKeyPresentBeforeCancel:true,signedTerminalCleanupSucceeded:true,exactUnacceptedKeyAbsent:true,certificateNeverAccepted:true,sameRequestSnapshotAndCsrPreserved:true,noAdditionalCaRequest:true,outgoingTrustedTlsUnchanged:true,terminalReconcileRefused:true,unusedIssuedLeafRevoked:true,databaseDatesRewritten:false,journalRewritten:false};verifyIssuedCancellationFacts(gate.report.nativeIssuedCancellation);
  const file="tests/e2e/helpers/certops-adcs-issued-cancellation.js";gate.report.fixtureSources??=[];gate.report.fixtureSources.push({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")});
 },{evidenceLevel:"real-host",oracle:"actual CA-signed matching-SPKI leaf exists before public cancellation, signed unaccepted-key cleanup without retrieval/acceptance, unchanged trusted IIS TLS and owned leaf revocation"});
}
module.exports={ID,qualifyIssuedCancellation,verifyIssuedCancellationFacts};
