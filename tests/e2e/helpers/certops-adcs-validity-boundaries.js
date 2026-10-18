"use strict";
/* Actual CA validity-policy refusal cases: older issued leaf and minimum remaining lifetime,
 * compared with the installed trusted outgoing IIS certificate. Called only by the protected
 * disposable-forest AD CS harness; native qualification requires that workflow to execute.
 */
const fs=require("node:fs");
const assert=require("node:assert/strict"),crypto=require("node:crypto"),path=require("node:path"),tls=require("node:tls");
const {buildEnrollmentContainerName}=require("../../../packages/agent/src/windows-cert-store");
const {readEnrollmentJournal}=require("../../../packages/agent/src/issuers/adcs-enrollment");
async function qualifyValidityBoundaries(context){
  const {gate,fixture,api,agentRowId,renewalFixture,configDir,preflight,until,ps,command,ownedEnrollmentIds,tlsAuthority}=context;
  assert.equal(process.platform,"win32");assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB,"1");assert.equal(ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),"S-1-5-18");
  gate.report.fixtureSources??=[];for(const file of ["tests/e2e/helpers/certops-adcs-validity-boundaries.js","infra/certops-adcs/owned-ca-request-certificate.ps1"])gate.report.fixtureSources.push({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"../../..",file))).digest("hex")});
  const {item,site,port,certificateId,authority,observed}=renewalFixture;const binding={site,port,sniHost:item.domain};
  const outgoingThumbprint=observed.fingerprint.replace(/:/g,"");const repo=path.resolve(__dirname,"../../..");
  const publicLeaf=id=>{const native=JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(repo,"infra/certops-adcs/owned-ca-request-certificate.ps1"),"-CommonName",item.domain,"-RequestId",String(id)]));assert.equal(String(native.requestId),String(id));return new crypto.X509Certificate(Buffer.from(native.certificateB64,"base64"));};
  const tlsFingerprint=()=>new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:item.domain,ca:tlsAuthority(authority),rejectUnauthorized:true},()=>{try{assert.equal(socket.authorized,true);resolve(socket.getPeerCertificate().fingerprint256);}catch(error){reject(error);}finally{socket.destroy();}});socket.setTimeout(10000,()=>socket.destroy(new Error("Validity boundary outgoing TLS timed out")));socket.once("error",reject);});
  for(const selected of [{id:"adcs-real-late-approved-older-leaf-refused",template:"TTQualificationPendingOlder",options:{requireLaterNotAfter:true},pending:true},{id:"adcs-real-minimum-remaining-validity-refused",template:"TTQualificationRSAShort",options:{minimumRemainingValidity:7*86400},pending:false}])await gate.scenario(selected.id,async()=>{
    assert.equal(await tlsFingerprint(),observed.fingerprint256);const current=await require("../../../packages/agent/src/windows-iis").queryCurrentBinding({binding});assert.equal(current.thumbprint.toUpperCase(),outgoingThumbprint);
    let issuerId=renewalFixture.issuerId;
    if(selected.pending){const checked=await preflight(selected.template);assert.equal(checked.result.templateCheck.verdict,"safe");assert.equal(checked.result.caCheck.verdict,"safe");assert.equal(checked.result.caCertificates[0].keySha256,authority.keySha256);issuerId=checked.issuerId;assert.equal((await fixture.request(`${api}/issuers/${issuerId}/confirm`,"POST",{caKeySha256:authority.keySha256,caConfig:context.caConfig,template:selected.template})).status,200);}
    else assert.equal(item.template,selected.template,"Reuse only the already confirmed unchanged issuer of this actual six-day outgoing certificate");
    const admitted=await fixture.request(`${api}/enrollments`,"POST",{issuerId,certificateId,agentId:agentRowId,target:{type:"windows-iis",reference:item.domain,store:"My",binding},authorizedDnsNames:[item.domain],keyAlgorithm:"rsa",keySize:2048,...selected.options});assert.equal(admitted.status,201);ownedEnrollmentIds.push(admitted.body.enrollmentId);
    const row=async()=>(await fixture.pool.query("SELECT state,request_id,next_poll_at,snapshot_bytes,snapshot_sha256 FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,admitted.body.enrollmentId])).rows[0];
    const original=await row(),frozen=JSON.parse(original.snapshot_bytes);for(const [field,value]of Object.entries(selected.options))assert.equal(frozen[field],value);assert.equal(original.snapshot_sha256,admitted.body.snapshotSha256);
    let jobId=admitted.body.jobId,leaf;
    if(selected.pending){
      const pending=await until(async()=>{const value=await row();return value.state==="pending_issuance"&&value.request_id&&value.next_poll_at?value:null;});
      const waiting=readEnrollmentJournal(configDir,admitted.body.enrollmentId);assert.equal(waiting.kind,"valid");assert.equal(waiting.journal.state,"pending");
      command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(repo,"infra/certops-adcs/officer-action.ps1"),"-RequestId",String(pending.request_id),"-Action","approve","-CommonName",item.domain]);
      leaf=publicLeaf(pending.request_id);assert.ok(Date.parse(leaf.validTo)<Date.parse(observed.validTo),"Actual approved certificate must expire earlier than the installed leaf; no certificate clock is rewritten");assert.ok(Date.parse(leaf.validTo)>Date.now());
      const dispatched=(await require("../../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments({client:fixture.pool,now:new Date(Date.parse(pending.next_poll_at)+1000)})).find(value=>value.enrollmentId===admitted.body.enrollmentId);assert.ok(dispatched);jobId=dispatched.jobId;
    }
    const outcome=await until(async()=>{const value=(await fixture.pool.query("SELECT status,error_message,result_metadata FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,jobId])).rows[0];if(value.status==="succeeded")throw new Error("Native validity policy incorrectly installed an inadmissible certificate");return ["failed","rejected"].includes(value.status)?value:null;});
    assert.equal(outcome.result_metadata.enrollmentResult.state,"rejected_invalid");assert.equal(outcome.result_metadata.enrollmentResult.errorCode,"ADCS_CERTIFICATE_INVALID");assert.match(outcome.error_message,selected.pending?/notAfter.*later/i:/minimumRemainingValidity/);
    const final=await row();assert.equal(final.state,"rejected_invalid");assert.ok(final.snapshot_bytes.equals(original.snapshot_bytes));assert.equal(final.snapshot_sha256,original.snapshot_sha256);leaf??=publicLeaf(final.request_id);
    assert.equal(leaf.verify(authorityCertificate(authority).publicKey),true,"Actual invalid-policy leaf must still carry the pinned CA signature");
    if(!selected.pending)assert.ok(Date.parse(leaf.validTo)<Date.now()+selected.options.minimumRemainingValidity*1000);
    const journal=readEnrollmentJournal(configDir,admitted.body.enrollmentId);assert.equal(journal.kind,"valid");assert.equal(journal.journal.state,"rejected_invalid");assert.equal(journal.journal.snapshotSha256,original.snapshot_sha256);
    const container=buildEnrollmentContainerName(admitted.body.enrollmentId);assert.ok(!command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(container),"Invalid unaccepted enrollment must free its exact CNG key");
    const rejectedThumbprint=leaf.fingerprint.replace(/:/g,"");assert.equal(ps(`$foundCertificates=@();foreach($store in @('My','WebHosting')){$storePath='Cert:\\LocalMachine\\'+$store;if(Test-Path -LiteralPath $storePath){$foundCertificates+=@(Get-ChildItem -LiteralPath $storePath|Where-Object Thumbprint -eq '${rejectedThumbprint}')}};$foundCertificates.Count`),"0");
    assert.equal((await require("../../../packages/agent/src/windows-iis").queryCurrentBinding({binding})).thumbprint.toUpperCase(),outgoingThumbprint);assert.equal(await tlsFingerprint(),observed.fingerprint256);
    gate.report.nativeValidityBoundaries??=[];gate.report.nativeValidityBoundaries.push({scenario:selected.id,requestId:String(final.request_id),snapshotSha256:original.snapshot_sha256,policy:selected.options,issuedNotAfter:leaf.validTo,installedNotAfter:observed.validTo,actualCaSignedLeaf:true,publicFrozenPolicy:true,refusedBeforeAccept:true,unacceptedOwnedKeyAbsent:true,outgoingTrustedTlsPreserved:true,nativeAndCaClocks:"actual"});
  },{evidenceLevel:"real-host",oracle:"actual approved or issued CA-signed leaf evaluated by installed signed agent against public immutable validity policy; no clock/journal/phase rewriting, no accept, exact CNG cleanup and outgoing trusted TLS preserved"});
}
function authorityCertificate(authority){return new crypto.X509Certificate(Buffer.from(authority.certificateB64,"base64"));}
module.exports={qualifyValidityBoundaries};
