"use strict";
/* Real owned LDAP template safety mutations with exact all-attribute snapshot/restore. Public
 * native preflight and signed enrollment must refuse unsafe facts before CA submission or CNG
 * creation. Called only by the protected disposable-forest AD CS harness; native qualification
 * requires that workflow to execute.
 */
const assert=require("node:assert/strict"),crypto=require("node:crypto"),fs=require("node:fs"),path=require("node:path"),tls=require("node:tls");
const {buildEnrollmentContainerName}=require("../../../packages/agent/src/windows-cert-store");
async function qualifyTemplateMutations({gate,fixture,api,agentRowId,renewalFixture,preflightCohorts,run,command,ps,until,ownedEnrollmentIds,tlsAuthority}){
  assert.equal(process.platform,"win32");assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB,"1");assert.equal(ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),"S-1-5-18");
  const root=path.resolve(__dirname,"../../.."),mutationScript=path.join(root,"infra/certops-adcs/template-safety-mutation.ps1");
  gate.report.fixtureSources??=[];for(const file of ["tests/e2e/helpers/certops-adcs-template-mutations.js","infra/certops-adcs/template-safety-mutation.ps1"])gate.report.fixtureSources.push({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")});
  const {item,issuerId,certificateId,site,port,authority,observed}=renewalFixture;assert.equal(item.template,"TTQualificationRSAShort");
  const checkpoint=()=>JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(root,"infra/certops-adcs/owned-ca-checkpoint.ps1"),"-RunId",run]));
  const served=()=>new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:item.domain,ca:tlsAuthority(authority),rejectUnauthorized:true},()=>{try{assert.equal(socket.authorized,true);resolve(socket.getPeerCertificate().fingerprint256);}catch(error){reject(error);}finally{socket.destroy();}});socket.once("error",reject);socket.setTimeout(10000,()=>socket.destroy(new Error("Template mutation TLS oracle timed out")));});
  const restart=async()=>{const previous=(await fixture.pool.query("SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,agentRowId])).rows[0].last_seen_at;command("sc.exe",["stop","TokenTimerAgent"]);await until(async()=>ps("(Get-Service TokenTimerAgent).Status")==="Stopped",30000);command("sc.exe",["start","TokenTimerAgent"]);await until(async()=>{const row=(await fixture.pool.query("SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,agentRowId])).rows[0];return Date.parse(row.last_seen_at)>Date.parse(previous);},45000);};
  for(const selected of [{id:"schema-one",reason:"schema_version_1"},{id:"application-policy-absent",reason:"application_policy_not_server_auth_only"},{id:"subject-client-auth",reason:"eku_not_server_auth_only"},...["schema-three-algorithm-absent","minimum-key-absent","template-oid-absent","schema-out-of-range"].map(id=>({id,reason:"template_unreadable"})),...["eku-absent","subject-any-purpose","subject-enrollment-agent","subject-smartcard","subject-pkinit"].map(id=>({id,reason:"eku_not_server_auth_only"})),...["application-policy-any-purpose","application-policy-client-mixed"].map(id=>({id,reason:"application_policy_not_server_auth_only"}))])await gate.scenario(`adcs-real-mutated-template-${selected.id}-native-refused`,async()=>{
    const ownershipToken=crypto.randomUUID(),before=checkpoint();assert.equal(await served(),observed.fingerprint256);
    const mutate=action=>JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",mutationScript,"-Action",action,"-CaseId",selected.id,"-RunId",run,"-OwnershipToken",ownershipToken]));
    let primaryError;const cleanupErrors=[];
    try{
      assert.equal(mutate("apply").applied,true);await restart();
      const actual=await preflightCohorts.preflight(item.template);assert.ok(actual.result.templateCheck.reasons.includes(selected.reason));assert.notEqual(actual.result.templateCheck.verdict,"safe");
      if(selected.id.startsWith("subject-"))assert.equal(actual.result.templateCheck.enrolleeSuppliesSubject,true);
      assert.equal((await actual.confirm({caKeySha256:authority.keySha256,caConfig:"tt-ca.lab.certops.test\\TTQualificationRoot",template:item.template})).status,400);
      const admitted=await fixture.request(`${api}/enrollments`,"POST",{issuerId,certificateId,agentId:agentRowId,target:{type:"windows-iis",reference:item.domain,store:"My",binding:{site,port,sniHost:item.domain}},authorizedDnsNames:[item.domain],keyAlgorithm:"rsa",keySize:2048});assert.equal(admitted.status,201);ownedEnrollmentIds.push(admitted.body.enrollmentId);
      const outcome=await until(async()=>{const row=(await fixture.pool.query("SELECT status,result_metadata FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,admitted.body.jobId])).rows[0];if(row.status==="succeeded")throw new Error("Mutated unsafe template was issued or installed");return ["failed","rejected"].includes(row.status)?row:null;});
      assert.equal(outcome.result_metadata.enrollmentResult.state,"refused");assert.equal(outcome.result_metadata.enrollmentResult.errorCode,"ADCS_TEMPLATE_UNSAFE");assert.deepEqual(checkpoint(),before,"Native refusal must precede any CA request allocation");
      assert.ok(!command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(buildEnrollmentContainerName(admitted.body.enrollmentId)),"Native refusal must precede CNG key generation");assert.equal(await served(),observed.fingerprint256);
      gate.report.nativeTemplateMutations??=[];gate.report.nativeTemplateMutations.push({caseId:selected.id,template:item.template,reason:selected.reason,preflightVerdict:actual.result.templateCheck.verdict,originalConfirmedIssuerReused:true,actualSignedJobRefused:true,noCaRequestAllocated:true,noKeyGenerated:true,outgoingTrustedTlsPreserved:true});
    }catch(error){primaryError=error;}
    finally{
      try{const restored=mutate("restore");assert.ok(restored.restored || restored.absent);if(restored.restored)assert.equal(restored.exactPublicAttributesVerified,true);}catch(error){cleanupErrors.push(error);}
      try{await restart();}catch(error){cleanupErrors.push(error);}
    }
    if(cleanupErrors.length)throw new AggregateError([...(primaryError?[primaryError]:[]),...cleanupErrors],"Owned template restoration or native agent recovery failed");if(primaryError)throw primaryError;
    assert.equal(await served(),observed.fingerprint256);assert.deepEqual(checkpoint(),before);
  },{evidenceLevel:"real-host",oracle:"real owned LDAP template mutation with exact receipt-bound attribute restoration; genuine original-confirmed-issuer signed job refused before CNG/CA allocation, unchanged independent trusted outgoing TLS"});
}
module.exports={qualifyTemplateMutations};
