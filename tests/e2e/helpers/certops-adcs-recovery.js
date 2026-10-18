"use strict";
/* Real pending/installation recovery through public API, durable enrollment journals, SCM restart
 * and CA officer actions. Protects exact CSR/key/request identity and checks terminal cleanup
 * without fabricated native responses. Called only by the protected disposable-forest AD CS
 * harness; native qualification requires that workflow to execute.
 */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const path = require("node:path");
const tls = require("node:tls");
const { buildEnrollmentContainerName } = require("../../../packages/agent/src/windows-cert-store");
const { readEnrollmentJournal } = require("../../../packages/agent/src/issuers/adcs-enrollment");

async function qualifyRecovery(context) {
  const { gate, fixture, api, agentRowId, configDir, serviceOwned, ps, command, until,
    jobFinished, ownedCertificateIds, ownedEnrollmentIds, ownedThumbprints, workDir, tlsAuthority, pendingRecoveryFixtures } = context;
  assert.equal(process.platform, "win32"); assert.equal(serviceOwned, true);
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  const scheduler = require("../../../apps/api/services/certops/certificateEnrollments");
  const getEnrollment = async (id) => (await fixture.pool.query(
    "SELECT state,request_id,next_poll_at,current_job_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId,id])).rows[0];
  function observe(item, requestId) {
    return JSON.parse(command("powershell.exe", ["-NoProfile","-NonInteractive","-File",
      path.resolve(__dirname,"../../../infra/certops-adcs/owned-request-observation.ps1"),
      "-CommonName",item.domain,"-RequestId",String(requestId)]));
  }
  function absent(item, enrollmentId, site, port) {
    assert.ok(!command("certutil.exe", ["-csp","Microsoft Software Key Storage Provider","-key"]).includes(buildEnrollmentContainerName(enrollmentId)), "Terminal owned key remains");
    assert.equal(ps(`@(Get-ChildItem Cert:\\LocalMachine\\My | Where-Object Subject -eq 'CN=${item.domain}').Count`),"0");
    const hash = ps(`Import-Module WebAdministration; $b=@(Get-WebBinding -Name '${site}' -Protocol https | Where-Object bindingInformation -eq '*:${port}:${item.domain}'); if($b.Count -ne 1){throw 'Owned binding disappeared or ambiguous'}; [string]$b[0].certificateHash`);
    assert.ok(hash === "" || /^0+$/.test(hash), "Late approval changed owned IIS certificate binding");
  }
  await gate.scenario("adcs-real-late-approval-remains-expired", async () => {
    const owned = pendingRecoveryFixtures.expire; assert.ok(owned);
    const id = owned.created.enrollmentId; const requestId = owned.pending.request_id;
    assert.equal((await getEnrollment(id)).state,"expired"); absent(owned.item,id,owned.site,owned.port);
    const before = observe(owned.item,requestId); assert.equal(before.disposition,9);
    command("powershell.exe", ["-NoProfile","-NonInteractive","-File",path.resolve(__dirname,"../../../infra/certops-adcs/officer-action.ps1"),"-RequestId",String(requestId),"-Action","approve","-CommonName",owned.item.domain]);
    await until(() => { const native = observe(owned.item,requestId); assert.equal(native.subjectRequestCount,before.subjectRequestCount); return native.disposition === 20; });
    const sweeps = await Promise.all(Array.from({length:4},()=>scheduler.scheduleDueEnrollments({client:fixture.pool,now:new Date(Date.now()+30*86400000)})));
    assert.equal(sweeps.flat().filter(row=>row.enrollmentId === id).length,0);
    const row = await getEnrollment(id); assert.equal(row.state,"expired"); assert.equal(String(row.request_id),String(requestId));
    absent(owned.item,id,owned.site,owned.port);
  }, { evidenceLevel:"real-host", oracle:"actual CA late issuance, terminal scheduler no-op, native key absence and unchanged IIS binding" });

  await gate.scenario("adcs-real-pending-restart-single-continuation", async () => {
    const owned = pendingRecoveryFixtures.cancel; assert.ok(owned);
    const certificateId = crypto.randomUUID(); ownedCertificateIds.push(certificateId);
    const created = await fixture.request(`${api}/enrollments`,"POST",{issuerId:owned.issuerId,certificateId,agentId:agentRowId,
      target:{type:"windows-iis",reference:owned.item.domain,store:"My",binding:{site:owned.site,port:owned.port,sniHost:owned.item.domain}},
      authorizedDnsNames:[owned.item.domain],keyAlgorithm:"rsa",keySize:2048}); assert.equal(created.status,201);
    const id = created.body.enrollmentId; ownedEnrollmentIds.push(id);
    const pending = await until(async()=> { const row=await getEnrollment(id); return row?.state === "pending_issuance" && row.request_id ? row : null; });
    const container = buildEnrollmentContainerName(id); assert.ok(command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(container));
    const native = observe(owned.item,pending.request_id); assert.equal(native.disposition,9);
    await gate.scenario("adcs-real-pending-abandon-refused", async () => {
      const result = await fixture.request(`${api}/enrollments/${id}/abandon`,"POST",{});
      assert.equal(result.status,400); assert.equal(result.body.code,"CERTOPS_ENROLLMENT_TRANSITION_INVALID");
      const unchanged = await getEnrollment(id); assert.equal(unchanged.state,"pending_issuance");
      assert.equal(String(unchanged.request_id),String(pending.request_id));
      assert.ok(command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(container));
      assert.deepEqual(observe(owned.item,pending.request_id),native);
    }, { evidenceLevel:"real-host", oracle:"public abandon refusal preserves actual pending CA request and protected native key" });
    const receipt = readEnrollmentJournal(configDir,id); assert.equal(receipt.kind,"valid");
    assert.equal(receipt.journal.containerName,container); assert.equal(String(receipt.journal.requestId),String(pending.request_id));
    const beforePid = Number(ps("(Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\").ProcessId")); assert.ok(beforePid>0);
    ps("Restart-Service -Name TokenTimerAgent -ErrorAction Stop");
    await until(()=> { const pid=Number(ps("(Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\").ProcessId")); return pid>0 && pid!==beforePid; });
    const after = readEnrollmentJournal(configDir,id); assert.equal(after.kind,"valid");
    for(const field of ["requestId","containerName","csrSha256","csrSpkiSha256","snapshotSha256"])assert.equal(after.journal[field],receipt.journal[field]);
    const now = new Date(new Date(pending.next_poll_at).getTime()+1000);
    const dispatched=(await Promise.all(Array.from({length:4},()=>scheduler.scheduleDueEnrollments({client:fixture.pool,now})))).flat().filter(row=>row.enrollmentId === id);
    assert.equal(dispatched.length,1,"Concurrent scheduler dispatch duplicated native continuation");
    await until(async()=> { const job=(await fixture.pool.query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,dispatched[0].jobId])).rows[0]; assert.ok(!["failed","rejected"].includes(job?.status)); return job?.status === "awaiting_issuer"; });
    assert.equal((await getEnrollment(id)).state,"pending_issuance");
    const unchanged=observe(owned.item,pending.request_id); assert.equal(unchanged.subjectRequestCount,native.subjectRequestCount); assert.equal(unchanged.disposition,9);
    assert.ok(command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(container));
    assert.equal((await fixture.request(`${api}/enrollments/${id}/cancel`,"POST",{})).status,204);
    const cleaned=(await scheduler.scheduleDueEnrollments({client:fixture.pool,now:new Date(Date.now()+30*86400000)})).find(row=>row.enrollmentId===id); assert.ok(cleaned);
    await jobFinished(cleaned.jobId); assert.equal((await getEnrollment(id)).state,"cancelled"); absent(owned.item,id,owned.site,owned.port);
  }, { evidenceLevel:"real-host", oracle:"actual SCM restart, persisted CSR/request identity, concurrent signed continuation and native CA request-count oracle" });

  await gate.scenario("adcs-real-installation-failure-audited-retry", async () => {
    const owned=pendingRecoveryFixtures.cancel; assert.ok(owned);
    const certificateId=crypto.randomUUID(); ownedCertificateIds.push(certificateId);
    const created=await fixture.request(`${api}/enrollments`,"POST",{issuerId:owned.issuerId,certificateId,agentId:agentRowId,
      target:{type:"windows-iis",reference:owned.item.domain,store:"My",binding:{site:owned.site,port:owned.port,sniHost:owned.item.domain}},
      authorizedDnsNames:[owned.item.domain],keyAlgorithm:"rsa",keySize:2048});assert.equal(created.status,201);
    const id=created.body.enrollmentId;ownedEnrollmentIds.push(id);
    const pending=await until(async()=>{const row=await getEnrollment(id);return row?.state==="pending_issuance"&&row.request_id?row:null;});
    const native=observe(owned.item,pending.request_id);assert.equal(native.disposition,9);
    const original=readEnrollmentJournal(configDir,id);assert.equal(original.kind,"valid");
    const physicalPath=ps(`Import-Module WebAdministration;[string](Get-Website -Name '${owned.site}').PhysicalPath`);
    assert.ok(path.resolve(physicalPath).startsWith(path.resolve(workDir)+path.sep),"Refusing to fault a foreign IIS site");
    let removed=false;
    try {
      // Only the exact already-owned site disappears. The CA request, CSR,
      // key, journal, database states and native CLI responses are untouched.
      ps(`Import-Module WebAdministration;Remove-Website -Name '${owned.site}';if(Test-Path 'IIS:\\Sites\\${owned.site}'){throw 'Owned fault site remains'}`);removed=true;
      command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.resolve(__dirname,"../../../infra/certops-adcs/officer-action.ps1"),"-RequestId",String(pending.request_id),"-Action","approve","-CommonName",owned.item.domain]);
      const dispatched=(await scheduler.scheduleDueEnrollments({client:fixture.pool,now:new Date(new Date(pending.next_poll_at).getTime()+1000)})).find(row=>row.enrollmentId===id);assert.ok(dispatched);
      await until(async()=>{const row=await getEnrollment(id);return row?.state==="install_failed";});
      const failed=readEnrollmentJournal(configDir,id);assert.equal(failed.kind,"valid");assert.equal(failed.journal.state,"install_failed");
      assert.equal(failed.journal.containerName,original.journal.containerName);assert.equal(failed.journal.csrSpkiSha256,original.journal.csrSpkiSha256);
      assert.ok(command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(original.journal.containerName));
      const noAutomaticRetry=await scheduler.scheduleDueEnrollments({client:fixture.pool,now:new Date(Date.now()+30*86400000)});
      assert.equal(noAutomaticRetry.filter(row=>row.enrollmentId===id).length,0);
    } finally {
      if(removed)ps(`Import-Module WebAdministration;if(Test-Path 'IIS:\\Sites\\${owned.site}'){throw 'Foreign site appeared during fault'};New-Website -Name '${owned.site}' -PhysicalPath '${physicalPath.replace(/'/g,"''")}' -IPAddress '*' -Port ${owned.port} -HostHeader '${owned.item.domain}' -Ssl|Out-Null;Set-WebBinding -Name '${owned.site}' -BindingInformation '*:${owned.port}:${owned.item.domain}' -PropertyName sslFlags -Value 1`);
    }
    const retries=await Promise.all(Array.from({length:4},()=>fixture.request(`${api}/enrollments/${id}/retry-installation`,"POST",{})));
    assert.equal(retries.filter(result=>result.status===201).length,1);
    for(const retry of retries)assert.ok([200,201].includes(retry.status));
    const jobId=retries.find(result=>result.status===201).body.jobId;assert.ok(retries.every(result=>result.body.jobId===jobId));
    await jobFinished(jobId);const installed=await getEnrollment(id);assert.equal(installed.state,"installed");assert.equal(String(installed.request_id),String(pending.request_id));
    const finalJournal=readEnrollmentJournal(configDir,id);assert.equal(finalJournal.kind,"valid");assert.equal(finalJournal.journal.state,"installed");
    for(const field of ["containerName","csrSha256","csrSpkiSha256","snapshotSha256","requestId"])assert.equal(finalJournal.journal[field],original.journal[field]);
    const finalNative=observe(owned.item,pending.request_id);assert.equal(finalNative.disposition,20);assert.equal(finalNative.subjectRequestCount,native.subjectRequestCount);
    const leaf=await new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port:owned.port,servername:owned.item.domain,ca:tlsAuthority(owned.authority),rejectUnauthorized:true},()=>{try{assert.equal(socket.authorized,true);resolve(new crypto.X509Certificate(socket.getPeerCertificate().raw));}catch(error){reject(error);}finally{socket.destroy();}});socket.setTimeout(10000,()=>socket.destroy(new Error("Trusted retry TLS oracle timed out")));socket.once("error",reject);});
    assert.equal(leaf.checkHost(owned.item.domain),owned.item.domain);ownedThumbprints.add(leaf.fingerprint.replace(/:/g,""));
    const audits=await fixture.pool.query("SELECT metadata FROM audit_events WHERE workspace_id=$1 AND action='certops.enrollment.installation_retry_requested' AND metadata->>'enrollmentId'=$2",[fixture.workspaceId,id]);assert.equal(audits.rows.length,1);assert.equal(audits.rows[0].metadata.jobId,jobId);
  },{evidenceLevel:"real-host",oracle:"actual owned IIS outage, protected accepted key, public audited retry, same CA RequestId/CSR and trusted restored IIS TLS"});
}
module.exports = { qualifyRecovery };
