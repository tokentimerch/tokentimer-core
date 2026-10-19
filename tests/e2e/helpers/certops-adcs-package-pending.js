"use strict";
// Manager approval through the installed package and deployed production worker.
// The public API creates state; SQL only observes it. No scheduler invocation,
// clock override, fabricated lease or journal edit can complete this journey.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const tls = require("node:tls");
const { readEnrollmentJournal } = require("../../../packages/agent/src/issuers");
const SCENARIO = "adcs-package-approved-request-production-worker-continuation";
function verifyProof(proof) {
  assert.equal(proof.scheduler,"deployed-production-runner"); assert.equal(proof.pollIntervalSeconds,60);
  for(const field of ["enrollmentId","initialJobId","continuationJobId"])assert.match(proof[field],/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  assert.notEqual(proof.initialJobId,proof.continuationJobId);
  assert.match(proof.requestId,/^[1-9][0-9]{0,9}$/); assert.ok(Number(proof.requestId)<=0xffffffff);
  for(const field of ["actualManagerApproval","claimBoundContinuation","originalCsrKeyAndSnapshotPreserved","trustedIisCutover","noSchedulerOrClockOverride"])assert.equal(proof[field],true);
  return true;
}
async function qualifyPackagePending({ gate, fixture, api, agentRowId, configDir, domain, site,
  port, authority, until, command, ownedEnrollmentIds, ownedThumbprints }) {
  const root = path.resolve(__dirname, "../../..");
  const file = "tests/e2e/helpers/certops-adcs-package-pending.js";
  gate.report.fixtureSources ??= [];
  gate.report.fixtureSources.push({file, sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")});
  const query = (sql, args) => fixture.pool.query(sql, args);
  const peer = () => new Promise((resolve, reject) => {
    const socket = tls.connect({host:"127.0.0.1",port,servername:domain,ca:authority.toString(),rejectUnauthorized:true},()=>{
      try { assert.equal(socket.authorized,true); resolve(new crypto.X509Certificate(socket.getPeerCertificate().raw)); }
      catch(error) { reject(error); } finally { socket.destroy(); }
    });
    socket.once("error",reject); socket.setTimeout(10000,()=>socket.destroy(new Error("Package pending TLS observation timed out")));
  });
  await gate.scenario(SCENARIO, async () => {
    const browser = gate.report.nativeBrowserAdcs; assert.ok(browser?.enrollmentId); assert.ok(browser.profileId);
    // This profile was created by this acceptance pass. Suspend its repeated
    // fresh renewals while testing one manager-approved continuation.
    assert.equal((await fixture.request(`${api}/profiles/${browser.profileId}`,"PATCH",{autoRenewEnabled:false})).status,200);
    const source = (await query("SELECT certificate_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,browser.enrollmentId])).rows[0]; assert.ok(source?.certificate_id);
    await until(async()=>Number((await query("SELECT count(*)::int AS count FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 AND status IN ('pending','pending_approval','approved','claimed','running')",[fixture.workspaceId,source.certificate_id])).rows[0].count)===0);
    const previous = await peer();
    const before=JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(root,"infra/certops-adcs/owned-request-observation.ps1"),"-CommonName",domain,"-RequestId",browser.requestId]));
    const createdIssuer = await fixture.request(`${api}/issuers`,"POST",{kind:"adcs",name:`package-pending-${crypto.randomUUID()}`}); assert.equal(createdIssuer.status,201);
    const issuerId=createdIssuer.body.issuer.id, caConfig="tt-ca.lab.certops.test\\TTQualificationRoot", template="TTQualificationPending";
    const preflight=await fixture.request(`${api}/issuers/${issuerId}/preflight`,"POST",{agentId:agentRowId,caConfig,template}); assert.equal(preflight.status,201);
    await until(async()=>{const row=(await fixture.request(`${api}/jobs/${preflight.body.job.id}`)).body.job; assert.ok(!["failed","rejected","cancelled"].includes(row?.status)); return row?.status==="succeeded";});
    const pin=crypto.createHash("sha256").update(authority.publicKey.export({type:"spki",format:"der"})).digest("hex");
    assert.equal((await fixture.request(`${api}/issuers/${issuerId}/confirm`,"POST",{caKeySha256:pin,caConfig,template})).status,200);
    const created=await fixture.request(`${api}/enrollments`,"POST",{issuerId,certificateId:source.certificate_id,agentId:agentRowId,
      target:{type:"windows-iis",reference:domain,store:"My",binding:{site,port,sniHost:domain}},authorizedDnsNames:[domain],keyAlgorithm:"rsa",keySize:2048,pollInterval:60});
    assert.equal(created.status,201); const enrollmentId=created.body.enrollmentId; ownedEnrollmentIds.push(enrollmentId);
    const enrollment=async()=> (await query("SELECT state,request_id,current_job_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,enrollmentId])).rows[0];
    const pending=await until(async()=>{const row=await enrollment();return row?.state==="pending_issuance"&&row.request_id?row:null;});
    const original=readEnrollmentJournal(configDir,enrollmentId); assert.equal(original.kind,"valid");
    assert.equal((await peer()).fingerprint256,previous.fingerprint256);
    command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(root,"infra/certops-adcs/officer-action.ps1"),"-CommonName",domain,"-RequestId",String(pending.request_id),"-Action","approve"]);
    // Wait for normal wall-clock eligibility and the deployed scheduler. There
    // is deliberately no direct scheduleDueEnrollments call in this lane.
    const installed=await until(async()=>{const row=await enrollment(); assert.ok(!["denied","expired","cancelled","rejected_invalid","install_failed"].includes(row?.state)); return row?.state==="installed"?row:null;},300000);
    assert.equal(String(installed.request_id),String(pending.request_id)); assert.notEqual(installed.current_job_id,created.body.jobId);
    const job=(await query("SELECT status,claim_id,enrollment_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,installed.current_job_id])).rows[0];
    assert.equal(job.status,"succeeded"); assert.ok(job.claim_id); assert.equal(job.enrollment_id,enrollmentId);
    const final=readEnrollmentJournal(configDir,enrollmentId); assert.equal(final.kind,"valid"); assert.equal(final.journal.state,"installed");
    for(const field of ["containerName","csrSha256","csrSpkiSha256","snapshotSha256"])assert.equal(final.journal[field],original.journal[field]);
    const leaf=await peer(); assert.equal(leaf.checkHost(domain),domain); assert.notEqual(leaf.fingerprint256,previous.fingerprint256);
    assert.equal(crypto.createHash("sha256").update(leaf.publicKey.export({type:"spki",format:"der"})).digest("hex"),original.journal.csrSpkiSha256);
    ownedThumbprints.add(leaf.fingerprint.replace(/:/g,""));
    const native=JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(root,"infra/certops-adcs/owned-issued-request.ps1"),"-CommonName",domain,"-FingerprintSha256",leaf.fingerprint256.replace(/:/g,"").toLowerCase()]));
    assert.equal(String(native.requestId),String(pending.request_id)); assert.equal(native.disposition,20);
    assert.equal(native.subjectRequestCount,before.subjectRequestCount+1,"Worker continuations must retrieve the original request without another CA submission");
    gate.report.packagePendingWorker={enrollmentId,initialJobId:created.body.jobId,continuationJobId:installed.current_job_id,requestId:String(pending.request_id),
      scheduler:"deployed-production-runner",pollIntervalSeconds:60,actualManagerApproval:true,claimBoundContinuation:true,originalCsrKeyAndSnapshotPreserved:true,trustedIisCutover:true,noSchedulerOrClockOverride:true};
    verifyProof(gate.report.packagePendingWorker);
  },{evidenceLevel:"real-host",oracle:"Installed candidate package receives manager-pending request; real CA officer approval and production scheduler wall-clock continuation install the original CSR/key into verified trusted IIS TLS"});
}
module.exports={SCENARIO,qualifyPackagePending,verifyProof};
