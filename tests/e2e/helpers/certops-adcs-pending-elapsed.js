"use strict";
/* Opt-in one-hour AD CS qualification, called by the dedicated elapsed-pending
 * workflow through the installed SYSTEM-agent harness. It owns one public
 * enrollment on an already-owned IIS fixture, never alters clocks/journals/DB
 * dates, and revokes its late-issued CA leaf. Native execution is required;
 * portable report tests are not evidence that this scenario ran. */
const assert=require("node:assert/strict"),crypto=require("node:crypto"),fs=require("node:fs"),path=require("node:path"),tls=require("node:tls");
const {readEnrollmentJournal}=require("../../../packages/agent/src/issuers/adcs-enrollment");
const {buildEnrollmentContainerName}=require("../../../packages/agent/src/windows-cert-store");
async function qualifyPendingElapsed(context){
 const {gate,fixture,api,agentRowId,renewalFixture,configDir,preflight,command,ps,until,jobFinished,ownedEnrollmentIds,tlsAuthority,caConfig}=context;
 await gate.scenario("adcs-elapsed-pending-one-hour-terminal-cleanup",async()=>{
  assert.equal(process.platform,"win32");assert.equal(process.env.CERTOPS_ADCS_PENDING_ELAPSED,"1");assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB,"1");
  const root=path.resolve(__dirname,"../../.."),{item,site,port,certificateId,authority,observed}=renewalFixture;
  const file="tests/e2e/helpers/certops-adcs-pending-elapsed.js";gate.report.fixtureSources??=[];gate.report.fixtureSources.push({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")});
  const scheduler=require("../../../apps/api/services/certops/certificateEnrollments");
  const officer=(requestId,action)=>command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(root,"infra/certops-adcs/officer-action.ps1"),"-RequestId",String(requestId),"-Action",action,"-CommonName",item.domain]);
  const observe=requestId=>JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(root,"infra/certops-adcs/owned-request-observation.ps1"),"-CommonName",item.domain,"-RequestId",String(requestId)]));
  const served=()=>new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:item.domain,ca:tlsAuthority(authority)},()=>{try{assert.equal(socket.authorized,true);resolve(socket.getPeerCertificate().fingerprint256);}catch(error){reject(error);}finally{socket.destroy();}});socket.once("error",reject);socket.setTimeout(10000,()=>socket.destroy(new Error("Pending expiry TLS oracle timed out")));});
  const {issuerId,result}=await preflight("TTQualificationPending");assert.equal(result.templateCheck.verdict,"safe");assert.equal(result.caCheck.verdict,"safe");assert.equal((await fixture.request(`${api}/issuers/${issuerId}/confirm`,"POST",{caKeySha256:result.caCertificates[0].keySha256,caConfig,template:"TTQualificationPending"})).status,200);
  assert.equal(await served(),observed.fingerprint256);
  const created=await fixture.request(`${api}/enrollments`,"POST",{issuerId,certificateId,agentId:agentRowId,target:{type:"windows-iis",reference:item.domain,store:"My",binding:{site,port,sniHost:item.domain}},authorizedDnsNames:[item.domain],keyAlgorithm:"rsa",keySize:2048,pendingTimeout:3600,pollInterval:60});assert.equal(created.status,201);
  const id=created.body.enrollmentId;ownedEnrollmentIds.push(id);const container=buildEnrollmentContainerName(id);
  const row=async()=>(await fixture.pool.query("SELECT state,request_id,pending_since,next_poll_at,snapshot_bytes,snapshot_sha256,current_job_id,NOW() AS database_now FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,id])).rows[0];
  const pending=await until(async()=>{const value=await row();return value.state==="pending_issuance"&&value.request_id?value:null;});
  const snapshot=JSON.parse(Buffer.from(pending.snapshot_bytes).toString("utf8"));assert.equal(snapshot.pendingTimeout,3600);assert.equal(snapshot.pollInterval,60);
  const initial=readEnrollmentJournal(configDir,id);assert.equal(initial.kind,"valid");assert.equal(initial.journal.state,"pending_issuance");assert.equal(initial.journal.containerName,container);
  const native=observe(pending.request_id);assert.equal(native.disposition,9);
  const hasKey=()=>command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(container);
  assert.equal(hasKey(),true);const started=process.hrtime.bigint(),dbStarted=Date.parse(pending.database_now),pendingSince=Date.parse(pending.pending_since),credential=fs.readFileSync(path.join(configDir,"credential"));
  assert.ok(Number.isFinite(pendingSince));assert.ok(dbStarted>=pendingSince&&dbStarted-pendingSince<180000);
  const oldPid=Number(ps("(Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\").ProcessId"));assert.ok(oldPid>0);
  const restartMarker=(await fixture.pool.query("SELECT NOW() AS marker")).rows[0].marker;
  ps("Restart-Service TokenTimerAgent -ErrorAction Stop");await until(()=>{const pid=Number(ps("(Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\").ProcessId"));return pid>0&&pid!==oldPid;},30000);
  await until(async()=>(await fixture.pool.query("SELECT last_seen_at>$3 AS fresh FROM certops_agents WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,agentRowId,restartMarker])).rows[0]?.fresh,45000);assert.ok(fs.readFileSync(path.join(configDir,"credential")).equals(credential));
  let signedCleanupJob;const elapsed=()=>Number(process.hrtime.bigint()-started)/1e9;
  const unchanged=journal=>{for(const field of ["containerName","csrSha256","csrSpkiSha256","snapshotSha256","requestId"])assert.equal(journal[field],initial.journal[field]);};
  while(elapsed()<3600){
   const current=await row();assert.equal(current.snapshot_sha256,pending.snapshot_sha256);assert.equal(Date.parse(current.pending_since),pendingSince);assert.equal(String(current.request_id),String(pending.request_id));unchanged(readEnrollmentJournal(configDir,id).journal);
   // Expiry is determined by the real server clock, which can precede our
   // conservative monotonic observation window by the initial polling delay.
   if(Date.parse(current.database_now)<pendingSince+3600000){assert.equal(current.state,"pending_issuance");assert.equal(hasKey(),true);}
   const jobs=await scheduler.scheduleDueEnrollments({client:fixture.pool});
   const after=await row();if(after.state==="expired")signedCleanupJob=jobs.find(job=>job.enrollmentId===id)?.jobId||signedCleanupJob;
   await new Promise(resolve=>setTimeout(resolve,15000));
  }
  const terminal=await until(async()=>{const jobs=await scheduler.scheduleDueEnrollments({client:fixture.pool});const current=await row();if(current.state==="expired"){signedCleanupJob=jobs.find(job=>job.enrollmentId===id)?.jobId||signedCleanupJob||current.current_job_id;return current;}return null;},180000);
  assert.ok(signedCleanupJob);await jobFinished(signedCleanupJob);assert.ok(Date.parse(terminal.database_now)-pendingSince>=3600000);assert.ok(Date.parse(terminal.database_now)-dbStarted>=3600000);
  const noAcceptance=()=>assert.equal(ps(`@(Get-ChildItem Cert:\\LocalMachine\\My,Cert:\\LocalMachine\\WebHosting -ErrorAction SilentlyContinue | Where-Object Subject -eq 'CN=${item.domain}' | Where-Object Thumbprint -ne '${renewalFixture.thumbprint}').Count`),"0");
  assert.equal(hasKey(),false);noAcceptance();
  assert.equal(observe(pending.request_id).subjectRequestCount,native.subjectRequestCount);assert.equal(await served(),observed.fingerprint256);
  let issued=false,primary;try{
   issued=true;officer(pending.request_id,"approve");await until(()=>observe(pending.request_id).disposition===20);
   const refusal=await fixture.request(`${api}/enrollments/${id}/reconcile`,"POST",{requestId:Number(pending.request_id)});assert.equal(refusal.status,400);assert.equal(refusal.body.code,"CERTOPS_ENROLLMENT_TRANSITION_INVALID");
   for(let n=0;n<3;n++)assert.equal((await scheduler.scheduleDueEnrollments({client:fixture.pool})).filter(job=>job.enrollmentId===id).length,0);
   assert.equal((await row()).state,"expired");assert.equal(hasKey(),false);noAcceptance();assert.equal(observe(pending.request_id).subjectRequestCount,native.subjectRequestCount);assert.equal(await served(),observed.fingerprint256);
  }catch(error){primary=error;throw error;}finally{if(issued){try{if(observe(pending.request_id).disposition===20){officer(pending.request_id,"revoke");assert.equal(observe(pending.request_id).disposition,21);}}catch(error){if(primary)throw new AggregateError([primary,error],"Elapsed pending case and owned late-issued certificate cleanup failed");throw error;}}}
  gate.report.nativePendingElapsed={pendingTimeoutSeconds:3600,pollIntervalSeconds:60,monotonicWaitSeconds:elapsed(),databaseElapsedSeconds:(Date.parse(terminal.database_now)-dbStarted)/1000,pendingSince:new Date(pendingSince).toISOString(),requestId:String(pending.request_id),snapshotSha256:pending.snapshot_sha256,clocks:"actual-host-and-database",schedulerClock:"default-real-now",databaseDatesRewritten:false,journalRewritten:false,snapshotAndCsrStableAcrossRestart:true,keyProtectedBeforeDeadline:true,signedTerminalCleanup:true,exactKeyAbsent:true,noCertificateAccepted:true,noCaResubmission:true,lateApprovalTerminalRefusal:true,lateIssuedCertificateRevoked:true,outgoingTrustedTlsUnchanged:true,qualificationScope:"configured-one-hour-not-default-fourteen-days"};
 },{evidenceLevel:"real-host",oracle:"actual hour elapsed, held CA request, production scheduler clock, installed SYSTEM signed cleanup, late CA approval terminal refusal and trusted TLS"});
}
module.exports={qualifyPendingElapsed};
