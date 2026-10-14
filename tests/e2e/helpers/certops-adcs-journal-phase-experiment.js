"use strict";
/* Opt-in observed-phase crash experiment, not release qualification. Stops only verified owned
 * service descendants after real journal phase observation, waits genuine lease expiry and uses
 * audited public recovery. Called only by the protected disposable-forest AD CS harness; native
 * qualification requires that workflow to execute.
 */
const assert=require("node:assert/strict");
const fs=require("node:fs");
const path=require("node:path");
const crypto=require("node:crypto");
const net=require("node:net");
const tls=require("node:tls");
const {pathToFileURL}=require("node:url");
const {buildEnrollmentContainerName}=require("../../../packages/agent/src/windows-cert-store");
const {readEnrollmentJournal}=require("../../../packages/agent/src/issuers/adcs-enrollment");
const startObserver=require("./certops-adcs-journal-phase");
module.exports=async function runJournalPhaseExperiment(context){
  const phase=process.env.CERTOPS_ADCS_JOURNAL_PHASE_EXPERIMENT;if(!phase)return;
  assert.ok(["keygen_intent","prepared","submitting","installing"].includes(phase));assert.equal(process.platform,"win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB,"1");assert.equal(process.env.CERTOPS_JOB_LEASE_SECONDS,"60");
  assert.equal(context.serviceOwned,true);
  assert.equal(process.env.CERTOPS_LEASE_HARD_GRACE_MS,"60000");
  const {fixture,api,agentRowId,configDir,workDir,run,preflight,jobFinished,until,ps,command,
    ownedSites,ownedCertificateIds,ownedEnrollmentIds,ownedThumbprints,tlsAuthority,gate}=context;
  const repoRoot=path.resolve(__dirname,"../../..");
  const domain=`certops-adcs-${run}-journal.example.test`;const site=`TTADCS-${run}-journal`;
  const report={schemaVersion:1,scope:"enterprise-adcs-journal-phase-experimental",qualificationStatus:"not-qualified",candidateSha:process.env.GITHUB_SHA,
    phase,status:"running",fixtureSource:{file:"tests/e2e/helpers/certops-adcs-journal-phase-experiment.js",sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")},
    qualificationEnvironment:gate.report.qualificationEnvironment,leaseSeconds:60,hardGraceMs:60000,clocks:"actual-host-and-database",databasePhaseRewritten:false,journalRewritten:false};
  let observer,enrollmentId,serviceStopped=false,primaryError,recoveryPolicy;
  const reportPath=process.env.CERTOPS_ADCS_JOURNAL_PHASE_REPORT || "C:\\ttqualification\\journal-phase-experimental.json";
  const getJob=async id=>(await fixture.pool.query("SELECT status,error_message,lease_expires_at,lease_renewed_at,needs_operator_reconciliation FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,id])).rows[0];
  const getEnrollment=async()=> (await fixture.pool.query("SELECT state,request_id,next_poll_at FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,enrollmentId])).rows[0];
  const observe=()=>JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.resolve(repoRoot,"infra/certops-adcs/owned-request-observation.ps1"),"-CommonName",domain,"-Discover"]));
  try{
    assert.equal(observe().subjectRequestCount,0);
    const {issuerId,result}=await preflight("TTQualificationRSAShort");assert.equal(result.templateCheck.verdict,"safe");assert.equal(result.caCheck.verdict,"safe");
    const authority=result.caCertificates[0];assert.equal((await fixture.request(`${api}/issuers/${issuerId}/confirm`,"POST",{caKeySha256:authority.keySha256,caConfig:context.caConfig,template:"TTQualificationRSAShort"})).status,200);
    const port=await new Promise((resolve,reject)=>{const server=net.createServer();server.once("error",reject);server.listen(0,"127.0.0.1",()=>{const selected=server.address().port;server.close(error=>error?reject(error):resolve(selected));});});
    const directory=path.join(workDir,site);fs.mkdirSync(directory);fs.writeFileSync(path.join(directory,"index.html"),"Observed native journal recovery");
    ps(`Import-Module WebAdministration;if(Test-Path 'IIS:\\Sites\\${site}'){throw 'Foreign fault site'};& netsh.exe http show sslcert hostnameport=${domain}:${port}|Out-Null;if($LASTEXITCODE -eq 0){throw 'Foreign fault endpoint'}`);
    ownedSites.push(site);ps(`Import-Module WebAdministration;New-Website -Name '${site}' -PhysicalPath '${directory.replace(/'/g,"''")}' -IPAddress '*' -Port ${port} -HostHeader '${domain}' -Ssl|Out-Null;Set-WebBinding -Name '${site}' -BindingInformation '*:${port}:${domain}' -PropertyName sslFlags -Value 1`);
    recoveryPolicy=JSON.parse(ps(`$r=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent');try{$owner=@($r.GetValue('Environment')|Where-Object {$_ -like 'TOKENTIMER_AGENT_CONFIG_DIR=*'});if($owner.Count -ne 1 -or $owner[0].Substring('TOKENTIMER_AGENT_CONFIG_DIR='.Length) -ine '${configDir.replace(/'/g,"''")}'){throw 'Foreign recovery policy'};$v=$r.GetValue('FailureActions');if($v -isnot [byte[]]){throw 'Native failure policy missing'};@{actions=[Convert]::ToBase64String($v);nonCrash=$r.GetValue('FailureActionsOnNonCrashFailures',$null)}|ConvertTo-Json -Compress}finally{$r.Dispose()}`));
    command("sc.exe",["failure","TokenTimerAgent","reset=","0","actions=",""]);report.ownedScmRecoveryTemporarilyDisabled=true;
    observer=startObserver({ownedDirectory:workDir,configDirectory:configDir,repositoryRoot:repoRoot,phase});await observer.ready;
    const certificateId=crypto.randomUUID();ownedCertificateIds.push(certificateId);
    const created=await fixture.request(`${api}/enrollments`,"POST",{issuerId,certificateId,agentId:agentRowId,target:{type:"windows-iis",reference:domain,store:"My",binding:{site,port,sniHost:domain}},authorizedDnsNames:[domain],keyAlgorithm:"rsa",keySize:2048});assert.equal(created.status,201);
    enrollmentId=created.body.enrollmentId;ownedEnrollmentIds.push(enrollmentId);
    fs.writeFileSync(path.join(workDir,"journal-phase-target.json"),JSON.stringify({enrollmentId,jobId:created.body.jobId,snapshotSha256:created.body.snapshotSha256,containerName:buildEnrollmentContainerName(enrollmentId)}));
    report.fault=await observer.result;serviceStopped=true;
    assert.equal(report.fault.enrollmentId,enrollmentId);assert.equal(report.fault.jobId,created.body.jobId);
    await until(()=>ps("(Get-Service TokenTimerAgent).Status")==="Stopped",30000);
    const stoppedJournal=readEnrollmentJournal(configDir,enrollmentId);assert.equal(stoppedJournal.kind,"valid");assert.equal(stoppedJournal.journal.state,phase);
    assert.equal(stoppedJournal.journal.containerName,buildEnrollmentContainerName(enrollmentId));assert.equal(stoppedJournal.journal.snapshotSha256,created.body.snapshotSha256);
    const nativeAtFault=observe();report.caRequestsAtFault=nativeAtFault.subjectRequestCount;
    assert.ok((await getJob(created.body.jobId)).lease_renewed_at,"Observed native fault requires an actual renewed lease");report.actualRenewedLeaseObserved=true;
    const worker=await import(pathToFileURL(path.join(repoRoot,"apps/worker/src/certops-worker.js")).href);
    await until(async()=>{const client=await fixture.pool.connect();try{await worker.reapExpiredLeases({client,hardGraceMs:60000,offlineAfterMs:60000,log:{debug(){},info(){},warn(){},error(){}}});}finally{client.release();}const job=await getJob(created.body.jobId);return job?.status==="orphaned_unknown_effect"&&job.needs_operator_reconciliation===true;},180000);
    report.actualOrphanedJobObserved=true;
    const recovery=await fixture.request(`${api}/enrollments/${enrollmentId}/recover`,"POST",{orphanedJobId:created.body.jobId,acknowledgeUnknownEffect:true,reason:`Disposable qualification inspected native ${phase} journal and stopped its exact service tree; resume only this frozen enrollment`});assert.equal(recovery.status,201);
    ps("Start-Service TokenTimerAgent -ErrorAction Stop");serviceStopped=false;await until(()=>ps("(Get-Service TokenTimerAgent).Status")==="Running",30000);
    if(phase==="keygen_intent"){
      assert.equal(report.fault.actualCertreqNewObserved,true);assert.equal(report.fault.nonExportableOwnedKeyObserved,true);
      assert.equal(stoppedJournal.artifacts.csrPem,null);assert.equal(nativeAtFault.subjectRequestCount,0);
      const refused=await until(async()=>{const row=await getJob(recovery.body.jobId);return ["blocked","failed"].includes(row?.status)?row:null;});assert.ok(["blocked","failed"].includes(refused.status));assert.match(refused.error_message,/ADCS_RECOVERY_CSR_REQUIRED/);
      const unchanged=readEnrollmentJournal(configDir,enrollmentId);assert.equal(unchanged.kind,"valid");assert.equal(unchanged.journal.state,"keygen_intent");assert.equal(unchanged.journal.containerName,stoppedJournal.journal.containerName);assert.equal(unchanged.artifacts.csrPem,null);
      const key=ps(`$key=[Security.Cryptography.CngKey]::Open('${stoppedJournal.journal.containerName}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey);try{if($key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None){throw 'Recovered intent key is exportable'};$key.KeyName}finally{$key.Dispose()}`);assert.equal(key,stoppedJournal.journal.containerName);
      assert.equal(observe().subjectRequestCount,0);report.preCsrRecoveryRefused=true;report.ownedProtectedKeyPreserved=true;report.durableCsrAbsent=true;
      assert.equal((await fixture.request(`${api}/enrollments/${enrollmentId}/cancel`,"POST",{})).status,204);
      const cleaned=(await require("../../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments({client:fixture.pool,now:new Date(Date.now()+1000)})).find(row=>row.enrollmentId===enrollmentId);assert.ok(cleaned);await jobFinished(cleaned.jobId);
      assert.ok(!command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(stoppedJournal.journal.containerName));
      report.outcome="pre-csr-recovery-refused-owned-key-cancelled";report.cancelledKeyAbsent=true;report.caRequestsAfterRecovery=0;
    }else if(phase==="submitting"){
      await until(async()=> (await getEnrollment())?.state==="submission_uncertain");
      const recovered=readEnrollmentJournal(configDir,enrollmentId);assert.equal(recovered.kind,"valid");assert.equal(recovered.journal.state,"submission_uncertain");
      const native=observe();assert.equal(native.subjectRequestCount,nativeAtFault.subjectRequestCount,"Uncertain recovery submitted another CA request");
      report.uncertainNoResubmitVerified=true;
      if(native.subjectRequestCount===0){
        assert.equal((await fixture.request(`${api}/enrollments/${enrollmentId}/abandon`,"POST",{})).status,204);
        const cleaned=(await require("../../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments({client:fixture.pool,now:new Date(Date.now()+1000)})).find(row=>row.enrollmentId===enrollmentId);assert.ok(cleaned);await jobFinished(cleaned.jobId);
        assert.ok(!command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(stoppedJournal.journal.containerName));
        report.outcome="uncertain-no-resubmit-abandoned-with-absent-key";report.caRequestsAfterRecovery=0;
        report.abandonedKeyAbsent=true;
      }else{
        assert.equal(native.subjectRequestCount,1);
        assert.equal((await fixture.request(`${api}/enrollments/${enrollmentId}/reconcile`,"POST",{requestId:native.requestId})).status,204);
        const dispatched=(await require("../../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments({client:fixture.pool,now:new Date(Date.now()+1000)})).find(row=>row.enrollmentId===enrollmentId);assert.ok(dispatched);await jobFinished(dispatched.jobId);report.outcome="uncertain-no-resubmit-operator-reconciled";
      }
    }else{await jobFinished(recovery.body.jobId);report.outcome="same-key-installation-recovered";}
    if(!["uncertain-no-resubmit-abandoned-with-absent-key","pre-csr-recovery-refused-owned-key-cancelled"].includes(report.outcome)){
      const installed=await getEnrollment();assert.equal(installed.state,"installed");
      const journal=readEnrollmentJournal(configDir,enrollmentId);assert.equal(journal.kind,"valid");assert.equal(journal.journal.containerName,stoppedJournal.journal.containerName);
      for(const field of ["csrSha256","csrSpkiSha256","snapshotSha256"])assert.equal(journal.journal[field],stoppedJournal.journal[field]);
      report.sameKeyAndCsrIdentityPreserved=true;
      const native=observe();assert.equal(native.subjectRequestCount,1);assert.equal(String(native.requestId),String(installed.request_id));report.caRequestsAfterRecovery=1;
      if(phase==="installing")assert.equal(String(installed.request_id),String(stoppedJournal.journal.requestId));
      const leaf=await new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:domain,ca:tlsAuthority(authority),rejectUnauthorized:true},()=>{try{assert.equal(socket.authorized,true);resolve(new crypto.X509Certificate(socket.getPeerCertificate().raw));}catch(error){reject(error);}finally{socket.destroy();}});socket.setTimeout(10000,()=>socket.destroy(new Error("Recovered trusted native TLS timed out")));socket.once("error",reject);});assert.equal(leaf.checkHost(domain),domain);ownedThumbprints.add(leaf.fingerprint.replace(/:/g,""));report.trustedNativeTls=true;
    }
    const audits=(await fixture.pool.query("SELECT metadata FROM audit_events WHERE workspace_id=$1 AND action='certops.enrollment.recovery_requested' AND metadata->>'enrollmentId'=$2",[fixture.workspaceId,enrollmentId])).rows;
    assert.equal(audits.length,1);assert.equal(audits[0].metadata.orphanedJobId,created.body.jobId);assert.equal(audits[0].metadata.acknowledgeUnknownEffect,true);report.operatorRecoveryAuditObserved=true;
    const original=await getJob(created.body.jobId);assert.equal(original.status,"orphaned_unknown_effect");assert.equal(original.needs_operator_reconciliation,true);report.originalUnknownEffectEvidencePreserved=true;
    report.status="passed";
  }catch(error){primaryError=error;report.status="failed";report.errorClass=error?.constructor?.name || "Error";throw error;}
  finally{
    observer?.stop();const cleanup=[];
    try{if(recoveryPolicy){ps(`$r=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent');try{$owner=@($r.GetValue('Environment')|Where-Object {$_ -like 'TOKENTIMER_AGENT_CONFIG_DIR=*'});if($owner.Count -ne 1 -or $owner[0].Substring('TOKENTIMER_AGENT_CONFIG_DIR='.Length) -ine '${configDir.replace(/'/g,"''")}'){throw 'Foreign recovery restore'}}finally{$r.Dispose()}`);command("sc.exe",["failure","TokenTimerAgent","reset=","86400","actions=","restart/5000"]);const restored=JSON.parse(ps(`$r=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent');try{@{actions=[Convert]::ToBase64String($r.GetValue('FailureActions'));nonCrash=$r.GetValue('FailureActionsOnNonCrashFailures',$null)}|ConvertTo-Json -Compress}finally{$r.Dispose()}`));assert.deepEqual(restored,recoveryPolicy,"Owned SCM recovery policy did not restore exact installer bytes");report.ownedScmRecoveryRestored=true;}}catch(error){cleanup.push(error);}
    try{if(serviceStopped||ps("(Get-Service TokenTimerAgent).Status")==="Stopped")ps("Start-Service TokenTimerAgent -ErrorAction Stop");}catch(error){cleanup.push(error);}
    // Every certificate for this unique name must carry this exact owned key.
    // Track its public thumbprint even when delivery failed before the TLS oracle.
    try{if(enrollmentId){const container=buildEnrollmentContainerName(enrollmentId);const thumbs=ps(`$matches=@();Get-ChildItem Cert:\\LocalMachine\\My|Where-Object Subject -eq 'CN=${domain}'|ForEach-Object{$c=$_;$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);if(-not $k -or $k.Key.KeyName -ne '${container}'){throw 'Foreign certificate under owned fault name'};$matches+=$c.Thumbprint}finally{if($k){$k.Dispose()};$c.Dispose()}};$matches|ConvertTo-Json -Compress`);if(thumbs){const parsed=JSON.parse(thumbs);for(const thumb of Array.isArray(parsed)?parsed:[parsed]){assert.match(thumb,/^[A-F0-9]{40}$/);ownedThumbprints.add(thumb);}}}}catch(error){cleanup.push(error);}
    if(cleanup.length){report.status="failed";report.cleanupFailed=true;}
    try{fs.mkdirSync(path.dirname(reportPath),{recursive:true});fs.writeFileSync(reportPath,JSON.stringify(report,null,2));}catch(error){cleanup.push(error);}
    if(cleanup.length)throw new AggregateError([...(primaryError?[primaryError]:[]),...cleanup],"Native journal experiment and finalization failed");
  }
};
