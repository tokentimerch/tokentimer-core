"use strict";
// Shared actual-agent lost-response recovery experiment. Full and scoped runners
// retain the same native interruption, candidate ambiguity and exact-key oracle.
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto"),tls=require("node:tls");
const SOURCE="tests/e2e/helpers/certops-adcs-response-loss-experiment.js";
module.exports=async function runResponseLossExperiment(context){
 assert.equal(process.platform,"win32");assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB,"1");assert.equal(context.serviceOwned,true);
 const {fixture,api,caConfig,agentRowId,configDir,workDir,run,preflight,jobFinished,until,ps,command,ownedSites,ownedCertificateIds,ownedEnrollmentIds,ownedThumbprints,gate,freePort,faultDomain,foreignRequestId,ownedPhaseObservers}=context;
 assert.match(faultDomain,/^certops-adcs-[a-f0-9]+-fault\.example\.test$/);assert.ok(Number.isInteger(Number(foreignRequestId))&&Number(foreignRequestId)>0&&Number(foreignRequestId)<=0xffffffff);
      // Experimental fault timing is deliberately outside the release qualification scenario set.
      const experiment={schemaVersion:1,scope:"enterprise-adcs-response-loss-experimental",qualificationStatus:"not-qualified",candidateSha:process.env.GITHUB_SHA,fixtureSource:{file:SOURCE,sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")},qualificationEnvironment:gate.report.qualificationEnvironment,status:"running"};
      const experimentPath=path.join(workDir,"response-loss-experimental.json");
      let controller;
      try{
        const {issuerId,result}=await preflight("TTQualificationPending");assert.equal(result.templateCheck.verdict,"safe");
        assert.equal((await fixture.request(`${api}/issuers/${issuerId}/confirm`,"POST",{caKeySha256:result.caCertificates[0].keySha256,caConfig,template:"TTQualificationPending"})).status,200);
        const site=`TTADCS-${run}-fault`;const port=await freePort();const directory=path.join(workDir,"fault");fs.mkdirSync(directory);fs.writeFileSync(path.join(directory,"index.html"),"fault");ownedSites.push(site);
        ps(`Import-Module WebAdministration;New-Website -Name '${site}' -PhysicalPath '${directory.replace(/'/g,"''")}' -IPAddress '*' -Port ${port} -HostHeader '${faultDomain}' -Ssl | Out-Null;Set-WebBinding -Name '${site}' -BindingInformation '*:${port}:${faultDomain}' -PropertyName sslFlags -Value 1`);
        controller=require("./certops-adcs-response-loss")({commonName:faultDomain,ownedDirectory:workDir});ownedPhaseObservers.push(controller);
        await controller.ready;
        const certificateId=await require("./certops-adcs-local-rules").provisionSurvivorSource({fixture,agentRowId,domain:faultDomain,site,port,ownedCertificateIds});
        const created=await fixture.request(`${api}/enrollments`,"POST",{issuerId,certificateId,agentId:agentRowId,target:{type:"windows-iis",reference:faultDomain,store:"My",binding:{site,port,sniHost:faultDomain}},authorizedDnsNames:[faultDomain],keyAlgorithm:"rsa",keySize:2048});assert.equal(created.status,201);ownedEnrollmentIds.push(created.body.enrollmentId);
        experiment.fault=await controller.result;
        await until(async()=> (await fixture.pool.query("SELECT state FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,created.body.enrollmentId])).rows[0]?.state === "submission_uncertain");
        const originalContainer=require("../../../packages/agent/src/windows-cert-store").buildEnrollmentContainerName(created.body.enrollmentId);
        assert.ok(command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(originalContainer),"Uncertain submission must retain its exact native CNG key");
        command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.resolve(__dirname,"../../../infra/certops-adcs/officer-action.ps1"),"-RequestId",String(experiment.fault.requestId),"-Action","approve","-CommonName",faultDomain]);
        experiment.candidateSearch=await require("./certops-adcs-response-loss-candidates").qualifyResponseLossCandidates({fixture,api,gate,configDir,workDir,enrollmentId:created.body.enrollmentId,domain:faultDomain,authority:result.caCertificates[0],requestId:experiment.fault.requestId,command});
        assert.ok(foreignRequestId);assert.notEqual(String(foreignRequestId),String(experiment.fault.requestId));
        assert.equal((await fixture.request(`${api}/enrollments/${created.body.enrollmentId}/reconcile`,"POST",{requestId:foreignRequestId})).status,204);
        const scheduler=require("../../../apps/api/services/certops/certificateEnrollments");
        const foreignDispatch=(await scheduler.scheduleDueEnrollments({client:fixture.pool})).find(row=>row.enrollmentId===created.body.enrollmentId);assert.ok(foreignDispatch);
        await until(async()=>{const row=(await fixture.pool.query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,foreignDispatch.jobId])).rows[0];if(row.status === "succeeded")throw new Error("Foreign CA RequestId incorrectly installed another enrollment's material");return row.status === "failed";});
        assert.equal((await fixture.pool.query("SELECT state FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,created.body.enrollmentId])).rows[0].state,"submission_uncertain");
        assert.equal(ps(`@(Get-ChildItem Cert:\\LocalMachine\\My | Where-Object Subject -eq 'CN=${faultDomain}').Count`),"0");
        assert.ok(command("certutil.exe",["-csp","Microsoft Software Key Storage Provider","-key"]).includes(originalContainer),"Foreign reconciliation candidate must preserve the owned key");
        experiment.foreignRequestRefused=true;
        assert.equal((await fixture.request(`${api}/enrollments/${created.body.enrollmentId}/reconcile`,"POST",{requestId:experiment.fault.requestId})).status,204);
        const scheduled=await require("../../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments({client:fixture.pool});const continuation=scheduled.find(row=>row.enrollmentId===created.body.enrollmentId);assert.ok(continuation);await jobFinished(continuation.jobId);
        const raw=await new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:faultDomain,ca:new crypto.X509Certificate(Buffer.from(result.caCertificates[0].certificateB64,"base64")).toString()},()=>{resolve(socket.getPeerCertificate().raw);socket.end();});socket.setTimeout(10000,()=>socket.destroy(new Error("Independent domain IIS TLS oracle timed out")));socket.on("error",reject);});assert.equal(new crypto.X509Certificate(raw).checkHost(faultDomain),faultDomain);const recoveredThumbprint=crypto.createHash("sha1").update(raw).digest("hex").toUpperCase();ownedThumbprints.add(recoveredThumbprint);
        assert.equal(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${recoveredThumbprint}';$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);try{if($k.Key.KeyName -ne '${originalContainer}' -or $k.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None){throw 'Recovery replaced or exposed original owned key'};'same-nonexportable-cng'}finally{$k.Dispose()}`),"same-nonexportable-cng");experiment.recoveredOwnedKey=true;
        assert.equal(JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.resolve(__dirname,"../../../infra/certops-adcs/owned-request-observation.ps1"),"-CommonName",faultDomain,"-RequestId",String(experiment.fault.requestId)])).subjectRequestCount,2,"Only the original lost response and explicit operator ambiguity fixture may allocate CA requests");
        const recoveredJournal=require("../../../packages/agent/src/issuers").readEnrollmentJournal(configDir,created.body.enrollmentId);assert.equal(recoveredJournal.kind,"valid");assert.equal(recoveredJournal.journal.state,"installed");assert.equal(recoveredJournal.journal.csrSha256,experiment.candidateSearch.originalCsrSha256);assert.equal(recoveredJournal.journal.csrSpkiSha256,experiment.candidateSearch.originalSpkiSha256);assert.equal(String(recoveredJournal.journal.requestId),String(experiment.fault.requestId));
        experiment.status="passed";
        require("../../../scripts/certops-adcs-response-loss-report").verify(experiment,process.env.GITHUB_SHA);
      }catch(error){experiment.status="failed";throw error;}
      finally{try{await controller?.stopAndDrain();}catch(error){experiment.status="failed";throw error;}finally{fs.writeFileSync(experimentPath,JSON.stringify(experiment));fs.copyFileSync(experimentPath,process.env.CERTOPS_ADCS_RESPONSE_LOSS_REPORT || "C:\\ttqualification\\response-loss-experimental.json");}}

      return experiment;
};

// A separate, genuinely issued API/agent enrollment supplies the foreign RequestId.
// It is never inferred from CA high water marks or another lab's fixtures.
module.exports.provisionForeignRequest=async function provisionForeignRequest(c){
 assert.equal(process.platform,"win32");assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB,"1");assert.equal(c.serviceOwned,true);
 const {fixture,api,agentRowId,caConfig,workDir,run,preflight,jobFinished,ps,command,freePort,ownedSites,ownedCertificateIds,ownedEnrollmentIds,ownedThumbprints}=c;
 const domain=`certops-adcs-${run}-faultforeign.example.test`,site=`TTADCS-${run}-faultforeign`,port=await freePort();
 const {issuerId,result}=await preflight("TTQualificationRSAShort");assert.equal(result.templateCheck.verdict,"safe");assert.equal(result.caCheck.verdict,"safe");
 assert.equal((await fixture.request(`${api}/issuers/${issuerId}/confirm`,"POST",{caKeySha256:result.caCertificates[0].keySha256,caConfig,template:"TTQualificationRSAShort"})).status,200);
 const directory=path.join(workDir,"faultforeign");fs.mkdirSync(directory);fs.writeFileSync(path.join(directory,"index.html"),"Owned foreign request fixture");
 ps(`Import-Module WebAdministration;if(Test-Path 'IIS:\\Sites\\${site}'){throw 'Foreign fixture site'};& netsh.exe http show sslcert hostnameport=${domain}:${port}|Out-Null;if($LASTEXITCODE -eq 0){throw 'Foreign fixture endpoint'}`);
 ownedSites.push(site);ps(`Import-Module WebAdministration;New-Website -Name '${site}' -PhysicalPath '${directory.replace(/'/g,"''")}' -IPAddress '*' -Port ${port} -HostHeader '${domain}' -Ssl|Out-Null;Set-WebBinding -Name '${site}' -BindingInformation '*:${port}:${domain}' -PropertyName sslFlags -Value 1`);
 const certificateId=await require("./certops-adcs-local-rules").provisionSurvivorSource({fixture,agentRowId,domain,site,port,ownedCertificateIds});
 const created=await fixture.request(`${api}/enrollments`,"POST",{issuerId,certificateId,agentId:agentRowId,target:{type:"windows-iis",reference:domain,store:"My",binding:{site,port,sniHost:domain}},authorizedDnsNames:[domain],keyAlgorithm:"rsa",keySize:2048});assert.equal(created.status,201);ownedEnrollmentIds.push(created.body.enrollmentId);await jobFinished(created.body.jobId);
 const row=(await fixture.pool.query("SELECT state,request_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,created.body.enrollmentId])).rows[0];assert.equal(row.state,"installed");assert.ok(Number.isInteger(Number(row.request_id))&&Number(row.request_id)>0&&Number(row.request_id)<=0xffffffff);
 const observed=JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.resolve(__dirname,"../../../infra/certops-adcs/owned-request-observation.ps1"),"-CommonName",domain,"-RequestId",String(row.request_id)]));assert.equal(observed.disposition,20);assert.equal(observed.subjectRequestCount,1);assert.equal(String(observed.requestId),String(row.request_id));
 return Number(row.request_id);
};
