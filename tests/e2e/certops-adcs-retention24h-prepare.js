"use strict";
/** Explicit disposable-domain prepare entry point. Two real public AD CS
 * enrollments perform the production A-to-B cutover on the same fresh VM.
 * This source does not shorten clocks or manufacture a retention ledger. It
 * leaves the stopped service, IIS site and nonexportable keys resident for the
 * separately attested keeper; failure belongs to independent Azure teardown. */
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto"),tls=require("node:tls"),net=require("node:net");
const {spawnSync}=require("node:child_process");
const {createApiFixture}=require("./helpers/certops-api-fixture");
const {applyRestrictivePermissions}=require("../../packages/agent/src/platform");
const {hostBinaryName}=require("../../packages/agent/scripts/build-windows-service-host");
const {readEnrollmentJournal}=require("../../packages/agent/src/issuers/adcs-enrollment");
const retention=require("../../packages/agent/src/windows-retention");
const contract=require("../../scripts/certops-retention24h-contract");
const runtime=require("../../scripts/certops-retention24h-runtime");
const ROOT=path.resolve(__dirname,"../..");
const PREPARATION_SOURCES=require("../../scripts/certops-retention24h-sources").PREPARATION_SOURCES;
function hash(file){return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");}
function command(file,args){const env={...process.env};if(path.basename(file).toLowerCase()==="powershell.exe")for(const name of Object.keys(env))if(name.toLowerCase()==="psmodulepath")delete env[name];const result=spawnSync(file,args,{env,encoding:"utf8",timeout:180000,windowsHide:true,maxBuffer:65536});assert.ifError(result.error);assert.equal(result.status,0,`Owned retention prepare command failed: ${path.basename(file)}`);return result.stdout.trim();}
function ps(script){return command("powershell.exe",["-NoProfile","-NonInteractive","-Command",`$ErrorActionPreference='Stop';${script}`]);}
async function until(check){const deadline=performance.now()+180000;while(performance.now()<deadline){const result=await check();if(result)return result;await new Promise(resolve=>setTimeout(resolve,500));}throw new Error("Actual retention preparation exceeded bounded deadline");}
function peer(port,domain,ca){return new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:domain,ca,rejectUnauthorized:true},()=>{try{assert.equal(socket.authorized,true);resolve(new crypto.X509Certificate(socket.getPeerCertificate().raw));}catch(error){reject(error);}finally{socket.destroy();}});socket.once("error",reject);socket.setTimeout(10000,()=>socket.destroy(new Error("Actual retention prepare TLS deadline")));});}
async function prepare(leasePath){
 const startedAt=new Date().toISOString();
 assert.equal(process.platform,"win32");assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB,"1");assert.equal(process.env.CERTOPS_ADCS_RETENTION24H,"1");
 assert.equal(ps("(Get-CimInstance Win32_OperatingSystem).BuildNumber"),"20348");assert.equal(ps("(Get-CimInstance Win32_OperatingSystem).ProductType"),"3");assert.equal(ps("(Get-UICulture).Name"),"en-US");assert.equal(ps("(Get-WinSystemLocale).Name"),"en-US");
 assert.equal(ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),"S-1-5-18");assert.equal(ps("(Get-CimInstance Win32_ComputerSystem).Domain"),"lab.certops.test");
 const lease=JSON.parse(fs.readFileSync(leasePath,"utf8"));contract.verifyLease(lease);assert.equal(lease.phase,"preparing");assert.equal(lease.candidateSha,process.env.GITHUB_SHA);assert.ok(Date.now()<Date.parse(lease.expiresAt));assert.equal(hash(process.execPath),lease.nodeSha256);assert.equal(hash(path.join(ROOT,"scripts/certops-retention24h-runtime.js")),lease.keeperSha256);
 const directory=`C:\\ttqualification\\retention24h\\${lease.nonce}`,stateDir=path.join(directory,"agent"),configPath=path.join(directory,"keeper-config.json"),run=crypto.randomBytes(5).toString("hex"),domain=`certops-adcs-${run}-retention24h.example.test`,site=`TTADCS-${run}-retention24h`,caConfig="tt-ca.lab.certops.test\\TTQualificationRoot",template="TTQualificationRSAShort";
 assert.equal(fs.existsSync(directory),false,"Never adopt a previous keeper directory");fs.mkdirSync(directory,{recursive:true});applyRestrictivePermissions(directory,{kind:"directory"});fs.mkdirSync(stateDir);applyRestrictivePermissions(stateDir,{kind:"directory"});
 assert.notEqual(spawnSync("sc.exe",["query","TokenTimerAgent"]).status,0,"Refuse a pre-existing installed agent");
 const url=new URL(process.env.CERTOPS_ADCS_API_URL);assert.equal(url.href,"https://10.64.0.6/");
 const fixture=await createApiFixture(url.href),api=`/api/v1/workspaces/${fixture.workspaceId}/certops`,agentId=`retention24h-${run}`;
 let serviceOwned=false,drained=false,drainedTree;
 async function finished(jobId){await until(async()=>{const row=(await fixture.pool.query("SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,jobId])).rows[0];assert.ok(!["failed","rejected","cancelled","orphaned_unknown_effect"].includes(row?.status),"Actual preparation job failed");return row?.status==="succeeded";});}
 function stopAndDrain(){
  if(!serviceOwned)return;
  // Capture the exact installed service tree before orderly stop. Never kill a
  // discovered PID or adopt a child after a parent PID can have been recycled.
  drainedTree=JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(ROOT,"scripts/certops-retention24h-stop-agent.ps1"),"-StateDir",stateDir,"-RepositoryRoot",ROOT,"-NodeExecutable",process.execPath]));
  assert.ok(Array.isArray(drainedTree) && drainedTree.length > 0 && drainedTree.length <= 64);
  drained=true;
 }
 try{
  const bootstrap=await fixture.request(`${api}/agent-bootstrap-tokens`,"POST",{name:agentId,expiresAt:new Date(Date.now()+3600000).toISOString()});assert.equal(bootstrap.status,201);
  fs.writeFileSync(path.join(stateDir,"config.json"),JSON.stringify({serverUrl:url.href,caBundlePath:process.env.NODE_EXTRA_CA_CERTS,agentId,heartbeatIntervalMs:5000,pollIntervalMs:2000,windows:{supersededRetentionHours:24,sweepIntervalMs:21600000},declaredTargetSelectors:[domain],execution:{enabled:true,dryRun:false},policy:{allowedPaths:[directory],allowedCommands:{},allowedCaEndpoints:[],allowedDnsZones:[],allowedDnsProviders:[]},adcs:{enrollmentRules:[{caConfig,template,dnsScopes:["example.test"],keyAlgorithms:["rsa"],operatorAttested:false}]}}));applyRestrictivePermissions(path.join(stateDir,"config.json"));
  const host=path.join(ROOT,"packages/agent/bin",hostBinaryName("amd64"));assert.ok(fs.existsSync(host));
  command("sc.exe",["create","TokenTimerAgent","type=","own","start=","demand","obj=","LocalSystem","binPath=",`"${host}" "${process.execPath}" "${path.join(ROOT,"packages/agent/bin/tokentimer-agent.js")}"`]);serviceOwned=true;
  command("reg.exe",["add","HKLM\\SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent","/v","Environment","/t","REG_MULTI_SZ","/d",`TOKENTIMER_AGENT_CONFIG_DIR=${stateDir}\\0TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=${bootstrap.body.plaintextToken}\\0TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID=${bootstrap.body.token.id}\\0NODE_EXTRA_CA_CERTS=${process.env.NODE_EXTRA_CA_CERTS}\\0PATH=${process.env.PATH}`,"/f"]);command("sc.exe",["start","TokenTimerAgent"]);
  const agentRowId=await until(async()=>(await fixture.pool.query("SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",[fixture.workspaceId,agentId])).rows[0]?.id);
  const issuer=await fixture.request(`${api}/issuers`,"POST",{kind:"adcs",name:`Retention24h-${run}`});assert.equal(issuer.status,201);const issuerId=issuer.body.issuer.id;
  const preflight=await fixture.request(`${api}/issuers/${issuerId}/preflight`,"POST",{agentId:agentRowId,caConfig,template});assert.equal(preflight.status,201);await finished(preflight.body.job.id);
  const safety=await until(async()=>(await fixture.pool.query("SELECT last_preflight FROM certificate_issuers WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,issuerId])).rows[0]?.last_preflight);assert.equal(safety.caCheck.verdict,"safe");assert.equal(safety.templateCheck.verdict,"safe");const authority=safety.caCertificates[0],caPem=new crypto.X509Certificate(Buffer.from(authority.certificateB64,"base64")).toString();
  assert.equal((await fixture.request(`${api}/issuers/${issuerId}/confirm`,"POST",{caKeySha256:authority.keySha256,caConfig,template})).status,200);
  const port=await new Promise((resolve,reject)=>{const server=net.createServer();server.once("error",reject);server.listen(0,"127.0.0.1",()=>{const p=server.address().port;server.close(error=>error?reject(error):resolve(p));});});
  const web=path.join(directory,"site");fs.mkdirSync(web);fs.writeFileSync(path.join(web,"index.html"),"Owned real retention24h AD CS cutover");
  ps(`Import-Module WebAdministration;if(Test-Path 'IIS:\\Sites\\${site}'){throw 'Foreign existing retention site'};New-Website -Name '${site}' -PhysicalPath '${web}' -IPAddress '*' -Port ${port} -HostHeader '${domain}' -Ssl|Out-Null;Set-WebBinding -Name '${site}' -BindingInformation '*:${port}:${domain}' -PropertyName sslFlags -Value 1`);
  const certificateId=crypto.randomUUID(),generations=[];
  for(let cycle=0;cycle<2;cycle++){
   const created=await fixture.request(`${api}/enrollments`,"POST",{issuerId,certificateId,agentId:agentRowId,target:{type:"windows-iis",reference:domain,store:"My",binding:{site,port,sniHost:domain}},authorizedDnsNames:[domain],keyAlgorithm:"rsa",keySize:2048});assert.equal(created.status,201);await finished(created.body.jobId);
   const journal=readEnrollmentJournal(stateDir,created.body.enrollmentId);assert.equal(journal.kind,"valid");assert.equal(journal.journal.state,"installed");
   const leaf=await peer(port,domain,caPem);assert.equal(leaf.fingerprint256,new crypto.X509Certificate(journal.artifacts.leafPem).fingerprint256);assert.equal(leaf.checkHost(domain),domain);assert.equal(leaf.verify(new crypto.X509Certificate(caPem).publicKey),true);
   const fingerprint=leaf.fingerprint256.replace(/:/g,"").toLowerCase(),native=JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(ROOT,"infra/certops-adcs/owned-issued-request.ps1"),"-CommonName",domain,"-FingerprintSha256",fingerprint]));assert.equal(native.disposition,20);assert.equal(native.subjectRequestCount,cycle+1);
   const evidence=(await fixture.pool.query("SELECT e.metadata FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.claim_id=j.claim_id AND e.evidence_type='validation.passed' AND e.metadata->>'step'='verify'",[fixture.workspaceId,created.body.jobId])).rows;assert.ok(evidence.some(row=>String(row.metadata.fingerprintSha256).replace(/:/g,"").toLowerCase()===fingerprint));
   generations.push({thumbprint:leaf.fingerprint.replace(/:/g,""),containerName:journal.journal.containerName,certificateDerB64:leaf.raw.toString("base64"),requestId:String(native.requestId),enrollmentId:created.body.enrollmentId,jobId:created.body.jobId,serial:leaf.serialNumber,spkiSha256:crypto.createHash("sha256").update(leaf.publicKey.export({type:"spki",format:"der"})).digest("hex")});
  }
  for(const field of ["thumbprint","containerName","requestId","enrollmentId","jobId","serial","spkiSha256"])assert.notEqual(generations[0][field],generations[1][field]);
  stopAndDrain();assert.equal(drained,true);
  runtime.assertOwnedLedgerInventory(stateDir,generations[0].thumbprint);
  const row=retention.readLedgerRow(path.join(stateDir,"windows-retention"),generations[0].thumbprint);assert.ok(row);assert.equal(row.replacementThumbprint,generations[1].thumbprint);assert.equal(row.cngKeyContainerId,generations[0].containerName);assert.equal(row.ownershipProvenance,"tokentimer_installed");
  const helper=require("../../packages/agent/src/issuers/chain-helper").resolveAdcsChainHelperPath();assert.equal(helper.error,undefined);
  const extra=PREPARATION_SOURCES;
  const config={lease,drainedTree,stateDir,retentionHours:24,domain,site,port,caPem,predecessor:generations[0],replacement:generations[1],originalLedgerRow:row,cleanupDeadline:retention.computeCleanupDeadline({...row,retentionHours:24}).toISOString(),collectorHelper:{file:path.relative(ROOT,helper.path).replace(/\\/g,"/"),sha256:hash(helper.path)},requiredSources:[...new Set([...runtime.REQUIRED_SOURCES,...extra])].map(file=>({file,sha256:hash(path.join(ROOT,file))}))};
  runtime.verifyConfig(config,configPath);fs.writeFileSync(configPath,JSON.stringify(config),{flag:"wx"});applyRestrictivePermissions(configPath);
  const configSha256=hash(configPath);const marker=command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(ROOT,"scripts/certops-retention24h-task.ps1"),"-Mode","Start","-ConfigPath",configPath,"-ConfigSha256",configSha256]);assert.equal(marker,"CERTOPS_RETENTION24H=task-started");
  await until(()=>fs.existsSync(path.join(directory,"resident-ready.json")));
  const task=JSON.parse(command("powershell.exe",["-NoProfile","-NonInteractive","-File",path.join(ROOT,"scripts/certops-retention24h-task.ps1"),"-Mode","Observe","-ConfigPath",configPath,"-ConfigSha256",configSha256]));
  const report={startedAt,finishedAt:new Date().toISOString(),scope:"prepared-real-domain-adcs-retention24h-not-elapsed-qualified",lease,configSha256,verifiedCutoverAt:row.verifiedCutoverAt,oldNotAfter:row.oldNotAfter,cleanupDeadline:config.cleanupDeadline,task,fixtureSources:config.requiredSources,collectorHelper:config.collectorHelper,ledgerIdentitySha256:crypto.createHash("sha256").update(JSON.stringify(row)).digest("hex"),generations:generations.map(({certificateDerB64,...publicIdentity})=>{assert.ok(certificateDerB64);return publicIdentity;}),sourceCount:config.requiredSources.length,actualRequestIds:generations.map(g=>g.requestId),fingerprints:generations.map(g=>new crypto.X509Certificate(Buffer.from(g.certificateDerB64,"base64")).fingerprint256.replace(/:/g,"").toLowerCase()),soleAgentStoppedAndDrained:true};
  fs.writeFileSync(path.join(directory,"prepare-public.json"),JSON.stringify(report),{flag:"wx"});return report;
 }finally{
  // The owning workflow deletes the complete disposable lab if prepare/handoff
  // fails. Never remove a private key/site while a resident keeper may own it.
  if(serviceOwned&&!drained)stopAndDrain();await fixture.pool.end();
 }
}
module.exports={PREPARATION_SOURCES,prepare};
if(require.main===module)prepare(process.argv[2]).then(()=>process.stdout.write("CERTOPS_RETENTION24H=prepared-real-cutover-and-owned-keeper\n")).catch(()=>{process.stderr.write("Owned retention24h preparation failed; independent teardown required.\n");process.exitCode=1;});
