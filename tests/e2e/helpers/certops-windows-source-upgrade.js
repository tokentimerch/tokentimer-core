"use strict";
/* Real distinct-version SCM upgrade supporting qualification. Called only by the
 * opted-in hosted Windows journey while the historical agent is running. Owns a
 * unique operator-created non-exportable CNG certificate and IIS endpoint, uses
 * independent trusted TLS before/after the actual candidate installer, and
 * removes exactly those resources. This is historical SOURCE build evidence;
 * it cannot qualify the incomplete published predecessor archive.
 */
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto"),net=require("node:net"),tls=require("node:tls");
const {createHostGate}=require("../../../packages/agent/scripts/host-gate");
const {historical}=require("../../../scripts/certops-historical-windows-package");
const required=["windows-source-upgrade-state-preserved"];
const fields=["werPolicyPreserved","schedulerHistoryPreserved","distinctVersionObserved","configurationPreserved","credentialPreserved","signingKeyPinPreserved","sameAgentIdentity","authenticatedCandidateHeartbeat","candidateHelperActivated","nonExportableCngKeyPreserved","iisBindingPreserved","trustedTlsPreserved","serviceIdentityPreserved","ownedFixtureRemoved"];
function verifyUpgradeFacts(facts){
 assert.equal(facts.provenance,"historical-source-build");assert.equal(facts.publishedArchiveUsedForInstallation,false);
 assert.equal(facts.historicalCommit,historical.commit);assert.equal(facts.historicalVersion,historical.version);
 assert.match(facts.candidateVersion,/^\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?$/i);assert.notEqual(facts.candidateVersion,historical.version);assert.equal(facts.candidateVersion,require("../../../packages/agent/package.json").version,"Upgrade evidence must describe the checked-out candidate package");
 assert.match(facts.historicalArchiveSha256,/^[a-f0-9]{64}$/);for(const arch of ["amd64","arm64"])assert.match(facts.historicalHelpers[arch],/^[a-f0-9]{64}$/);
 for(const field of fields)assert.equal(facts[field],true,field);return true;
}
async function freePort(){const socket=net.createServer();await new Promise((resolve,reject)=>{socket.once("error",reject);socket.listen(0,"127.0.0.1",resolve);});const port=socket.address().port;await new Promise((resolve,reject)=>socket.close(error=>error?reject(error):resolve()));return port;}
function peer(port,pem){return new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port,servername:"localhost",ca:pem,rejectUnauthorized:true},()=>{try{assert.equal(socket.authorized,true);resolve(socket.getPeerCertificate().fingerprint.replace(/:/g,""));}catch(error){reject(error);}finally{socket.destroy();}});socket.once("error",reject);socket.setTimeout(10000,()=>socket.destroy(new Error("Upgrade TLS observation timed out")));});}
async function qualifySourceUpgrade({workDir,repoRoot,ps,waitUntil,reportDirectory,historicalEvidence,candidateVersion,migrate}){
 const site=`CertOpsUpgrade-${crypto.randomUUID()}`,subject=`CN=${site}`,directory=path.join(workDir,site),receipt=path.join(directory,"certificate.receipt"),port=await freePort();
 const quote=value=>value.replace(/'/g,"''"),endpoint=`ipport=127.0.0.1:${port}`;
 const gate=createHostGate({suite:"windows-historical-source-upgrade",strict:true,evidenceLevel:"e2e",reportPath:path.join(reportDirectory,"windows-source-upgrade.json"),fixtureSource:{file:"tests/e2e/helpers/certops-windows-source-upgrade.js",sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")},requiredCapabilities:["windows","system","scm","api","historicalSource"],probeCapabilities:()=>({windows:{available:process.platform==="win32"},system:{available:ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value")==="S-1-5-18"},scm:{available:ps("(Get-Service TokenTimerAgent).Status")==="Running"},api:{available:true,evidence:"Parent has independently observed authenticated historical-version heartbeat"},historicalSource:{available:historicalEvidence.commit===historical.commit}})});
 await gate.preflight();gate.report.qualificationEnvironment.identity="LocalSystem";let ownedKeyName;let siteOwned=false,sslOwned=false,certificateOwned=false;let primary;const errors=[];
 const facts={provenance:"historical-source-build",publishedArchiveUsedForInstallation:false,historicalCommit:historicalEvidence.commit,historicalVersion:historicalEvidence.version,historicalArchiveSha256:historicalEvidence.archiveSha256,historicalHelpers:historicalEvidence.helpers,candidateVersion};
 try{
 await gate.scenario(required[0],async()=>{
 fs.mkdirSync(directory);fs.writeFileSync(path.join(directory,"index.htm"),"Owned upgrade fixture");
 ps(`if(Get-ChildItem Cert:\\LocalMachine\\My | Where-Object Subject -eq '${subject}'){throw 'Certificate collision'}; & netsh.exe http show sslcert ${endpoint} | Out-Null; if($LASTEXITCODE -eq 0){throw 'Existing native binding'};Import-Module WebAdministration;if(Test-Path 'IIS:\\Sites\\${site}'){throw 'Existing IIS site'}`);
 certificateOwned=true;
 const certificate=JSON.parse(ps(`$c=New-SelfSignedCertificate -Subject '${subject}' -DnsName localhost -Provider 'Microsoft Software Key Storage Provider' -KeyAlgorithm RSA -KeyLength 2048 -KeyExportPolicy NonExportable -CertStoreLocation Cert:\\LocalMachine\\My;try{[IO.File]::WriteAllText('${quote(receipt)}',$c.Thumbprint);[pscustomobject]@{thumbprint=$c.Thumbprint;der=[Convert]::ToBase64String($c.RawData)}|ConvertTo-Json -Compress}finally{$c.Dispose()}`));
 assert.match(certificate.thumbprint,/^[A-F0-9]{40}$/);const pem=`-----BEGIN CERTIFICATE-----\n${certificate.der}\n-----END CERTIFICATE-----\n`;
 const key=()=>JSON.parse(ps(`$c=Get-Item 'Cert:\\LocalMachine\\My\\${certificate.thumbprint}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);[pscustomobject]@{name=$k.Key.KeyName;policy=[string]$k.Key.ExportPolicy;bits=$k.KeySize;machine=$k.Key.IsMachineKey}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`));
 const beforeKey=key();ownedKeyName=beforeKey.name;assert.match(ownedKeyName,/^[a-zA-Z0-9_.{}-]{1,256}$/);assert.equal(beforeKey.policy,"None");assert.equal(beforeKey.bits,2048);assert.equal(beforeKey.machine,true);
 siteOwned=true;ps(`Import-Module WebAdministration;New-Website -Name '${site}' -PhysicalPath '${quote(directory)}' -IPAddress 127.0.0.1 -Port ${port} -Ssl | Out-Null`);
 sslOwned=true;ps(`Import-Module WebAdministration;(Get-WebBinding -Name '${site}' -Protocol https).AddSslCertificate('${certificate.thumbprint}','My')`);
 const binding=()=>ps(`Import-Module WebAdministration;Get-WebBinding -Name '${site}' -Protocol https | Select-Object bindingInformation,sslFlags,certificateHash,certificateStoreName | ConvertTo-Json -Compress`);
 const beforeBinding=binding();await waitUntil(async()=>await peer(port,pem)===certificate.thumbprint);
 const beforeIdentity=ps("$s=Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\";$p=Get-CimInstance Win32_Process -Filter \"ProcessId=$($s.ProcessId)\";(Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid).Sid");assert.equal(beforeIdentity,"S-1-5-18");
 Object.assign(facts,await migrate());
 assert.deepEqual(key(),beforeKey);assert.equal(binding(),beforeBinding);await waitUntil(async()=>await peer(port,pem)===certificate.thumbprint);
 assert.equal(ps("$s=Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\";$p=Get-CimInstance Win32_Process -Filter \"ProcessId=$($s.ProcessId)\";(Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid).Sid"),beforeIdentity);
 Object.assign(facts,{nonExportableCngKeyPreserved:true,iisBindingPreserved:true,trustedTlsPreserved:true,serviceIdentityPreserved:true});
 },{evidenceLevel:"real-host",oracle:"Real distinct-version product installer and authenticated historical/candidate heartbeats; fresh native CNG, IIS and authenticated TLS observations across SCM migration"});
 }catch(error){primary=error;}finally{
 const clean=action=>{try{action();}catch(error){errors.push(error);}};
 if(sslOwned)clean(()=>ps(`& netsh.exe http delete sslcert ${endpoint} | Out-Null; if($LASTEXITCODE -ne 0){throw 'Owned endpoint cleanup failed'}`));
 if(siteOwned)clean(()=>ps(`Import-Module WebAdministration;if(Test-Path 'IIS:\\Sites\\${site}'){Remove-Website -Name '${site}'};if(Test-Path 'IIS:\\Sites\\${site}'){throw 'Site survived cleanup'}`));
 if(certificateOwned)clean(()=>ps(`$owned=@(Get-ChildItem Cert:\\LocalMachine\\My | Where-Object Subject -eq '${subject}');foreach($c in $owned){Remove-Item -LiteralPath $c.PSPath -DeleteKey};if(Get-ChildItem Cert:\\LocalMachine\\My | Where-Object Subject -eq '${subject}'){throw 'Certificate survived cleanup'}`));
 if(ownedKeyName)clean(()=>assert.equal(ps(`[Security.Cryptography.CngKey]::Exists('${ownedKeyName}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)`),"False","Owned upgrade CNG key survived cleanup"));
 facts.ownedFixtureRemoved=errors.length===0;
 if(!primary&&!errors.length)clean(()=>{verifyUpgradeFacts(facts);Object.assign(gate.report,{sourceUpgrade:facts,fixtureSources:["tests/e2e/helpers/certops-windows-source-upgrade.js","tests/e2e/windows-real-journey.js","scripts/certops-historical-windows-package.js"].map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(repoRoot,file))).digest("hex")}))});});
 try{if(primary||errors.length)gate.report.status="failed";await gate.finish({requiredScenarios:required,cleanup:{status:errors.length?"failed":"passed",summary:"Remove only owned IIS endpoint, site, certificate and CNG key"}});}catch(error){errors.push(error);}
 }
 if(primary||errors.length)throw new AggregateError([...(primary?[primary]:[]),...errors],"Historical source upgrade or owned cleanup failed");return gate.report;
}
function verifySourceUpgradeReport(report,{expectedSha=process.env.GITHUB_SHA}={}){
 assert.equal(report.suite,"windows-historical-source-upgrade");assert.equal(report.status,"passed");assert.equal(report.strict,true);assert.deepEqual(report.requiredScenarios,required);assert.equal(report.scenarios.length,1);assert.equal(report.scenarios[0].id,required[0]);assert.equal(report.scenarios[0].status,"passed");assert.equal(report.cleanup.status,"passed");assert.match(report.candidateSha,/^[a-f0-9]{40}$/);if(expectedSha)assert.equal(report.candidateSha,expectedSha);
 assert.equal(report.qualificationEnvironment.osFamily,"windows");assert.ok(["2022","2025"].includes(report.qualificationEnvironment.osVersion));assert.equal(report.qualificationEnvironment.measurement,"native");assert.equal(report.qualificationEnvironment.identity,"LocalSystem");
 assert.deepEqual(report.fixtureSource,{file:"tests/e2e/helpers/certops-windows-source-upgrade.js",sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")});
 for(const file of ["tests/e2e/helpers/certops-windows-source-upgrade.js","tests/e2e/windows-real-journey.js","scripts/certops-historical-windows-package.js"]){const sources=report.fixtureSources.filter(source=>source.file===file);assert.equal(sources.length,1);assert.equal(sources[0].sha256,crypto.createHash("sha256").update(fs.readFileSync(path.join(__dirname,"../../..",file))).digest("hex"));}
 return verifyUpgradeFacts(report.sourceUpgrade);
}
module.exports={qualifySourceUpgrade,verifyUpgradeFacts,verifySourceUpgradeReport,requiredScenarios:required};
