/*
 * Qualification notes: shared-port-sni-qualification
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Require windows-iis-shared-port-sni-isolation on disposable elevated Server2022/2025,IIS and host
 * prerequisites. Own2 unique sites,2 hostnameport selectors on one free port,5 nonexportable certs
 * covering both names; refuse site/selector collisions/concrete-IP shadows. Actual SNI loopback
 * trustedTLS and native IIS/store/sslFlags/HTTP.sys hashes must agree after primary
 * cutover,missing-cert rollback,and reversed roles; same-cert replay no mutation.
 * nativeSamePortSni,current fixture/TLS hashes,both isolation directions and cleanup mandatory; not
 * installed multi-binding/public API qualification. Record cert/key receipts before
 * output/creation,attempt all exact owned deletions and require absence; any cleanup failure prevents
 * pass.
 */
"use strict";
/* Supporting native Windows qualification for two IIS sites sharing one TCP
 * port with different SNI names. Owns unique certificate subjects, sites and
 * hostnameport endpoints, and calls the real product binding mutator. Native
 * IIS metadata plus authenticated TLS independently verify cutover/rollback
 * isolation. Only an opted-in disposable elevated Windows host may invoke it;
 * portable tests validate evidence only and never create native resources.
 */
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const {deployIisBinding,checkSniPrecedenceConflict}=require("../../src/windows-iis");
const {freePort,expectServed}=require("./iis-fixture");
const FLAGS=["twoSitesSamePort","distinctHostnameSelectors","primaryCutoverPeerUnchanged","primaryRollbackPeerUnchanged","peerCutoverPrimaryUnchanged","peerRollbackPrimaryUnchanged","sameCertificateReplayVerified","independentAuthenticatedTls","ownedCleanupVerified"];
function verifyIsolationFacts(facts){assert.equal(facts.siteCount,2);assert.equal(facts.hostnameCount,2);assert.equal(facts.certificateStore,"My");for(const field of FLAGS)assert.equal(facts[field],true,field);return true;}
function verifyNativeBinding(native,target){assert.equal(native.coordinates,`127.0.0.1:${target.port}:${target.sniHost}`);assert.equal(native.sslFlags,1);assert.equal(native.store.toUpperCase(),"MY");assert.match(native.hash,/^[A-F0-9]{40}$/);return true;}
async function qualifySamePortSni({powershell,run,workDir}){
 assert.equal(process.platform,"win32");assert.equal(process.env.CERTOPS_HOST_TESTS,"1");
 const token=crypto.randomUUID(),directory=path.join(workDir,`sni-isolation-${token}`),port=await freePort(),names=[`primary-${token}.localhost`,`peer-${token}.localhost`];
 const targets=names.map((name,index)=>({site:`CertOpsSni-${index}-${token}`,address:"127.0.0.1",port,sniHost:name,store:"My"}));
 const certificates=[],siteOwned=new Set(),sslOwned=new Set(),keyNames=new Set(),subjects=new Set(),errors=[];let primary,facts;
 const quote=value=>value.replace(/'/g,"''");
 const certPem=certificate=>`-----BEGIN CERTIFICATE-----\n${certificate.der}\n-----END CERTIFICATE-----\n`;
 const served=(target,certificate)=>expectServed(port,certificate.thumbprint,target.sniHost,certPem(certificate));
 const bindingState=target=>{
  const native=JSON.parse(powershell(`Import-Module WebAdministration;$b=@(Get-WebBinding -Name '${target.site}' -Protocol https|Where-Object bindingInformation -eq '127.0.0.1:${port}:${target.sniHost}');if($b.Count -ne 1){throw 'Expected exact owned SNI binding'};$h=$b[0].certificateHash;if($h -is [byte[]]){$h=[BitConverter]::ToString($h).Replace('-','')};@{coordinates=[string]$b[0].bindingInformation;sslFlags=[int]$b[0].sslFlags;hash=([string]$h).ToUpperInvariant();store=[string]$b[0].certificateStoreName}|ConvertTo-Json -Compress`));
  verifyNativeBinding(native,target);
  assert.ok(run("netsh.exe",["http","show","sslcert",`hostnameport=${target.sniHost}:${port}`]).toLowerCase().includes(native.hash.toLowerCase()),"Independent HTTP.sys selector must agree with IIS certificate hash");return native;
 };
 const assertPair=async(primaryCertificate,peerCertificate)=>{assert.equal(bindingState(targets[0]).hash,primaryCertificate.thumbprint);assert.equal(bindingState(targets[1]).hash,peerCertificate.thumbprint);await served(targets[0],primaryCertificate);await served(targets[1],peerCertificate);};
 try{
  fs.mkdirSync(directory);fs.writeFileSync(path.join(directory,"index.htm"),"Owned same-port SNI fixture");
  for(const target of targets){powershell(`Import-Module WebAdministration;if(Test-Path 'IIS:\\Sites\\${target.site}'){throw 'Refuse existing IIS site'};& netsh.exe http show sslcert hostnameport=${target.sniHost}:${port}|Out-Null;if($LASTEXITCODE -eq 0){throw 'Refuse existing hostname endpoint'}`);assert.equal(await checkSniPrecedenceConflict({binding:target}),undefined,"Refuse existing concrete-IP shadow of the owned fixture");}
  for(let index=0;index<5;index++){
   const subject=`CN=CertOpsSni-${token}-${index}`,receipt=path.join(directory,`certificate-${index}.receipt`),keyReceipt=path.join(directory,`certificate-${index}.key-receipt`);
   assert.equal(powershell(`[bool](Get-ChildItem Cert:\\LocalMachine\\My|Where-Object Subject -eq '${subject}')`),"False");subjects.add(subject);
   const certificate=JSON.parse(powershell(`$c=New-SelfSignedCertificate -Subject '${subject}' -DnsName '${names[0]}','${names[1]}' -Provider 'Microsoft Software Key Storage Provider' -KeyAlgorithm RSA -KeyLength 2048 -KeyExportPolicy NonExportable -CertStoreLocation Cert:\\LocalMachine\\My;$k=$null;try{[IO.File]::WriteAllText('${quote(receipt)}',$c.Thumbprint);$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);[IO.File]::WriteAllText('${quote(keyReceipt)}',$k.Key.KeyName);@{thumbprint=$c.Thumbprint;der=[Convert]::ToBase64String($c.RawData)}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`));
   assert.match(certificate.thumbprint,/^[A-F0-9]{40}$/);const parsed=new crypto.X509Certificate(Buffer.from(certificate.der,"base64"));for(const name of names)assert.equal(parsed.checkHost(name),name);assert.equal(parsed.fingerprint.replace(/:/g,""),certificate.thumbprint);certificates.push(certificate);
  }
  for(const [index,target]of targets.entries()){
   siteOwned.add(target.site);powershell(`Import-Module WebAdministration;New-Website -Name '${target.site}' -PhysicalPath '${quote(directory)}' -IPAddress 127.0.0.1 -Port ${port} -HostHeader '${target.sniHost}' -Ssl|Out-Null;Set-WebBinding -Name '${target.site}' -BindingInformation '127.0.0.1:${port}:${target.sniHost}' -PropertyName sslFlags -Value 1`);
   sslOwned.add(target.sniHost);powershell(`Import-Module WebAdministration;(Get-WebBinding -Name '${target.site}' -Protocol https).AddSslCertificate('${certificates[index*2].thumbprint}','My')`);
  }
  await assertPair(certificates[0],certificates[2]);const peerBefore=bindingState(targets[1]);
  const primaryChange=await deployIisBinding({binding:targets[0],certificatePem:certPem(certificates[1]),verifyTimeoutMs:15000});assert.equal(primaryChange.ok,true);assert.equal(primaryChange.outgoingThumbprint,certificates[0].thumbprint);assert.deepEqual(bindingState(targets[1]),peerBefore);await assertPair(certificates[1],certificates[2]);
  // An actual accepted public certificate loses its store copy. Product bind
  // must fail after delete and restore this target, leaving its peer intact.
  run("certutil.exe",["-delstore","My",certificates[4].thumbprint]);assert.equal(powershell(`Test-Path 'Cert:\\LocalMachine\\My\\${certificates[4].thumbprint}'`),"False");
  const primaryFailure=await deployIisBinding({binding:targets[0],certificatePem:certPem(certificates[4]),verifyTimeoutMs:3000});assert.equal(primaryFailure.ok,false);assert.equal(primaryFailure.rolledBack,true);assert.deepEqual(bindingState(targets[1]),peerBefore);await assertPair(certificates[1],certificates[2]);
  const primaryBefore=bindingState(targets[0]);const peerChange=await deployIisBinding({binding:targets[1],certificatePem:certPem(certificates[3]),verifyTimeoutMs:15000});assert.equal(peerChange.ok,true);assert.equal(peerChange.outgoingThumbprint,certificates[2].thumbprint);assert.deepEqual(bindingState(targets[0]),primaryBefore);await assertPair(certificates[1],certificates[3]);
  const peerFailure=await deployIisBinding({binding:targets[1],certificatePem:certPem(certificates[4]),verifyTimeoutMs:3000});assert.equal(peerFailure.ok,false);assert.equal(peerFailure.rolledBack,true);assert.deepEqual(bindingState(targets[0]),primaryBefore);await assertPair(certificates[1],certificates[3]);
  const replay=await deployIisBinding({binding:targets[0],certificatePem:certPem(certificates[1]),verifyTimeoutMs:15000});assert.equal(replay.ok,true);assert.equal(replay.skippedMutation,true);await assertPair(certificates[1],certificates[3]);
  facts={siteCount:2,hostnameCount:2,certificateStore:"My",...Object.fromEntries(FLAGS.filter(field=>field!=="ownedCleanupVerified").map(field=>[field,true]))};
 }catch(error){primary=error;}
 finally{
  const clean=action=>{try{action();}catch(error){errors.push(error);}};
  for(const name of sslOwned)clean(()=>powershell(`& netsh.exe http show sslcert hostnameport=${name}:${port}|Out-Null;if($LASTEXITCODE -eq 0){& netsh.exe http delete sslcert hostnameport=${name}:${port}|Out-Null;if($LASTEXITCODE -ne 0){throw 'Owned SSL cleanup failed'}};& netsh.exe http show sslcert hostnameport=${name}:${port}|Out-Null;if($LASTEXITCODE -eq 0){throw 'Owned SSL selector remains'}`));
  for(const site of siteOwned)clean(()=>powershell(`Import-Module WebAdministration;if(Test-Path 'IIS:\\Sites\\${site}'){Remove-Website -Name '${site}'};if(Test-Path 'IIS:\\Sites\\${site}'){throw 'Owned site remains'}`));
  // Receipts recover names even if certificate creation/JSON parsing failed.
  if(fs.existsSync(directory))for(const file of fs.readdirSync(directory).filter(name=>/^certificate-\d+\.key-receipt$/.test(name)))clean(()=>{const name=fs.readFileSync(path.join(directory,file),"utf8").trim();assert.match(name,/^[A-Za-z0-9_{}.-]{1,256}$/);keyNames.add(name);});
  for(const subject of subjects)clean(()=>powershell(`$certs=@(Get-ChildItem Cert:\\LocalMachine\\My|Where-Object Subject -eq '${subject}');foreach($c in $certs){Remove-Item -LiteralPath $c.PSPath -DeleteKey};if(Get-ChildItem Cert:\\LocalMachine\\My|Where-Object Subject -eq '${subject}'){throw 'Owned certificate remains'}`));
  for(const name of keyNames)clean(()=>powershell(`$p=[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider;$o=[Security.Cryptography.CngKeyOpenOptions]::MachineKey;if([Security.Cryptography.CngKey]::Exists('${name}',$p,$o)){$k=[Security.Cryptography.CngKey]::Open('${name}',$p,$o);try{$k.Delete()}finally{$k.Dispose()}};if([Security.Cryptography.CngKey]::Exists('${name}',$p,$o)){throw 'Owned CNG key remains'}`));
 }
 if(primary||errors.length)throw new AggregateError([...(primary?[primary]:[]),...errors],"Same-port SNI fixture or exact owned cleanup failed");facts.ownedCleanupVerified=true;verifyIsolationFacts(facts);return facts;
}
module.exports={qualifySamePortSni,verifyIsolationFacts,verifyNativeBinding};
