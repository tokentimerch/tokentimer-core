"use strict";
/* Native language-independent IIS identity/idempotency/verification rollback checks on existing
 * owned enrollment fixtures; compares concrete bindings/store hashes and independently trusted
 * TLS. Called only by the protected disposable-forest AD CS harness; native qualification
 * requires that workflow to execute.
 */
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto"),tls=require("node:tls");
const {deployIisBinding}=require("../../../packages/agent/src/windows-iis");
function nativeSnapshotScript(item){
  const selector=`${item.item.domain}:${item.port}`;
  return `Import-Module WebAdministration;$keys=@(Get-ChildItem -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslSniBindingInfo'|Where-Object { [string]$_.GetValue('HostnamePort') -ieq '${selector}' });if($keys.Count -ne 1){throw 'Exact native SNI registry entry absent or ambiguous'};$k=$keys[0];$values=[ordered]@{};foreach($name in ($k.GetValueNames()|Where-Object { $_ -ne 'AppId' }|Sort-Object)){$value=$k.GetValue($name);$values[$name]=@{kind=[string]$k.GetValueKind($name);value=$value}};$b=@(Get-WebBinding -Name '${item.site}' -Protocol https|Where-Object bindingInformation -eq '*:${item.port}:${item.item.domain}');if($b.Count -ne 1){throw 'Exact owned IIS binding absent or ambiguous'};@{httpValues=$values;appId=([Guid]::new([byte[]]$k.GetValue('AppId'))).ToString();hash=[BitConverter]::ToString([byte[]]$k.GetValue('SslCertHash')).Replace('-','');iisBinding=$b[0].bindingInformation;iisFlags=[int]$b[0].sslFlags}|ConvertTo-Json -Depth 12 -Compress`;
}
async function qualifyIisLocale({gate,issuedFixtures,ps,command,workDir,run,tlsAuthority,ownedNativeBindings}){
  gate.report.fixtureSources ??=[];gate.report.fixtureSources.push({file:"tests/e2e/helpers/certops-adcs-iis-locale.js",sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")});
  assert.equal(process.platform,"win32");assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB,"1");assert.ok(issuedFixtures.length>=3);
  const target=issuedFixtures.find(item=>item.item.id==="rsa2048"),unrelated=issuedFixtures.find(item=>item.item.id==="rsa3072"),candidate=issuedFixtures.find(item=>item.item.id==="rsa4096");assert.ok(target&&unrelated&&candidate);
  const snapshot=item=>JSON.parse(ps(nativeSnapshotScript(item)));
  const preservedSnapshot=value=>{const {appId,...preserved}=value;assert.match(appId,/^[a-f0-9-]{36}$/i);return preserved;};
  const observe=(item,trusted=true)=>new Promise((resolve,reject)=>{const socket=tls.connect({host:"127.0.0.1",port:item.port,servername:item.item.domain,ca:tlsAuthority(item.authority),rejectUnauthorized:trusted},()=>{try{if(trusted)assert.equal(socket.authorized,true);resolve(new crypto.X509Certificate(socket.getPeerCertificate().raw));}catch(error){reject(error);}finally{socket.destroy();}});socket.setTimeout(10000,()=>socket.destroy(new Error("Native locale IIS TLS observation timed out")));socket.once("error",reject);});
  const binding={address:"127.0.0.1",port:target.port,site:target.site,sniHost:target.item.domain,store:"My"};
  await gate.scenario("adcs-real-localized-iis-repeat-deployment-idempotent",async()=>{
    const before=snapshot(target),sibling=snapshot(unrelated),old=await observe(target);assert.equal(before.hash,target.thumbprint);assert.equal(before.iisFlags,1);
    for(let i=0;i<2;i++){const replay=await deployIisBinding({binding,certificatePem:target.observed.toString(),verifyTimeoutMs:15000});assert.equal(replay.ok,true);assert.equal(replay.skippedMutation,true);assert.equal(replay.boundThumbprint,target.thumbprint);assert.deepEqual(snapshot(target),before);assert.deepEqual(snapshot(unrelated),sibling);assert.equal((await observe(target)).fingerprint256,old.fingerprint256);assert.equal((await observe(unrelated)).fingerprint256,unrelated.observed.fingerprint256);}
    gate.report.localizedIisRepeat={nativeLanguage:gate.report.qualificationEnvironment.nativeLanguage,nativeHttpSysValuesPreserved:true,iisSslFlags:before.iisFlags,repeatedDeployments:2,skippedMutation:true,independentTrustedTls:true,unrelatedBindingUnchanged:true};
  },{evidenceLevel:"real-host",oracle:"actual native deployIisBinding replay on CA-issued owned SNI endpoint, exact native registry values/IIS flags and independent trusted TLS unchanged across two repeat deployments"});
  await gate.scenario("adcs-real-localized-iis-verification-failure-rolls-back",async()=>{
    const before=snapshot(target),sibling=snapshot(unrelated),old=await observe(target),selector=`ipport=127.0.0.1:${target.port}`,appId=`{${crypto.randomUUID()}}`;
    ps(`& netsh.exe http show sslcert ${selector}|Out-Null;if($LASTEXITCODE -eq 0){throw 'Refusing existing concrete-IP shadow binding'}`);
    const receipt={selector,appId,thumbprint:unrelated.thumbprint,runId:run};const receiptPath=path.join(workDir,`iis-locale-shadow-${run}.json`);assert.equal(fs.existsSync(receiptPath),false);fs.writeFileSync(receiptPath,JSON.stringify(receipt),{flag:"wx",mode:0o600});ownedNativeBindings.push(receipt);
    let primaryError;const cleanupErrors=[];
    try{
      command("netsh.exe",["http","add","sslcert",selector,`certhash=${receipt.thumbprint}`,`appid=${appId}`,"certstorename=My"]);
      assert.equal((await observe(target,false)).fingerprint256,unrelated.observed.fingerprint256,"Actual native IP precedence must activate the owned shadow before interpreting the fault");
      const failed=await deployIisBinding({binding,certificatePem:candidate.observed.toString(),verifyTimeoutMs:3000});assert.equal(failed.ok,false);assert.equal(failed.code,"VERIFY_FAILED");assert.equal(failed.rolledBack,true);assert.equal(failed.outgoingThumbprint,target.thumbprint);assert.deepEqual(preservedSnapshot(snapshot(target)),preservedSnapshot(before));assert.deepEqual(snapshot(unrelated),sibling);
      assert.equal((await observe(target,false)).fingerprint256,unrelated.observed.fingerprint256);assert.equal((await observe(unrelated)).fingerprint256,unrelated.observed.fingerprint256);
      gate.report.localizedIisRollback={nativeLanguage:gate.report.qualificationEnvironment.nativeLanguage,fault:"actual-owned-concrete-ip-TLS-precedence",verificationFailure:"VERIFY_FAILED",nativeRolledBack:true,nativeHttpSysValuesPreserved:true,iisSslFlags:before.iisFlags,unrelatedBindingUnchanged:true,issuerEnrollmentReused:false};
    }catch(error){primaryError=error;}
    finally{
      try{const visible=command("netsh.exe",["http","show","sslcert",selector]);assert.ok(visible.toLowerCase().includes(appId.toLowerCase()));assert.ok(visible.toLowerCase().includes(receipt.thumbprint.toLowerCase()));command("netsh.exe",["http","delete","sslcert",selector]);ps(`& netsh.exe http show sslcert ${selector}|Out-Null;if($LASTEXITCODE -eq 0){throw 'Owned concrete-IP shadow remains'}`);fs.unlinkSync(receiptPath);}catch(error){cleanupErrors.push(error);}
      try{const restored=await deployIisBinding({binding,certificatePem:target.observed.toString(),verifyTimeoutMs:15000});assert.equal(restored.ok,true);assert.deepEqual(preservedSnapshot(snapshot(target)),preservedSnapshot(before));assert.deepEqual(snapshot(unrelated),sibling);assert.equal((await observe(target)).fingerprint256,old.fingerprint256);}catch(error){cleanupErrors.push(error);}
    }
    if(cleanupErrors.length)throw new AggregateError([...(primaryError?[primaryError]:[]),...cleanupErrors],"Native localized IIS rollback or owned shadow cleanup failed");if(primaryError)throw primaryError;
  },{evidenceLevel:"real-host",oracle:"real owned IP TLS shadow forces actual post-bind fingerprint verification failure; native rollback preserves exact HTTP.sys/IIS metadata and sibling binding, then shadow removal independently restores trusted original SNI TLS"});
}
module.exports={qualifyIisLocale,nativeSnapshotScript};
