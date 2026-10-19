"use strict";
/* Shared owned program-scoped CRL outage fixture. Snapshots/restores the exact global chain-cache
 * value, requires actual native revocation_unknown, and removes only its verified firewall rule.
 * Called only by the protected disposable-forest AD CS harness; native qualification requires
 * that workflow to execute.
 */
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto"),net=require("node:net");
const {execFile}=require("node:child_process");
const {promisify}=require("node:util");
const {resolveAdcsChainHelperPath,validateCertificateChain}=require("../../../packages/agent/src/issuers/chain-helper");
const execFileAsync=promisify(execFile);
function nativeProbeEnvironment(){const env={};for(const key of ["PATH","SystemRoot","WINDIR","COMSPEC","TEMP","TMP"])if(process.env[key])env[key]=process.env[key];return env;}
function createCrlFault({gate,workDir,run,observed,authority,command,ps,ownedFirewallRules}){
  assert.equal(process.platform,"win32");assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB,"1");assert.equal(ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),"S-1-5-18");
  const source="tests/e2e/helpers/certops-adcs-crl-fault.js";gate.report.fixtureSources??=[];if(!gate.report.fixtureSources.some(value=>value.file===source))gate.report.fixtureSources.push({file:source,sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")});
  const resolved=resolveAdcsChainHelperPath();assert.equal(resolved.error,undefined);const program=path.resolve(resolved.path),escaped=program.replace(/'/g,"''");
  const suffix=crypto.randomBytes(4).toString("hex"),rule=`TTQualificationChainCRL-${run}-${suffix}`;
  const leafPath=path.join(workDir,`crl-probe-${suffix}.cer`),caPath=path.join(workDir,`crl-authority-${suffix}.cer`);
  fs.writeFileSync(leafPath,observed.raw);fs.writeFileSync(caPath,Buffer.from(authority.certificateB64,"base64"));
  const cdp=ps(`$c=[Security.Cryptography.X509Certificates.X509Certificate2]::new('${leafPath.replace(/'/g,"''")}');try{$e=@($c.Extensions|Where-Object {$_.Oid.Value -eq '2.5.29.31'});if($e.Count -ne 1){throw 'Expected actual CDP extension'};$e[0].Format($true)}finally{$c.Dispose()}`);
  assert.match(cdp,/ldap:\/\//i);assert.doesNotMatch(cdp,/https?:\/\//i,"LDAP-only fault cannot qualify another CRL transport");
  const cacheSnapshot=path.join(workDir,`crl-cache-${suffix}.clixml`),escapedSnapshot=cacheSnapshot.replace(/'/g,"''");
  ps(`$key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CertDllCreateCertificateChainEngine\\Config');try{$exists=$key -and @($key.GetValueNames()) -contains 'ChainCacheResyncFiletime';$state=@{exists=[bool]$exists};if($exists){$state.kind=$key.GetValueKind('ChainCacheResyncFiletime').ToString();if($state.kind -notin @('QWord','Binary')){throw 'Refusing unsupported native chain-cache value kind'};$state.value=$key.GetValue('ChainCacheResyncFiletime')};$state|Export-Clixml -LiteralPath '${escapedSnapshot}' -NoClobber}finally{if($key){$key.Dispose()}}`);
  let owned=false,cacheRestored=false;
  const restoreCache=()=>{assert.equal(ps(`$state=Import-Clixml -LiteralPath '${escapedSnapshot}';$key=[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CertDllCreateCertificateChainEngine\\Config');try{if($state.exists){$kind=[Microsoft.Win32.RegistryValueKind][Enum]::Parse([Microsoft.Win32.RegistryValueKind],$state.kind);if($state.kind -eq 'Binary'){$expected=[byte[]]$state.value;$key.SetValue('ChainCacheResyncFiletime',$expected,$kind);$equal=[Convert]::ToBase64String([byte[]]$key.GetValue('ChainCacheResyncFiletime')) -ceq [Convert]::ToBase64String($expected)}else{$key.SetValue('ChainCacheResyncFiletime',[long]$state.value,$kind);$equal=[long]$key.GetValue('ChainCacheResyncFiletime') -eq [long]$state.value};if($key.GetValueKind('ChainCacheResyncFiletime').ToString() -ne $state.kind -or -not $equal){throw 'Original native chain-cache value restoration mismatch'}}else{$key.DeleteValue('ChainCacheResyncFiletime',$false);if(@($key.GetValueNames()) -contains 'ChainCacheResyncFiletime'){throw 'Original absent native chain-cache value remains'}};'original-chain-cache-value-restored'}finally{$key.Dispose()}`),"original-chain-cache-value-restored");cacheRestored=true;};
  const clearCache=()=>{command("certutil.exe",["-urlcache","CRL","delete"]);command("certutil.exe",["-setreg","chain\\ChainCacheResyncFiletime","@now"]);};
  const probe=()=>validateCertificateChain({helperPath:program,certPath:leafPath,caKeySha256:authority.keySha256,caCertPath:caPath,revocationCheck:"require",execFileImpl:(file,args,options)=>execFileAsync(file,args,{...options,env:nativeProbeEnvironment()})});
  const fault={
    get cacheRestored(){return cacheRestored;},
    rule,programSha256:crypto.createHash("sha256").update(fs.readFileSync(program)).digest("hex"),
    probe,clearCache,
    async install(){
      assert.equal(ps(`@(Get-NetFirewallRule -Name '${rule}' -ErrorAction SilentlyContinue).Count`),"0");owned=true;ownedFirewallRules.push(rule);
      ps(`New-NetFirewallRule -Name '${rule}' -DisplayName '${rule}' -Direction Outbound -Action Block -Program '${escaped}' -RemoteAddress '10.64.0.4' -Protocol TCP -RemotePort 389,636 | Out-Null`);
      // Template preflight uses another executable. Keep the actual CA online
      // and prove this fault did not block all callers before first-submit safety.
      const reachable=await new Promise(resolve=>{const socket=net.createConnection({host:"10.64.0.4",port:389},()=>{socket.destroy();resolve(true);});socket.setTimeout(3000,()=>{socket.destroy();resolve(false);});socket.once("error",()=>{socket.destroy();resolve(false);});});assert.equal(reachable,true,"CA LDAP must remain available outside the chain-helper fault");
      clearCache();assert.equal((await probe()).verdict,"revocation_unknown","Actual protected chain-helper process must observe revocation unavailability");
    },
    restore(){
      if(owned){ps(`$r=Get-NetFirewallRule -Name '${rule}' -ErrorAction SilentlyContinue;if($r){$application=$r|Get-NetFirewallApplicationFilter;if($r.DisplayName -ne '${rule}' -or $application.Program -ine '${escaped}'){throw 'Refusing replacement CRL firewall rule'};Remove-NetFirewallRule -Name '${rule}'}`);owned=false;}
      clearCache();
    },
    cleanup(){for(const file of [leafPath,caPath,...(cacheRestored?[cacheSnapshot]:[])]){assert.equal(path.dirname(file),workDir);if(fs.existsSync(file)){assert.ok(!fs.lstatSync(file).isSymbolicLink());fs.unlinkSync(file);}}}
  };
  fault.close=async primaryError=>{const failures=[];try{fault.restore();assert.equal((await fault.probe()).verdict,"valid","Actual native chain verification must recover after owned firewall removal");}catch(error){failures.push(error);}try{restoreCache();}catch(error){failures.push(error);}try{fault.cleanup();}catch(error){failures.push(error);}if(failures.length)throw new AggregateError([...(primaryError?[primaryError]:[]),...failures],"Owned CRL fault cleanup failed");};
  return fault;
}
module.exports={createCrlFault};
