/*
 * Qualification notes: native-discovery-qualification
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * windows-discovery-http-sys-selectors owns2 CNG certificates/3 bindings:IPv4ipport,IPv6ipport,non-IIS
 * hostnameport. Move one certificate toWebHosting while configuring productionMy-only:referenced store
 * must auto-include. Native registry/publicDER SHA256 bind
 * selector,AppID,store,thumbprint,address/hostname/port,LocalMachine/key-presence without invented
 * IIS. Cleanup compares original coordinates/AppIDs/hashes/stores/flags;changedAppID/hash forbids
 * deletion. CCS enumeration and realTLS listener/remote deployment outside this case.
 * Run elevated disposable host native discovery with independent certutil/HTTP.sys registry/TLS
 * oracles. Compare exact machine-store boundaries, certificate/provider/key identity and known binding
 * settings; malformed/unknown/incomplete native metadata or missing/incompatible PowerShell must fail
 * before mutation rather than become empty inventory. Preserve owned endpoint hash/TLS while injecting
 * supported metadata faults and restore exact originals in cleanup. Actual configured runtime
 * execution is required; portable decoder/source tests are supporting only.
 */
"use strict";
/* Native discovery coverage for the protected disposable Windows host lane.
 * Owns three HTTP.sys selectors and two certificate receipts, compares production
 * observations with independently read native registry/public DER facts, then
 * removes only matching application/certificate identities. Never run on a user host.
 */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { freePort } = require("./iis-fixture");
const { collectWindowsDiscoveryObservations } = require("../../src/discovery/windows");

const inventoryScript = String.raw`
$rows=@(); $root='HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters'
foreach($kind in @('SslBindingInfo','SslSniBindingInfo')) {
 $base=Join-Path $root $kind
 if(Test-Path -LiteralPath $base) { foreach($key in Get-ChildItem -LiteralPath $base) {
  $v=Get-ItemProperty -LiteralPath $key.PSPath
  $selector=if($kind -eq 'SslSniBindingInfo') { [string]$v.HostnamePort } else { [string]$key.PSChildName }
  $rows+=@{kind=$kind;selector=$selector;appId=([guid]::new([byte[]]$v.AppId)).ToString();thumbprint=([BitConverter]::ToString([byte[]]$v.SslCertHash)).Replace('-','');store=[string]$v.SslCertStoreName;flags=$v.DefaultFlags}
 }}
}
ConvertTo-Json -InputObject @($rows | Sort-Object kind,selector) -Compress -Depth 4`;
function verifyObservations(expected, native, observations) {
  for (const item of expected) {
    const actual=native.filter(row=>row.selector.toLowerCase()===item.selector.toLowerCase()&&row.kind===item.kind);
    assert.equal(actual.length,1,"Exactly one native selector must exist");
    assert.equal(actual[0].appId.toLowerCase(),item.appId);assert.equal(actual[0].thumbprint,item.thumbprint);assert.equal(actual[0].store.toLowerCase(),item.store.toLowerCase());
    const found=observations.filter(row=>row.locationKind==="http_sys"&&row.boundAddress===item.address&&row.port===item.port);
    assert.equal(found.length,1,"Standalone selector must be observed exactly once without an IIS site");
    assert.equal(found[0].fingerprintSha256,item.fingerprint);assert.equal(found[0].thumbprint.toUpperCase(),item.thumbprint);assert.equal(found[0].storeName.toLowerCase(),item.store.toLowerCase());assert.equal(found[0].storeLocation,"LocalMachine");assert.equal(found[0].keyPresent,true);
    assert.equal(found[0].locationSlot,`${item.address}:${item.port}`);
  }
}
async function qualifyHttpSysDiscovery({powershell,run,workDir,gate}) {
  assert.equal(process.platform,"win32");assert.equal(process.env.CERTOPS_HOST_TESTS,"1");
  const token=crypto.randomBytes(8).toString("hex"),appId=crypto.randomUUID(),owned=path.join(workDir,`discovery-http-${token}`);
  fs.mkdirSync(owned);const quote=value=>value.replace(/'/g,"''");
  const native=()=>JSON.parse(powershell(inventoryScript));let baseline;
  const ports=[];
  const host=`certops-${token}.example.test`;
  const expected=[];let primary;
  try {
    baseline=native();
    while(ports.length<3){const candidate=await freePort();if(!ports.includes(candidate))ports.push(candidate);}
    const specifications=[{kind:"SslBindingInfo",key:"ipport",address:"127.0.0.1",selector:`127.0.0.1:${ports[0]}`,port:ports[0],store:"My",certificate:0},{kind:"SslBindingInfo",key:"ipport",address:"::1",selector:`[::1]:${ports[1]}`,port:ports[1],store:"WebHosting",certificate:1},{kind:"SslSniBindingInfo",key:"hostnameport",address:host,selector:`${host}:${ports[2]}`,port:ports[2],store:"WebHosting",certificate:1}];
    for(let index=0;index<2;index++) {
      const receipt=quote(path.join(owned,`${index}.thumbprint`)), keyReceipt=quote(path.join(owned,`${index}.key-name`));
      powershell(`$cert=New-SelfSignedCertificate -DnsName '${host}' -CertStoreLocation 'Cert:\\LocalMachine\\My' -KeyAlgorithm RSA -KeyLength 2048 -KeyExportPolicy NonExportable -Provider 'Microsoft Software Key Storage Provider'; [IO.File]::WriteAllText('${receipt}',$cert.Thumbprint); $rsa=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert); try { if($rsa -isnot [Security.Cryptography.RSACng]){throw 'Fixture key is not CNG'}; [IO.File]::WriteAllText('${keyReceipt}',$rsa.Key.UniqueName) } finally { $rsa.Dispose() }; ${index===1?"Move-Item -LiteralPath ('Cert:\\LocalMachine\\My\\'+$cert.Thumbprint) -Destination 'Cert:\\LocalMachine\\WebHosting'":""}`);
    }
    for(const specification of specifications) {
      const thumbprint=fs.readFileSync(path.join(owned,`${specification.certificate}.thumbprint`),"utf8").trim();assert.match(thumbprint,/^[A-F0-9]{40}$/);
      const publicData=JSON.parse(powershell(`$cert=Get-Item -LiteralPath 'Cert:\\LocalMachine\\${specification.store}\\${thumbprint}'; @{raw=[Convert]::ToBase64String($cert.RawData);hasPrivateKey=$cert.HasPrivateKey} | ConvertTo-Json -Compress`));assert.equal(publicData.hasPrivateKey,true);
      const fingerprint=new crypto.X509Certificate(Buffer.from(publicData.raw,"base64")).fingerprint256.replace(/:/g,"").toLowerCase();
      assert.equal(baseline.some(row=>row.selector.toLowerCase()===specification.selector.toLowerCase()),false,"Refuse preexisting native selector");
      powershell(`& netsh.exe http show sslcert '${specification.key}=${specification.selector}' | Out-Null; if($LASTEXITCODE -eq 0){throw 'Refuse existing native selector'}`);
      expected.push({...specification,appId,thumbprint,fingerprint});
      run("netsh.exe",["http","add","sslcert",`${specification.key}=${specification.selector}`,`certhash=${thumbprint}`,`appid={${appId}}`,`certstorename=${specification.store}`]);
      run("netsh.exe",["http","show","sslcert",`${specification.key}=${specification.selector}`]);
    }
    const warnings=[],observations=await collectWindowsDiscoveryObservations({stores:["My"],onWarning:warning=>warnings.push(warning)});
    verifyObservations(expected,native(),observations);
    assert.ok(observations.some(row=>row.locationKind==="windows_store"&&row.storeName==="WebHosting"&&row.thumbprint.toUpperCase()===expected[1].thumbprint),"Binding-referenced store must be inventoried without configuring it");
    const file="packages/agent/scripts/host/discovery-http-sys-fixture.js";gate.report.fixtureSources||=[];gate.report.fixtureSources.push({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")});
    gate.report.httpSysDiscovery={selectors:["ipv4-ipport","ipv6-ipport","hostnameport"],bindingReferencedStore:"WebHosting",configuredStores:["My"],independentPublicDer:true,ccs:"unsupported-not-enumerated"};
  } catch(error){primary=error;throw error;}
  finally {
    const failures=[];
    for(const item of expected){try{const current=native().filter(row=>row.kind===item.kind&&row.selector.toLowerCase()===item.selector.toLowerCase());if(current.length){assert.equal(current.length,1);assert.equal(current[0].appId.toLowerCase(),appId);assert.equal(current[0].thumbprint,item.thumbprint);run("netsh.exe",["http","delete","sslcert",`${item.key}=${item.selector}`]);}}catch(error){failures.push(error);}}
    for(let index=0;index<2;index++){try{const receipt=path.join(owned,`${index}.thumbprint`);if(!fs.existsSync(receipt))continue;const thumbprint=fs.readFileSync(receipt,"utf8").trim();assert.match(thumbprint,/^[A-F0-9]{40}$/);powershell(`foreach($store in @('My','WebHosting')){$p='Cert:\\LocalMachine\\'+$store+'\\${thumbprint}';if(Test-Path -LiteralPath $p){Remove-Item -LiteralPath $p -DeleteKey};if(Test-Path -LiteralPath $p){throw 'Owned discovery certificate remains'}}`);const keyReceipt=path.join(owned,`${index}.key-name`);if(fs.existsSync(keyReceipt)){const keyName=fs.readFileSync(keyReceipt,'utf8').trim();assert.match(keyName,/^[A-Za-z0-9_-]{1,256}$/);powershell(`if(Test-Path -LiteralPath (Join-Path $env:ProgramData 'Microsoft\\Crypto\\Keys\\${keyName}')){throw 'Owned discovery CNG key remains'}`);}}catch(error){failures.push(error);}}
    try{if(baseline)assert.deepEqual(native(),baseline,"All original native bindings must remain unchanged");}catch(error){failures.push(error);}
    if(failures.length)throw new AggregateError(primary?[primary,...failures]:failures,"Owned HTTP.sys discovery cleanup failed");
    fs.rmSync(owned,{recursive:true});
  }
}
module.exports={qualifyHttpSysDiscovery,verifyObservations,inventoryScript};
