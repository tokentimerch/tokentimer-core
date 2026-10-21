/*
 * Qualification notes: cng-export-refusal-qualification
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Require windows-cng-private-export-refusal on Server2022/2025 for all10 owned accepted
 * RSA2048/3072/4096 and ECP256/P384 certificates in My/WebHosting. Reopen exact
 * provider/container/size/machine identity and None export policy; verify fresh nonce signatures
 * before/after with public certificate (EC IEEE-P1363). Same-provider/profile exportable control must
 * successfully export PKCS8, while protected key must throw native cryptographic exception; retain
 * bounded HRESULT without inventing error classification. Private arrays remain inside native process,
 * are zeroed/verified in finally, never printed/written/reported; workdir unchanged. Register each
 * control before creation, retry exact cleanup and independently require native absence. Portable
 * checks are not provider/architecture/enterprise qualification.
 */
"use strict";
/* Verify native CNG custody for already owned accepted host certificates.
 * Every profile/store gets an exact disposable exportable control. Exported
 * control/private buffers stay in the PowerShell process and are zeroed in finally;
 * only public signatures, metadata and denial codes cross the process boundary.
 */
const assert=require("node:assert/strict"),crypto=require("node:crypto"),fs=require("node:fs"),path=require("node:path");
const {buildEnrollmentContainerName}=require("../../src/windows-cert-store");
const PROFILES=Object.freeze({"rsa-2048":{size:2048,algorithm:"RSA"},"rsa-3072":{size:3072,algorithm:"RSA"},"rsa-4096":{size:4096,algorithm:"RSA"},"ec-p256":{size:256,algorithm:"ECDSA_P256"},"ec-p384":{size:384,algorithm:"ECDSA_P384"}});
const CASES=Object.freeze(["My","WebHosting"].flatMap(store=>Object.keys(PROFILES).map(profile=>`${profile}/${store}`)));
function validateRecord(record){assert.ok(PROFILES[record.algorithm]);assert.ok(["My","WebHosting"].includes(record.store));assert.match(record.thumbprint,/^[A-F0-9]{40}$/);assert.match(record.containerName,/^[A-Za-z0-9_-]{1,180}$/);}
function buildExportScript(record,controlName,nonce){
 validateRecord(record);assert.match(controlName,/^[A-Za-z0-9_-]{1,180}$/);assert.equal(Buffer.from(nonce,"base64").length,32);assert.match(nonce,/^[A-Za-z0-9+/=]+$/);const profile=PROFILES[record.algorithm],rsa=profile.algorithm==="RSA";
 return `
$cert=Get-Item -LiteralPath 'Cert:\\LocalMachine\\${record.store}\\${record.thumbprint}'
$private=$null;$control=$null;$controlPrivate=$null;[byte[]]$controlBytes=$null;[byte[]]$protectedBytes=$null
$controlZeroed=$false;$protectedZeroed=$true;$result=$null
try {
 $private=${rsa?"[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)":"[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)"}
 if($null -eq $private -or $private.Key.KeyName -ne '${record.containerName}' -or $private.Key.Provider.Provider -ne 'Microsoft Software Key Storage Provider' -or $private.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None){throw 'Protected fixture key custody mismatch'}
 $nonce=[Convert]::FromBase64String('${nonce}')
 $signature=${rsa?"$private.SignData($nonce,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)":"$private.SignData($nonce,[Security.Cryptography.HashAlgorithmName]::SHA256)"}
 $parameters=[Security.Cryptography.CngKeyCreationParameters]::new();$parameters.Provider=[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
 $parameters.KeyCreationOptions=[Security.Cryptography.CngKeyCreationOptions]::MachineKey
 $parameters.ExportPolicy=[Security.Cryptography.CngExportPolicies]::AllowExport -bor [Security.Cryptography.CngExportPolicies]::AllowPlaintextExport
 ${rsa?`[void]$parameters.Parameters.Add([Security.Cryptography.CngProperty]::new('Length',[BitConverter]::GetBytes([int]${profile.size}),[Security.Cryptography.CngPropertyOptions]::None))`:""}
 $control=[Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::new('${profile.algorithm}'),'${controlName}',$parameters)
 $controlPrivate=${rsa?"[Security.Cryptography.RSACng]::new($control)":"[Security.Cryptography.ECDsaCng]::new($control)"}
 $controlBytes=[byte[]]$control.Export([Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
 if($controlBytes.Length -le 0){throw 'Exportable control did not export the supported private blob'}
 $denied=$false;$hresult=$null
 try{$protectedBytes=[byte[]]$private.Key.Export([Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)}catch{
  $exception=$_.Exception;for($index=0;$index -lt 8 -and $exception -isnot [Security.Cryptography.CryptographicException] -and $null -ne $exception.InnerException;$index++){$exception=$exception.InnerException}
  if($exception -isnot [Security.Cryptography.CryptographicException]){throw 'Private-export refusal was not a native cryptographic failure'}
  $denied=$true;$hresult=[int]$exception.HResult
 }
 $afterSignature=${rsa?"$private.SignData($nonce,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)":"$private.SignData($nonce,[Security.Cryptography.HashAlgorithmName]::SHA256)"}
 $result=@{signatureAfter=[Convert]::ToBase64String($afterSignature);signature=[Convert]::ToBase64String($signature);controlProvider=$control.Provider.Provider;controlAlgorithm=$control.Algorithm.Algorithm;controlSize=$controlPrivate.KeySize;controlExportPolicy=[int]$control.ExportPolicy;controlMachineKey=$control.IsMachineKey;controlExportSucceeded=($controlBytes.Length -gt 0);protectedExportDenied=$denied;privateExportHResult=$hresult}
} finally {
 if($null -ne $controlBytes){[Array]::Clear($controlBytes,0,$controlBytes.Length);$controlZeroed=(@($controlBytes|Where-Object{$_ -ne 0}).Count -eq 0);$controlBytes=$null}
 if($null -ne $protectedBytes){[Array]::Clear($protectedBytes,0,$protectedBytes.Length);$protectedZeroed=(@($protectedBytes|Where-Object{$_ -ne 0}).Count -eq 0);$protectedBytes=$null}
 if($private){$private.Dispose()};if($controlPrivate){$controlPrivate.Dispose()};if($control){$control.Dispose()};$cert.Dispose()
}
$result.controlBytesZeroed=$controlZeroed;$result.protectedBytesZeroed=$protectedZeroed
$result | ConvertTo-Json -Compress`;
}
function metadataScript(record){validateRecord(record);return `$c=Get-Item -LiteralPath 'Cert:\\LocalMachine\\${record.store}\\${record.thumbprint}';$private=$null;try{$private=if($c.PublicKey.Oid.Value -eq '1.2.840.113549.1.1.1'){[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)}else{[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c)};@{raw=[Convert]::ToBase64String($c.RawData);thumbprint=$c.Thumbprint;keyName=$private.Key.KeyName;uniqueName=$private.Key.UniqueName;provider=$private.Key.Provider.Provider;size=$private.KeySize;machineKey=$private.Key.IsMachineKey;exportPolicy=[int]$private.Key.ExportPolicy;hasPrivateKey=$c.HasPrivateKey}|ConvertTo-Json -Compress}finally{if($private){$private.Dispose()};$c.Dispose()}`;}
function verifySignatures(profile,nonce,key,result){const options=PROFILES[profile].algorithm==="RSA"?key:{key,dsaEncoding:"ieee-p1363"};for(const field of ["signature","signatureAfter"])assert.equal(crypto.verify("sha256",nonce,options,Buffer.from(result[field],"base64")),true,"Actual native signatures before/after refusal must verify with the independent public certificate key");}
function verifyResult(record,result,nonce,before,after){
 validateRecord(record);const profile=PROFILES[record.algorithm];assert.deepEqual(after,before,"Native certificate/container/store custody changed");
 const certificate=new crypto.X509Certificate(Buffer.from(before.raw,"base64"));assert.equal(certificate.fingerprint.replace(/:/g,""),record.thumbprint);assert.equal(before.thumbprint,record.thumbprint);assert.equal(before.keyName,record.containerName);assert.equal(before.provider,"Microsoft Software Key Storage Provider");assert.equal(before.size,profile.size);assert.equal(before.exportPolicy,0);assert.equal(before.machineKey,true);assert.equal(before.hasPrivateKey,true);
 assert.equal(result.controlProvider,before.provider);assert.equal(result.controlAlgorithm,profile.algorithm);assert.equal(result.controlSize,profile.size);assert.equal(result.controlExportPolicy,3);assert.equal(result.controlMachineKey,true);
 for(const field of ["controlExportSucceeded","protectedExportDenied","controlBytesZeroed","protectedBytesZeroed"])assert.equal(result[field],true,field);
 assert.ok(Number.isInteger(result.privateExportHResult)&&result.privateExportHResult<0&&result.privateExportHResult>=-2147483648);
 verifySignatures(record.algorithm,nonce,certificate.publicKey,result);
}
function verifyCustodyProof(value){assert.equal(value.privateExportBytesWritten,false);assert.equal(value.privateExportBytesReported,false);assert.equal(value.workDirectoryUnchanged,true);assert.equal(value.cases.length,CASES.length);const seen=new Set();for(const item of value.cases){assert.ok(CASES.includes(item.caseId));assert.equal(seen.has(item.caseId),false);seen.add(item.caseId);for(const key of ["exportableControlSucceeded","controlBytesZeroed","protectedBytesZeroed","protectedExportDenied","publicNonceSignatureVerified","originalCustodyUnchanged","controlKeyRemoved"])assert.equal(item[key],true,key);assert.ok(Number.isInteger(item.privateExportHResult)&&item.privateExportHResult<0&&item.privateExportHResult>=-2147483648);}return true;}
function files(directory){const items=[];for(const name of fs.readdirSync(directory)){const file=path.join(directory,name),stat=fs.lstatSync(file);assert.equal(stat.isSymbolicLink(),false);if(stat.isDirectory())for(const item of files(file))items.push([`${name}/${item[0]}`,item[1]]);else if(stat.isFile())items.push([name,crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex")]);}return items.sort((a,b)=>a[0].localeCompare(b[0]));}
function buildCleanupScript(name){assert.match(name,/^[A-Za-z0-9_-]{1,180}$/);return `$provider=[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider;$options=[Security.Cryptography.CngKeyOpenOptions]::MachineKey;if([Security.Cryptography.CngKey]::Exists('${name}',$provider,$options)){$key=[Security.Cryptography.CngKey]::Open('${name}',$provider,$options);try{$key.Delete()}finally{$key.Dispose()}};if([Security.Cryptography.CngKey]::Exists('${name}',$provider,$options)){throw 'Owned exportable control remains'};'absent'`;}
async function qualifyCngExportRefusal({powershell,records,containers,workDir,gate}){
 assert.equal(process.platform,"win32");assert.equal(process.env.CERTOPS_HOST_TESTS,"1");assert.equal(records.length,CASES.length);assert.deepEqual(records.map(record=>`${record.algorithm}/${record.store}`).sort(),[...CASES].sort());
 const initialFiles=files(workDir),controls=[],proof=[];let primary;const errors=[];
 const cleanup=name=>assert.equal(powershell(buildCleanupScript(name)),"absent");
 try{
  for(const record of records){validateRecord(record);const before=JSON.parse(powershell(metadataScript(record))),nonce=crypto.randomBytes(32),controlName=buildEnrollmentContainerName(crypto.randomUUID());
   assert.equal(powershell(`[Security.Cryptography.CngKey]::Exists('${controlName}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)`),"False");controls.push(controlName);containers.push(controlName);let result,caseError;
   try{result=JSON.parse(powershell(buildExportScript(record,controlName,nonce.toString("base64"))));verifyResult(record,result,nonce,before,JSON.parse(powershell(metadataScript(record))));}
   catch(error){caseError=error;throw error;}finally{try{cleanup(controlName);}catch(error){if(caseError)throw new AggregateError([caseError,error],"CNG case and control cleanup failed");throw error;}}
   proof.push({caseId:`${record.algorithm}/${record.store}`,exportableControlSucceeded:true,controlBytesZeroed:true,protectedBytesZeroed:true,protectedExportDenied:true,publicNonceSignatureVerified:true,originalCustodyUnchanged:true,controlKeyRemoved:true,privateExportHResult:result.privateExportHResult});
  }
  assert.deepEqual(files(workDir),initialFiles,"Private export test must create or modify no work-directory files");const facts={privateExportBytesWritten:false,privateExportBytesReported:false,workDirectoryUnchanged:true,cases:proof};verifyCustodyProof(facts);gate.report.cngCustody=facts;
  const file="packages/agent/scripts/host/cng-export-fixture.js";gate.report.fixtureSources||=[];gate.report.fixtureSources.push({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")});
 }catch(error){primary=error;}
 finally{for(const name of controls){try{cleanup(name);}catch(error){errors.push(error);}}}
 if(errors.length)throw new AggregateError(primary?[primary,...errors]:errors,"CNG export refusal and exact control cleanup failed");if(primary)throw primary;
}
module.exports={PROFILES,CASES,buildExportScript,metadataScript,buildCleanupScript,verifyResult,verifySignatures,verifyCustodyProof,qualifyCngExportRefusal};
