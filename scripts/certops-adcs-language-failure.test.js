// Native PowerShell command doubles exercise the real language bootstrap failure
// trap. Fake SAS and exception text must never enter exported diagnostics.
'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{spawnSync}=require('node:child_process');
for(const mode of ['download','package-install'])test('language '+mode+' failure exports bounded diagnostics without private URI',()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'language-failure-'));
 const probe=path.join(directory,'probe.ps1');
 const source=path.resolve(__dirname,'../infra/certops-adcs/language-pack.ps1');
 const script=String.raw`
$ErrorActionPreference='Stop'
function Get-CimInstance { @{Domain='WORKGROUP'} }
function Invoke-WebRequest {param($Uri,$OutFile);if($env:LANGUAGE_FAILURE_MODE -eq 'download'){throw [Net.WebException]::new('SECRET_SAS_AND_EXCEPTION')};[IO.File]::WriteAllText($OutFile,'owned placeholder')}
function Get-FileHash {param($LiteralPath,$Algorithm);@{Hash='a'*64}}
function Add-WindowsPackage {param([switch]$Online,$PackagePath,[switch]$NoRestart);throw [Runtime.InteropServices.COMException]::new('SECRET_SAS_AND_EXCEPTION',-2146498530)}
$body=[IO.File]::ReadAllText($env:LANGUAGE_FAILURE_SOURCE)
# The producer targets Windows. Adapt only its directory separator when these
# command doubles run under the Linux tooling job; its ownership check remains.
if($env:LANGUAGE_TEST_UNIX -eq '1'){$body=$body.Replace(".TrimEnd('\')+'\'",".TrimEnd('/')+'/'")}
try{& ([scriptblock]::Create($body)) -Language fr-FR -PackageUri 'https://owned.blob.core.windows.net/fixture.cab?sig=SECRET_SAS_AND_EXCEPTION' -PackageSha256 ('a'*64);exit 2}catch{Write-Output 'EXPECTED_LANGUAGE_FAILURE';exit 0}
`;
 try{fs.writeFileSync(probe,script);const result=spawnSync(process.platform==='win32'?'powershell.exe':'pwsh',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',probe],{encoding:'utf8',timeout:30000,windowsHide:true,env:{...process.env,LANGUAGE_FAILURE_SOURCE:source,LANGUAGE_FAILURE_MODE:mode,LANGUAGE_TEST_UNIX:process.platform==='win32'?'0':'1',TEMP:directory}});
 assert.equal(result.status,0,result.stderr);assert.match(result.stdout,new RegExp('CERTOPS_LANGUAGE_FAILURE='+mode+':[0-9]+:-?[0-9]+:[A-Za-z]+:Unclassified'));assert.doesNotMatch(result.stdout+result.stderr,/SECRET_SAS_AND_EXCEPTION|sig=|https:\/\//);
 const provision=fs.readFileSync(path.resolve(__dirname,'../infra/certops-adcs/provision-lab.ps1'),'utf8');
 const pattern=provision.match(/\$languageDiagnostic=\[regex\]::Match\(\$message,'([^']+)'\)/)[1];
 const compatible=pattern.replace('(?m)','');assert.ok(new RegExp(compatible,'m').test(result.stdout));
 }finally{fs.rmSync(directory,{recursive:true});}
});
