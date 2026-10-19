"use strict";
// Execute the actual guest PowerShell bootstrap with native AD/servicing doubles.
// These are orchestration regressions; real domain setup remains a native gate.
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),{spawnSync}=require("node:child_process");
function run(t,mode){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),"adcs-ca-bootstrap-"));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const script=path.join(dir,"domain-ca.ps1"),wrapper=path.join(dir,"wrapper.ps1");
 fs.writeFileSync(script,fs.readFileSync(path.resolve(__dirname,"../infra/certops-adcs/domain-ca.ps1"),"utf8").replaceAll("C:\\ttqualification",dir.replaceAll("'","''")));
 fs.writeFileSync(wrapper,String.raw`
$ErrorActionPreference='Stop'
function ConvertTo-SecureString {param($String,[switch]$AsPlainText,[switch]$Force)$secret=[Security.SecureString]::new();foreach($c in $String.ToCharArray()){$secret.AppendChar($c)};$secret}
$global:stopped=$false;$global:removed=$false;$global:roleCalls=0;$global:received=$false
function Get-CimInstance {param($ClassName)[pscustomobject]@{Domain='lab.certops.test'}}
function Import-Module {param($Name)}
function Get-ADDomain {[pscustomobject]@{DomainSID=[pscustomobject]@{Value='fixture-sid'}}}
function Enable-PSRemoting {param([switch]$Force)}
function New-PSSessionOption {param($OpenTimeout,$OperationTimeout)if($OpenTimeout -ne 30000 -or $OperationTimeout -ne 60000){throw 'Missing bounded connection settings'};@{Fixture=$true}}
function Set-DnsServerForwarder {param($IPAddress)}
function New-ADUser {param($Name,$SamAccountName,$AccountPassword,$Enabled)}
function Add-ADGroupMember {param($Identity,$Members)}
function Get-ADPrincipalGroupMembership {param($Identity)@{SID=@{Value='fixture-sid-512'}},@{SID=@{Value='fixture-sid-519'}}}
function Test-Path {param($Path)if($Path -like 'HKLM:*'){return $false};Microsoft.PowerShell.Management\Test-Path $Path}
function Install-WindowsFeature {param($Name,[switch]$IncludeManagementTools)$global:roleCalls++;if($env:CA_MODE -eq 'role-failure'){throw 'fixture-sensitive-password'};[pscustomobject]@{Success=$true;RestartNeeded='No'}}
function Install-AdcsCertificationAuthority {param($CAType,$CACommonName,$CryptoProviderName,$KeyLength,$HashAlgorithmName,$ValidityPeriod,$ValidityPeriodUnits,[switch]$Force)}
function Get-Service {param($Name)[pscustomobject]@{Status='Running'}}
function Invoke-Command {
 param($ComputerName,$Credential,$SessionOption,[switch]$AsJob,$ArgumentList,$ScriptBlock)
 if(-not $AsJob -or $ComputerName -ne 'localhost' -or $Credential.UserName -ne 'TTQUAL\ttqualification'){throw 'Unbound remoting invocation'}
 $global:capturedError=$null;$global:jobOutput=@()
 if($env:CA_MODE -ne 'timeout'){try{$global:jobOutput=@(& $ScriptBlock @ArgumentList)}catch{$global:capturedError=$_}}
 [pscustomobject]@{State=$(if($env:CA_MODE -eq 'timeout'){'Running'}elseif($global:capturedError){'Failed'}else{'Completed'})}
}
function Wait-Job {param($Job,$Timeout)if($Timeout -ne 600){throw 'Execution deadline changed'};if($env:CA_MODE -ne 'timeout'){$Job}}
function Receive-Job {param($Job,$ErrorAction)$global:received=$true;if($global:capturedError){throw $global:capturedError};$global:jobOutput}
function Stop-Job {param($Job,$ErrorAction)$global:stopped=$true;$Job.State='Stopped'}
function Remove-Job {param($Job,[switch]$Force,$ErrorAction)$global:removed=$true}
$failed=$false
try{& $env:CA_SCRIPT -DomainPassword 'fixture-sensitive-password'}catch{$failed=$true;Write-Output ($_.Exception.Message.Replace('fixture-sensitive-password','[redacted]'));if($_.Exception.Message -match 'fixture-sensitive-password'){throw 'Private error escaped'}}
$receipt=Get-Content (Join-Path (Split-Path $env:CA_SCRIPT) 'domain-ca-stage.json') -Raw|ConvertFrom-Json
if(-not $global:removed){throw 'Owned remoting job was retained'}
if($env:CA_MODE -eq 'success'){
 if($failed -or $receipt.status -ne 'completed' -or $receipt.stage -ne 'service-check' -or $global:roleCalls -ne 1 -or -not $global:received){throw 'Normal CA path failed'}
}elseif($env:CA_MODE -eq 'timeout'){
 if(-not $failed -or $receipt.status -ne 'failed' -or $receipt.timedOut -ne $true -or $receipt.stage -ne 'remoting-setup' -or -not $global:stopped -or $global:received -or $global:roleCalls -ne 0){throw 'Timeout failed to contain stalled job'}
}else{
 if(-not $failed -or $receipt.status -ne 'failed' -or $receipt.stage -ne 'role-install' -or $global:roleCalls -ne 1){throw 'Role failure was not classified without a retry'}
}
Write-Output ('CA_FIXTURE_OK='+$env:CA_MODE)
`);
 return spawnSync(process.platform==="win32"?"powershell.exe":"pwsh",["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",wrapper],{encoding:"utf8",windowsHide:true,timeout:20000,env:{...process.env,CA_MODE:mode,CA_SCRIPT:script}});
}
for(const mode of ["success","timeout","role-failure"])test(`CA bootstrap ${mode} executes once with bounded sanitized diagnosis`,t=>{const result=run(t,mode);assert.equal(result.status,0,result.stderr+result.stdout);assert.match(result.stdout,new RegExp(`CA_FIXTURE_OK=${mode}`));assert.doesNotMatch(result.stdout+result.stderr,/fixture-sensitive-password/);});

test("real provisioner forwards only bounded CA phases and gives only CA setup a 900s outer deadline",t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),"adcs-ca-stage-"));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const wrapper=path.join(dir,"stage.ps1");
 fs.writeFileSync(wrapper,String.raw`
$ErrorActionPreference='Stop'
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CA_PROVISION,[ref]$null,[ref]$null)
$definition=$ast.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-Stage'},$true)
. ([scriptblock]::Create($definition.Extent.Text))
function Refresh-LabAuthentication {}
function Invoke-CertOpsVmRunCommand {
 param($SubscriptionId,$ResourceGroup,$Machine,$Script,$Parameters,$TimeoutSeconds,$RefreshAuthentication)
 if($TimeoutSeconds -ne [int]$env:CA_EXPECT_TIMEOUT){throw 'Wrong outer bootstrap timeout'}
 [pscustomobject]@{value=@([pscustomobject]@{message=$env:CA_RESPONSE})}
}
$ResourceGroup='tt-certops-123-1';$receipts=[Collections.Generic.List[string]]::new();$publicStageData=@{}
Invoke-Stage domain-ca $env:CA_STAGE_SCRIPT 'CERTOPS_STAGE=enterprise-ca-service-running'
`);
 const invoke=(leaf,response)=>spawnSync(process.platform==="win32"?"powershell.exe":"pwsh",["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",wrapper],{encoding:"utf8",windowsHide:true,timeout:10000,env:{...process.env,CA_PROVISION:path.resolve(__dirname,"../infra/certops-adcs/provision-lab.ps1"),CA_STAGE_SCRIPT:path.resolve(__dirname,"../infra/certops-adcs",leaf),CA_EXPECT_TIMEOUT:leaf==="domain-ca.ps1"?"900":"3600",CA_RESPONSE:response}});
 const failed=invoke("domain-ca.ps1","private-credential-needle\nCERTOPS_CA_FAILED_STAGE=role-install\n");
 assert.notEqual(failed.status,0);assert.match(failed.stdout,/CERTOPS_CA_FAILED_STAGE=role-install/);assert.doesNotMatch(failed.stdout+failed.stderr,/private-credential-needle|Wrong outer/);
 for(const phase of ["private-credential-needle","role-install private-credential-needle","role-install\\nprivate-credential-needle"]){const bad=invoke("domain-ca.ps1",`CERTOPS_CA_FAILED_STAGE=${phase}`);assert.notEqual(bad.status,0);assert.doesNotMatch(bad.stdout+bad.stderr,/private-credential-needle|CERTOPS_CA_FAILED_STAGE=/);}
 const ordinary=invoke("templates.ps1","CERTOPS_STAGE=enterprise-ca-service-running");assert.equal(ordinary.status,0,ordinary.stderr);
});
