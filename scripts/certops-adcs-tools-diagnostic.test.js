"use strict";
// Actual PowerShell bootstrap/classification with read-only native doubles.
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),{spawnSync}=require("node:child_process");
test("Windows tools failures classify the exact metadata phase and bounded HTTP details without private text",t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),"certops-tools-error-"));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const file=path.join(dir,"probe.ps1");
 fs.writeFileSync(file,String.raw`
$ErrorActionPreference='Stop'
class FixtureHttpException : System.Exception {
 [object]$Response
 FixtureHttpException() : base('fixture-sensitive-value') {$this.Response=[pscustomobject]@{StatusCode=503}}
}
function Get-CimInstance {[pscustomobject]@{Domain='lab.certops.test'}}
function Test-Path {$false}
function New-Item {}
function Invoke-RestMethod {
 [CmdletBinding()]param($Uri,[switch]$UseBasicParsing,$TimeoutSec)
 if(-not $UseBasicParsing -or $TimeoutSec -ne 60){throw 'Metadata transfer was not bounded'}
 $record=[Management.Automation.ErrorRecord]::new([FixtureHttpException]::new(),'WebCmdletWebResponseException',[Management.Automation.ErrorCategory]::InvalidOperation,$null)
 $PSCmdlet.ThrowTerminatingError($record)
}
$failed=$false
try{& $env:TOOLS_SCRIPT -CandidateSha ('a'*40) -ApiPublicPemBase64 'AA=='}catch{
 $failed=$true
 if($_.Exception.Message -match 'fixture-sensitive-value'){throw 'Private native error escaped'}
 if($_.Exception.Message -ne 'Windows qualification tools bootstrap failed; inspect bounded step receipt'){throw 'Unexpected public failure'}
}
if(-not $failed){throw 'Metadata failure was accepted'}
Write-Output 'TOOLS_DIAGNOSTIC_TEST_PASSED'
`);
 const result=spawnSync(process.platform==="win32"?"powershell.exe":"pwsh",["-NoProfile","-NonInteractive","-File",file],{encoding:"utf8",windowsHide:true,timeout:10000,env:{...process.env,TOOLS_SCRIPT:path.resolve(__dirname,"../infra/certops-adcs/windows-tools.ps1")}});
 assert.equal(result.status,0,result.stdout+result.stderr);assert.match(result.stdout,/CERTOPS_TOOLS_FAILURE=node-metadata:(Exception|ActionPreferenceStopException):WebCmdletWebResponseException:503/);assert.doesNotMatch(result.stdout+result.stderr,/fixture-sensitive-value/);
});
test("provisioner forwards only complete allowlisted tools diagnostic records",t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),"certops-tools-stage-"));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const file=path.join(dir,"probe.ps1");
 fs.writeFileSync(file,String.raw`
$ErrorActionPreference='Stop'
$ast=[Management.Automation.Language.Parser]::ParseFile($env:PROVISION_SCRIPT,[ref]$null,[ref]$null)
$d=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-Stage'},$true)
. ([scriptblock]::Create($d.Extent.Text))
function Refresh-LabAuthentication {}
function Invoke-CertOpsVmRunCommand {[pscustomobject]@{value=@(@{message=$env:TOOLS_MESSAGE})}}
$ResourceGroup='tt-certops-123-1';$receipts=[Collections.Generic.List[string]]::new();$publicStageData=@{}
try{Invoke-Stage windows-agent $env:TOOLS_SCRIPT CERTOPS_STAGE=isolated-candidate-windows-tools-built}catch{Write-Output 'STAGE_REFUSED'}
`);
 for(const [message,accepted]of [["CERTOPS_TOOLS_FAILURE=node-download:WebException:WebCmdletWebResponseException:403",true],["CERTOPS_TOOLS_FAILURE=fixture-sensitive-value:WebException:Timeout:0",false],["CERTOPS_TOOLS_FAILURE=node-metadata:fixture-sensitive-value:Timeout:0",false],["CERTOPS_TOOLS_FAILURE=node-metadata:WebException:fixture-sensitive-value:0",false],["CERTOPS_TOOLS_FAILURE=node-metadata:WebException:Timeout:0 fixture-sensitive-value",false],["CERTOPS_TOOLS_FAILURE=node-metadata:WebException:Timeout:999",false]]){
  const result=spawnSync(process.platform==="win32"?"powershell.exe":"pwsh",["-NoProfile","-NonInteractive","-File",file],{encoding:"utf8",windowsHide:true,timeout:10000,env:{...process.env,PROVISION_SCRIPT:path.resolve(__dirname,"../infra/certops-adcs/provision-lab.ps1"),TOOLS_SCRIPT:path.resolve(__dirname,"../infra/certops-adcs/windows-tools.ps1"),TOOLS_MESSAGE:message}});
  assert.equal(result.status,0,result.stdout+result.stderr);assert.match(result.stdout,/STAGE_REFUSED/);assert.equal(result.stdout.includes('CERTOPS_TOOLS_FAILURE='),accepted);assert.doesNotMatch(result.stdout+result.stderr,/fixture-sensitive-value/);
 }
});
