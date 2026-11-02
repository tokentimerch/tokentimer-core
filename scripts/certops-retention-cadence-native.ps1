<#
Read-only SYSTEM oracle for the installed default retention timer campaign.
Checks the sole owned service process, omitted timing defaults and native custody.
It never starts/stops a service, invokes a collector, or mutates a certificate/key.
#>
param(
 [Parameter(Mandatory)][ValidatePattern('^C:\\ttqualification\\retention-cadence\\[a-f0-9]{64}\\observer-config.json$')][string]$ConfigPath,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ConfigSha256
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if($env:CERTOPS_ADCS_DISPOSABLE_LAB -ne '1' -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'Owned disposable SYSTEM observer required'}
# Hash and parse the same bytes; the caller separately guards the file identity.
$bytes=[IO.File]::ReadAllBytes($ConfigPath)
$hash=[Security.Cryptography.SHA256]::Create()
try{$actual=[BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
if($actual -cne $ConfigSha256){throw 'Frozen observer configuration changed'}
$c=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json
if($ConfigPath -cne "C:\ttqualification\retention-cadence\$($c.lease.nonce)\observer-config.json"){throw 'Observer scope mismatch'}
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Disposable domain membership required'}
$os=Get-CimInstance Win32_OperatingSystem
if($os.BuildNumber -ne '20348' -or $os.ProductType -ne 3 -or (Get-UICulture).Name -ne 'en-US' -or (Get-WinSystemLocale).Name -ne 'en-US'){throw 'Server2022 en-US required'}
$metadata=Invoke-RestMethod -Uri 'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01' -Headers @{Metadata='true'} -TimeoutSec 5
if($metadata.vmId -cne $c.lease.vmId -or $metadata.resourceId -ine $c.lease.vmResourceId){throw 'Azure VM identity changed'}
$runtime=Get-Content -LiteralPath 'C:\ttqualification\runtime.json' -Raw|ConvertFrom-Json
$entry=Join-Path $runtime.source 'packages\agent\bin\tokentimer-agent.js'
$hostExe=Join-Path $runtime.source 'packages\agent\bin\tokentimer-agent-host-amd64.exe'
$service=Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'"
if(!$service -or $service.State -ne 'Running' -or $service.ProcessId -le 0 -or $service.StartName -ne 'LocalSystem'){throw 'Owned installed SYSTEM service is not running'}
if($service.PathName -cne ('"'+$hostExe+'" "'+$runtime.node+'" "'+$entry+'"')){throw 'Installed service command changed'}
$registry=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\TokenTimerAgent'
if($registry.PSObject.Properties.Name -contains 'FailureActions'){throw 'SCM recovery configuration is not owned'}
$envValues=@($registry.Environment)
if(@($envValues|Where-Object {$_ -ceq "TOKENTIMER_AGENT_CONFIG_DIR=$($c.stateDir)"}).Count -ne 1){throw 'Installed service configuration path changed'}
$rawConfig=Get-Content -LiteralPath (Join-Path $c.stateDir 'config.json') -Raw|ConvertFrom-Json
if(!$rawConfig.windows -or @($rawConfig.windows.PSObject.Properties.Name|Where-Object {$_ -in @('sweepIntervalMs','supersededRetentionHours')}).Count -ne 0){throw 'Production retention timing overrides are forbidden'}
$all=@(Get-CimInstance Win32_Process)
$hostRows=@($all|Where-Object {$_.ProcessId -eq $service.ProcessId -and $_.ExecutablePath -ieq $hostExe})
$agents=@($all|Where-Object {$_.ParentProcessId -eq $service.ProcessId -and $_.ExecutablePath -ieq $runtime.node})
if($hostRows.Count -ne 1 -or $agents.Count -ne 1){throw 'Exact sole installed service tree required'}
$agent=$agents[0]
# Native argv parsing avoids treating a substring or alternate quoting as proof.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class CadenceCommandLine {
 [DllImport("shell32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern IntPtr CommandLineToArgvW(string text, out int count);
 [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
 public static string[] Parse(string text) {
  int count; IntPtr value=CommandLineToArgvW(text,out count);
  if(value==IntPtr.Zero || count<1 || count>16) throw new InvalidOperationException("Bounded native arguments required");
  try { var result=new string[count]; for(int i=0;i<count;i++) result[i]=Marshal.PtrToStringUni(Marshal.ReadIntPtr(value,i*IntPtr.Size)); return result; }
  finally { LocalFree(value); }
 }
}
'@
$argv=[CadenceCommandLine]::Parse($agent.CommandLine)
if($argv.Count -ne 2 -or $argv[0] -cne $runtime.node -or $argv[1] -cne $entry){throw 'Installed Node arguments changed'}
foreach($p in @($hostRows[0],$agent)){
 $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid
 if($owner.ReturnValue -ne 0 -or $owner.Sid -ne 'S-1-5-18'){throw 'Installed process authority changed'}
}
# No native operation child may race the read-only cadence observation.
if(@($all|Where-Object {$_.ParentProcessId -eq $agent.ProcessId}).Count -ne 0){throw 'RETENTION_CADENCE_NATIVE_CHILD_BUSY'}
if(@($all|Where-Object {$_.ExecutablePath -ieq $hostExe}).Count -ne 1){throw 'Another installed agent host exists'}
if(@($all|Where-Object {$_.ProcessId -ne $agent.ProcessId -and $_.CommandLine -and $_.CommandLine.Contains($entry)}).Count -ne 1){throw 'Unexpected agent entry process inventory'}
Import-Module WebAdministration
$bindings=@(Get-WebBinding -Name $c.site -Protocol https|Where-Object {$_.bindingInformation -ceq "*:$($c.port):$($c.domain)"})
if($bindings.Count -ne 1 -or [int]$bindings[0].sslFlags -ne 1){throw 'Exact native IIS SNI binding changed'}
$iisHash=if($bindings[0].certificateHash -is [byte[]]){[BitConverter]::ToString($bindings[0].certificateHash).Replace('-','')}else{([string]$bindings[0].certificateHash).Replace(' ','').ToUpperInvariant()}
if($iisHash -cne $c.replacement.thumbprint -or [string]$bindings[0].certificateStoreName -ine 'My'){throw 'Exact IIS replacement certificate or store changed'}
function Assert-Custody($item){
 if($item.thumbprint -cnotmatch '^[A-F0-9]{40}$' -or $item.containerName -cnotmatch '^tokentimer-enr-[a-f0-9-]{36}$'){throw 'Invalid exact native identity'}
 $cert=Get-Item -LiteralPath "Cert:\LocalMachine\My\$($item.thumbprint)" -ErrorAction Stop
 $private=$null;$public=$null
 try{
  if([Convert]::ToBase64String($cert.RawData) -cne $item.certificateDerB64){throw 'Native certificate identity changed'}
  $private=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
  if(!$private -or $private.Key.KeyName -cne $item.containerName -or $private.Key.Provider.Provider -ne 'Microsoft Software Key Storage Provider' -or !$private.Key.IsMachineKey -or $private.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None -or $private.KeySize -ne 2048){throw 'Protected native custody changed'}
  $challenge=[Text.Encoding]::UTF8.GetBytes([guid]::NewGuid().ToString())
  $signature=$private.SignData($challenge,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
  $public=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
  if(!$public.VerifyData($challenge,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)){throw 'Native key possession mismatch'}
 }finally{if($public){$public.Dispose()};if($private){$private.Dispose()};$cert.Dispose()}
}
Assert-Custody $c.predecessor
Assert-Custody $c.replacement
@{principalSid='S-1-5-18';bootTime=$os.LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ');serviceHostPid=[int]$service.ProcessId;serviceHostCreatedAt=$hostRows[0].CreationDate.ToUniversalTime().ToString('o');agentPid=[int]$agent.ProcessId;agentCreatedAt=$agent.CreationDate.ToUniversalTime().ToString('o');nativeCustodyVerified=$true;defaultsOmittedVerified=$true;soleInstalledAgentVerified=$true;soleLedgerWriterVerified=$true}|ConvertTo-Json -Compress
