<#
Independent read-only native custody oracle for the resident retention24h keeper.
Never creates/accepts/deletes a certificate/key or changes task/service state.
The trusted preparation controller supplies and fingerprints the exact config;
this local oracle cannot authorize an extended Azure resource lease on its own.
#>
param([Parameter(Mandatory)][ValidatePattern('^C:\\ttqualification\\retention24h\\[a-f0-9]{64}\\keeper-config.json$')][string]$ConfigPath,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ConfigSha256,
 [Parameter(Mandatory)][ValidateSet('kept-before-deadline','removed-after-real-day')][string]$Expected)
$ErrorActionPreference='Stop'
if($env:CERTOPS_ADCS_DISPOSABLE_LAB -ne '1' -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'Owned disposable SYSTEM keeper required'}
if((Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ConfigSha256){throw 'Frozen keeper config changed'}
$c=Get-Content -LiteralPath $ConfigPath -Raw|ConvertFrom-Json
if($ConfigPath -cne "C:\ttqualification\retention24h\$($c.lease.nonce)\keeper-config.json"){throw 'Keeper config scope mismatch'}
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Disposable domain membership required'}
$os=Get-CimInstance Win32_OperatingSystem
if($os.BuildNumber -ne '20348' -or $os.ProductType -ne 3 -or (Get-UICulture).Name -ne 'en-US' -or (Get-WinSystemLocale).Name -ne 'en-US'){throw 'Actual Server2022 en-US qualification profile required'}
$metadata=Invoke-RestMethod -Uri 'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01' -Headers @{Metadata='true'} -TimeoutSec 5
if($metadata.vmId -cne $c.lease.vmId -or $metadata.resourceId -ine $c.lease.vmResourceId){throw 'Actual Azure VM identity changed'}
Import-Module WebAdministration
$bindings=@(Get-WebBinding -Name $c.site -Protocol https|Where-Object {$_.bindingInformation -ceq "*:$($c.port):$($c.domain)"})
if($bindings.Count -ne 1 -or [int]$bindings[0].sslFlags -ne 1){throw 'Exact native IIS SNI binding changed'}
$service=Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'"
if(!$service -or $service.State -ne 'Stopped' -or $service.ProcessId -ne 0){throw 'Sole installed agent must remain stopped'}
$self=Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
$parent=Get-CimInstance Win32_Process -Filter "ProcessId=$($self.ParentProcessId)"
if(!$parent){throw 'Resident parent identity absent'}
$parentOwner=Invoke-CimMethod -InputObject $parent -MethodName GetOwnerSid
if($parentOwner.ReturnValue -ne 0 -or $parentOwner.Sid -ne 'S-1-5-18'){throw 'Resident parent is not SYSTEM'}
$allProcesses=@(Get-CimInstance Win32_Process)
foreach($old in $c.drainedTree){foreach($live in $allProcesses){if($live.ProcessId -eq $old.pid -and $live.CreationDate.ToUniversalTime().ToString('o') -ceq $old.createdAt){throw 'Captured service descendant still live'}}}
$runtime=Get-Content 'C:\ttqualification\runtime.json' -Raw|ConvertFrom-Json
$agentScript=Join-Path $runtime.source 'packages\agent\bin\tokentimer-agent.js'
$serviceHost=Join-Path $runtime.source 'packages\agent\bin\tokentimer-agent-host-amd64.exe'
foreach($live in $allProcesses){if($live.ExecutablePath -ieq $serviceHost -or ($live.CommandLine -and $live.CommandLine.Contains($agentScript))){throw 'Independent installed-agent process remains live'}}
$boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
function Assert-Custody($thumb,$container,$expectedDer){
 if($thumb -cnotmatch '^[A-F0-9]{40}$' -or $container -cnotmatch '^tokentimer-enr-[a-f0-9-]{36}$'){throw 'Invalid exact native identity'}
 $cert=Get-Item -LiteralPath "Cert:\LocalMachine\My\$thumb" -ErrorAction Stop
 $private=$null;$public=$null
 try{
  if([Convert]::ToBase64String($cert.RawData) -cne $expectedDer){throw 'Native leaf identity changed'}
  $private=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
  if(!$private -or $private.Key.KeyName -cne $container -or $private.Key.Provider.Provider -ne 'Microsoft Software Key Storage Provider' -or !$private.Key.IsMachineKey -or $private.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None -or $private.KeySize -ne 2048){throw 'Native protected custody mismatch'}
  $challenge=[Text.Encoding]::UTF8.GetBytes([guid]::NewGuid().ToString())
  $signature=$private.SignData($challenge,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
  $public=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
  if(!$public.VerifyData($challenge,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)){throw 'Native key possession failed'}
 }finally{if($private){$private.Dispose()};if($public){$public.Dispose()};$cert.Dispose()}
}
Assert-Custody $c.replacement.thumbprint $c.replacement.containerName $c.replacement.certificateDerB64
if($Expected -eq 'kept-before-deadline'){
 Assert-Custody $c.predecessor.thumbprint $c.predecessor.containerName $c.predecessor.certificateDerB64
 $oldPresent=$true;$oldKeyPresent=$true
}else{
 # Complete metadata-only enumeration ensures an alias in another machine store
 # cannot be mistaken for actual predecessor deletion.
 $count=0;$matches=0
 Get-ChildItem Cert:\LocalMachine -Recurse -ErrorAction Stop|ForEach-Object {if($_ -is [Security.Cryptography.X509Certificates.X509Certificate2]){if(++$count -gt 100000){throw 'Certificate inventory exceeded bound'};if($_.Thumbprint -eq $c.predecessor.thumbprint){$matches++}}}
 if($matches -ne 0){throw 'Predecessor certificate survives in a machine store'}
 $oldKeyPresent=[Security.Cryptography.CngKey]::Exists($c.predecessor.containerName,[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)
 if($oldKeyPresent){throw 'Predecessor native key still exists'};$oldPresent=$false
}
@{expected=$Expected;principalSid='S-1-5-18';bootTime=$boot;processId=[int]$parent.ProcessId;processCreatedAt=$parent.CreationDate.ToUniversalTime().ToString('o');soleAgentStopped=$true;replacementCustodyVerified=$true;predecessorPresent=$oldPresent;predecessorKeyPresent=$oldKeyPresent}|ConvertTo-Json -Compress
