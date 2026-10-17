<#
Fixed member-to-owned-CA broker. The caller contains this PowerShell process in
its retained native Job before execution. Officer credentials stay in the
private inherited environment and a transient PSCredential, never arguments,
outputs, phase receipts or artifacts. Each call uses a fresh remote session.
RevokeHistorical and RefreshHistoricalRevocation belong to the separate
revoked-status proof. Native lab execution is still pending.
#>
param(
 [Parameter(Mandatory)][string]$InputPath,
 [Parameter(Mandatory)][string]$OutputPath,
 [Parameter(Mandatory)][string]$OwnedGoPath
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if($env:CERTOPS_ADCS_DISPOSABLE_LAB -cne '1' -or
   (Get-CimInstance Win32_ComputerSystem).Domain -ine 'lab.certops.test' -or
   [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or
   !$env:CERTOPS_ADCS_OFFICER_PASSWORD) { throw 'Exact disposable member context required' }
$candidate=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))

function Read-BrokerBytes([string]$Path,[int]$Maximum) {
 $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
 if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
  throw 'Regular broker input required'
 }
 $stream=[IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try {
  if($stream.Length -lt 1 -or $stream.Length -gt $Maximum) { throw 'Broker input exceeds bound' }
  $buffer=[byte[]]::new($Maximum+1);$length=0
  while($length -lt $buffer.Length) {
   $count=$stream.Read($buffer,$length,$buffer.Length-$length)
   if(!$count){break};$length+=$count
  }
  if($length -gt $Maximum -or $stream.Length -ne $length) { throw 'Broker input changed or exceeds bound' }
  $bytes=[byte[]]::new($length);[Array]::Copy($buffer,$bytes,$length)
  return ,$bytes
 } finally { $stream.Dispose() }
}
function Get-BrokerDigest([byte[]]$Bytes) {
 $sha=[Security.Cryptography.SHA256]::Create()
 try { return [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant() }
 finally { $sha.Dispose() }
}

$requestBytes=Read-BrokerBytes $InputPath 65536
$request=[Text.UTF8Encoding]::new($false,$true).GetString($requestBytes)|ConvertFrom-Json -ErrorAction Stop
$fields=@('schemaVersion','action','runId','token','caThumbprint','templateName','payload','sources','helperPath')
if(@($request.PSObject.Properties).Count -ne $fields.Count -or
   @($request.PSObject.Properties|Where-Object {$_.Name -cnotin $fields}).Count -or
   $request.schemaVersion -isnot [int] -or $request.schemaVersion -ne 1 -or
   $request.runId -cnotmatch '^[a-f0-9]{10}$' -or
   $request.token -cnotmatch '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$' -or
   $request.caThumbprint -cnotmatch '^[A-F0-9]{40}$' -or
   $request.templateName -cnotmatch '^TTQualificationOcsp[a-f0-9]{16}$') {
 throw 'Closed original OCSP broker request required'
}
if($OwnedGoPath -cne ($InputPath+'.go')) { throw 'Exact owned launch gate required' }
$gateClock=[Diagnostics.Stopwatch]::StartNew()
while(!(Test-Path -LiteralPath $OwnedGoPath)) {
 if($gateClock.Elapsed.TotalSeconds -gt 30) { throw 'Owned OCSP launch gate timed out' }
 Start-Sleep -Milliseconds 25
}
if([Text.Encoding]::ASCII.GetString((Read-BrokerBytes $OwnedGoPath 64)) -cne $request.token) {
 throw 'Owned OCSP launch challenge mismatch'
}
$actions=@('Prepare','InstallRoles','CreateTemplate','PublishTemplate','RequestSigner','AcceptSigner','ReadCrl','Configure','CaptureIis','ApplyPublication','RestorePublication','Observe','RemoveConfiguration','StopResponder','StopIis','RemoveSigner','RestoreTemplate','RevokeHistorical','RefreshHistoricalRevocation')
if($request.action -cnotin $actions) { throw 'Fixed OCSP operation required' }
$sourceNames=@(
 'infra/certops-adcs/ocsp-owned-key.ps1',
 'infra/certops-adcs/ocsp-responder-fixture.ps1',
 'infra/certops-adcs/ocsp-iis-owned.ps1',
 'infra/certops-adcs/ocsp-revoked-fixture.ps1',
 'infra/certops-adcs/ocsp-native-survivors.ps1',
 'tests/e2e/helpers/certops-windows-contained-process.ps1',
 'tests/e2e/helpers/certops-windows-owned-process.ps1',
 'nativeChainHelper'
)
if(@($request.sources.PSObject.Properties).Count -ne $sourceNames.Count -or
   @($request.sources.PSObject.Properties|Where-Object {$_.Name -cnotin $sourceNames}).Count) {
 throw 'Exact candidate OCSP source inventory required'
}
$sources=@{}
$helperPaths=@(
 [IO.Path]::GetFullPath((Join-Path $candidate 'packages/agent/bin/tokentimer-adcs-chain-amd64.exe')),
 [IO.Path]::GetFullPath((Join-Path $candidate 'packages/agent/reference/adcs-chain/dist/tokentimer-adcs-chain-windows-amd64.exe'))
)
if($request.helperPath -isnot [string] -or $request.helperPath -cnotin $helperPaths) {
 throw 'Exact shipped candidate x64 chain helper required'
}
foreach($relative in $sourceNames) {
 $maximum=if($relative -ceq 'nativeChainHelper'){6291456}else{262144}
 $sourcePath=if($relative -ceq 'nativeChainHelper'){$request.helperPath}else{Join-Path $candidate $relative}
 $bytes=Read-BrokerBytes $sourcePath $maximum
 if($request.sources.$relative -cnotmatch '^[a-f0-9]{64}$' -or
    (Get-BrokerDigest $bytes) -cne $request.sources.$relative) { throw 'Candidate OCSP broker source changed' }
 $sources[$relative]=$bytes
}
# Before any remote dispatch, independently reopen the private exchange aliases
# themselves with the reviewed native bounded reader. This binds the first
# parsed buffer to current regular-file identities/ACLs and denies replacement
# during each read, rather than trusting Get-Item followed by a managed open.
. ([scriptblock]::Create([Text.UTF8Encoding]::new($false,$true).GetString([byte[]]$sources['infra/certops-adcs/ocsp-responder-fixture.ps1'])))
Initialize-OcspReceiptReader
if([Convert]::ToBase64String([TTQualificationOcspReceipt]::Read($InputPath)) -cne [Convert]::ToBase64String($requestBytes) -or
   [Text.Encoding]::ASCII.GetString([TTQualificationOcspReceipt]::Read($OwnedGoPath)) -cne $request.token) {
 throw 'Original private OCSP exchange changed before remote dispatch'
}
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force))
$session=$null
try {
 $session=New-PSSession -ComputerName 'tt-ca.lab.certops.test' -Credential $credential -ErrorAction Stop
 $result=Invoke-Command -Session $session -ArgumentList $request,$sources -ScriptBlock {
  param($Request,$Sources)
  $ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
  if($env:COMPUTERNAME -ine 'tt-ca' -or
     (Get-CimInstance Win32_ComputerSystem).Domain -ine 'lab.certops.test') { throw 'Exact original CA host required' }
  foreach($relative in @('infra/certops-adcs/ocsp-owned-key.ps1','infra/certops-adcs/ocsp-responder-fixture.ps1','infra/certops-adcs/ocsp-iis-owned.ps1','infra/certops-adcs/ocsp-revoked-fixture.ps1')) {
   # Bytes have already been bound to the candidate digest before remoting.
   # These modules contain definitions only; the closed switch below is the
   # sole remote operation entrypoint.
   . ([scriptblock]::Create([Text.UTF8Encoding]::new($false,$true).GetString([byte[]]$Sources[$relative])))
  }
  $expectedFields=switch -CaseSensitive ($Request.action) {
   'AcceptSigner' { @('certificateSha256') }
   'Configure' { @('crlDerBase64') }
   'Observe' { @('caDerBase64','signerDerBase64','crlDerBase64') }
   'RemoveConfiguration' { @('caDerBase64','signerDerBase64','crlDerBase64') }
   'RevokeHistorical' { @('historicalRequestId','currentRequestId','historicalDerBase64','currentDerBase64','caDerBase64','signerDerBase64','crlDerBase64') }
   'RefreshHistoricalRevocation' { @('caDerBase64','signerDerBase64','originalCrlDerBase64','crlDerBase64') }
   default { @() }
  }
  Assert-OcspClosedObject $Request.payload @($expectedFields)
  foreach($field in @($expectedFields)) {
   if($field -cin @('historicalRequestId','currentRequestId')) {
    if(($Request.payload.$field -isnot [int] -and $Request.payload.$field -isnot [long]) -or $Request.payload.$field -lt 1 -or $Request.payload.$field -gt 4294967295) { throw 'Exact native historical/current RequestId required' }
   } elseif($field -ceq 'certificateSha256') {
    if($Request.payload.$field -cnotmatch '^[a-f0-9]{64}$'){throw 'Exact verified signer digest required'}
   } elseif($Request.payload.$field -isnot [string] -or $Request.payload.$field.Length -gt 32768 -or
            $Request.payload.$field -cnotmatch '^[A-Za-z0-9+/]+={0,2}$') { throw 'Bounded public DER required' }
  }
  if($Request.action -ceq 'Prepare') {
   $owner=New-OcspOwnershipReceipt $Request.runId $Request.token $Request.caThumbprint $Request.templateName
  } else {
   $owner=Read-OwnedOcspOwnershipReceipt $Request.runId $Request.token $Request.caThumbprint $Request.templateName
  }
  Invoke-OwnedOcspPinnedOperation $owner {
   param($PinnedOwner)
   if($Request.action -ceq 'Prepare') {
    foreach($pair in @(
     @('infra/certops-adcs/ocsp-native-survivors.ps1','ocsp-native-survivors.ps1'),
     @('tests/e2e/helpers/certops-windows-contained-process.ps1','certops-windows-contained-process.ps1'),
     @('tests/e2e/helpers/certops-windows-owned-process.ps1','certops-windows-owned-process.ps1'),
     @('nativeChainHelper','chain-helper.exe')
    )) {
     [void](Write-OwnedOcspPublicTool $PinnedOwner $pair[1] ([byte[]]$Sources[$pair[0]]) $Request.sources.($pair[0]))
    }
    return @{prepared=$true;originalPublication=$PinnedOwner.ownership.originalPublication;directoryIdentity=$PinnedOwner.ownership.directoryIdentity}
   }
   $contained=Join-Path $PinnedOwner.directory 'certops-windows-contained-process.ps1'
   $retained=Join-Path $PinnedOwner.directory 'certops-windows-owned-process.ps1'
   Initialize-OcspContainedCommand $contained $Request.sources.'tests/e2e/helpers/certops-windows-contained-process.ps1'
   Initialize-OcspRetainedProcessWait $retained $Request.sources.'tests/e2e/helpers/certops-windows-owned-process.ps1'
   switch -CaseSensitive ($Request.action) {
    'InstallRoles' { $r=Install-OwnedOcspRoles $Request.runId $Request.token $Request.caThumbprint $Request.templateName;return @{serviceIdentity=$r.serviceIdentity;newFeatures=$r.newFeatures} }
    'CreateTemplate' { return New-OwnedOcspSigningTemplate $PinnedOwner }
    'PublishTemplate' { return Publish-OwnedOcspSigningTemplate $PinnedOwner }
    'RequestSigner' { return Request-OwnedOcspSigner $PinnedOwner }
    'AcceptSigner' { return Accept-OwnedOcspSigner $PinnedOwner $Request.payload.certificateSha256 }
    'ReadCrl' {
     $key=Open-OwnedOcspCaRegistry $PinnedOwner $false
     try { [void](Get-OwnedOcspPublication $key) } finally { $key.Dispose() }
     # The source is only the fixed original CA's public base CRL. Its native
     # regular-file identity is held through the bounded read; the member must
     # independently verify signature/issuer/pin/times before configuration.
     $directory=Join-Path $env:SystemRoot 'System32\CertSrv\CertEnroll'
     [void][TTQualificationOcspReceipt]::DirectoryIdentity($directory)
     $crl=[TTQualificationOcspReceipt]::ReadPublic((Join-Path $directory 'TTQualificationRoot.crl'))
     return @{crlDerBase64=[Convert]::ToBase64String($crl)}
    }
    'Configure' { return Set-OwnedOcspConfiguration $PinnedOwner ([Convert]::FromBase64String($Request.payload.crlDerBase64)) }
    'RevokeHistorical' { return Invoke-OwnedOcspHistoricalRevocation $PinnedOwner $Request.payload.historicalRequestId ([Convert]::FromBase64String($Request.payload.historicalDerBase64)) $Request.payload.currentRequestId ([Convert]::FromBase64String($Request.payload.currentDerBase64)) ([Convert]::FromBase64String($Request.payload.caDerBase64)) ([Convert]::FromBase64String($Request.payload.signerDerBase64)) ([Convert]::FromBase64String($Request.payload.crlDerBase64)) }
    'RefreshHistoricalRevocation' { return Set-OwnedOcspRevokedProvider $PinnedOwner ([Convert]::FromBase64String($Request.payload.caDerBase64)) ([Convert]::FromBase64String($Request.payload.signerDerBase64)) ([Convert]::FromBase64String($Request.payload.originalCrlDerBase64)) ([Convert]::FromBase64String($Request.payload.crlDerBase64)) }
    'CaptureIis' { return Capture-OwnedOcspIis $PinnedOwner }
    'ApplyPublication' { return Set-OwnedOcspOnlyPublication $PinnedOwner }
    'RestorePublication' { return Restore-OwnedOcspPublication $PinnedOwner }
    'Observe' { return Get-OwnedOcspConfigurationObservation $Request.templateName ([Convert]::FromBase64String($Request.payload.caDerBase64)) ([Convert]::FromBase64String($Request.payload.signerDerBase64)) ([Convert]::FromBase64String($Request.payload.crlDerBase64)) }
    'RemoveConfiguration' { return Remove-OwnedOcspConfiguration $PinnedOwner ([Convert]::FromBase64String($Request.payload.caDerBase64)) ([Convert]::FromBase64String($Request.payload.signerDerBase64)) ([Convert]::FromBase64String($Request.payload.crlDerBase64)) }
    'StopResponder' { return Stop-OwnedOcspResponder $PinnedOwner }
    'StopIis' { return Stop-AndRecordOwnedOcspIis $PinnedOwner }
    'RemoveSigner' { return Remove-OwnedOcspSigner $PinnedOwner $Request.sources.'nativeChainHelper' $Request.sources.'infra/certops-adcs/ocsp-native-survivors.ps1' }
    'RestoreTemplate' { return Restore-OwnedOcspSigningTemplate $PinnedOwner }
    default { throw 'Unsupported fixed OCSP operation' }
   }
  }
 }
 $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes(($result|ConvertTo-Json -Depth 20 -Compress))
 if($bytes.Length -lt 1 -or $bytes.Length -gt 65536) { throw 'Bounded OCSP operation result required' }
 $stream=[IO.FileStream]::new($OutputPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try {
  # The containing parent owns/protects this output directory. Never repair an
  # existing output or emit remoting diagnostics into the public report.
  $acl=[Security.AccessControl.FileSecurity]::new();$acl.SetAccessRuleProtection($true,$false)
  foreach($sid in @('S-1-5-18','S-1-5-32-544')) {
   $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow))
  }
  $stream.SetAccessControl($acl);$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)
 } finally { $stream.Dispose() }
} finally {
 if($null -ne $session){Remove-PSSession -Session $session -ErrorAction Stop}
 $credential=$null
}
