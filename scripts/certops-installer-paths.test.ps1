<# Supporting native filesystem regression for the actual installer copy and
activation functions. Only exclusively created temporary public files and
junctions inside that fixture are touched. No installer top-level, service,
registry, certificate or CNG operations execute. Run with Windows PowerShell5.1.
All 'outside' destinations below remain inside the owned temporary root. #>
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$installer=Join-Path $PSScriptRoot '..\packages\agent\scripts\install-agent.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $installer).Path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Candidate installer source parse failed'}
foreach($name in @('Copy-PackageTree','Activate-StagedPackage')){
 $definitions=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true))
 if($definitions.Count -ne 1){throw 'Expected unique actual installer function'}
 Invoke-Expression $definitions[0].Extent.Text
}
Add-Type @'
using System;using System.Runtime.InteropServices;using Microsoft.Win32.SafeHandles;
public static class CertopsPathIdentity {
 [StructLayout(LayoutKind.Sequential)]public struct Info{public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written;public uint Volume,High,Low,Links,IndexHigh,IndexLow;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]public static extern SafeFileHandle CreateFile(string p,uint a,uint s,IntPtr security,uint d,uint f,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)]public static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info i);
 public static string Identity(string p){using(var h=CreateFile(p,0x80000000,7,IntPtr.Zero,3,0x02000000,IntPtr.Zero)){Info i;if(h.IsInvalid||!GetFileInformationByHandle(h,out i))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());return i.Volume.ToString("x8")+":"+i.IndexHigh.ToString("x8")+i.IndexLow.ToString("x8");}}
}
'@
$root=Join-Path ([IO.Path]::GetTempPath()) ('certops-installer-path-support-'+[Guid]::NewGuid().ToString('N'))
if(Test-Path -LiteralPath $root){throw 'Refuse existing path fixture'}
$null=[IO.Directory]::CreateDirectory($root)
$junctions=New-Object 'System.Collections.Generic.List[string]'
function Directory([string]$Path){$null=[IO.Directory]::CreateDirectory($Path);return $Path}
function Junction([string]$Link,[string]$Target){
 if(Test-Path -LiteralPath $Link){throw 'Refuse existing junction path'}
 $junctions.Add($Link)
 $null=New-Item -ItemType Junction -Path $Link -Target ([Management.Automation.WildcardPattern]::Escape($Target))
 if(((Get-Item -LiteralPath $Link -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0){throw 'Actual junction prerequisite missing'}
}
function Refused([scriptblock]$Operation){
 $matched=$false
 try{& $Operation}catch{$matched=$_.Exception.Message -match 'refusing linked'}
 if(!$matched){throw 'Actual product did not refuse the linked path'}
}
function Snapshot([string]$Path){return @([CertopsPathIdentity]::Identity($Path),(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash)}
function Unchanged($Before,[string]$Path){$after=Snapshot $Path;if(($Before -join '|') -ne ($after -join '|')){throw 'Owned public marker identity or bytes changed'}}
$positive=0;$copyRefusals=0;$activationRefusals=0
try{
 $unicode=([string][char]0x00E9)+([string][char]0x6F22)
 foreach($name in @('spaces in root',('unicode-'+$unicode),'literal [root]')){
  $case=Directory (Join-Path $root $name);$source=Directory (Join-Path $case ('candidate [files] '+$unicode));$app=Directory (Join-Path $case 'app');$staging="$app.staging.$PID";$previous="$app.previous.$PID"
  $leaf='entry [x] '+$unicode+'.txt';[IO.File]::WriteAllText((Join-Path $source $leaf),'candidate public bytes');[IO.File]::WriteAllText((Join-Path $app 'version.txt'),'original public bytes')
  $excluded=Directory (Join-Path $case 'excluded-owned-target');[IO.File]::WriteAllText((Join-Path $excluded 'must-not-copy.txt'),'excluded public control');Junction (Join-Path $source 'node_modules') $excluded;Junction (Join-Path $source '.git') $excluded
  $old=Snapshot (Join-Path $app 'version.txt');$oldDirectoryId=[CertopsPathIdentity]::Identity($app)
  Copy-PackageTree -Source $source -Destination $staging
  Activate-StagedPackage -AppDirectory $app -StagingDirectory $staging -PreviousDirectory $previous
  if([IO.File]::ReadAllText((Join-Path $app $leaf)) -ne 'candidate public bytes'){throw 'Literal candidate copy/activation failed'}
  if((Test-Path -LiteralPath (Join-Path $app 'node_modules')) -or (Test-Path -LiteralPath (Join-Path $app '.git'))){throw 'Excluded source junctions were copied'}
  Unchanged $old (Join-Path $previous 'version.txt');if([CertopsPathIdentity]::Identity($previous) -ne $oldDirectoryId){throw 'Positive cutover changed predecessor directory identity'}
  $positive++
 }
 foreach($kind in @('source-root','source-nested','source-ancestor','destination-root','destination-nested','destination-ancestor')){
  $case=Directory (Join-Path $root $kind);$outside=Directory (Join-Path $case 'owned-outside');$outsideMarker=Join-Path $outside 'outside-marker.txt';[IO.File]::WriteAllText($outsideMarker,'outside bytes must survive');$before=Snapshot $outsideMarker
  $source=Join-Path $case 'candidate';$destination=Join-Path $case 'stage';$app=Directory (Join-Path $case 'app');$appMarker=Join-Path $app 'version.txt';[IO.File]::WriteAllText($appMarker,'original app must survive');$appBefore=Snapshot $appMarker
  switch($kind){
   'source-root'{Junction $source $outside}
   'source-nested'{$null=Directory $source;[IO.File]::WriteAllText((Join-Path $source 'first.txt'),'must not copy before preflight');Junction (Join-Path $source 'nested') $outside}
   'source-ancestor'{$null=Directory (Join-Path $outside 'candidate');Junction (Join-Path $case 'alias') $outside;$source=Join-Path $case 'alias\candidate'}
   'destination-root'{$null=Directory $source;Junction $destination $outside}
   'destination-nested'{$nested=Directory (Join-Path (Directory $source) 'nested');[IO.File]::WriteAllText((Join-Path $nested 'outside-write-attempt.txt'),'must not escape staging');$null=Directory $destination;Junction (Join-Path $destination 'nested') $outside}
   'destination-ancestor'{$null=Directory $source;Junction (Join-Path $case 'alias') $outside;$destination=Join-Path $case 'alias\stage'}
  }
  if($kind -notmatch '^source-root$'){[IO.File]::WriteAllText((Join-Path $source 'candidate.txt'),'candidate public control')}
  Refused {Copy-PackageTree -Source $source -Destination $destination}
  Unchanged $before $outsideMarker;Unchanged $appBefore $appMarker
  if($kind -match '^source-' -and (Test-Path -LiteralPath $destination)){throw 'Source preflight refusal already mutated destination'}
  if(Test-Path -LiteralPath (Join-Path $outside 'candidate.txt')){throw 'Destination copy wrote outside staging'}
  if(Test-Path -LiteralPath (Join-Path $outside 'outside-write-attempt.txt')){throw 'Nested destination copy escaped staging'}
  if($kind -eq 'destination-ancestor' -and (Test-Path -LiteralPath (Join-Path $outside 'stage'))){throw 'Destination ancestor junction was followed'}
  $copyRefusals++
 }
 foreach($kind in @('app','staging','previous','parent')){
  $case=Directory (Join-Path $root ('activation-'+$kind));$outside=Directory (Join-Path $case 'owned-outside');$outsideMarker=Join-Path $outside 'outside.txt';[IO.File]::WriteAllText($outsideMarker,'outside activation bytes');$before=Snapshot $outsideMarker
  $install=Directory (Join-Path $case 'install');if($kind -eq 'parent'){Junction (Join-Path $case 'alias') $install;$install=Join-Path $case 'alias'}
  $app=Join-Path $install 'app';$staging="$app.staging.$PID";$previous="$app.previous.$PID"
  if($kind -eq 'app'){Junction $app $outside}else{$null=Directory $app}
  [IO.File]::WriteAllText((Join-Path $app 'version.txt'),'original activation bytes');$appBefore=Snapshot (Join-Path $app 'version.txt')
  if($kind -eq 'staging'){Junction $staging $outside}else{$null=Directory $staging}
  if($kind -eq 'previous'){Junction $previous $outside}
  Refused {Activate-StagedPackage -AppDirectory $app -StagingDirectory $staging -PreviousDirectory $previous}
  Unchanged $before $outsideMarker;Unchanged $appBefore (Join-Path $app 'version.txt');$activationRefusals++
 }
 $proof=[ordered]@{scope='actual-production-copy-activation-temporary-filesystem';positivePathShapes=$positive;copyJunctionRefusals=$copyRefusals;activationJunctionRefusals=$activationRefusals;outsideBytesAndIdentityPreserved=$true;predecessorBytesAndIdentityPreserved=$true;noDestinationMutationBeforeSourceRefusal=$true;excludedSourceJunctionsNotFollowedOrCopied=$true;serviceOrCertificateExecutionQualified=$false}
}finally{
 foreach($link in @($junctions.ToArray())|Sort-Object Length -Descending){
  $full=[IO.Path]::GetFullPath($link);if(!$full.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Refuse foreign junction cleanup'}
  if(Test-Path -LiteralPath $full){if(((Get-Item -LiteralPath $full -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0){throw 'Fixture junction ownership changed'};[IO.Directory]::Delete($full)}
 }
 $resolved=[IO.Path]::GetFullPath($root);$parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
 if([IO.Path]::GetDirectoryName($resolved) -ne $parent -or [IO.Path]::GetFileName($resolved) -notmatch '^certops-installer-path-support-[a-f0-9]{32}$'){throw 'Refuse foreign path fixture cleanup'}
 Remove-Item -LiteralPath $resolved -Recurse -Force
 if(Test-Path -LiteralPath $resolved){throw 'Owned installer path fixture remains'}
}
$proof.ownedTemporaryFixtureRemoved=$true
$proof|ConvertTo-Json -Compress
