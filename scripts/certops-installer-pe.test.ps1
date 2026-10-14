# Supporting production PE preactivation tests. Extract functions through the
# parser, never execute installer top-level code or any candidate executable.
# All writes/deletes remain in one exclusively created temporary directory.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$installer=Join-Path $PSScriptRoot '..\packages\agent\scripts\install-agent.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $installer).Path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Production installer parser errors'}
foreach($name in @('Assert-WindowsPeImage','Assert-WindowsPackageHelpers','Get-PackageDirectoryIdentity','Remove-OwnedPackageStaging','Copy-PackageTree')){
 $functions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true))
 if($functions.Count -ne 1){throw 'Expected one production preactivation function'}
 Invoke-Expression $functions[0].Extent.Text
}
$calls=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Assert-WindowsPackageHelpers'},$true))
$activation=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Activate-StagedPackage'},$true))
$copy=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Copy-PackageTree' -and $node.Extent.Text.Contains('$script:AppStaging')},$true))
$rootCreation=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'New-Item' -and $node.Extent.Text.Contains('-Path $InstallRoot')},$true))
if($calls.Count -ne 2 -or $copy.Count -ne 1 -or $activation.Count -ne 1 -or $rootCreation.Count -ne 1){throw 'Production preactivation hook cardinality mismatch'}
if($calls[0].Extent.StartOffset -ge $rootCreation[0].Extent.StartOffset -or $calls[1].Extent.StartOffset -le $copy[0].Extent.StartOffset -or $calls[1].Extent.StartOffset -ge $activation[0].Extent.StartOffset){throw 'PE checks must precede source mutation and staged activation'}
if(!$activation[0].Extent.Text.Contains('-ExpectedStagingIdentity $stagingIdentity')){throw 'Activation must bind the measured staging identity'}
$script:NodeExe=(Get-Command node -ErrorAction Stop).Source
$bin=Join-Path $PSScriptRoot '..\packages\agent\bin'
$token=[guid]::NewGuid().ToString('N')
$root=Join-Path ([IO.Path]::GetTempPath()) "certops-pe-$token"
if(Test-Path -LiteralPath $root){throw 'Refusing preexisting PE fixture'}
New-Item -ItemType Directory -Path $root | Out-Null
$rootIdentity=Get-PackageDirectoryIdentity -Directory $root
$cases=New-Object 'System.Collections.Generic.List[string]'
$positive=0
function Must-Refuse {
 param([scriptblock]$Action,[string]$Case)
 $refused=$false
 try{& $Action}catch{$refused=$true}
 if(!$refused){throw "PE negative accepted: $Case"}
 $cases.Add($Case)
}
try {
 foreach($arch in @('AMD64','ARM64')){
  $tag=$arch.ToLowerInvariant();$other=if($arch -eq 'AMD64'){'arm64'}else{'amd64'}
  foreach($kind in @('tokentimer-agent-host','tokentimer-adcs-chain')){
   $real=Join-Path $bin "$kind-$tag.exe"
   Assert-WindowsPeImage -LiteralPath ([IO.Path]::GetFullPath($real)) -Architecture $arch
   $positive++
   [byte[]]$original=[IO.File]::ReadAllBytes($real)
   $file=Join-Path $root "$kind-$tag.exe"
   foreach($variant in @('missing','truncated-header','wrong-architecture','truncated-section','bad-optional-magic','bad-entrypoint','raw-overrun','overlapping-raw-sections','dll-characteristic','bad-pe-offset','nonexecutable-entry')){
    if(Test-Path -LiteralPath $file){Remove-Item -LiteralPath $file -Force}
    [byte[]]$bytes=$original.Clone();$pe=[BitConverter]::ToUInt32($bytes,60);$optional=$pe+24;$table=$optional+[BitConverter]::ToUInt16($bytes,$pe+20)
    switch($variant){
     'missing' { }
     'truncated-header' {[IO.File]::WriteAllBytes($file,$bytes[0..63])}
     'wrong-architecture' {Copy-Item -LiteralPath (Join-Path $bin "$kind-$other.exe") -Destination $file}
     'truncated-section' {[IO.File]::WriteAllBytes($file,$bytes[0..($bytes.Length-2)])}
     'bad-optional-magic' {[BitConverter]::GetBytes([UInt16]0x10b).CopyTo($bytes,$optional);[IO.File]::WriteAllBytes($file,$bytes)}
     'bad-entrypoint' {[BitConverter]::GetBytes([UInt32]1).CopyTo($bytes,$optional+16);[IO.File]::WriteAllBytes($file,$bytes)}
     'raw-overrun' {[BitConverter]::GetBytes([UInt32]::MaxValue).CopyTo($bytes,$table+20);[IO.File]::WriteAllBytes($file,$bytes)}
     'overlapping-raw-sections' {[Array]::Copy($bytes,$table+20,$bytes,$table+60,4);[IO.File]::WriteAllBytes($file,$bytes)}
     'dll-characteristic' {$flags=[BitConverter]::ToUInt16($bytes,$pe+22) -bor 0x2000;[BitConverter]::GetBytes([UInt16]$flags).CopyTo($bytes,$pe+22);[IO.File]::WriteAllBytes($file,$bytes)}
     'bad-pe-offset' {[BitConverter]::GetBytes([UInt32]::MaxValue).CopyTo($bytes,60);[IO.File]::WriteAllBytes($file,$bytes)}
     'nonexecutable-entry' {$flags=[BitConverter]::ToUInt32($bytes,$table+36) -band [UInt32]3758096383;[BitConverter]::GetBytes([UInt32]$flags).CopyTo($bytes,$table+36);[IO.File]::WriteAllBytes($file,$bytes)}
    }
    Must-Refuse -Action {Assert-WindowsPeImage -LiteralPath $file -Architecture $arch} -Case "$tag/$kind/$variant"
   }
  }
 }
 foreach($name in @('literal [brackets]',"literal quote's path")){
  $literal=Join-Path $root $name;New-Item -ItemType Directory -Path $literal|Out-Null
  $literalIdentity=Get-PackageDirectoryIdentity -Directory $literal
  $image=Join-Path $literal 'selected [helper].exe';Copy-Item -LiteralPath (Join-Path $bin 'tokentimer-agent-host-amd64.exe') -Destination $image
  Assert-WindowsPeImage -LiteralPath $image -Architecture AMD64
  Remove-OwnedPackageStaging -Directory $literal -ExpectedIdentity $literalIdentity
 }
 # Execute the actual top-level staging try/catch without installer top-level setup.
 # Only Fail is replaced by a throwing adapter; copy, PE checks and cleanup stay real.
 $stagingTry=$copy[0].Parent
 while($stagingTry -and $stagingTry -isnot [Management.Automation.Language.TryStatementAst]){$stagingTry=$stagingTry.Parent}
 if(!$stagingTry){throw 'Production staging recovery boundary missing'}
 function Fail {param([string]$Message) throw $Message}
 $PackageDir=Join-Path $root 'bad-source';New-Item -ItemType Directory -Path $PackageDir|Out-Null
 $AppDir=Join-Path $root 'untouched-app';New-Item -ItemType Directory -Path $AppDir|Out-Null
 $appMarker=Join-Path $AppDir 'operator-marker';[IO.File]::WriteAllText($appMarker,'preserve')
 $arch='AMD64'
 $script:AppStaging=Join-Path $root 'top-level-stage';New-Item -ItemType Directory -Path $script:AppStaging|Out-Null
 $stagingIdentity=Get-PackageDirectoryIdentity -Directory $script:AppStaging
 $observedError=''
 try {Invoke-Expression $stagingTry.Extent.Text}catch{$observedError=$_.Exception.Message}
 if($observedError -notlike '*failed to stage the agent package*' -or $observedError -like '*cleanup refused*' -or (Test-Path -LiteralPath $script:AppStaging) -or [IO.File]::ReadAllText($appMarker) -ne 'preserve'){throw 'Actual staging catch did not clean owned stage and preserve original failure/app'}
 $originalStagingFailure=$observedError.Substring($observedError.IndexOf('('))
 # Re-run that same catch against a replacement stage: preserve it and retain the root error.
 New-Item -ItemType Directory -Path $script:AppStaging|Out-Null
 $stagingIdentity=Get-PackageDirectoryIdentity -Directory $script:AppStaging
 Remove-OwnedPackageStaging -Directory $script:AppStaging -ExpectedIdentity $stagingIdentity
 New-Item -ItemType Directory -Path $script:AppStaging|Out-Null
 $foreignMarker=Join-Path $script:AppStaging 'foreign-owner';[IO.File]::WriteAllText($foreignMarker,'preserve replacement')
 $observedError=''
 try {Invoke-Expression $stagingTry.Extent.Text}catch{$observedError=$_.Exception.Message}
 if($observedError -notlike '*staging cleanup refused*' -or !$observedError.EndsWith($originalStagingFailure) -or !(Test-Path -LiteralPath $foreignMarker)){throw 'Actual staging catch erased replacement or lost original failure'}
 # A source success cannot replace validation of the bytes actually staged.
 $source=Join-Path $root 'valid-source';New-Item -ItemType Directory -Path (Join-Path $source 'bin') -Force|Out-Null
 foreach($name in @('tokentimer-agent-host-amd64.exe','tokentimer-adcs-chain-amd64.exe')){Copy-Item -LiteralPath (Join-Path $bin $name) -Destination (Join-Path $source "bin\$name")}
 Assert-WindowsPackageHelpers -PackageDirectory $source -Architecture AMD64
 $stage=Join-Path $root 'copied-stage';Copy-PackageTree -Source $source -Destination $stage
 $stageIdentity=Get-PackageDirectoryIdentity -Directory $stage
 $oldApp=Join-Path $root 'old-app';New-Item -ItemType Directory -Path $oldApp|Out-Null
 $marker=Join-Path $oldApp 'state-marker';[IO.File]::WriteAllText($marker,'original app/config/service stand-in')
 $before=[IO.File]::ReadAllBytes($marker)
 [IO.File]::WriteAllBytes((Join-Path $stage 'bin\tokentimer-agent-host-amd64.exe'),[byte[]](0,1))
 Must-Refuse -Action {Assert-WindowsPackageHelpers -PackageDirectory $stage -Architecture AMD64} -Case 'valid-source/copied-staging-truncated'
 if([Convert]::ToBase64String([IO.File]::ReadAllBytes($marker)) -ne [Convert]::ToBase64String($before)){throw 'Preactivation refusal changed original marker'}
 Remove-OwnedPackageStaging -Directory $stage -ExpectedIdentity $stageIdentity
 New-Item -ItemType Directory -Path $stage|Out-Null
 $replacementMarker=Join-Path $stage 'replacement-owner';[IO.File]::WriteAllText($replacementMarker,'replacement must survive')
 Must-Refuse -Action {Remove-OwnedPackageStaging -Directory $stage -ExpectedIdentity $stageIdentity} -Case 'replaced-stage-cleanup-refused'
 if(!(Test-Path -LiteralPath $replacementMarker)){throw 'Foreign replacement stage was removed'}
 $alias=Join-Path $root 'owned-alias';$target=Join-Path $root 'owned-link-target'
 New-Item -ItemType Directory -Path (Join-Path $target 'child') -Force|Out-Null
 New-Item -ItemType Junction -Path $alias -Target $target|Out-Null
 try {
  Must-Refuse -Action {Get-PackageDirectoryIdentity -Directory (Join-Path $alias 'child')} -Case 'linked-stage-ancestor-refused'
  Must-Refuse -Action {Remove-OwnedPackageStaging -Directory $alias -ExpectedIdentity $stageIdentity} -Case 'linked-stage-cleanup-refused'
 } finally {[IO.Directory]::Delete($alias)}
 if(!(Test-Path -LiteralPath (Join-Path $target 'child'))){throw 'Linked target was modified'}
 @{scope='supporting-production-pe-preactivation-not-installer-service-execution';positiveRealCompiledImages=$positive;positiveLiteralPathShapes=2;refusedCases=@($cases);productionSourceAndStageHooks=$true;oldMarkerPreserved=$true;replacementStagePreserved=$true}|ConvertTo-Json -Compress
}finally{
 if([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($root)).TrimEnd('\') -ne [IO.Path]::GetTempPath().TrimEnd('\') -or [IO.Path]::GetFileName($root) -ne "certops-pe-$token"){throw 'PE fixture cleanup boundary mismatch'}
 Remove-OwnedPackageStaging -Directory $root -ExpectedIdentity $rootIdentity
}
