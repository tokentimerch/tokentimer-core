<# Benign temporary-file controls only. Extracts the immutable C# literal by
AST; never executes the CA mutator, certreq, service or certificate operations. #>
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot '..\infra\certops-adcs\issued-san-fault.ps1'
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'SAN source AST invalid'}
$nodes=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$publicFileSource'},$true))
if($nodes.Count -ne 1 -or $nodes[0].Right.Expression -isnot [Management.Automation.Language.StringConstantExpressionAst]){throw 'Expected one immutable public-file C# literal'}
Add-Type -TypeDefinition $nodes[0].Right.Expression.Value
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot ('..\.build\san-file-control-'+[Guid]::NewGuid().ToString('N'))))
$bound=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\.build'))+[IO.Path]::DirectorySeparatorChar
if(-not $root.StartsWith($bound,[StringComparison]::OrdinalIgnoreCase)){throw 'Temporary control outside owned build directory'}
[IO.Directory]::CreateDirectory($root)|Out-Null
$file=Join-Path $root 'public.der';$bytes=[Text.Encoding]::ASCII.GetBytes('owned-public-temp-sentinel');$owner=$null
function Read-Guard([string]$path){$stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]'ReadWrite,Delete');$reader=[IO.StreamReader]::new($stream);try{$reader.ReadToEnd()}finally{$reader.Dispose()}}
try {
  $owner=[TTSanPublicFile]::Create($file,$bytes)
  $null=& certutil.exe -hashfile $file SHA256 2>&1
  if($LASTEXITCODE -ne 0){throw 'Actual certutil public reader incompatible with retained ownership'}
  $replacementRefused=$false;try{[IO.File]::Delete($file)}catch{$replacementRefused=$true}
  if(-not $replacementRefused){throw 'Retained public reader allowed replacement'}
  $owner.VerifyAndDelete();$owner.Dispose();$owner=$null
  if((Test-Path -LiteralPath $file)-or(Test-Path -LiteralPath ($file+'.owner.json'))){throw 'Verified handle cleanup incomplete'}
  $owner=[TTSanPublicFile]::Create($file,$bytes)
  $guard=Read-Guard ($file+'.owner.json')
  # Controlled fault: dispose only this test object's retained reader, replace
  # its path, and substitute a reader of the foreign replacement. File ID must
  # reject even identical public bytes; no CA-side code executes.
  $field=[TTSanPublicFile].GetField('file',[Reflection.BindingFlags]'Instance,NonPublic')
  $field.GetValue($owner).Dispose();[IO.File]::Delete($file);[IO.File]::WriteAllBytes($file,$bytes)
  $field.SetValue($owner,[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))
  $refused=$false;try{$owner.VerifyAndDelete()}catch{$refused=$true}
  if(-not $refused -or -not(Test-Path -LiteralPath $file)-or (Read-Guard ($file+'.owner.json')) -cne $guard){throw 'Replacement or owner guard not preserved'}
  $owner.Dispose();$owner=$null
  # Remove only the two exact controlled files after all handles close and
  # exact public content/receipt/reparse checks; never recursive cleanup.
  if(@(Get-ChildItem -LiteralPath $root -Force).Count -ne 2 -or [Convert]::ToBase64String([IO.File]::ReadAllBytes($file)) -cne [Convert]::ToBase64String($bytes)){throw 'Preserve changed control root'}
  foreach($path in @($file,($file+'.owner.json'))){if((Get-Item -LiteralPath $path).Attributes-band [IO.FileAttributes]::ReparsePoint){throw 'Preserve linked control file'}}
  Remove-Item -LiteralPath $file;Remove-Item -LiteralPath ($file+'.owner.json')
  'SAN public-file controls: actual certutil reader, replacement refusal, exact cleanup, foreign replacement preservation PASS'
}finally{if($owner){$owner.Dispose()};if([IO.Directory]::GetFileSystemEntries($root).Length -eq 0){[IO.Directory]::Delete($root)}else{Write-Output ('Preserved public control root: '+$root)}}
