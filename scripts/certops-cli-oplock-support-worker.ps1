<# Supporting benign worker: executes only the actual candidate copy/activation
functions on temporary public files. This is NOT the complete installer CLI and
cannot satisfy native installed-service qualification. #>
param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Arguments)
$ErrorActionPreference='Stop'
if($Arguments.Count -ne 6 -or $Arguments[0] -ne '-InstallerSource' -or $Arguments[2] -ne '-PackageDirectory' -or $Arguments[4] -ne '-InstallRoot'){throw 'Exact supporting CLI arguments required'}
$InstallerSource=$Arguments[1];$PackageDirectory=$Arguments[3];$InstallRoot=$Arguments[5]
if([IO.Path]::GetFileName([IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')) -notmatch '^certops-cli-oplock-support-'){throw 'Refuse non-supporting root'}
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $InstallerSource).Path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Candidate installer parse failed'}
foreach($name in @('Copy-PackageTree','Activate-StagedPackage')){
 $definitions=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true))
 if($definitions.Count -ne 1){throw 'Missing unique candidate activation function'}
 Invoke-Expression $definitions[0].Extent.Text
}
$app=Join-Path $InstallRoot 'app';$staging="$app.staging.$PID";$previous="$app.previous.$PID"
try{
 Copy-PackageTree -Source $PackageDirectory -Destination $staging
 Activate-StagedPackage -AppDirectory $app -StagingDirectory $staging -PreviousDirectory $previous
 throw 'Second rename unexpectedly succeeded'
}catch{[Console]::Error.WriteLine($_.Exception.Message);exit 31}
