$ErrorActionPreference = 'Stop'
$file = Join-Path $PSScriptRoot 'install-agent.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'PowerShell parse failure' }
$helper = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-ProtectedNodeExecutable' }, $true))
if ($helper.Count -ne 1) { throw 'Node guard not found uniquely' }
Invoke-Expression $helper[0].Extent.Text
$blocks = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.StatementBlockAst] -and @($n.Statements | Where-Object { $_.Extent.Text -ceq 'Assert-ProtectedNodeExecutable -Path $script:NodeExe' }).Count -eq 1 -and @($n.Statements | Where-Object { $_.Extent.Text -like '$nodeVersionRaw = (Invoke-PackagedNode*' }).Count -eq 1 }, $true))
if ($blocks.Count -ne 1) { throw 'guard and version probe not found together' }
$stmts=@($blocks[0].Statements);$first=-1;$last=-1
for($i=0;$i -lt $stmts.Count;$i++){
 if($stmts[$i].Extent.Text -ceq 'Assert-ProtectedNodeExecutable -Path $script:NodeExe'){$first=$i}
 if($stmts[$i].Extent.Text -like '$nodeVersionRaw = (Invoke-PackagedNode*'){$last=$i}
}
if($first -lt 0 -or $last -le $first -or $stmts[$first+1].Extent.Text -cne 'Assert-AuthorizedLauncherIdentities'){throw 'guard does not precede both Node execution points'}
$snippet=[scriptblock]::Create((($stmts[$first..$last] | ForEach-Object {$_.Extent.Text}) -join "`n"))
$script:NodeExe='C:\Program Files\nodejs\node.exe';$package=@{engines=@{node='>=22.0.0 <25.0.0'}};$script:case='';$script:launches=0;$script:identities=0
function Get-Item {
 param($LiteralPath,[switch]$Force,$ErrorAction)
 $isFile=$LiteralPath -ieq $script:NodeExe
 $linked=($isFile -and $script:case -eq 'file-link') -or (-not $isFile -and $script:case -eq 'parent-link')
 [pscustomobject]@{Attributes=if($linked){[IO.FileAttributes]::ReparsePoint}else{[IO.FileAttributes]::Normal};PSIsContainer=(-not $isFile)}
}
function Get-Acl {
 param($LiteralPath,$ErrorAction)
 $isFile=$LiteralPath -ieq $script:NodeExe
 $isCase=if($isFile){'file'}else{'parent'}
 $badOwner=$script:case -eq "$isCase-owner";$badWrite=$script:case -eq "$isCase-write";$empty=$script:case -eq "$isCase-empty"
 $obj=[pscustomobject]@{badOwner=$badOwner;badWrite=$badWrite;empty=$empty}
 $obj | Add-Member ScriptMethod GetOwner {param($type) if($this.badOwner){[pscustomobject]@{Value='S-1-1-0'}}else{[pscustomobject]@{Value='S-1-5-32-544'}}}
 $obj | Add-Member ScriptMethod GetAccessRules {param($a,$b,$type) if(-not $this.empty){[pscustomobject]@{AccessControlType=[Security.AccessControl.AccessControlType]::Allow;PropagationFlags=[Security.AccessControl.PropagationFlags]::None;IdentityReference=[pscustomobject]@{Value=if($this.badWrite){'S-1-1-0'}else{'S-1-5-32-544'}};FileSystemRights=[Security.AccessControl.FileSystemRights]::WriteData}}}
 return $obj
}
function Assert-AuthorizedLauncherIdentities {$script:identities++}
function Invoke-PackagedNode {param($NodeArguments) $script:launches++;return 'v24.18.0'}
foreach($case in @('file-link','parent-link','file-owner','parent-owner','file-write','parent-write','file-empty','parent-empty')){
 $script:case=$case;$script:launches=0;$script:identities=0;$rejected=$false
 try{& $snippet}catch{$rejected=$true}
 if(-not $rejected -or $script:launches -ne 0 -or $script:identities -ne 0){throw "unsafe case reached Node: $case"}
 Write-Output "PASS: $case rejected before Node"
}
$script:case='';$script:launches=0;$script:identities=0;& $snippet
if($script:launches -ne 1 -or $script:identities -ne 1){throw 'trusted path refused'}
Write-Output 'PASS: trusted path reaches both Node probes'
Write-Output 'AST and ACL mocks only; no executable, service, installer, rollback or recovery scenario run.'
