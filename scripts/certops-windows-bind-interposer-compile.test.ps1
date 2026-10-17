# Compile/parse only: no native constructor, executable, store or SCM call.
$ErrorActionPreference='Stop'
$helper=Join-Path $PSScriptRoot '../tests/e2e/helpers'
foreach($name in @('certops-windows-contained-process.ps1','certops-windows-bind-interposer-build.ps1')){
 $tokens=$null;$errors=$null
 $null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $helper $name),[ref]$tokens,[ref]$errors)
 if($errors.Count){throw $errors[0]}
}
$source=[IO.File]::ReadAllText((Join-Path $helper 'certops-windows-contained-process.ps1'))
$matches=[regex]::Matches($source,"Add-Type\s+-TypeDefinition\s+@'\r?\n([\s\S]*?)\r?\n'@")
if($matches.Count-ne 1){throw 'One reviewed native retained-job type required'}
$combined=$matches[0].Groups[1].Value+"`n"+[IO.File]::ReadAllText((Join-Path $helper 'certops-windows-bind-interposer.cs'))
Add-Type -TypeDefinition $combined -ReferencedAssemblies System.dll,System.Core.dll,System.Security.dll,System.Web.Extensions.dll
if(![CertOpsBindInterposer]::SameNativePath('C:\WINDOWS\System32\netsh.exe','c:\windows\system32\netsh.exe')){throw 'Native path casing must preserve the original binary'}
if([CertOpsBindInterposer]::SameNativePath('C:\WINDOWS\System32\netsh.exe','C:\foreign\netsh.exe')){throw 'Foreign native path accepted'}
if([CertOpsBindInterposer]::ParseNativeError("SSL Certificate add failed, Error: 183`r`n")-ne 183){throw 'Actual native error parsing failed'}
if([CertOpsBindInterposer]::ParseNativeError("SSL Certificate add failed, Error: 1312`r`n")-ne 1312){throw 'Other native errors must remain distinct'}
foreach($invalid in @('unrelated 183 text',"SSL Certificate add failed, Error: 183`nSSL Certificate add failed, Error: 183",'SSL Certificate add failed, Error: 4294967296')){
 $refused=$false;try{$null=[CertOpsBindInterposer]::ParseNativeError($invalid)}catch{$refused=$true};if(!$refused){throw 'Ambiguous or unrelated native error accepted'}
}
$compare=& node -p "require('./tests/e2e/helpers/certops-windows-bind-interposer').ENVIRONMENT_COMPARE"
if($LASTEXITCODE){throw 'Environment comparison source unavailable'}
$adversaries=@'
$original=@('NODE_OPTIONS=--trace-warnings','Path=C:\Windows\System32')
if(!(Same-Environment $original @('NODE_OPTIONS=--trace-warnings','Path=C:\Windows\System32'))){throw 'Original exact environment refused'}
foreach($other in @(@('NODE_OPTIONS=--TRACE-WARNINGS','Path=C:\Windows\System32'),@('Path=C:\Windows\System32','NODE_OPTIONS=--trace-warnings'),@('NODE_OPTIONS=--trace-warnings'))){if(Same-Environment $original $other){throw 'Changed environment accepted'}}
'@
& ([ScriptBlock]::Create($compare+$adversaries))
'Interposer types compiled without native invocation'
