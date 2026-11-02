# Compile only inside a receipt-owned disposable fixture directory. This does
# not install, execute or replace any system executable.
param([Parameter(Mandatory)][string]$Directory)
$ErrorActionPreference='Stop'
if($Directory-notmatch'\\\.bind-failure-interposer-[a-f0-9]{32}$'){throw 'Owned fixture namespace required'}
$root=Get-Item -LiteralPath $Directory
if(!$root.PSIsContainer-or($root.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Native fixture directory required'}
$source=Join-Path $Directory 'combined.cs';$output=Join-Path $Directory 'netsh.exe'
if((Get-Item -LiteralPath $source).Length-gt 65536-or(Test-Path -LiteralPath $output)){throw 'Original bounded source and absent executable required'}
$acl=Get-Acl -LiteralPath $Directory
if(@($acl.Access|Where-Object{$_.AccessControlType-eq'Allow'-and$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value-notin@('S-1-5-18','S-1-5-32-544')}).Count){throw 'Protected SYSTEM/Administrators fixture ACL required'}
Add-Type -Path $source -OutputAssembly $output -OutputType ConsoleApplication -ReferencedAssemblies System.dll,System.Core.dll,System.Security.dll,System.Web.Extensions.dll
