<#
Read-only shipped-helper invocation inside the enclosing retained native Job.
The parent must prove wrapper/root exit, Active0 and closed handles before
using this receipt for any irreversible key cleanup. No PID kill or private
key operation exists here. This script is never run by supporting AST checks.
#>
param(
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$HelperSha256,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$')][string]$Token
)
$ErrorActionPreference='Stop'
$directory=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'TokenTimerOcspQualification'
$item=Get-Item -LiteralPath $directory -Force -ErrorAction Stop
if(!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
 throw 'Original protected OCSP fixture directory required'
}
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed=@($owner,'S-1-5-18','S-1-5-32-544')
$acl=Get-Acl -LiteralPath $directory -ErrorAction Stop
if(!$acl.AreAccessRulesProtected) { throw 'OCSP directory inherits access' }
foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
 if($rule.IsInherited -or ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -cnotin $allowed)) {
  throw 'OCSP directory grants foreign access'
 }
}
$helper=Join-Path $directory 'chain-helper.exe'
$output=Join-Path $directory ('survivors-'+$Token+'.json')
if(Test-Path -LiteralPath $output) { throw 'Never overwrite native survivor observation' }
$file=Get-Item -LiteralPath $helper -Force -ErrorAction Stop
if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
 throw 'Original regular shipped helper required'
}
$binary=$null;$process=$null
try {
 # Deny binary writes/replacement for the complete hash-and-execution lifetime.
 # The exact candidate digest proves code provenance; deletion ownership is
 # independently recorded and checked by the enclosing fixture.
 $binary=[IO.File]::Open($helper,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 if($binary.Length -lt 1024 -or $binary.Length -gt 67108864) { throw 'Bounded shipped helper required' }
 $hash=[Security.Cryptography.SHA256]::Create()
 try { $actual=[BitConverter]::ToString($hash.ComputeHash($binary)).Replace('-','').ToLowerInvariant() }
 finally { $hash.Dispose() }
 if($actual -cne $HelperSha256) { throw 'Shipped helper digest mismatch' }
 $start=[Diagnostics.ProcessStartInfo]::new()
 $start.FileName=$helper
 $start.Arguments='--key-survivors --container tokentimer-enr-'+$Token
 $start.WorkingDirectory=$directory
 $start.UseShellExecute=$false
 $start.CreateNoWindow=$true
 $start.RedirectStandardOutput=$true
 # stderr stays on the outer retained Job's NUL handle. No raw native error
 # or private fixture coordinate is emitted to a workflow/public report.
 $process=[Diagnostics.Process]::new()
 $process.StartInfo=$start
 if(!$process.Start()) { throw 'Owned read-only helper did not start' }
 $buffer=[byte[]]::new(4097);$length=0
 while($length -lt $buffer.Length) {
  $count=$process.StandardOutput.BaseStream.Read($buffer,$length,$buffer.Length-$length)
  if($count -eq 0) { break }
  $length+=$count
 }
 if($length -lt 1 -or $length -gt 4096 -or !$process.WaitForExit(30000) -or $process.ExitCode -ne 0) {
  throw 'Bounded complete native survivor output unavailable'
 }
 $value=[Text.UTF8Encoding]::new($false,$true).GetString($buffer,0,$length)|ConvertFrom-Json -ErrorAction Stop
 $fields=@('complete','shared','storesScanned','certificatesScanned','matches')
 if(@($value.PSObject.Properties).Count -ne $fields.Count -or
    @($value.PSObject.Properties|Where-Object {$_.Name -cnotin $fields}).Count -or
    $value.complete -isnot [bool] -or $value.complete -ne $true -or
    $value.shared -isnot [bool] -or $value.shared -ne $false) {
  throw 'Complete unshared native inventory required'
 }
 foreach($name in @('storesScanned','certificatesScanned','matches')) {
  $number=$value.$name
  $maximum=if($name -ceq 'storesScanned'){512}else{100000}
  if(($number -isnot [int] -and $number -isnot [long]) -or $number -lt 0 -or $number -gt $maximum) {
   throw 'Bounded native inventory counts required'
  }
 }
 if($value.storesScanned -lt 1 -or $value.matches -ne 0) { throw 'Native key references survive' }
 $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes(($value|ConvertTo-Json -Compress))
 $security=[Security.AccessControl.FileSecurity]::new()
 $security.SetAccessRuleProtection($true,$false)
 foreach($sid in $allowed) {
  $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','Allow'))
 }
 $stream=[IO.File]::Open($output,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try {
  [IO.File]::SetAccessControl($output,$security)
  $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)
 } finally { $stream.Dispose() }
} finally {
 # Unknown native lifetime is handled solely by the outer retained Job. Closing
 # this Process object is not claimed to prove process/descendant drainage.
 if($null -ne $process) { $process.Dispose() }
 if($null -ne $binary) { $binary.Dispose() }
}
