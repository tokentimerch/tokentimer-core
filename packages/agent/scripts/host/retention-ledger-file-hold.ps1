<#
Hold one public retention-ledger fixture file without delete sharing so the real
atomic writer must encounter a native replacement refusal. All paths stay in an
exclusively owned temporary fixture; this child never accesses certificates,
services, registry or real agent state. Atomic receipts expose only ownership
and file identity. The exact parent releases the handle with a random token.
#>
param(
  [Parameter(Mandatory)][string]$FixtureRoot,
  [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{40}$')][string]$Thumbprint,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Token,
  [Parameter(Mandatory)][int]$OwnerProcessId
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = [IO.Path]::GetFullPath($FixtureRoot).TrimEnd('\')
if ([IO.Path]::GetFileName($root) -notmatch '^certops-retention-atomic-[A-Za-z0-9]{6}$') { throw 'Unexpected owned retention fixture root' }
$file = Join-Path $root ('ledger\' + $Thumbprint + '.json')
foreach ($target in @($root, (Join-Path $root 'ledger'), $file)) {
  $item = Get-Item -LiteralPath $target -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Refuse linked retention fixture paths' }
}
$process = Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
if ($process.ParentProcessId -ne $OwnerProcessId) { throw 'Retention file holder parent mismatch' }
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class RetentionLedgerNativeFile {
 [StructLayout(LayoutKind.Sequential)] public struct Information {
  public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
  public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
 }
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetFileInformationByHandle(SafeFileHandle handle,out Information information);
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,StringBuilder path,uint count,uint flags);
}
'@
function Publish-Receipt([string]$Name, $Value) {
  $destination = Join-Path $root $Name
  $temporary = $destination + '.tmp'
  $bytes = [Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Compress))
  $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
  try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
  [IO.File]::Move($temporary, $destination)
}
$handle = $null
$published = $false
try {
  # GENERIC_READ and FILE_SHARE_READ|WRITE; omitting SHARE_DELETE prevents
  # replacing this actual file while permitting independent read verification.
  $handle = [RetentionLedgerNativeFile]::CreateFile($file, [uint32]2147483648, 3, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
  if ($handle.IsInvalid) { throw 'Could not hold owned ledger file' }
  $info = New-Object RetentionLedgerNativeFile+Information
  if (-not [RetentionLedgerNativeFile]::GetFileInformationByHandle($handle, [ref]$info) -or ($info.Attributes -band 16) -ne 0) { throw 'Held ledger object is not a regular file' }
  $buffer = New-Object Text.StringBuilder 32768
  $length = [RetentionLedgerNativeFile]::GetFinalPathNameByHandle($handle, $buffer, $buffer.Capacity, 0)
  if ($length -lt 1 -or $length -ge $buffer.Capacity) { throw 'Held ledger final path unavailable' }
  $final = $buffer.ToString()
  if ($final.StartsWith('\\?\')) { $final = $final.Substring(4) }
  if (-not $final.Equals($file, [StringComparison]::OrdinalIgnoreCase)) { throw 'Held ledger target differs from the owned file' }
  $identity = @{ token = $Token; pid = $PID; parentPid = $OwnerProcessId; created = $process.CreationDate.ToUniversalTime().ToString('o'); fileId = ('{0:x8}{1:x8}' -f $info.IndexHigh, $info.IndexLow); phase = 'held'; shareMask = 3 }
  Publish-Receipt 'held.json' $identity
  $published = $true
  $release = Join-Path $root 'release.txt'
  $deadline = [DateTime]::UtcNow.AddSeconds(90)
  while (-not (Test-Path -LiteralPath $release)) {
    if ([DateTime]::UtcNow -ge $deadline) { throw 'Owned retention handle release deadline exceeded' }
    Start-Sleep -Milliseconds 50
  }
  if ([IO.File]::ReadAllText($release) -ne $Token) { throw 'Owned retention release token mismatch' }
} finally {
  if ($handle) { $handle.Dispose() }
  if ($published) { $identity.phase = 'closed'; Publish-Receipt 'closed.json' $identity }
}
