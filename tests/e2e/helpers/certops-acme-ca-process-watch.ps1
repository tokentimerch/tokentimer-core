param(
 [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ObservedProcessId,
 [Parameter(Mandatory)][string]$ExpectedExecutable,
 [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSha256,
 [ValidateRange(1,300)][int]$MaximumSeconds=60
)
$ErrorActionPreference='Stop'
# This diagnostic primitive monitors process lifetime only; it does not claim
# complete CA observation, socket continuity, or qualification coverage.
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class QualificationProcessHandle {
 [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] public static extern bool QueryFullProcessImageName(IntPtr process,uint flags,StringBuilder path,ref uint length);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool CloseHandle(IntPtr handle);
}
'@
$handle=[IntPtr]::Zero
try {
 $expected=[IO.Path]::GetFullPath($ExpectedExecutable)
 $stream=[IO.File]::OpenRead($expected);$sha=[Security.Cryptography.SHA256]::Create()
 try{$digest=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','')}finally{$stream.Dispose();$sha.Dispose()}
 if($digest -ine $ExpectedSha256){throw 'BINARY_DIGEST_MISMATCH'}
 # SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, no process mutation or memory access.
 $handle=[QualificationProcessHandle]::OpenProcess(0x00101000,$false,$ObservedProcessId)
 if($handle -eq [IntPtr]::Zero){throw 'PROCESS_HANDLE_UNAVAILABLE'}
 $buffer=[Text.StringBuilder]::new(32768);[uint32]$length=$buffer.Capacity
 if(-not [QualificationProcessHandle]::QueryFullProcessImageName($handle,0,$buffer,[ref]$length)){throw 'PROCESS_IMAGE_UNAVAILABLE'}
 if(-not [string]::Equals([IO.Path]::GetFullPath($buffer.ToString()),$expected,[StringComparison]::OrdinalIgnoreCase)){throw 'PROCESS_IMAGE_MISMATCH'}
 $wait=[QualificationProcessHandle]::WaitForSingleObject($handle,0)
 if($wait -ne 258){throw 'PROCESS_NOT_RUNNING'}
 $watchId=[guid]::NewGuid().ToString('N')
 @{event='started';watchId=$watchId;processId=$ObservedProcessId;binarySha256=$ExpectedSha256.ToLowerInvariant();coverageComplete=$false} | ConvertTo-Json -Compress
 $clock=[Diagnostics.Stopwatch]::StartNew()
 while($clock.Elapsed.TotalSeconds -lt $MaximumSeconds){
  $wait=[QualificationProcessHandle]::WaitForSingleObject($handle,1000)
  if($wait -eq 0){@{event='process-exited';watchId=$watchId;coverageComplete=$false} | ConvertTo-Json -Compress;exit 0}
  if($wait -ne 258){throw 'PROCESS_WAIT_FAILED'}
  @{event='heartbeat';watchId=$watchId;elapsedSeconds=[int]$clock.Elapsed.TotalSeconds;coverageComplete=$false} | ConvertTo-Json -Compress
 }
 @{event='monitor-expired';watchId=$watchId;coverageComplete=$false} | ConvertTo-Json -Compress
} finally {
 if($handle -ne [IntPtr]::Zero){[void][QualificationProcessHandle]::CloseHandle($handle)}
}
