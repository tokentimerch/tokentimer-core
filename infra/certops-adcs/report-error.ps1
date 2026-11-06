# Return only fixed diagnostics; guest output and exception text remain private.
function Get-CertOpsReportFailureCode([System.Management.Automation.ErrorRecord]$ErrorRecord) {
  $status=$ErrorRecord.Exception.Data['CertOpsArmHttpStatus']
  if($status -is [int] -and $status -ge 400 -and $status -le 599){return "arm-http-$status"}
  switch -Exact ($ErrorRecord.Exception.Message) {
    'Could not retrieve sanitized guest execution evidence' { return 'guest-execution' }
    'Guest report length receipt absent' { return 'length-receipt-missing' }
    'Guest report exceeds bounded evidence size' { return 'length-out-of-bounds' }
    'Guest report changed during retrieval' { return 'report-changed' }
    'Guest report hash receipt absent' { return 'hash-receipt-missing' }
    'Guest report bytes changed during retrieval' { return 'report-changed' }
    'Guest report chunk receipt absent' { return 'chunk-receipt-missing' }
    'Guest compressed report length receipt absent' { return 'compressed-length-missing' }
    'Guest compressed report exceeds bounded evidence size' { return 'compressed-length-out-of-bounds' }
    'Guest report chunk length mismatch' { return 'chunk-length-mismatch' }
    'Reconstructed guest evidence checksum mismatch' { return 'checksum-mismatch' }
    'Production worker ownership or drain evidence incomplete' { return 'worker-evidence-incomplete' }
    default { return 'unclassified' }
  }
}
