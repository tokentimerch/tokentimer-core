# Return only fixed diagnostics; guest output and exception text remain private.
function Get-CertOpsReportFailureCode([System.Management.Automation.ErrorRecord]$ErrorRecord) {
  $status=$ErrorRecord.Exception.Data['CertOpsArmHttpStatus']
  if($status -is [int] -and $status -ge 400 -and $status -le 599){return "arm-http-$status"}
  switch -Exact ($ErrorRecord.Exception.Message) {
    'Could not obtain fresh lab ARM access token' { return 'arm-token-unavailable' }
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
    default {
      # Only fixed type categories are returned; never include exception text,
      # paths, parameter names, response bodies or arbitrary type names.
      if($ErrorRecord.Exception -is [System.Management.Automation.ParameterBindingException]){return 'parameter-binding'}
      if($ErrorRecord.Exception -is [System.Management.Automation.PSSecurityException]){return 'execution-security'}
      if($ErrorRecord.Exception -is [System.Management.Automation.CommandNotFoundException]){return 'command-unavailable'}
      if($ErrorRecord.Exception -is [System.UnauthorizedAccessException]){return 'access-denied'}
      if($ErrorRecord.Exception -is [System.IO.IOException]){return 'local-io'}
      return 'unclassified'
    }
  }
}
