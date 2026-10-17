# Crash-dump containment

Crash-dump containment stays explicitly unqualified. The proof records
`crashDumpContainmentQualified: false`. `rejectReport` throws when a report
sets that field to true, including a report that otherwise looks closed.

`nativeExecutionQualified` stays false. A missing host is a failure. The
dispatch workflow writes a failed report and does not claim qualification.

Catalog row `windows-install.crash-recovery` can mention the contract
without a status change.
