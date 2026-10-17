# Full-installer second-rename failure

When the second directory rename fails, recovery puts the install back under
its original name. The in-use service binary stays in place. The in-use CNG
key is not deleted.

The owned manifest names the original directory, the staging directory, and
the previous directory with the run id. Commands that delete that binary or
key, or that issue a blanket netsh reset, are refused.

`nativeExecutionQualified`, `powerLossDurabilityQualified`, and
`realRebootQualified` stay false. A missing installer host is a failure.

This is a script contract for the full installer failure path. It does not
qualify activation-function restoration or a completed native rollback.
Catalog row `windows-install.upgrade-rollback` can mention the contract
without a status change.
