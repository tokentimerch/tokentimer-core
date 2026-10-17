# Certificate-operation interruption

This contract records a point at key generation, submit, install, and bind.
Recovery starts the same owned service, or re-executes the same owned image
after a process kill of that pid. It does not delete the in-use key.

The interruption is a service stop or a process kill. It is not power loss
and it is not a reboot. `powerLossDurabilityQualified` and
`realRebootQualified` stay false. `nativeExecutionQualified` stays false.

The proof object uses evidence level `host-integration`. The suite level is
`integration`. A missing host is a failure. Catalog rows
`windows-installed.deterministic-interruption-recovery` and
`windows-install.crash-recovery` can mention the additional stages without a
status change.
