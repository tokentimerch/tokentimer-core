# Deterministic interruption and startup recovery

This is host-integration evidence. It is not power-loss durability and it is
not a real reboot. The case records a ledger point or a CNG point, stops the
owned service or kills the owned process at that point, and then starts that
same service or re-executes the owned image. Startup reads the recorded digest
before it continues. A digest mismatch preserves the point and does not start
recovery.

The owned service name and key container are `tt-int-` plus the run id. The
plan never names a machine service, and a process kill carries one recorded
pid. It does not kill by image name. The recovery commands do not shut the
machine down.

An in-use key is never deleted. A command that would delete the recorded
container, or that names key deletion, is refused while the key remains in
use. The point stays on disk until recovery accepts the same bytes.

The node tests perform the record, stop-or-kill plan, and startup decision
without a Windows host. The PowerShell path checks for service control and
process control, and for an owned point file, before it runs a command. A
missing host exits 1. A missing host is not a pass. The manual workflow is
`workflow_dispatch` only and runs those node tests. It does not stop a service
or reboot a runner.

Native execution of the service stop or process kill, and of the following
process startup, remains pending. This case does not qualify power loss, a
real reboot, or deletion of an in-use key.
