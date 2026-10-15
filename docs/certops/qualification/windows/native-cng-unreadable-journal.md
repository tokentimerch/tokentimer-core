# Native CNG custody when an enrollment journal is unreadable

This source composition accepts the existing owned orphan fixture's actual
prepared machine key and genuine public CSR/journal. It complements the
software-CSR journal-reader ACL controls and the native corrupt-journal orphan
controls; it does not manufacture an installed agent or CA enrollment.

A native ACL holder opens the exact journal file, then the enrollments root,
with retained ACL-only access. Its native volume/file identity must match the
original Node handle observation. The holder runs inside the shared suspended
before-resume owned native Job, with the actual current principal SID.

Each case independently requires a fresh OS `EACCES` or `EPERM`. The production
protected-enrollment scan must fail closed and actual orphan reconciliation
must defer deletion. A fresh native signature/SPKI observation must show that
the same private machine key still exists and is usable. The ACL holder then
restores the exact original permissions through its retained handle, exits,
and proves native Job drainage before any parent key cleanup is permitted.
Original journal bytes, directory/file identities and production readers must
recover unchanged.

Unknown restoration, native child or guard ownership preserves the original
fixture and its key. Both the in-memory registry and durable guard participate
in parent cleanup refusal. The original orphan fixture remains responsible for
its separate positive terminal-journal/native-key cleanup.

Both cases are mandatory in the Windows host suite and require a closed
`nativeCngJournalAcl` report with all native facts and critical source hashes.
Supporting contract checks passed; protected Windows execution remains pending.
They qualify neither a CA request
nor installed-service recovery, and do not establish orphan-age timing.
