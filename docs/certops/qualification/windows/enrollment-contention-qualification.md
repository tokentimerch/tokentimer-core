# Enrollment lock and CNG contention

The Windows host suite requires `windows-enrollment-lock-cng-contention` on
Windows Server 2022 and 2025. Run only through its opted-in disposable elevated
host workflow, with CNG, PowerShell and OpenSSL available. No CA or IIS is needed
for this case, and native execution remains pending.

Three actual child processes share one owned state directory and enrollment
UUID. The winner acquires the production enrollment lock, generates a real
RSA-2048 CNG CSR, and holds the lock. The loser must return
`ENROLLMENT_LOCKED` before its delegating native-command observer records any
execution. After explicit release, retry acquires the same lock but the actual
existing-container query must refuse another `certreq` invocation.

Independent native KSP metadata, exact fixture-owned public CSR bytes, OpenSSL CSR public
SPKI and fresh native signatures verified with that public key prove that the
winner's machine key remains unchanged and non-exportable. The generator removes
its temporary INF/REQ files before returning; the child writes an exclusive
fixture-owned public copy of its returned CSR and independently requires the
original request temporary to be absent. No production request-file persistence
is claimed. This exercises the
supported lock/executor contract; the raw `generateCsrViaCng` function is not
claimed to provide atomic concurrent generation on its own.

Each child waits before native work until the parent measures its real PID,
parent PID, executable, entry path, enrollment token and creation time. Forced
cleanup rechecks that identity before targeting its process tree. Only explicit
native callback completion, release acknowledgement and clean process exit
permit key deletion. Unexpected or forced leader death is not treated as proof
that descendants drained: the case fails and retains the exact key for disposal
with the VM. The parent host's generic container list does not include that key.

The report retains bounded booleans and command counts; public CSR, nonce,
signature, PID details and key names stay local. Both host slots require current
fixture, child, lock worker and I/O support-source fingerprints. Missing custody,
nonzero loser native work, retry key generation, or unverified cleanup fails
release verification. Portable proof checks do not count as native qualification.

Participants now launch suspended inside a retained native JobObject before product code executes. The current runner SID is independently bound, including elevated non-SYSTEM host runs. Bounded atomic public file messages replace IPC; a clean native root exit, zero active job members and wrapper close authorize release. Emergency cleanup terminates only the retained owned job. Unknown drainage preserves the receipt, native key and host state before broad cleanup. This source change has not been executed against native CNG.
