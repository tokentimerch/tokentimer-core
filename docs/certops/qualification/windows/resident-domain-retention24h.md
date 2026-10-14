# Resident domain retention over a real day

This dedicated source tests the supported minimum 24-hour retention policy after
an actual public AD CS enrollment and a second enrollment replace A with B on the
same disposable Windows Server 2022 member. The six-day certificate template keeps
A valid beyond the retention deadline, so genuine cutover plus 24 hours determines
eligibility. The preparation source reads the actual production ledger; it never
creates a replacement row, changes dates or transfers a private key.

Preparation stops and drains the exact installed agent tree after both signed jobs
are terminal. The installed service remains stopped throughout the wait. One
SYSTEM ScheduledTask starts one resident Node process; no reboot trigger or restart
policy can join elapsed measurements from different processes. The keeper invokes
`runWindowsRetentionSweep` with its real clock, native discovery and cleanup. It
checks actual protected CNG key possession, certificate identity, ledger identity,
Azure VM and boot identity, and trusted replacement SNI TLS around the sweeps.

The same process measures at least 86,400,000 monotonic milliseconds. Hourly sweep
observation gaps must remain within 65 minutes; the final retained observation must
finish before the genuine deadline. A final due sweep occurs only after the full
resident day and must remove exactly the predecessor certificate/key while B and
trusted TLS remain available. Wall-clock disagreement over five seconds, a missed
boundary, incomplete native inventory, unexpected service descendants or process
interruption fails qualification. The keeper must start within ten minutes of the
actual cutover; its reviewed resident bound is 25 hours and its task limit 26 hours.

A normal disposable environment keeps its four-hour TTL. Only an independent
controller can extend it after verifying the exact candidate, owning workflow,
run/attempt, nonce, Azure VM identity, task XML, executable/source/config hashes and
current native readiness. The original preparation receipt must come from the
trusted owning GitHub artifact. Its immutable creation time bounds the extended
lease to 32 hours. Serialized comparison and readback do not promise an atomic
Azure update against unrelated external actors. Failed or canceled preparation and
handoff remain eligible for independent owned-resource cleanup.

The CA and Linux control plane can be deallocated after the actual issuer/cutover
facts and local keeper are frozen. This scope measures the real production
collector after issuance; it does not qualify a background agent interval, network
AD CS availability throughout the day, the default seven-day policy or other OS
and language profiles. Short preparation/finalization jobs surround the resident
VM wait. Finalization independently rechecks the original same-task/process/boot
identity, completed task result, actual native deletion, ledger and trusted TLS
before collecting a bounded public report and destroying the exact owned lab.

The source and pure refusal checks are implemented. No actual 24-hour native run
or hosted qualification has been performed here; an initial preparation receipt or
a timing-only keeper result must never be promoted to complete qualification.
