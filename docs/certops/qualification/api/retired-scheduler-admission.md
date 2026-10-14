# Automatic renewal after identity retirement

The trusted manual `certops-scheduler-capacity-qualification.yml` workflow runs
`certops-retired-scheduler-e2e.test.js` sequentially after the existing capacity
and toggle fixtures have removed their resources. It requires an exclusive
API/PostgreSQL database, OpenSSL and `CERTOPS_SCHEDULER_EXCLUSIVE_STACK=1`.

Five mandatory integration scenarios import real two-day certificates through
the public API. Explicit SQL prerequisites supply complete agent-local profiles
and key mode; public management replacement links the profile. A separate active
control must create a real automation job under the workspace approval policy,
then public rejection and retirement close that control. The two retirement
subjects have never had an automation job, so prior idempotency cannot mask a bug.

An owned `FOR NO KEY UPDATE` lock changes no data while public retirement commits
revoked/decommissioned identity lifecycle. Retirement deliberately skips that
locked source cache. After rollback and release, the test independently requires
terminal identity status and still-active cached status. The real SQL `NOW()`
sweep must scan/create zero jobs; disabled-profile counts also exclude these
identities. Actual eligible scan snapshots captured before retirement are then
passed to the production default job creator inside PostgreSQL transactions.
Both API and automation sources must refuse with `CERTOPS_CERTIFICATE_NOT_RENEWABLE`, leave job history
unchanged and roll back. Fixture cleanup removes only owned users/workspaces/files.

The scheduler scan and disabled count use authoritative identity lifecycle.
Final renewal admission locks that identity `FOR SHARE` through the caller's
job/enrollment transaction, without locking the source cache. Retirement either
wins before admission, or serializes after admission and cancels queued work.
The shared job creator covers both ordinary renewal and AD CS enrollment
creation; the latter rolls its provisional enrollment back with job refusal.
A scan/admission retirement race increments `skippedRetired`; unexpected errors
remain visible. This supporting scope proves control-plane admission, not native
certificate issuance or a complete Windows qualification result.

Focused isolated execution reproduced two created jobs before the guard and
passed all five scenarios after it. No expiry, job, observation or clock value
was fabricated. Full CI and native qualification remain separate.
