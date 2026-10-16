# Scheduler and public admission capacity

The separate manual `certops-scheduler-capacity-qualification.yml` workflow creates a fresh API/PostgreSQL stack, runs six mandatory supporting integration scenarios, verifies the report and destroys the stack even after failure. It is deliberately separate from concurrent API suites: the production scheduler scans globally. The test requires `CERTOPS_SCHEDULER_EXCLUSIVE_STACK=1` and refuses any foreign active automation period before creating its own.

Real OpenSSL leaves naturally expire within the actual SQL `NOW()` renewal window. Complete linked profiles and agent-local admission metadata are explicit seeded prerequisites; automation is enabled through the public replace-management endpoint. Five genuine public issuance reservations must block all automatic renewals at the shared CA cap. Public rejection frees one slot; two concurrent production sweeps must create exactly one automatic renewal. Public bulk admission shares that occupied capacity. Pause must prevent creation after another slot is released; resume permits one renewal and repeated sweeping creates no duplicate.

No certificate date, scheduler clock, job outcome or CA response is rewritten. Jobs remain pending approval: this proves scheduler/API/database admission, not native execution or successful CA renewal. All six scenarios passed focused execution against an independently created database and API on a separate loopback port. Independent strict report verification passed; the owned API stopped and the generated database was destroyed. Source lint and workflow YAML checks passed. Hosted qualification remains pending.

## Automatic renewal toggle boundaries

The same exclusive workflow runs `renewal-toggle-scheduler-api` after the capacity suite has cleaned its fixture. Seven mandatory supporting integration scenarios use actual public certificate imports, public profile edits, real PostgreSQL and production SQL-NOW scheduler/admission code:

- Disabling both profiles excludes them before scheduler selection and records the disabled count without creating jobs.
- Direct production automation admission also refuses a disabled profile, preventing alternate callers from bypassing scheduler SQL.
- A public manual renewal remains allowed while automatic renewal is disabled, retains the stored SAN/CA/command contract, and awaits approval without native execution.
- A separate public bulk request also creates an approved-policy pending job while disabled. Both manual and bulk jobs preserve independently declared target paths, deployment targets, key algorithm/size/rotation, SANs and verification, and leave stored profile metadata unchanged. The API intentionally labels both session-write routes `source: api`; this does not claim an internal `bulk` job source. Both jobs are publicly rejected before automatic scheduling.
- With `batchSize: 1`, an active peer is selected despite the disabled profile.
- Re-enabling the original profile followed by two concurrent sweeps creates one automatic job; a further sweep creates none.
- Owned workspace and private temporary fixtures are removed.

Complete linked agent-local profiles are explicitly seeded prerequisites. Expiry dates come from genuine OpenSSL certificates; no certificate timestamps, jobs or observations are rewritten. Focused local execution passed all seven cases on a separately owned database/API. Native CA execution, archived-profile lifecycle and hosted release execution are not established by this supporting report. The suite must never run a global scheduler sweep on a shared development stack; `CERTOPS_SCHEDULER_EXCLUSIVE_STACK=1` is mandatory and foreign active automation is refused.
