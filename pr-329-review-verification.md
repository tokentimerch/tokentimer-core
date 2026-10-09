# PR #329 review verification

Verified 9 October 2026 against `7c9b34f0`, including current main
`fdb92438ce3de345e14520a845858b3dd7797b1a`. All four findings are **confirmed**.
The corrections are ready for another review, not a release qualification.

## Findings

### 1. Distribution mutation authorization — Confirmed

**Evidence/root cause:** `middleware/auth.js:requireAuth` accepts the internal
worker Bearer credential; `services/rbac.js:loadWorkspace` grants that worker an
effective admin role without workspace membership. Consequently neither the
upstream membership gate nor `routes/certops.js:requireCertOpsWriteRole` prevents
worker writes. Before the fix, the binding PUT actually returned **200**, not 403.
CertOps API tokens follow a separate authentication surface; even a valid scoped
token is rejected by `requireAuth` on these workspace routes (401).

**Fix:** Dedicated `distributionWriteGuards` adds `requireCertOpsSessionUser` to
binding PUT, rollout creation, rollout state changes, and material-job retry.
Other CSR/worker paths retain their existing policy. Internal expansion continues
through the approved outbox, not these human mutation endpoints.

**Tests:** The integration test runs the real authentication, workspace lookup,
membership and route middleware. All four mutations reject workers (403), valid
API tokens (401), anonymous callers (401), viewers and nonmembers (403).
An administrator and a manager successfully exercise all four mutations.
Worker metadata reads still succeed. Session identities replace only Passport
deserialization; this is not a browser/login/CSRF end-to-end test.

### 2. Stale rollout lifecycle — Confirmed

**Evidence/root cause:** `distributionOperations.js:advanceRollout` previously
called `assertDeployableVersion` before its expiry retirement branch. Real worker
drains reported `CERTOPS_ROLLOUT_VERSION_INVALID`, retried the event and left the
rollout `deploying`. Revoked/decommissioned identities behaved similarly;
disabled groups and closed periods threw `CERTOPS_DISTRIBUTION_INACTIVE`.
Supersession of otherwise valid material already worked and is preserved.

**Fix:** Lock the group/period with an explicitly read-only-inactive option for
retirement, then retire stale generations, inactive management and invalid
material before scheduling consumers. Only the specific version-invalid domain
error is converted to retirement; infrastructure errors still propagate.
Admission, snapshot creation and dispatch retain their strict validity checks.

**Tests:** A valid rollout queues an offline consumer, expires in real elapsed
time and then retires without creating more jobs. Six additional worker/outbox
cases cover expired, revoked, decommissioned, superseded, closed-period and
disabled-group work. Invalid work becomes `retired`; its event becomes `skipped`
after one attempt with no error, and no new child is authorized. Replay is inert.
Fresh rollout admission and the dispatch validator for an already queued child
reject expired material.

### 3. Historical renewal issuers — Confirmed

**Evidence/root cause:** `renewalPathHealth.js:CERTIFICATE_ROW_SELECT` joined every
group marked active, including groups attached to ended management periods.
A source stopped and managed again returned **two certificate rows** before
the fix; single/page projections could consequently select historical authority.

**Fix:** Join the unique open management period first, then its active group.
The existing open-period and per-period-group unique constraints guarantee at
most one group per certificate without hiding corruption with a LIMIT clause.

**Tests:** Real PostgreSQL exercises retained active historical groups, stop/re-add
management with a different issuer, single/workspace/page projections, closure
and certificate retirement. Current issuer dependencies agree across all three
projections. Group authority reassignment is rejected by its existing immutable
trigger; changing issuer requires a new management period. Closed periods return
no distribution issuer. The transfer restriction below was independently checked.

### 4. Stale approved rollout requests — Confirmed

**Evidence/root cause:** `materialDistribution.js:createRolloutSnapshot` correctly
rejects a changed membership/revision/generation hash. Previously
`distributionOperations.js:processDistributionIntent` let that logical rejection
escape into transient outbox retries: the job remained **pending**, with no
rollout and no invalidation decision.

**Fix:** Recognized stale preconditions, detected before snapshot writes, now
atomically fail the request with `CERTOPS_ROLLOUT_APPROVAL_STALE`, clear its current
approval binding, append an `invalidated` approval decision and job-log event,
and return a terminal skipped outbox outcome. The frozen payload and prior
approval ledger are retained. Unknown/infrastructure failures still retry.
Operators request a new rollout with a new idempotency key and obtain a new
approval; existing keys keep resolving to the original failed request.

**Tests:** Approve → edit binding through HTTP → real worker drain now yields a
failed request, approved/invalidated ledger, zero rollouts, and one skipped event.
The original request replays unchanged and cannot gain another invalidation.
A fresh HTTP request/approval expands successfully. Completed requests replay
after subsequent edits without duplicate rollouts or invalidation.
A separate two-connection transaction test makes expansion win a concurrent
binding edit: its immutable snapshot remains at the approved revision, and
advancement pauses rather than deploying the subsequently changed binding.

## Executed regression assessment

The integration regressions were compared against the four original files
from `7c9b34f0`, then against the corrections, in separate newly migrated
PostgreSQL 17 databases: **3 passed / 10 failed before; 13 passed / 0 failed after**
(counts include lifecycle subtests). A final run also passed all 13 tests after
adding the already-queued-child dispatch validity assertion. Before/after logs are retained locally in
`.scratch/pr329-review/`. All database fixtures contain synthetic public metadata.
No existing audit database, service, container or other checkout was modified.

| Check executed | Result |
| --- | --- |
| New isolated PostgreSQL/API/outbox regressions | 13 passed |
| Existing distribution PostgreSQL lifecycle | 2 passed: publication/renewal identities, approvals, signed claims/results/replay, frozen waves, stale proof, retries, cancellation/backfill and uncertainty fences |
| `pnpm run test:unit` | 2,307 passed, including AD CS mixed contracts, dispatch, approvals and renewal health |
| `pnpm run test:agent` | 1,554 passed, 15 skips, zero failures; cached Go 1.26.6 on PATH |
| `pnpm run test:contracts` (`CONTRACT_API_REQUIRED=0`) | 42 passed |
| API / worker / agent lint | Passed; API 31 and agent 149 existing warnings, worker zero |
| API / worker / agent / dashboard builds | Passed; dashboard existing chunk-size warning |
| Contract manifest/OpenAPI coverage/integrity, lockfile overrides, secret logging | Passed |
| Agent vendor synchronization and generated capability build | Passed; no generated/vendored diff |
| Production dependency audit | No known vulnerabilities |
| Migrations 1–69 on fresh isolated PostgreSQL, then rerun | Passed; rerun reports up to date; no migration changes required |
| Latest main compatibility | Fetched main `fdb92438`; already an ancestor, no further merge necessary |

The agent suite executes `createAcmeIssuer` typed success/failure/pending/uncertain
cases, native Linux renewal/publication/recovery tests, Windows CNG execution
contracts, AD CS continuation/mixed-contract guards and signed job validation.
These are fixture-driven tests, not a new live CA/Vault/Windows-domain enrollment
qualification. The PostgreSQL lifecycle used an isolated-port copy of the
existing runner (59470 instead of 57470) and its existing public-only renewal
certificate fixture; its assertions were unchanged.

The latest main CI and its Docker Build & Security Scan were inspected and both
were successful: [run 37938974015](https://github.com/tokentimerch/tokentimer-core/actions/runs/37938974015).
This is main's result, not a scan of these changes or a claim of full local CI parity.

## Changed files

- `apps/api/routes/certops.js`: human session guard for the four distribution mutations.
- `apps/api/services/certops/distributionOperations.js`: retire invalid rollout work and terminally invalidate stale approval requests.
- `apps/api/services/certops/materialDistribution.js`: narrowly scoped inactive-group locking option for retirement; default admission remains strict.
- `apps/api/services/certops/renewalPathHealth.js`: authoritative open-period group join.
- `tests/wildcard-vault/pr329-review.test.cjs`: isolated real PostgreSQL, HTTP middleware, outbox, elapsed-expiry and concurrency regressions.
- `pr-329-review-verification.md`: this report.

No issuer, dispatch, wire schema, key-custody or migration architecture changed.
No Cloud or Enterprise changes were required for these Core-local corrections.

## Remaining risks / unexecuted qualification

- **Existing transfer limitation:** invoking `certops_transfer_management_sources`
  for published distribution history fails with foreign key
  `certops_material_versions_workspace_id_publishing_job_id_fkey`: the transfer
  relocates publishing jobs while versions retain their workspace binding.
  This occurs both before and after these fixes. The test verifies full rollback,
  preservation of the source period and no destination issuer dependency.
  Supporting this transfer needs a separate history/migration design; these
  corrections do not make it supported. This remains a merge/release consideration.
- No new production-image build/scan, full HTTP integration suite, browser UX
  lab, live ACME/Vault exercise, real AD CS domain/CNG enrollment, appliance/HA
  qualification, or Cloud/Enterprise qualification was executed in this review.
  The earlier UX lab remains running and its evidence was left untouched.
- The 15 agent skips retain their platform/fixture prerequisites. Unsupported
  appliance execution capabilities remain unqualified. No PR merge or release.

## Reproduce the new tests

Use a new container and database, ensure loopback port 59470 is unused, and run
from an isolated checkout. These are public fixture credentials only:

```powershell
$taskContainer = 'tt-pr329-review-' + [guid]::NewGuid().ToString('N')
$env:DB_HOST='127.0.0.1'; $env:DB_PORT='59470'
$env:DB_USER='pr329_fixture'; $env:DB_PASSWORD='isolated-review-only'
$env:DB_NAME='pr329_review_' + [guid]::NewGuid().ToString('N')
$env:NODE_ENV='test'; $env:CERTOPS_ENABLED='true'
docker run -d --name $taskContainer -p 127.0.0.1:59470:5432 `
  -e POSTGRES_USER=$env:DB_USER -e POSTGRES_PASSWORD=$env:DB_PASSWORD `
  -e POSTGRES_DB=$env:DB_NAME postgres:17-alpine
node apps/api/migrations/migrate.js
node --test tests/wildcard-vault/pr329-review.test.cjs
```

The migrator waits for database readiness. Do not point this runner at shared
services or existing audit databases; its environment fences are intentional.
