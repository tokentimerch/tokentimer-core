# Certificate identity hardening review

Source review base: `3402b282720196418c7bb37d5464456cf48ef65b`.
Integrated into Core PR #284, `feat/certops-fingerprint-identity`.

## Pre-implementation findings

| Severity | Invariant / behavior | Existing protection and confirmed gap | Required change |
| --- | --- | --- | --- |
| P1 | INV-01, INV-02, INV-04 | v62 has workspace/fingerprint uniqueness and observation upserts preserve identity lifecycle. SQL normalization omits trimming, and lifecycle itself can be reset or downgraded by direct writes. | Canonical SQL normalization and terminal identity lifecycle constraints/triggers. |
| P1 | INV-03 | `admin.js` closes only `endpoint_monitor` source rows. The bridge can reuse a `domain_checker` row linked through instances/targets, leaving that source managed after deletion. Direct endpoint deletion has no database lifecycle boundary; the source FK cascades delete periods and instances when a managed source is physically removed. | Close every endpoint-owned period before FK references are nulled. Archive periods and detach observations on ordinary source removal. |
| P1 | INV-05, INV-06 | Period-based counting is correct; lifecycle does not release units. `readdManagingSource` accepts an optional admission callback, but its route supplies none. v62's managed-row INSERT trigger, provisioning, reconciliation and rotation have no shared admission boundary. Core currently has unlimited quota; Cloud owns finite plan limits. | Mandatory database admission on opening/changing periods with the existing workspace advisory lock; optional database workspace limit, unlimited by default. Remove the optional callback bypass. |
| P1 | INV-07 / workspace isolation | Application rediscovery does not reopen periods, but direct UPDATE can reopen or rewrite closed periods. Association/job period FKs do not enforce workspace equality. | Terminal period immutability and composite workspace FKs for periods, associations, jobs, identities and profiles. |
| P1 | INV-08 | The worker checks claim ownership on its first UPDATE and bridge transaction. Token adoption/creation and linking occur outside that transaction; deletion or lease takeover can leave token side effects behind. Health alerts have the same check/write gap. | One owner-locked transaction for all effects of each result, with network work outside the transaction. |
| P1 | Rotation / late observations | Source upserts overwrite fingerprints in arrival order, with no observation watermark. Late A can replace current B. v62's association history starts at migration time, and older fingerprint observations are not represented there. | Monotonic source observation watermark; history updates must not advance current management. |
| P1 | Jobs | v62 guards status transitions using a period SHARE lock, but INSERT can directly create claimed/running work. Closing periods only cancels jobs in application routes. Stop holds period then locks jobs, whereas claim holds job then period: a deadlock is possible. | Database tagging/claim validation on INSERT and UPDATE; atomic close/cancel with nonblocking job locking and a fail-closed claim result. Preserve existing claimed/running work for reconciliation. |
| P1 | Lifecycle / shared token | Retirement queries exclude active siblings, but concurrent observation/rotation and retirement are not serialized with the same workspace primitive. The exported legacy retirement helper still updates source/token lifecycle without retiring the identity. | Serialize lifecycle and source transitions, derive token lifecycle from all siblings, and route the compatibility helper through identity retirement. |
| P2 | Inventory pagination | `listCertificateIdentities` pages identities, then appends provisional rows sorted by creation time regardless of requested sort. Filters and display status can disagree; invalid source/sort filters are silently accepted. | One globally filtered/sorted union, stable tie-breaker and bounded batched history loading. |
| P1 | Migration v62 | `UPDATE ... FROM managed_certificates` chooses metadata nondeterministically when fingerprints have several sources. Whitespace fingerprints are missed. Deleted Domain Checker sources remain open. Job identity is inferred from the mutable current source for historic jobs; retired records with unverified audit status and prior observations need explicit issues. | Add v63; repair deterministic metadata/backfill and report insufficient historic evidence instead of guessing. Preserve all earlier migration versions. |
| P2 | Observations | v62 observation trigger fires only on observed_at, so fingerprint-only changes bypass identity creation. Endpoint binding replacement does not distinguish current from superseded fingerprints. | Cover fingerprint-only updates and monotonic captures; preserve repeated slot observations and establish proven absence at a superseded service binding. |

No P0 issue was confirmed. These notes were written before implementation; the
table also includes the physical source deletion and legacy-helper gaps verified
while exercising their database paths.

## Further confirmed findings from validation

| Severity | Path | Confirmed issue and resolution |
| --- | --- | --- |
| P1 | v62 audit backfill | After workspace erasure, retirement audit rows can have `workspace_id = NULL`. Unchanged raw v62 fails with PostgreSQL `23502`. The runner now uses a connection-local temporary audit view to filter unattributable rows during v62 only. Audit metadata and the immutability guard remain untouched; rollback removes the view. |
| P2 | `certificateIdentity.js:inTransaction` | A connected `pg.Client` has `connect()`, so the helper mistakes a caller-owned client for a pool. Identify real clients and retain their transaction; rollback tests cover identity retirement, legacy retirement and stop/re-add. |
| P2 | `agentDispatch.js:claimJobs` | The management-period predicate excludes legitimate `protocol_smoke` diagnostic jobs with no certificate subject. Restore their narrowly scoped selection; existing diagnostic-agent integration tests pass. |
| P2 | management stop route | The new stop route omits the existing key-material rejection middleware. Restore it and verify retirement, stop and re-add reject secret-bearing bodies without echoing their content. |
| P1 | production dependency audit | Axios 1.18.0 causes 5 moderate and 7 high audit findings. Exact-pin 1.20.0 in API, worker and dashboard, refresh the lockfile and verify the production audit is clean. |
| P2 | local Docker build context | An ignored local Windows service-host executable is copied by `COPY packages` into Linux API/worker images. Its old Go libraries fail the image scan. Exclude only generated `tokentimer-agent-host-*.exe` files from the context; preserve the local executable and tracked agent scripts. |

Validation also exposed test isolation defects: a fixed September delivery used
for a current-month assertion, a fixed local-user email without cleanup, shared
Default-workspace token fixtures, cached notifier credentials, and dashboard
fixtures still using pre-identity actions/payloads. Their assertions remain
strict; fixtures now isolate their state, use a current delivery where required,
and validate identity/fingerprint/reason/uncertainty inputs. A provisional-source
period-date error in the hardening candidate was caught and corrected: the
returned start time comes from the new period rather than source creation.

## Existing invariants retained

- Certificate uniqueness is enforced within a workspace, with independent identities across workspaces.
- Certificate lifecycle and management are separate; rotation creates a new identity and history association.
- Explicit stop creates a terminal period; re-add uses a new row.
- Identity retirement keeps observations and does not close management or free quota.
- Service-binding evidence and uncertainty acknowledgment guard decommission.
- Routes use the existing workspace membership and manager RBAC boundaries; key material rejection remains mandatory.

## Migration policy decision

The repository records migration version/name pairs and skips applied versions.
Its runner explicitly supports historic shipped migration sequences, and its DDL
guard requires transactional, additive changes. On the original review base, the
identity schema was v62 and the hardening schema was appended as v63. During the
rebase onto `main`, auto-sync became v61, identity remained v62, and hardening
remained v63. The identity migration body was retained. Both a fresh pre-v62
upgrade and an already-v62 upgrade were tested. Ambiguous historic
associations and lifecycle remain reported rather than guessed.

The runner's v62 compatibility view resolves the qualified existing audit
relation using PostgreSQL `quote_ident`; it affects only that connection's
backfill reads. It is dropped before commit. It does not rewrite a historical
migration or mutate audit data. Use the repository migration runner for pre-v62
upgrades; manually executing raw v62 still encounters its historical defect on
erased-workspace audit rows.

## Resulting invariant enforcement

| Invariant | Enforcement and meaningful coverage |
| --- | --- |
| INV-01 | SQL and JavaScript canonicalize trimmed, colon-separated SHA-256. Workspace/fingerprint uniqueness is retained. Eight concurrent discoveries converge; another workspace has its own identity. |
| INV-02 | Identity INSERT/UPDATE guard makes revoked/decommissioned retirement sticky, including revoked-to-decommissioned rejection. Rediscovery adds evidence without resetting lifecycle. Shared-token retirement and later rotation are covered. |
| INV-03 | Endpoint BEFORE DELETE closes both endpoint-monitor and reused Domain Checker periods. Source BEFORE DELETE closes management and detaches instances. Snapshot source references and identity/association/job history survive ordinary deletion. Account/workspace erasure retains its deliberate cascade semantics. |
| INV-04 | Rotation changes an open period's current identity, closes its previous association and appends another. Source observation watermarks reject late A after B, including equal-time and cert-manager resource-version regressions. A's lifecycle does not transfer to B. Late job reconciliation requires the original open period and matching identity. |
| INV-05 | Count distinct identities with open periods plus each fingerprintless provisional. Retirement does not release units. Closing the last period does. Tests cover shared fingerprints, provisional promotion, rotation and both transfer outcomes. |
| INV-06 | Every open-period INSERT and identity change invokes `certops_admit_management`, including trigger-created periods. Explicit re-add also invokes it; there is no optional callback bypass. The existing workspace advisory lock serializes boundary admissions. One remaining unit admits only one of two concurrent requests. |
| INV-07 | Closed period updates and ownership/start/source mutations fail at the database. Explicit re-add inserts another admitted row. Source history beyond the list's 20-row summary is available through detail. |
| INV-08 | Each worker result's database effects take the workspace lock and lock a live endpoint matching workspace, UUID and `check_claim_id` before token, certificate, management or health-alert changes. Network checks occur outside the transaction. Deleted/recreated endpoints and lease takeover suppress the complete old result path. |

List count and pagination use one PostgreSQL snapshot over a global identity /
provisional union. All six requested sortable dimensions are tested in both
directions with stable kind/UUID tie-breakers, complete page traversal and an
offset beyond the total. Source/location enrichment uses three SQL requests per
page, replacing per-identity requests. Manager history and viewer redaction are
tested alongside cross-workspace reads/writes and secret-material rejection.

Closing management cancels unstarted pending, approved and pending-approval jobs.
Existing claimed/running jobs retain their attribution and receive reconciliation
state. Database guards validate both INSERT and UPDATE. Close uses `SKIP LOCKED`
for jobs so it cannot wait on a claimant holding a job row while waiting for the
period; that claimant cancels itself after observing the closed period. Both
claim-first and stop-first races use explicit PostgreSQL blocking barriers.

## Database changes

- Add v63, `certops_identity_invariants_hardening`; preserve every earlier version.
- Add optional workspace `certops_managed_identity_limit`, source observation
  watermark, and frozen period source/reference snapshots.
- Enforce composite workspace references for associations, jobs, identities and
  renewal profiles. Retain closed source UUIDs without a destructive source FK;
  locked validation enforces ownership when management opens.
- Make instance source links nullable so physical source removal retains facts.
- Add indexes for normalized source/observation fingerprints, source period
  history, period job state and identity expiry; retain identity uniqueness,
  active-period identity and association/location indexes.
- Centralize admission, lifecycle, source deletion, association tracking,
  observation ordering and job boundaries in PostgreSQL triggers/functions.
- Support existing authorized workspace transfers: preserve old closed history,
  deduplicate destination identities, carry the strongest verified retirement,
  cancel unstarted work, reject in-flight transfers and admit new management.
- Backfill metadata deterministically. Only verified fingerprint/status audit
  evidence establishes retirement. Clear guessed historic job identity when
  rotation evidence exists, and retain explicit migration issues for ambiguity.
- Raw v63 re-execution is tested with live records, closed periods and orphaned
  audit rows; the runner continues using its version/name migration ledger.

## Validation and final assessment

Validation date: 2026-10-01. Native Node 24.11.1, pnpm 11.13.0 and disposable
Docker PostgreSQL 17.10. The packaged API also runs its real migration CLI against
a pre-v62 database containing live retirement evidence and an erased-workspace
audit row. This completes v62/v63 and preserves the orphan audit metadata.

| Check | Result |
| --- | --- |
| Unit suite | 2,250 passed; 345 suites; no failures or skips. |
| New PostgreSQL invariant suite | 36 passed; real triggers, transactions, migration upgrades and races. |
| New identity HTTP suite | 9 passed; manager/viewer/outsider isolation, redaction, preconditions, secret rejection and finite quota. |
| Full core integration suite | 1,213 passed; 2 existing environment-dependent tests pending; no failures. |
| Dashboard tests and coverage floor | 733 passed across 74 files; floor passed (56.23% lines, 48.59% branches, 54.63% functions). |
| Runtime contract tests with API required | 50 passed across 17 suites; no failures or skips. |
| API/worker/dashboard lint | Passed; 21 existing API warnings and 64 existing dashboard warnings; no errors. |
| Dashboard formatting, types and build | Passed; existing bundle-size warning remains. |
| Contracts/OpenAPI, integrity, lockfile pins, secret logging | Passed; 39 contract files, 7 namespaces, 30 required dependency pins, 171 secret-logging source files. |
| Production dependency audit | No known vulnerabilities. |
| Compose / Helm | All four Compose configurations passed; Helm 3.20.1 verification passed. |
| API/dashboard/worker image builds and boot paths | Passed; final API image migrated/booted against the disposable database and returned HTTP 200 from `/health`; all six worker entrypoints and dashboard nginx configuration checked. |
| Grype 0.112.0, `--fail-on high --only-fixed` | All three final images passed: zero reported matches; five matches per image excluded by the existing repository policy. No ignores added. |

The two existing core skips are Twilio signature callback tests requiring the
external callback fixture. Tests use isolated ports/databases; pre-existing
Docker test stacks and the user's `audit-*` files are preserved. The repository's
backend coverage collector, which manages the standard Compose stack, was not
run; complete unit/core tests and frontend coverage were run independently.
These results were recorded on the source hardening branch before integration
into PR #284. They are historical validation evidence, not a claim that each
check was rerun after the rebase.

### Rebase and manual validation, 2026-10-02

Rebased the identity and hardening commits onto current `main`, retaining the
v61 auto-sync, v62 identity, v63 hardening migration sequence. Against a
disposable PostgreSQL 17 instance, the actual migration CLI applied all 63
migrations. The invariant suite passed 36 tests; the HTTP identity suite passed
9 tests against a containerized API. The API image built, started and returned
HTTP 200 from `/health`. The complete Core unit suite passed 2,260 tests across
346 suites. The focused dashboard component suite passed 33 tests, and the
dashboard production build passed. These checks used the rebased PR branch.

## PostgreSQL performance evidence

The reproducible `scripts/certops-identity-performance.cjs` creates and drops its
own database. It migrates the schema, populates two workspaces with 5,000 identities
and 10,000 sources each, adds 100 provisional sources and 10,000 observations, then
uses `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` on actual inventory SQL, admission
predicates and the admission function. The listed workspace total is 5,100. The
table below records the source-branch run; the rebased branch was measured again.

| Query | Execution time |
| --- | ---: |
| Grouped inventory, 50-row expiry page | 143.644 ms |
| Source history, 50 identities | 2.878 ms |
| Locations, 50 identities | 3.570 ms |
| Exact workspace/fingerprint lookup | 0.034 ms |
| Distinct managed quota count | 3.900 ms |
| Admission function: already-managed identity | 0.240 ms |
| Admission function: new identity | 3.193 ms |

`IDENTITY_HARDENING_POSTGRES_PLANS.json` records index use, sequential scans and
buffer counts from that run. Exact identity lookup uses its unique index;
existing-identity admission uses `idx_certops_management_identity_open`. Quota
counting scans the period population once in the measured plan.
Source history uses the association identity/time index. The global count/sort and
batched history/location joins still scan relevant populations where PostgreSQL
chooses that plan; they do so once per batch. An early correlated-query hardening
candidate took 2.63 seconds at this population; batching and correcting the SQL
normalizer's cost removed that pattern. This is local warm-cache evidence under
concurrent build/test load, not a production latency guarantee.

On the rebased branch with the same 5,100-row inventory workload, the grouped
expiry page took 97.422 ms, source history 0.455 ms, locations 2.794 ms,
fingerprint lookup 0.025 ms, distinct quota count 0.989 ms, and the new-identity
admission function 2.306 ms. These are local measurements, not latency targets.

## Remaining limits and review readiness

- Core's OSS quota remains unlimited by default. A finite installation must
  populate `workspaces.certops_managed_identity_limit`; Cloud's production plan
  overlay must wire its plan limits to this boundary before relying on it for
  finite Cloud plans. No Cloud or Enterprise repository was changed.
- Historic lifecycle/association evidence can be insufficient. The migration
  issue mechanism reports those records; it does not fabricate past lifecycle,
  association dates or job attribution. Operators must resolve those cases.
- Apply additive migrations before deploying the changed code. v63 adds indexes
  and validation triggers with normal PostgreSQL DDL locks; no production-scale
  migration-duration, sustained-load or maintenance-window rehearsal was run.
  The pre-v62 migration role needs the normal database TEMP privilege for the
  compatibility view.
- Existing claimed/running work needs genuine reconciliation after management
  closes. It is retained and prevented from updating a new management association;
  closing management cannot undo an external operation that already ran.
- Grype uses the repository's existing ignore policy; no scanner ignores were
  added. Local lint/build warnings and the two environment-dependent core skips
  are disclosed above. Backend coverage and a production deployment were not run.

Within Core's configured quota policy, the branch enforces all eight requested
domain invariants with database boundaries and owner-scoped transactions, backed
by real PostgreSQL and HTTP tests. It is suitable for invariant-focused human
review. This assessment does not assert deployment readiness for unconfigured
finite Cloud plans or unresolved historical migration issues. The hardening is
integrated into Core PR #284.
