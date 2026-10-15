# PR #329 feature coverage matrix

`E2E lab` means real public HTTP, PostgreSQL, enrolled CLI, Vault/Pebble and
native nginx/HAProxy processes on disposable containers, with experimental
capabilities. `Integration` includes injected SQL/receipts or bounded adapter
fault servers. Neither classification means released/native qualification.
Execution outcomes are recorded separately in [execution.md](execution.md).

Sources below are rooted at `tests/wildcard-vault/` unless stated otherwise.

| Feature | Tests / mandatory phase | Evidence level | Remaining gap |
|---|---|---|---|
| Ordinary DNS-01 certificate | `ux-lab/journey.cjs`, ordinary cohort, publish | E2E lab | Exact artifact/customer CA and DNS credentials |
| SAN DNS-01 certificate | Same, san cohort | E2E lab | Native hosts/provider permutations |
| Wildcard and apex DNS-01 | Same, wildcard cohort; `real-lifecycle.cjs` | E2E lab / direct executor fixture | Live authorized provider |
| Customer Vault publication and receipt | publish; `postgres.test.cjs`; agent material-store tests | E2E lab / integration | AppRole sink/rotation on native host |
| Immutable version/CAS and old version retained | qualification rollback; adapter CAS test | E2E lab / integration | Customer retention/deletion policy |
| Renewal creates a distinct version/identity | recovery; `postgres.test.cjs` | E2E lab / integration | Unattended native schedule |
| Vault authentication rejection/rotation | publish with revoked scoped token and same-job retry | E2E lab | AppRole/login/provider variants |
| Outage and committed write response loss | recovery; material-store fault tests | E2E lab / integration | Native crash points/default time windows |
| Private keys/Vault execution tokens absent from Core and logs | privacy; scanner; material-store tests | Read-only audit / integration | Secret DNS provider; all encodings and log sinks |
| Workspace group and explicitly authorized binding | publish/bindings; `pr329-review.test.cjs` | E2E lab / integration | Native cross-host policy races |
| One certificate to nginx and HAProxy | bindings; qualification external probes | E2E lab | Separate native hosts |
| Signed and version-pinned real agent jobs | bindings, recovery, qualification; dispatch/signing unit tests | E2E lab / unit | Exact shipped artifact |
| Actual install/reload and independent served leaf | qualification external TLS vs installed public fingerprint | E2E lab | Other supported target families |
| Offline consumer stays stale | recovery and offline canary | E2E lab | Physical outages/default stale intervals |
| Required canary and later wave ordering | qualification with stopped agents | E2E lab | Every failure/wave permutation |
| Required failure and explicit recovery | deployment-recovery | E2E lab | Native crash/lease-loss at every stage |
| Optional failure preserves required consumer success | qualification optional HAProxy reload failure | E2E lab | Degraded aggregate verified in PostgreSQL; no aggregate read UI invented |
| Concurrency and partial execution | concurrent requests, maxParallel=2; PostgreSQL waves | E2E lab / integration | Timed proof of actual overlapping native mutations |
| Rollout approval and separation of duties | stale authorization; self-approval refusal; different approver | E2E lab / integration | Membership change exactly during native claim |
| Viewer/manager/admin boundaries | qualification role change; publish repair admin check; review fixtures | E2E lab / integration | Full browser role matrix |
| Binding revision invalidates approval/proof | authorization genuine PUT, failed approved expansion; review race tests | E2E lab / integration | Native claim race |
| Pause/resume | qualification rollout state routes; paused-workspace review tests | E2E lab / integration | Native workspace freeze with in-flight effects |
| Retry and cancellation | same-job retries; retired unstarted rollout; transfer tests | E2E lab / integration | No standalone public job-cancel endpoint exists |
| Idempotent duplicate/concurrent requests | concurrent PUT and rollout requests; post-membership replay | E2E lab / integration | Cross-process native request races |
| Frozen approved material and authorization snapshot | qualification pinned canary job; PostgreSQL approval snapshots | E2E lab / integration | All native stale-result timing |
| Approval/job success does not imply fleet convergence | offline canary; matrix comparisons | E2E lab | Native release proof |
| Explicit approved rollback to retained version | qualification rollback, external leaf check, restore | E2E lab | Real retention windows/policy exhaustion |
| Interrupted reload/uncertain effect reconciliation | deployment-recovery; optional failure; local read-only reconcile CLI then signed retry | E2E lab | Host death/default lease duration |
| Stale claims, expired leases, late results | `postgres.test.cjs`; existing agent lease/result suites | Integration | Distribution native interruption and late outbox journey |
| Stale evidence never promotes state | PostgreSQL stale generation/receipt tests | Integration | Native default freshness expiry |
| Drift and verification-only recovery | qualification mismatch/current verification, unchanged served leaf and ACME order count | E2E lab | Native filesystem drift/adversarial replacement |
| Old certificates cannot silently replace current | pinned rollback approval; retired unstarted old rollout and leaf checks | E2E lab / integration | Native late result after source retirement |
| Workspace material and binding scope | authorization cross-workspace API; Vault ACL tests | E2E lab / integration | All native unauthorized hosts |
| Consumer read-only retrieval | Scoped lab tokens; real Vault ACL fixture | E2E lab / integration | Customer AppRole ACL configuration |
| Invalid signature, replay and modified jobs | Existing real-agent protocol/signing/replay suites; `postgres.test.cjs` | Supporting protocol/unit/integration | Distribution-specific tampered signed transport through CLI |
| Retirement blocks unstarted work, preserves history | qualification retired rollout; transfer fixtures; existing retirement suites | E2E lab / integration | Concurrent native source retirement |
| Certificate/token workspace transfer | transfer phase; `transfer.test.cjs` all admission states/locks | E2E lab / integration | Native race cross-product |
| Pending safe handling; claimed/running/uncertain reconciliation | transfer phase, publication/reload 409; transfer SQL fixtures | E2E lab / integration | All real native claim statuses |
| Workspace pause/freeze retains containment | `pr329-review.test.cjs`; existing pause/ingestion tests | Integration | Native paused/frozen rollout race |
| Distribution API contracts and identifiers | validation; group/versions/consumers/rollouts/retry; contract tests | E2E lab / contract | Full endpoint role/native race matrix |
| Renewals desired/observed identity and verification | real Chromium `ux-lab/browser.cjs` | Browser E2E lab | Viewer read is denied by current operator route contract |
| Pending, failure and reconciliation states visible | real browser at pending canary, reload uncertainty, optional failure, drift and converged state | Browser E2E lab | Dedicated aggregate publication/degraded/reconciliation labels are not exposed; no invented flow |

Every catalog row remains **partial**. Native qualification requires the
protected environments listed in the companion guide. Missing evidence,
unexecuted modes and skipped mandatory tests must remain failures/gaps.
