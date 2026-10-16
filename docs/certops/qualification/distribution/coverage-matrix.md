# PR #329 feature coverage matrix

`E2E lab` means real public HTTP, PostgreSQL, enrolled CLI, Vault/Pebble and
native nginx/HAProxy processes on disposable containers, with experimental
capabilities. `Integration` includes injected SQL/receipts or bounded adapter
fault servers. Neither classification means released/native qualification.
Latest execution outcomes are recorded separately in
[execution-2026-10-16.md](execution-2026-10-16.md). All three fresh 15-phase
cohorts passed; the original 13-phase reports remain historical supporting
evidence. Neither set qualifies a released/native artifact.

Sources below are rooted at `tests/wildcard-vault/` unless stated otherwise.

| Feature | Tests / mandatory phase | Evidence level | Remaining gap |
|---|---|---|---|
| Ordinary DNS-01 certificate | `ux-lab/journey.cjs`, ordinary cohort, publish | E2E lab | Exact artifact/customer CA and DNS credentials |
| SAN DNS-01 certificate | Same, san cohort | E2E lab | Native hosts/provider permutations |
| Wildcard and apex DNS-01 | Same, wildcard cohort; `real-lifecycle.cjs` | E2E lab / direct executor fixture | Live authorized provider |
| Customer Vault publication and receipt | publish; `postgres.test.cjs`; agent material-store tests | E2E lab / integration | AppRole sink/rotation on native host |
| Immutable version/CAS and old version retained | qualification rollback; live adapter CAS, delete/undelete/destroy | E2E lab / integration | Elapsed customer retention windows and native unavailable-version rollback |
| Renewal creates a distinct version/identity | recovery; `postgres.test.cjs` | E2E lab / integration | Unattended native schedule |
| Vault authentication rejection/rotation | publish with revoked issuer token; security with revoked consumer read token and original pinned retry | E2E lab | AppRole/login/provider variants |
| Outage and committed write response loss | recovery; material-store fault tests | E2E lab / integration | Native crash points/default time windows |
| Private keys/Vault execution tokens absent from Core and logs | privacy; read-only fetch of every published version; retained revoked/rotated token history; scanner | Read-only audit / integration | Secret DNS provider, exhaustive encodings, ACME account credentials and external log sinks |
| Workspace group and explicitly authorized binding | publish/bindings; `pr329-review.test.cjs` | E2E lab / integration | Native cross-host policy races |
| One certificate to nginx and HAProxy | bindings; qualification external probes | E2E lab | Separate native hosts |
| Signed and version-pinned real agent jobs | bindings, recovery, qualification; dispatch/signing unit tests | E2E lab / unit | Exact shipped artifact |
| Actual install/reload and independent served leaf | qualification external TLS vs installed public fingerprint | E2E lab | Other supported target families |
| Offline consumer stays stale | recovery and offline canary | E2E lab | Physical outages/default stale intervals |
| Required canary and later wave ordering | qualification with stopped agents | E2E lab | Every failure/wave permutation |
| Required failure and explicit recovery | deployment-recovery | E2E lab | Native crash/lease-loss at every stage |
| Optional failure preserves required consumer success | qualification optional HAProxy reload failure | E2E lab | Degraded aggregate verified in PostgreSQL; no aggregate read UI invented |
| Concurrency and partial execution | concurrent requests; runtime-controls proves actual reload serialization at maxParallel=1 and overlapping hooks at maxParallel=2 | E2E lab / integration | Independent native hosts, file-rename timing and every failure/wave permutation |
| Rollout approval and separation of duties | stale authorization; self-approval refusal; different approver | E2E lab / integration | Membership change exactly during native claim |
| Viewer/manager/admin boundaries | qualification API role change; security real Chromium manager access and same-session viewer denial; admin browser matrix | Browser E2E lab / integration | Cross-workspace membership races and native roles |
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
| Drift and verification-only recovery | qualification mismatch; runtime-controls physically replaces old material and reloads, then verifies drift refusal and approved repair | E2E lab | Exact artifact on native filesystem variants and adversarial race timing |
| Old certificates cannot silently replace current | pinned rollback approval; retired unstarted old rollout and leaf checks | E2E lab / integration | Native late result after source retirement |
| Workspace material and binding scope | authorization cross-workspace API; Vault ACL tests | E2E lab / integration | All native unauthorized hosts |
| Consumer read-only retrieval | Scoped lab tokens; real Vault ACL fixture | E2E lab / integration | Customer AppRole ACL configuration |
| Invalid signature, replay and modified jobs | security injects captured genuine distribution envelopes into actual CLI transport: bad signature, modified version, replay and foreign-agent delivery | E2E lab / supporting protocol | Expired signed transport/default timing and independent native-host attacks |
| Retirement blocks unstarted work, preserves history | qualification retired rollout; transfer fixtures; existing retirement suites | E2E lab / integration | Concurrent native source retirement |
| Certificate/token workspace transfer | transfer phase; `transfer.test.cjs` all admission states/locks | E2E lab / integration | Native race cross-product |
| Pending safe handling; claimed/running/uncertain reconciliation | transfer phase, publication/reload 409; transfer SQL fixtures | E2E lab / integration | All real native claim statuses |
| Workspace pause/freeze retains containment | runtime-controls uses real admin pause, manager denial, rejected expansion/resume, unclaimed work and browser warning; review fixtures | E2E lab / integration | In-flight native pause races; billing/license freeze is a variant hook, with no Core freeze API |
| Distribution API contracts and identifiers | validation; group/versions/consumers/rollouts/retry; contract tests | E2E lab / contract | Full endpoint role/native race matrix |
| Renewals desired/observed identity and verification | real Chromium `ux-lab/browser.cjs` | Browser E2E lab | Viewer read is denied by current operator route contract |
| Pending, failure and reconciliation states visible | real browser at pending canary, reload uncertainty, optional failure, drift and converged state | Browser E2E lab | Dedicated aggregate publication/degraded/reconciliation labels are not exposed; no invented flow |

Every catalog row remains **partial**. Native qualification requires the
protected environments listed in the companion guide. Missing evidence,
unexecuted modes and skipped mandatory tests must remain failures/gaps.
