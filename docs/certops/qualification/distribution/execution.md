# Distribution execution record

The original record below is preserved. The latest continuation and fresh
15-phase cohorts are in [execution-2026-10-16.md](execution-2026-10-16.md).

Date: 2026-10-15. Candidate is PR #358's branch after integration of PR #329.
The final enrolled-agent cohort candidate is `3d47e52c6b89b9c72d2dc9c73b453f6b12b9afb4`.
The concurrent native qualification additions at `f1359f66` were merged and
preserved. Local runs use source mounts and source digests; they do not qualify an exact
released binary or enable distribution in the production capability manifest.

| Check | Actual result |
|---|---|
| Core unit suite | 2,619 passed; no skips. Earlier merge-schema and Windows fixture failures corrected; transient HTTP-watch timeout passed in targeted and bounded-concurrency reruns. |
| Qualification tooling | Initial 707 passed; after the concurrent merge, all 841 tests passed with four workers and no skips. The normal five-minute Windows launcher timed out; the same exact discovered inventory took 449 seconds with bounded concurrency. This is not a claim that the launcher or full CI passed. Official Actionlint 1.7.12 was checksum-verified and all workflows passed semantic validation. |
| Collector/authentication/privacy regressions | Initial 172 and merged 206 passed; no native lab operations. Bundled Python used after the system alias was unavailable. |
| Existing distribution PostgreSQL fixtures | All three passed on fresh disposable servers: 2 lifecycle, 21 review/concurrency and 19 transfer events, all 42 passed without skips. Includes the new retired-job starvation regression. Owned containers removed. |
| Real Vault adapter and ACL fixtures | All nine passed with live isolated Vault and no skips; owned container removed. Initial attempt without a readiness wait failed and was not counted. |
| Contract tests without runtime API | 42 passed, no skips. This does not replace the live lab API journey. |
| Contracts/integrity/OpenAPI | Passed after regenerating the merged OpenAPI digest and preserving both renewal constraints. |
| API, worker and dashboard lint / formatting / type-check / build | Passed; lint has existing warnings and zero errors. Dashboard builds were executed by the owned lab controller. |
| Secret-logging / lockfile / production dependency audit | Passed; pnpm production audit found no known vulnerabilities in its scope. |
| Scenario/suite/release/skip/workflow guards | Distribution and all metadata/security/skip guards passed. The Windows aggregate had 17/18 passes: the unchanged Bash two-decode guard could not generate its fixture through the workstation shell bridge. That actual guard subsequently passed in an isolated Linux container with OpenSSL, jq and curl. No aggregate CI-parity claim. |
| SAN enrolled-agent lab | All 13 mandatory phases passed on the final cohort candidate; no missing scenarios. Earlier failed/stale reports retained separately. |
| Ordinary enrolled-agent lab | All 13 mandatory phases passed on the final cohort candidate, including trusted TLS on both destinations using the single ordinary DNS name. |
| Wildcard enrolled-agent lab | All 13 mandatory phases passed on the same final cohort candidate, including wildcard/apex issuance and both trusted TLS destinations. |
| Existing direct native-executor lifecycle fixture | Passed: two real ACME orders, real Vault, nginx/HAProxy and all 15 declared lifecycle/failure checks. Its injected lease callbacks remain supporting evidence. |
| Exact production artifact on independent native hosts | Blocked: protected issuer/consumer hosts and live customer CA/Vault/DNS credentials not supplied. |
| Full release qualification | Not qualified. Catalog/native gaps and experimental lab evidence intentionally prevent promotion. |

The latest main CI at `6fc0c44a` completed successfully, including its
[Docker Build & Security Scan](https://github.com/tokentimerch/tokentimer-core/actions/runs/38755936377/job/116497953748).
That run qualifies main's CI scope, not the changed PR candidate. Full image
security scans, Windows native campaigns and all existing release matrix cells
have not been rerun for this branch.

Runtime secrets, raw logs, customer volumes and local session state remain in
ignored task-local storage. Only bounded public execution reports may be used
as CI artifacts. Refer to the coverage matrix for unimplemented/native gaps.

Earlier failures were not promoted: missing Chromium, an unready Vault, the
reproduced unsafe generated nonce, the retired-rollout starvation, an incorrect
viewer-read expectation, and source drift during a concurrent merge all failed
their respective run or verifier. A direct CLI import cycle was fixed and now
has a subprocess regression. The ordinary fixture's initial reload readiness
check failed because agent command environments correctly omit the lab mode
variable; the fixture now derives SNI from the approved local binding. A fresh
project was used for every strict replay.

The final privacy audits check actual current customer PEM fragments and scoped
Vault execution tokens against the owned Core database and API/worker/agent
logs. They return counts only. They do not establish exhaustive historical-key
encoding, secret DNS-provider or external log-sink coverage.

All three final strict cohorts used the same code candidate, executed three
ACME orders apiece, and passed all 39 mandatory phase executions without skips.
Each passed publication recovery, authorization changes, native consumer
reload/reconciliation, explicit rollback/restore, drift/verification-only,
retired-work fencing, real browser checks, privacy audit and workspace transfer.
Only their uniquely owned containers/networks were stopped; evidence and
customer/database volumes were retained. The bounded
[public evidence summary](evidence-summary.json) records actual report hashes
and scope, without sessions, credentials, host identity or private material.
