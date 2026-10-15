# Distribution execution record

Date: 2026-10-15. Candidate is PR #358's branch after integration of PR #329.
Local runs use source mounts and source digests; they do not qualify an exact
released binary or enable distribution in the production capability manifest.

| Check | Actual result |
|---|---|
| Core unit suite | 2,619 passed; no skips. Earlier merge-schema and Windows fixture failures corrected; transient HTTP-watch timeout passed in targeted and bounded-concurrency reruns. |
| Qualification tooling | 707 passed; no skips; official Actionlint 1.7.12 installed and verified before rerun. |
| Collector/authentication/privacy regressions | 172 passed; no native lab operations. Bundled Python used after the system alias was unavailable. |
| Existing distribution PostgreSQL fixtures | All three passed on a fresh disposable server; owned container removed. Reports retain each actual Node test event. |
| Real Vault adapter and ACL fixtures | All nine passed with live isolated Vault and no skips; owned container removed. Initial attempt without a readiness wait failed and was not counted. |
| Contract tests without runtime API | 42 passed, no skips. This does not replace the live lab API journey. |
| Contracts/integrity/OpenAPI | Passed after regenerating the merged OpenAPI digest and preserving both renewal constraints. |
| API lint / secret-logging / lockfile | Passed; API lint has existing warnings and zero errors. |
| Scenario/suite/release/skip/workflow guards | Passed in focused validation; rerun before delivery. |
| SAN enrolled-agent lab | In progress; earlier strict runs failed on missing Chromium, the reproduced nonce defect, and an incorrect viewer-read expectation. Failed reports retained. |
| Ordinary / wildcard enrolled-agent cohorts | Pending execution. |
| Existing direct native-executor lifecycle fixture | In progress; its injected lease callbacks remain supporting evidence. |
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
