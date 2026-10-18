# Distribution follow-up execution — 2026-10-16

The three fresh enrolled-agent cohorts executed code candidate
`248de16d31448e573a0300039d2916ae6a2f431a`. The subsequent CI-only candidate
`75cc6a66d5a4f92d423710c4e1de3bfa90f94ede` adds the Windows tooling job and its
guards. Reports keep their actual candidate identities; none were relabelled.
The [public evidence summary](evidence-summary-2026-10-16.json) records actual
report hashes, timestamps, source counts and bounded privacy verdicts.

| Executed check | Result and scope |
|---|---|
| Ordinary, SAN and wildcard enrolled-agent cohorts | All three passed 15/15 mandatory phases: 45 phase executions, no skips, nine real Pebble ACME orders in total. Each standalone report CLI accepted the current source scope and explicitly returned native `not-qualified`. |
| Distribution security through actual CLI transport | Corrupted signature, changed material-version pin, genuinely signed foreign-agent delivery and replay all refused without file replacement, reload or rewriting the original successful Core outcome. Only genuine dispatches captured from Core were injected; no signing or receipts were mocked. |
| Revoked consumer Vault credential | Real fetch refused; independent file/TLS checks confirmed no mutation. Customer rotation and retry of the original pinned job restored genuine verification. Core's conservative uncertainty fence cleared only after its validated receipt. |
| Roles and workspace pause | Chromium manager access, same-session viewer demotion/refusal and admin matrix access passed. Real admin pause fenced claims and rollout resumption/expansion; manager bypass failed. Containment remained available, and explicit unpause/resume recovered pending work. The actual pause warning was checked in Chromium. |
| Actual deployment concurrency | Owned barriers held genuine service-hook processes. `maxParallel=1` serialized reload admission; `maxParallel=2` admitted overlapping NGINX/HAProxy hooks. Both services then completed verified deployments. This is one container host, not independent native-host qualification. |
| Physical drift and recovery | Customer replaced and reloaded an old retained pair. Current-version verification-only rollout failed without mutation. Separately approved repair restored the current installed and externally served leaves without a new ACME order. |
| Historical zero-custody audits | Each cohort scanned Core DB/API/worker and customer-agent logs against eight private-key sources, thirteen scoped credential files, all three published Vault versions and ten credential issuance-history files, including revoked/replaced tokens. Counts include repeated key/credential sources, not distinct secrets. Needles never left the customer host. |
| Complete Windows tooling launcher | 846 tests passed, zero failures/skips; 220 discovered files, four workers, 257.887 seconds. Earlier complete successful inventories: 843 in 270.126 seconds and 844 in 252.214 seconds. The actual normal launcher passed, not only a manually reconstructed inventory. |
| Tooling failure controls | Real child assertion failure and timeout produced failure. Invalid worker overrides and empty inventory were refused. Parent `NODE_TEST_CONTEXT` was removed so nested Node workers cannot return false success without executing their inventory. |
| PostgreSQL lifecycle/review/transfer | All 42 passed without skips on a fresh owned server, candidate `069f822b06ffe3c6977559b42cb9fbb4dc455594`; server removed. Production source remained unchanged by subsequent continuation commits. |
| Real Vault adapter/ACL/fault tests | All nine passed without skips, same supporting candidate. The real KV test now additionally covers historical soft deletion, undelete, destroy, refusal to recreate destroyed material and continued availability of the independent next object. Owned Vault removed. |
| Collector regressions | 206 passed on the frozen distribution candidate; no native operations. |
| Workflow validation | Official checksum-verified Actionlint 1.7.12, workflow security guards and 56 focused selection/security/runner regressions passed. The exact new Windows download/checksum/extraction script executed locally and produced the expected official version. |
| Hosted Windows tooling job | Implemented for trusted-main tooling selection; source/schema/local execution validated. The GitHub-hosted job itself has not run for this unmerged branch. |
| Full CI/release/native campaigns | Not rerun or qualified. Earlier unit, lint, build and contract results remain in the original execution record; they are not claimed as fresh continuation runs. |

The Windows launcher now limits filesystem/hash contention with four workers
by default and retains a finite twelve-minute limit. Its CI job budget is
thirty minutes. No inventory was dropped and no timeout, skip or missing
prerequisite is converted to success.

Earlier diagnostic runs remain failed and are excluded from the final cohorts:
the first tooling run lacked Actionlint on PATH and had an unregenerated skip
mapping; an in-flight browser module cache changed during fixture development;
the revoked-fetch test initially expected only `failed` rather than Core's
supported `orphaned_unknown_effect`; and a pause locator matched two genuine
warnings. The fixture expectations/locator were corrected before the frozen
cohorts. No additional production defect was demonstrated or production
behavior changed in this continuation.

All newly owned containers and networks were stopped. Evidence and customer
volumes were retained; no shared database, production credential or manual
audit resource was used. Only bounded public reports, privacy counts and
dashboard screenshots are eligible artifacts. Credential-history files,
sessions, dumps, raw logs and customer keys remain excluded.

## Native qualification blockers

Every feature remains partial and the release collector still rejects these
experimental source-mounted reports. Precise prerequisites and source gaps are
listed in [the native blocker table](README.md#remaining-native-obligations).

* No exact packaged, immutable candidate has executed the distribution phases;
  the agent is a volume-local source copy with experimental capabilities.
* No independent owned issuer and NGINX/HAProxy hosts, native installation,
  restart/crash/cleanup receipts or external host campaign were supplied.
* A reviewed native artifact-bound distribution producer/collector contract
  is still missing. Supplying credentials alone cannot qualify this lab.
* Customer CA trust, secret DNS provider credentials, Vault AppRole and customer
  ACL/logging variants remain unexecuted. DNS credential qualification is false.
  Generic Vault inventory remains a separate credential-bearing API, outside
  the distribution execution-credential audit.
* Distribution-specific default lease/freshness expiry, host-death, late-outbox,
  retention elapsed-window and membership/claim/transfer race campaigns still
  lack native execution. Existing SQL/receipt fixtures are integration evidence.
* Core exposes workspace pause; billing/license freeze belongs to variants and
  has no Core endpoint. No freeze UI/API flow was invented.

These gaps are not successful qualification results. The feature-by-feature
[coverage matrix](coverage-matrix.md) retains their evidence levels and scope.
