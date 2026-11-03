# CertOps completion and acceptance record — 2026-11-03

Core product changes: `8a8cb8cd545d0473eace90058956466765978fd5`, on the existing
`feat/certops-distribution-lifecycle` branch. The three pre-existing unpublished
commits and authorized worktree changes were preserved. Published starting head:
`e076f3c7b4ca6ef56cc44cacdaf69ffc5c621a2b`. No merge or deployment occurred.
This is a preview, not completed production qualification. The [current PR](https://github.com/tokentimerch/tokentimer-core/pull/498)
records final branch-head CI and remaining failures.

## A. Cleanup diagnosis

The original incident's API exception and signed request were not recovered from
available local evidence. Its reported valid receipt must not be relabelled as
the deliberately invalid receipt used in the controlled reproduction. Historical
causal closure remains **BLOCKED / unconfirmed**.

A fresh isolated Vault/PostgreSQL reproduction established a definite defect:
after real exact-version deletion, a mismatched receipt throws
`CERTOPS_MATERIAL_CLEANUP_RECEIPT_MISMATCH` in `acceptCleanupReceipt`. The result
route had no domain-error mapping and returned 500. Its transaction rolled back,
leaving the job running and the permanent fence intact. A valid fresh receipt
completed normally. This proves an error-boundary defect, not the missing
historical incident's cause.

The route now returns 409 for mismatched receipts/expired claims and 422 for
missing, malformed or unexpected evidence. Unknown runtime/SQL errors retain
500. Committed duplicates must match the canonical persisted receipt: the old
same-status shortcut could acknowledge changed or absent evidence. Exact
acknowledgements survive interrupted responses and an API process restart.
Invalid evidence cannot produce success or release the permanent fence.

The real-provider runner denies the ACL, restores only the required permission,
retries the original job, verifies signed dispatch, runs the production source
executor with live lease validation, drops the response after commit, restarts
the API, retries delivery, rejects contradictory/missing evidence and reconciles
metadata without a second deletion. Version 1 is soft-deleted, version 2 retained,
neither destroyed, audit count one. These are source functional tests, not native
production artifact qualification.

## B. Requirement classification

| Requirement | Classification and observed result | Remaining boundary |
| --- | --- | --- |
| Exact approvals, fresh detail, workspace protection | Existing implementation retained; regression tests pass | Full operator campaign remains partial |
| Reviewer revocation | Fixed current-authority rechecks for exact/manual rollout expansion, claim, renewal and retry; real PG removal/restoration regression passes | Migration 97 requires fresh independent review of existing grants |
| Cleanup completion/retry | Error mapping and committed-duplicate validation fixed; real Vault/OpenBao functional campaigns pass | Original incident unconfirmed; native capability gated |
| Independent staging (#376) | Implemented Linux preparation/activation jobs, protected bundle, durable generation intent, immutable child pointers; three real PG staging tests pass | Explicit server/local opt-ins and gated staging capability; Windows staging unavailable |
| Maintenance/activation | Existing IANA/DST/blackout/emergency model retained; supported method checks and immediate calendar/lease revalidation added | Native IIS qualification outstanding; unsupported restart/refresh unavailable |
| Installed/served/trust | Preparation cannot advance assurance; activation needs intact bytes and current authority; canary proof remains enforced | Publication/preparation/request is not installation proof |
| Waves, pause/retry, rollback, leases | Existing behavior retained; 74 real PG lifecycle tests pass | Manual fleet/outage campaign incomplete |
| Verification/incidents/recovery | Existing durable scheduling/delivery retained; 77 real PG PagerDuty lifecycle tests pass | New live external delivery acceptance not established |
| Discovery (#369) | Stable normalized service slots, rotation/conflict/future/stale/partial handling; every matching IIS service preserved | SQL Server/RDP and broader typed connectors remain separate follow-ups; store presence is not consumption |
| Advanced activation (#366) | Constrained Linux file/reload, typed IIS rebind, manual read-only verification retained | No generic PowerShell or arbitrary service commands; native matrix outstanding |
| OpenBao cleanup (#248) | Explicit provider/method and separate gated capability; real OpenBao 2.4.1 campaign passes | Cannot relabel Vault authority; released qualification manifest unchanged |
| Azure/Windows | Merged adapters retained, source regression coverage | No Azure tenant or Server 2022/2025 exact artifact campaign; no capability promotion |

Issues #248, #376, #366 and #369 stay open for their broader scope.

## C. Changes per repository

Core adds migrations 96 (preparation) and 97 (durable review authority epochs),
cleanup acknowledgement fixes, safe preparation/activation, distinct OpenBao
cleanup, discovery corrections, UI controls and reproducible provider/browser
fixtures. Original SQL, applied identities and timestamps are preserved. Migration
97 invalidates old distribution authorizations once; obtain fresh review.

Cloud #218 retains Core `4a5dedcacf600db2406f756ca97f986cfba2cc1a`. An observed
Docusaurus heap exhaustion is addressed only in the disposable documentation
build stage. Hosted plan/freeze/role/recipient and release-ancestry gates remain.

Enterprise #193 retains `bc9bbe6142dec17060a02123f4a40463ee8cd144` and the same
`4a5dedca` Core preview. No license, SSO, custody or overlay gate was relaxed.
Full CI was dispatched with `full_validation=true`, that exact `expected_sha`,
and `expected_core_sha=4a5dedcacf600db2406f756ca97f986cfba2cc1a`.

## D. Actual validation

| Campaign | Observed result |
| --- | --- |
| Core canonical unit | 3,197 passed, no failures/skips; `TEST_CONCURRENCY=2 pnpm run test:unit`; frozen product source now committed as `8a8cb8cd` |
| Real PG lifecycle | 74 passed, no skips, including preparation and reviewer removal/restoration |
| Upgrades/concurrency | Lifecycle upgrade fixture, 30 migration histories, seven PagerDuty histories and 77 PagerDuty lifecycle tests passed; fresh plan ends at 97 |
| Vault/OpenBao | Final migration-97 reruns: 15 passed per provider, no skips; manifests retain actual product SHA/dirty-worktree provenance. Head `a541dd1e` CI did not start those suites: Vault was OOM-killed at 384m |
| Agent focused supported Linux fixture | 86 passed, no skips, with real OpenSSL; staging/calendar/discovery and file/read-only boundaries |
| Native packaging retry | Eight passed, zero failures, two explicit host/tar-mode skips; system tar resolves Git GNU tar's Windows drive-path collision |
| Dashboard | Original three targeted files: 60 passed; updated distribution file: 15 passed including two new cases; typecheck/build/lint passed |
| Contracts/privacy | 47 contract tests passed; 52 contract files verified; runtime OpenAPI coverage and secret-logging guard passed; moderate audit passed, one low advisory |
| Full native agent | 2,105 passed, four failures and three cancelled children from the system/Git tar PATH collision, 19 explicit skips. All affected packaging checks rerun with system tar: eight passed, two explicit host/tar-mode skips. Workstation tests are not Server qualification |
| Cloud | 2,351 unit and 228 inherited/hosted real PG lifecycle/delivery tests passed; web lint/build/tests passed; full development image/smoke/integration campaign recorded in PR |
| Enterprise | Local: 1,434 unit passed, one connection reset; affected suite rerun: 14 passed. Initial full CI passed unit/Vault/PG/baseline/image builds, then one import UI assertion failed under coverage. Retry preserves assertions and thresholds |

The Core baseline [41603078735](https://github.com/tokentimerch/tokentimer-core/actions/runs/41603078735)
passed all 37 jobs / 41 checks on `e076f3c7`; it was not pending. This is not a
pass for new code. New-head CI is linked in the PR. Edition-specific workflow
results are recorded in their respective private PR descriptions. Cloud release
validation correctly rejects the unmerged Core preview for release.

Head `a541dd1e` workflow
[41623801301](https://github.com/tokentimerch/tokentimer-core/actions/runs/41623801301)
failed four jobs. Skip inventory and skip-qualification drift followed a main
merge that moved Windows discovery lines. Leak scan matched private repository
names in this note. The provider step never reached its tests: PostgreSQL was
still running and Vault was OOM-killed at 384m (exit 137). Ownership files are
regenerated, those names are removed, and the disposable provider limit is
1024m. This note does not treat that correction as a passing CI run.

Head `325cab4e` workflow
[41628492419](https://github.com/tokentimerch/tokentimer-core/actions/runs/41628492419)
passed the other 40 checks, including Vault startup at 1024m. The remaining job
failed in the claim-lock fixture: successful claims rejected
`CERTOPS_DISTRIBUTION_POLICY_STALE` because the approval job had no current
rollout review. The fixture now records the workspace owner and the current
authorization revision. A disposable PostgreSQL rerun of that file passed 4/4.
That rerun is not a new full CI result.

Head `3703e7f1` workflow
[41631331217](https://github.com/tokentimerch/tokentimer-core/actions/runs/41631331217)
passed the claim-lock step. The provider-pin step then rejected Vault, OpenBao,
and Azure publication with `CERTOPS_DISTRIBUTION_POLICY_STALE`. Those approval
jobs had no current requester, and the Azure approver had no workspace role.
The fixtures now record the workspace owner and a workspace manager. A local
rerun of the three provider cases passed. The offline Azure bridge still
requires Linux for its endpoint target, so that case remains a CI check.

Head `465c31a4` workflow
[41634444722](https://github.com/tokentimerch/tokentimer-core/actions/runs/41634444722)
passed those three provider cases. The Azure bridge then reported `failed`
for a lease loss on the pre-install admission check. That check is before the
filesystem write, so a clean failure is correct. The bridge now interrupts on
the following check, after the write, where the uncertain binding must be
reconciled.

Head `aa1d4a1c` workflow
[41636868443](https://github.com/tokentimerch/tokentimer-core/actions/runs/41636868443)
passed the provider-pin step, including that post-write lease interruption.
The pinned-rollback step then left the first wave without a job.
`advanceRollout` pauses when the recorded approver is not a current workspace
manager. The wildcard PostgreSQL fixture now grants that role before building
the rollout intent. A disposable PostgreSQL rerun of
`tests/wildcard-vault/postgres.test.cjs` passed 2/2. That rerun is not a new
full CI result.

## E. Evidence and reproduction

See the [sanitized evidence index](evidence/2026-11-03/README.md), public provider
readback and genuine screenshots. The real API/dashboard used normal session
login and disposable PostgreSQL. Publication metadata was synthetic; cleanup and
provider deletion were genuine. Screenshots establish those fixture states only.

```powershell
node scripts/run-cleanup-completion-acceptance.cjs
node scripts/run-cleanup-completion-acceptance.cjs --openbao
node scripts/run-distribution-lifecycle-postgres.cjs
# Optional genuine browser fixture; use the printed new evidence/config paths:
node scripts/run-cleanup-completion-acceptance.cjs --keep-lab
node scripts/start-certops-completion-ui.cjs qualification-results/cleanup-completion-<id>
node scripts/capture-certops-completion-ui.cjs .tmp/cleanup-ui-<id>/ui-private.json
```

Helpers require owned loopback fixtures and verify container labels. Credentials
remain in protected ignored `.tmp` files outside exports. Default provider runs
remove only their own containers. CI uploads sanitized provider artifacts. Neither
fixture execution nor UI settings promote a compiled production capability.

## F. Remaining blockers

- Original valid-receipt cleanup exception unavailable: historical causal closure
  unconfirmed. Production qualification remains blocked.
- Azure and Server 2022/2025 exact native artifacts/hosts not exercised. Protected
  environments, reviewers, spending controls and compiled gates remain intact.
- Operator acceptance remains partial: not every live rollout, failed canary,
  drift/recovery or requested screenshot was rerun in the final browser flow.
- Editions still compose `4a5dedca`, not complete latest Core. Final composition,
  signed installation/installed proof and edition UI acceptance must follow an
  explicitly approved protected Core-main merge.
- No new real outbound WhatsApp delivery verified; Enterprise Twilio `63112` and
  historical maintainer waiver remain explicit, not counted as a pass.
- Any failing/pending final workflow/build remains a blocker until its actual
  result is recorded in the PR; failed attempts remain available.

## G. Verdicts

**Core:** preview fixes and regression evidence available; complete acceptance and
production qualification **BLOCKED**.

**Cloud:** independent preview validation in progress; release/final composition
**BLOCKED** on accepted Core-main and remaining operator evidence.

**Enterprise:** full exact-head CI dispatched; release/final composition
**BLOCKED** on validation, accepted Core-main and operator evidence.
