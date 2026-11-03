# PR #498 scope freeze and merge review — 2026-11-03

This is the current disposition for [PR #498](https://github.com/tokentimerch/tokentimer-core/pull/498).
The [earlier completion record](pr498-completion-20261103.md) retains historical
attempts and evidence. Its earlier combined release/qualification verdict does
not mean that every optional connector must be implemented before this PR merges.

## Frozen scope

Finish the existing distribution lifecycle. No additional connector, generic
command execution, service restart strategy or edition-only feature belongs in
this PR. Baseline customer Vault publication and Linux distribution shipped in
0.18.x. Provider PR #460, recipient-verification PR #461 and PagerDuty PR #496
are merged dependencies. PR #498 integrates their runtime and migration histories;
its own changes remain unreleased.

The review candidate preserves `e4ea87ffb1aae104c9f306ce9c5bbecafe51ca7b` and
merges `main` at `ece47164344a6908a29820909c634e5b2d451b67`. That merge is
`1c844f6824c8a551aea952c4ae01be8b9161c0f2`. No existing commit was rewritten.
The unrelated workstation checkout and its uncommitted work were preserved.

## Completion matrix

“Enabled” below means allowed by the committed production capability manifest,
subject to normal workspace, role, local-policy and runtime settings. It does not
mean this unmerged PR has shipped or that a new release artifact is qualified.
The authority is `packages/agent/src/capabilities/qualified-capabilities.json`;
source tests and UI settings cannot add a compiled capability.

| Feature | Implemented | Tested / evidence | Production-enabled | Remaining limitation |
| --- | --- | --- | --- | --- |
| Issuance/publication, immutable exact material versions | Yes; released baseline retained | Canonical unit; provider compatibility; enrolled-agent journey | Vault/OpenBao publication and Linux deployment capabilities present | Customer credentials and private material stay local; publication is not installation |
| Manual, approval-request and reviewed automatic distribution | Yes | `distribution-lifecycle.test.js`, `pr329-review.test.cjs`, provider-pin CI | Yes, explicit policy; manual default | Standing review expires and is invalidated by scope/authority changes |
| Consumer administration, required/optional destinations, waves/concurrency, pause/resume, partial failure, retained rollback | Yes | Real PostgreSQL lifecycle/claim locks; dashboard distribution suites; enrolled-agent journey | Yes for qualified destinations | Required failure pauses; rollback requires a retained unfenced version and explicit review |
| Independent exact-scope review, current membership, expiry and revocation | Yes | Real PG reviewer removal/restoration and transfer; signed claim/retry regressions | Yes | Migration 97 requires fresh review of existing authorizations |
| Workspace isolation, signed dispatch, generation/policy fencing, key custody | Yes | RBAC/unit, PG approval/claim, contracts, privacy guards; enrolled-agent journey | Yes | No remotely supplied commands, secrets or private keys in public control-plane data |
| Maintenance calendar, timezone/DST, blackouts, emergency exception | Yes | API/agent calendar regressions and real PG staging cohort | Yes with `maintenance-calendar-v1` and matching versions | Deliberate per-consumer configuration; only supported activation methods |
| Linux installation/reload and installed/served/trust verification | Yes; baseline retained | Linux agent tests; real nginx/HAProxy journey and independent TLS probes | Yes | Allowlisted local reload profiles; manual activation is read-only verification |
| IIS shared-material rebind integration | Yes; merged #460 retained | Native fixture cohorts on Server 2022/2025; source/contract regressions | **No**: `windows-material-iis-v1` omitted | Exact production artifact/native matrix is separate from baseline IIS support |
| Independent Linux preparation and later activation | Yes | `distribution-staging.test.js`; agent staging/calendar/integrity tests | **No**: `material-consumer-staging-v1` omitted | Server/local opt-ins and independent qualification; Windows staging unavailable |
| Verification-only and recurring jobs, drift/offline/stale incidents | Yes | Real PG lifecycle and monitoring tests | Yes, verification/alerts initially disabled | Fresh current-version consumer proof is required; source renewal cannot resolve an incident |
| Durable notification/recovery delivery and PagerDuty | Yes; merged #496 integrated | Real PG PagerDuty lifecycle and seven migration histories; full CI | Yes with configured channels/consent | New live external-provider delivery is not inferred from fixture or queue tests |
| Retention preview and protection of referenced/uncertain versions | Yes | Real PG cleanup, concurrency and retained-count tests; dashboard tests | Yes, report-only default | Eligibility is not deletion authority; at least two versions remain protected |
| Independently approved exact-version cleanup, permanent fences, receipts/reconciliation | Yes for Vault and OpenBao | Real provider ACL denial/recovery, signed source executor, lost acknowledgement/API restart, exact duplicate and contradictory receipt tests | **No**: both `material-cleanup-*-kv2-v1` capabilities omitted | Soft deletion only; no destroy, purge, metadata/all-version or Azure cleanup |
| OpenBao / Azure material providers | Yes; merged #460 | Real Vault/OpenBao compatibility and cleanup; historical Azure development campaign and current fixture CI | OpenBao **yes**; Azure **no** | `material-store-azure-key-vault-v1` omitted; historical Azure run is not final artifact qualification |
| Management UI, approvals, policy, maintenance, job/incident details, preflight/recovery/retention | Yes | Dashboard distribution/workspace/approval regressions, build/typecheck, genuine browser fixture evidence | Yes for supported operations | Unsupported restart/refresh choices disabled; gated operations require qualified agents |
| Stable IIS/HTTP.sys discovery and uncertainty | Yes | Agent discovery regressions and PG stable-consumer tests | Existing read-only discovery retained | Store presence is not consumption or served/trust proof; broader services remain backlog |
| Migration composition through 97 | Yes | Real PG upgrade, historical-ledger preservation, concurrent runners and seven PagerDuty histories | Apply before matching API/workers | Never rewrite deployed identities or timestamps; retain a restorable backup |

## Findings and disposition

**A — must fix before merge:** the first enrolled-agent campaign found a genuine
optional-consumer recovery defect: a rollout completed as `degraded`, then retry
returned `CERTOPS_MATERIAL_RETRY_AUTHORIZATION_STALE` despite unchanged current
generation, version, consumer and independent authority. Retry now accepts that
current deployment only after all existing fences pass and atomically changes
the rollout to `paused`. Explicit Resume is still required; successful siblings,
the original payload/job and uncertain proof remain intact. Completed recurring
verification cycles retain scheduler/backoff semantics. New PostgreSQL regressions
failed before the fix; the full review suite passes **39/39** afterward, including
changed-binding, revoked-reviewer and workspace-pause epoch rejection. The
composed enrolled-agent acceptance below validates the fix through genuine local
effects and public APIs. Final-head CI remains required. Any remaining failed
required check, supported-flow regression, unsafe migration or security defect
blocks readiness. Focused review also covers exact-scope/current-authority checks at
expansion, claim, renewal and retry; workspace/group locking; permanent cleanup
reference fences; atomic receipt/nonce/audit completion; staging versus assurance;
and disabled unsupported UI operations. It is not a new production qualification.

**B — implemented, qualification-gated:** Azure material storage, shared Windows/IIS
material deployment, Linux independent staging, and Vault/OpenBao cleanup remain
absent from the shipped manifest. Preserve implementation and gates. Qualification
must follow trusted-main/protected-environment and exact-artifact evidence rules
in [the qualification guide](../../.github/maintainers/certops/e2e-qualification.md)
and ADR-0012/ADR-0015. This PR does not promote any capability or grant a release
waiver. Existing enabled publication/deployment functionality must still pass.

**C — future enhancement:** [#504](https://github.com/tokentimerch/tokentimer-core/issues/504)
coordinates broader Windows work. Keep discovery/typed contracts in #369 and #366; RDP/WinRM #368, RDS #367, SQL Server
#374, Exchange #371, NPS #372, LDAPS #375 and
AD FS/WAP #373 remain backlog. Windows independent staging and unsupported
restart/refresh stay under #376 and #366. Appliance connectors,
additional providers and full MSP ITSM integration are outside this PR; MSP evidence integration remains in the existing downstream backlog. None is a new #498 gate.

**D — wider/customer acceptance:** broader fleet/outage/browser and live outbound
provider campaigns remain explicit follow-ups under #248 and specific capability
issues. Already-closed #354 supplies the existing host-qualification infrastructure;
its completed work is not reopened by this PR. A
source-mounted isolated lab is supporting functional evidence, not a production
native artifact or a customer-host acceptance claim.

The inaccessible original valid-receipt cleanup exception remains historically
unconfirmed. Current invalid evidence maps to 409/422, valid receipts complete,
exact duplicates survive acknowledgement loss/API restart, and real providers
reconcile without a second delete. Do not claim a historical cause or reopen it
as a new supported-flow blocker without a reproducible current defect. Cleanup's
separate production qualification gate remains closed.

## Validation record

Historical exact head `e4ea87ff`: [CI 41641478948](https://github.com/tokentimerch/tokentimer-core/actions/runs/41641478948)
passed all **37 jobs / 41 checks**. This does not qualify subsequent commits.
Latest inspected main `ece47164`: [CI 41622867685](https://github.com/tokentimerch/tokentimer-core/actions/runs/41622867685)
passed, including Docker image boot and Grype scans. The old native OpenBao matrix
contains skipped executor steps; green jobs do not establish that native cohort.

Post-fix canonical/database/provider checks use product source `e66add85`.
The later `b996f969` commit changes only helper tests/docs, with identical product
and dependency trees. Earlier agent/dashboard/contracts checks below exercise
unchanged components; full CI must additionally test the final repository head.

| Command / campaign | Actual result |
| --- | --- |
| `pnpm install --frozen-lockfile` | Passed; Node 24.11.1, pnpm 11.28.8 |
| `TEST_CONCURRENCY=1 pnpm run test:unit` (PowerShell environment assignment) | Post-fix **3,197 passed, zero failed/cancelled/skipped**. Pre-fix isolated concurrency-2 rerun also passed 3,197; initial loaded concurrency-2 run had one HTTP-watch timeout/cancellation, and its unchanged focused retry passed 1/1. No assertion or timeout was relaxed |
| `node scripts/run-distribution-lifecycle-postgres.cjs` | **74/74** lifecycle/cleanup/staging; **1/1** lifecycle upgrade; **30/30** migration/concurrency histories; **7/7** PagerDuty histories; **77/77** PagerDuty lifecycle; no skips, owned database removed |
| `node scripts/run-cleanup-completion-acceptance.cjs` | Real Vault: **15/15**, no skips; owned fixtures removed |
| `node scripts/run-cleanup-completion-acceptance.cjs --openbao` | Real OpenBao: **15/15**, no skips; owned fixtures removed |
| `node --test --test-force-exit --test-concurrency=1 tests/wildcard-vault/pr329-review.test.cjs` with an owned disposable qualification database | **39/39**, no skips; original-job recovery, sibling proof, explicit resume, changed binding, reviewer revocation and workspace pause epoch covered |
| Dashboard lint, `prettier --check "src/**/*.{js,jsx,css}"`, type-check and build | All passed |
| API/worker lint; `check:contracts`, `check:contracts:integrity`, `check:lockfile-overrides`, `check:secret-logging`, `check:certops-keygen-ban` | All passed; **52** contract files verified |
| `CONTRACT_API_REQUIRED=0 pnpm run test:contracts` | **47/47**, no skips |
| `pnpm audit --prod --audit-level=moderate` | Passed; one low advisory |
| `node scripts/ci-guards/run-all.cjs` in an isolated Node 24.22.2 Linux container | **18/18 guards passed**. Windows runner attempts retained shell/toolchain failures; Linux reproduces CI's Bash/OpenSSL/jq execution without relaxing guards |
| `node --test scripts/certops-distribution-report.test.js` | **8/8**, including mandatory inventory validation |
| `pnpm --filter @tokentimer/dashboard exec vitest run tests/unit/CertOpsDistribution.test.jsx tests/unit/CertOpsDistribution.workspace.test.jsx tests/unit/ApprovalDecisionModal.test.jsx tests/unit/EvidenceTimeline.test.jsx tests/unit/ExecutorJobsPanel.test.jsx` | **112/112**, five files passed |
| `node --test packages/agent/src/material-store/lifecycle.test.js packages/agent/src/material-store/cleanup.test.js packages/agent/src/material-store/cleanup-provider-compatibility.test.js packages/agent/src/material-store/platform-policy.test.js packages/agent/src/windows-discovery/windows-discovery.test.js packages/agent/src/capabilities/capabilities.test.js` | **171/171**, no skips; source/fixture evidence, not a Server qualification campaign |

The initial complete enrolled-agent journey on `3021793e` reached genuine
issuance, two trusted consumers, renewal/offline recovery and canary progression,
then failed at optional-consumer retry. It is retained as failed evidence, not
reported as a pass.
The subsequent `e66add85` campaign passed the optional failure/reconciliation/retry
scenario and correctly kept an old review inactive after the workspace kill
switch changed its epoch. Its helper still expected that old approval to resume.
The helper now asserts refusal of the old job and obtains a fresh independent
exact-scope review. Product authorization fences are unchanged; that interrupted
campaign is retained rather than relabelled as a complete pass.
[Full CI 41652216212](https://github.com/tokentimerch/tokentimer-core/actions/runs/41652216212)
passed **37 jobs / 41 checks** on `3021793e` before the recovery fix. Full trusted `ci.yml` must run on the pushed final head;
retain the exact SHA/run link in the PR description and final acceptance report.
No earlier green workflow substitutes for it.

Finalization head `0eb8b805` [CI 41665181662](https://github.com/tokentimerch/tokentimer-core/actions/runs/41665181662)
failed Backend Quality's mandatory inventory guard: the new PostgreSQL regression
names had not been registered in `qualification-suites.json`. Both names are now
required alongside every original case; the guard is unchanged. The report tests
and all 18 Linux guards pass after that registration. This failed run is retained;
the new head requires its own complete CI run before draft promotion.

## Supported functional acceptance

The [sanitized final functional record](evidence/2026-11-03/pr498-final-functional.json)
retains exact source identities, helper digest, counts and limitations. This is
**composed supporting evidence**, not a completed fresh strict qualification
campaign or native release approval.

- The new `b996f969` installation passed **12 connected product phases** through
  real API/session/CSRF flows, enrolled signed-job agents, customer Vault, actual
  Pebble DNS-01 issuance/renewal, nginx/HAProxy and independent trusted TLS.
  It covers two consumers, offline catch-up, canary waves, required/optional
  failure, exact original-job retry/reconciliation, retained rollback, drift,
  explicit repair/verification, real reload concurrency, current review,
  kill-switch re-review and signed-message rejection. No product DB injection,
  fake receipt, response interception or clock rewriting was used.
- The aggregate then stopped at an obsolete Vault-only onboarding helper.
  Its failed report remains intact. The current UI uses **Configure material
  store** and **Connect and validate consumers**. The helper now follows that
  existing interface; product UI/code is unchanged. Fresh focused browser
  sessions on the same verified fixture passed Start over, explicit publication
  selection/save/Continue and reload. Exactly **two signed noop dry runs** were
  added; original jobs, material, consumers and **three ACME orders** stayed
  unchanged. Browser runtime errors and unexpected product writes: **zero**.
- Privacy scanned the Core database/logs and customer agent logs, including
  current/historical test credentials and private keys; it passed and exports
  counts only. Public workspace transfer then passed, preserving source history
  and refusing cross-workspace publication repair. There are **41 recorded public
  product checks** across the connected/focused evidence. A resumed/focused run
  is not relabelled as a fresh strict campaign pass.
- Authenticated retention preview returned **200**, four published versions,
  all four protected, cleanup unavailable. Separate clean `e66add85` Vault and
  OpenBao campaigns passed **15/15 each**, including signed cleanup, provider
  deletion, lost acknowledgement/API restart, duplicate validation and permanent
  fences. Their publication metadata is synthetic; provider effects are genuine.

All owned journey projects were stopped. Evidence and their named volumes remain
local for review; provider/database helper containers were removed under owner
checks. Wider live-provider/fleet and exact native artifact campaigns remain
separate. The closed capability manifest is unchanged.

## Edition handoff

The related Cloud PR #218 is open at `e6b5138be49d74901b299f09c04cc3e71f8af863`;
Enterprise PR #193 is draft at `bc9bbe6142dec17060a02123f4a40463ee8cd144`.
Both still compose Core preview `4a5dedcacf600db2406f756ca97f986cfba2cc1a`.
Neither includes the complete current #498. These are coordination identifiers,
not a claim that the editions have adopted this candidate.

The Cloud release ancestry check correctly rejects the preview. Enterprise
full CI run `41613282001` now passes after its retry; the old PR description's
pending result is stale. Edition run links remain in their private PRs.
No pin changes are authorized before a human-approved protected Core merge.
After that merge, identify the accepted Core-main SHA, use each edition's normal
pin/composition process, adopt migrations/contracts/API/workers/agents together,
and run its canonical compatibility/CI skill. Preserve Cloud plan/billing/freeze/
consent and Enterprise license/SSO/custody boundaries. No edition-only feature,
production deployment or release is part of this finalization.

## Merge decision

Current disposition: **READY FOR REVIEW — exact final-head CI and independent
maintainer review are the remaining decision gates.** The PR description records
their current SHA/run/review status; this source report does not predict a future
workflow result. Mark the draft ready only after successful final-head CI, then
request normal maintainer review. Preserve all branch protections. Human approval and explicit
human merge authorization remain required; no automatic merge is requested.

Repository [pre-merge policy](../../CONTRIBUTING.md#maintainer-pre-merge-validation)
requires relevant validation and trusted dispatch. Native promotion/release
collection is separately governed; merging disabled optional implementation does
not assert that the production artifact qualifies it. No policy is waived here.

## Tracking and documentation

Updated GitHub #248, #376, #366, #369, #354 and #504. Broad open issues stay open;
#354 was already closed and keeps that state. Edition PR #218/#193 handoffs now
retain their old preview pins and the accepted-Core-main adoption requirement.
Connected project/parent/future-ticket tracking was reconciled separately.

Updated `ROADMAP.md`, `CHANGELOG.md`, `distribution-lifecycle.md`,
`distribution-lifecycle-status.md`, `distribution-compatibility.md`,
`distribution-retention-cleanup.md`, `pr498-completion-20261103.md`, this merge
matrix, `evidence/2026-11-03/README.md`, `evidence/2026-11-03/pr498-final-functional.json`,
and the maintainer `qualification/distribution/README.md` and
`unified-distribution-ui.md`. Unsupported connectors remain discoverable in
existing issues; no duplicate feature issue or speculative date was added.
