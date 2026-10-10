# PR #329 remaining fixes

## Transfer design (recorded before implementation)

Transfer the public managed-certificate inventory source and token, not the
source workspace's execution authority. Retain distribution groups, versions,
bindings, rollouts, all jobs for those sources, approval/log/evidence records
and original identity/period history in their source workspace. Their scoped
foreign keys and immutable values must remain intact.

Close source management, retire unfinished rollouts and distribution groups,
and cancel never-started pending jobs. Block claimed/running/uncertain work with
an actionable 409 requiring reconciliation. Serialize with publication,
renewal/rollout admission and claims; do not wait for a job lock held by a result
ingester while holding authority locks that ingester might need.

Copy only public identity/association history using the existing destination
deduplication/admission rules. Clear renewal profile, deployed agent/path,
key-reference and execution metadata on transferred distribution inventory.
The new destination period has automation disabled, no distribution group and
no issuer/consumer authorization. A destination Vault integration is unnecessary
for public inventory transfer; execution requires explicit local configuration
and a new authorization workflow. Ordinary certificate transfer semantics stay
unchanged. Add a forward migration; do not rewrite applied migrations 63/68.

The complete transfer remains one database transaction. Source audit/proof
history remains attributable to its original tenant. Destination history records
public certificate provenance, not source credentials or execution payloads.

## Findings and implementation

### Workspace transfer: confirmed and fixed

Independently reproduced against PostgreSQL 17 and the actual HTTP transfer
route before changing production code. An ordinary certificate transferred
successfully; a published Vault certificate returned HTTP 500 with PostgreSQL
`23503`, constraint
`certops_material_versions_workspace_id_publishing_job_id_fkey`.

Migration 63 moved historical publishing jobs into the destination tenant.
Migration 68 correctly pins immutable versions to their publishing jobs with a
workspace-scoped foreign key. Moving the job breaks that provenance. Moving the
version, bindings or consumer agents would instead carry source authorization
across a tenant boundary.

Migration **70** replaces the transfer function without changing applied
migrations 63/68/69, constraints, agent contracts or issuer interfaces. The
service also excludes jobs belonging to distribution sources from its generic
job/log/evidence relocation. Both layers are necessary: changing only the SQL
function would leave the subsequent generic job update unsafe.

Final semantics:

- The inventory certificate, token and public identity/association history move
  under existing destination collision, membership and quota rules. Original
  source identity and closed-period provenance remain. Fingerprints deduplicate
  per tenant; there is at most one open period for the moved source.
- All certificate jobs for a source with distribution history remain in the
  source tenant, including issuance, renewal, orchestration and deployment jobs.
  Their signed payloads, approvals, logs, evidence and executor events remain
  there, along with immutable versions, consumer bindings and rollout snapshots.
- Source periods close. Never-started pending jobs are cancelled by the existing
  closure trigger. Migration 69 releases only provably unused allocations.
  Unfinished rollouts and all historical/current groups retire; completed
  verified rollouts keep their historical result.
- Claimed, running, uncertain, reconciliation-required and attempted pending
  jobs block transfer. An unresolved attempted publication also blocks even
  when its job has entered a terminal state. A job locked by result ingestion
  blocks immediately. These cases return HTTP **409** with
  `CERTOPS_DISTRIBUTION_TRANSFER_RECONCILIATION_REQUIRED` and an instruction to
  reconcile in the source workspace before retrying.
- The destination gets a new open period only if management was open at the
  source. It has automation disabled and no renewal profile. Distribution
  inventory loses key reference, deployed agent/path, source execution reference
  and execution metadata. There is no destination distribution group, binding,
  issuer grant, Vault credential or private key. Public inventory transfer does
  not require a destination Vault integration. Future execution needs explicit
  destination configuration and authorization.
- Ordinary certificates retain existing transfer behavior. All changes are in
  one transaction; authorization denial, quota denial and reconciliation refusal
  leave inventory and execution authority unchanged.

Workspace rows are locked in UUID order before transfer, matching the workspace
lock used by admission/dispatch. The SQL helper takes that lock as well so direct
callers receive the same boundary. It locks retained jobs with `NOWAIT` before
group/period changes: result ingestion can lock a job first, so waiting on it
while holding authority locks could deadlock. Concurrent rollout admission was
observed waiting in PostgreSQL, then rejected after transfer committed. Existing
identity tests cover management-period/job fencing and concurrent admission;
the distribution suite covers signed claims, publication replay and renewal.

Changed files: `apps/api/migrations/070-certops-distribution-transfer.sql`,
`apps/api/migrations/migrate.js`, `apps/api/services/workspaceTokenTransfer.js`,
`apps/api/routes/workspaces.js`, `tests/wildcard-vault/transfer.test.cjs`,
`tests/wildcard-vault/pr329-review.test.cjs`, and the migration-ledger expectations
in `tests/unit/certops-migration.test.js`.

### Dependency alerts: confirmed; targeted fixes installed

Verified all three GitHub alerts and the actual pnpm graph, rather than treating
a production-only audit as proof of remediation.

| Alert | Actual dependency and exposure | Change |
| --- | --- | --- |
| 179 / 181, GHSA-wq5f-xc86-pv6w | `sharp` 0.35.4, direct dashboard dev dependency. Alert 181 labels the lockfile runtime, but `pnpm why` and the full audit classify its installed paths as development. The only application use is the local image-generation script reading a fixed repository AVIF; no customer SVG processing route was found. The affected SVG/librsvg functionality remains relevant to build tooling. | Pin `sharp` 0.35.5, including its native packages; runtime inspection reports librsvg 2.63.2. Native PNG generation and the dashboard build pass. |
| 180, GHSA-68fv-2mgg-jv7q | `source-map-js` 1.2.1 through Vite/PostCSS and coverage tooling (transitive development paths). Indexed source maps with hostile offsets can exhaust resources during tooling. The final dashboard image serves static files with nginx. | Exact override 1.2.2; regenerated lockfile, build and coverage tests. |

Changes are limited to `apps/dashboard/package.json`, `pnpm-workspace.yaml`,
`scripts/check-lockfile-overrides.js` and `pnpm-lock.yaml`. The patched versions
support the repository's Node 24 runtime. No broad dependency upgrades or new
audit exclusions were introduced. GitHub alerts are repository/default-branch
state and may remain open until these changes reach its scanned branch.

The **full** post-fix audit still exits 1 with one High advisory:
`braces` 3.0.3, GHSA-vfj7-8cjw-p6xm, stack exhaustion on deeply nested patterns.
All reported paths are development tooling: Mocha/Chokidar, Nodemon and
TypeScript ESLint/Globby/Micromatch. The audit advertises `>=3.0.4`, but
`pnpm view braces@3.0.4 version` returns package-not-found and the registry's
latest version is 3.0.3 as checked on 2026-10-10. A minimal pin was attempted,
failed installation and was removed; no unsupported override is committed.
Untrusted glob patterns can still affect development/CI processes. Follow up
with the upstream release, then pin the published patch and repeat the full
audit. Do not expose these tools to untrusted patterns meanwhile.

`pnpm audit --prod --audit-level=moderate` reports no known vulnerabilities.
Both audits use the repository's pre-existing React Router RSC advisory exclusion
(`GHSA-qwww-vcr4-c8h2`); this change neither adds nor broadens that policy.

### Regression discovered during validation

The dashboard certificate test mocked `useCertOpsCanManage` but omitted the
existing `useCertOpsIsWorkspaceAdmin` export consumed by the page. This caused
38 tests to fail before rendering. Added the missing mock with a non-admin
default in `apps/dashboard/tests/unit/CertOpsCertificates.test.jsx`; no product
authorization logic changed. Two unrelated tests timed out under the initial
high-concurrency coverage run; the three affected files pass together with two
workers (61 tests).

## Executed validation

Validated on Windows, Node 24.11.1, pnpm 11.13.0, PostgreSQL 17, after merging
latest `origin/main` **538900c797f114fd498d3a4faee728cc3151fda1** into the PR
history without conflicts. This includes PR #337's actual AD CS issuer adapter
and CMC helper. Latest main did not advance at the final fetch.

| Command / scope | Actual result |
| --- | --- |
| `pnpm install --frozen-lockfile` | Pass |
| `node --test tests/wildcard-vault/transfer.test.cjs` | **15 pass** on dedicated PostgreSQL: ordinary/publication/historical groups, completed rollout evidence, pending deployment/publication cancellation, claimed/running/orphaned/attempted retries, terminal unresolved publication, busy ingestion lock, concurrent rollout, destination authorization, quota rollback, repeat transfer/deduplication and no destination issuer reuse |
| `node --test tests/wildcard-vault/pr329-review.test.cjs` | **13 pass**; all four prior fixes preserved, old FK-failure assertion replaced with successful isolated transfer |
| Existing `tests/wildcard-vault/postgres.test.cjs` | **2 pass**: actual publication/renewal identities, approval waves, binding revisions, signed dispatch, stale results, tenant scope, unused allocations and uncertainty fences |
| `pnpm exec mocha --no-config --no-package tests/integration/workspace-transfer-tokens.test.js --timeout 60000 --exit` | **8 pass** against a dedicated running API on port 60400, using real registration/login and transfer requests |
| `pnpm exec mocha --no-config --no-package tests/integration/certops-identity-invariants.test.js --timeout 90000 --exit` | **57 pass** on real PostgreSQL, including history backfill, period authority, transfer/quota rollback and concurrent identity rules |
| `pnpm run test:unit` | **2307 pass**, none skipped; includes ACME/AD CS validation, typed outcomes, continuation contracts and Vault restrictions |
| `pnpm run test:agent` | **1580 pass, 15 skipped**, no failures; includes ACME execution/recovery, AD CS adapter/continuation, Windows CNG/native behavior and Vault execution tests |
| `pnpm run test:contracts` | **42 pass** |
| `pnpm run check:contracts`, `check:contracts:integrity`, `check:lockfile-overrides`, `check:secret-logging` | All pass |
| `pnpm run lint:api`, `lint:worker`, `lint:agent`, `lint:dashboard` | All pass, no errors; existing API 31 / agent 176 warnings remain |
| `pnpm run build:api`, `build:worker`, `build:agent`, `build:dashboard` | All pass; agent validates 65 shipped files and PowerShell installer; dashboard retains bundle-size warnings |
| Dashboard `type-check`, Prettier `--check "src/**/*.{js,jsx,css}"` | Pass |
| `pnpm --filter @tokentimer/dashboard test:coverage --maxWorkers=2` | **787 pass / 81 files**, no failures; 55.56% statements, 50.53% branches, 56.57% functions, 57.99% lines |
| `pnpm run coverage:check:frontend` | Pass; repository coverage floors respected |
| Fresh migrations 1–70; upgrade from already-applied 69 to 70; migrator replay | Pass on dedicated databases; replay reports all migrations up to date |
| Full / production dependency audit | Full: one unresolved development High (`braces`); production: no known vulnerabilities under existing audit policy |
| Native Sharp inspection / PNG generation | Sharp 0.35.5, librsvg 2.63.2, generated valid PNG buffer |
| `git diff --check` | Pass |

Database settings were explicit for every invocation, with no workstation `.env`
loaded into fixtures. Transfer fixtures use `DB_HOST=127.0.0.1`, port **60470**
and `DB_NAME=pr329_final`; the prior-four suite uses our previous isolated
PostgreSQL container on **59470** with a **new** database
`pr329_review_final_20261010`. The existing distribution test's task-local runner
changes only its port fence (57470 to 60470) and resolves original fixture paths;
assertions are unchanged. Its clean database is
`wildcard_candidate_final_clean_20261010`. This suite's scheduler is database-wide,
so failed setup attempts were retained separately and the passing run used an
empty dedicated database. The API database is `pr329_final_http_20261010`.

Local command logs and before/after evidence are retained in
`.scratch/pr329-final/` (ignored, not part of the commit). Initial failures are
retained too: migration-ledger test expectations were updated from 69 to 70;
an invalid test fixture tried to mutate an immutable published version and was
corrected to use a genuinely allocated version. No constraint was bypassed.

Latest main CI run [37953479690](https://github.com/tokentimerch/tokentimer-core/actions/runs/37953479690)
and its Docker Build & Security Scan job **113901377661** succeeded. This is
supporting evidence for the incorporated base, not a scan of the new PR head.
Full local CI parity is **not claimed**: the complete integration/coverage,
Helm/Compose and image rebuild/Grype matrix was not rerun for this targeted fix.

## Isolation and qualification limits

Only the isolated review checkout was edited. No other worktree was reset or
modified. Existing application containers, audit databases, fixtures and retained
evidence were not stopped, reconfigured or changed. New fixtures use our own
dedicated PostgreSQL containers/databases and loopback API port. The manual
audit's existing Vault/Pebble/application lab was not used for writes.

No new live Microsoft CA, live external Vault round trip, browser end-to-end
issuance/renewal/deployment, appliance qualification or packaged Windows service
host/CMC execution was performed in this pass. Agent/unit contracts and public
receipt ingestion do not establish qualification against every real CA,
firewall or load balancer. The running manual-audit lab was deliberately left
untouched. No agent protocol, credential flow or private-key custody boundary
was changed; all API fixtures use public PEM and synthetic identifiers only.

The forward migration changes transfer semantics for existing distribution
sources. Operators must reconcile uncertain source execution before moving them,
and explicitly configure destination automation afterward. Retained source
evidence remains subject to that tenant's normal data-retention policy.

## Verdict

**READY WITH RESERVATIONS.** The transfer defect and the three requested
dependency alerts have targeted fixes with PostgreSQL, HTTP, contract and agent
evidence. All executed functional, lint/build and coverage checks pass. The full
dependency audit remains red for the unpublished development-only `braces`
patch; live release-qualification scenarios remain unexecuted as listed above.
These reservations must remain visible to the merge/release owner. This verdict
does not claim a clean full audit or complete appliance/CA qualification. No
merge or release was performed.
