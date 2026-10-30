# Unified certificate distribution UI

The read-only visualization described here is retained. Ongoing configuration now lives in the separate **Distribution Management** page, reached through **Manage distribution** in Deployments. See [lifecycle administration](distribution-lifecycle.md). The historical implementation notes below describe the original visualization slice.

Implemented on branch `feat/certops-unified-distribution-ui` from freshly fetched
`origin/main` commit `714e6a1f8bfbb55702b1e0195315f2768d0d4b31`.
The isolated checkout is `C:/Users/Admin/.codex/worktrees/certops-unified-distribution-ui/tokentimer-core`.
No merge, push, PR, database migration, or lab scenario changes were made.

## Behavior

- Certificates has a clickable Deployment summary with current verified/total counts and healthy, partial, pending, stale, failed, uncertain, not deployed, or not distributed states. The main table no longer displays certificate UUIDs.
- Tokens has a compact indicator inside certificate names, only for authoritative managed-certificate links with active distribution. Other asset categories gain no column or deployment state. Multiple linked certificates show a choice, never blended counts.
- The shared CertificateDetailsModal contains Deployments: Vault store reference, publication and publication attempts, consumers, desired/observed provider versions, verification time/method, deployed expiry, explanations, and workspace-scoped job/evidence links. Technical identifiers and publication history are expandable. Consumers paginate in groups of 20.
- Renewals contains renewal profiles and issuers; DistributionGroupsPanel was removed and its useful reads/job navigation moved into certificate details.
- Multiple managed registrations require explicit selection, even when fingerprints match. Selected certificate facts take precedence over mutable asset certificate metadata. Immutable identity history remains scoped to its fingerprint. Ended management periods cannot be shown as currently verified. Registrations without tokens can still load their selected renewal and distribution context.

## API and security

The existing GET /api/v1/workspaces/{id}/certops/distribution-groups accepts optional
managedCertificateIds and identityIds (each up to 200 comma-separated UUIDs), and
summaries=true. Summary reads require IDs, select active management periods, and
return group-to-certificate relationships and consumer counts/status only. Ordinary
reads retain the previous group fields and include public period/publication metadata;
identity detail reads can include relevant historical publications.

The consumer endpoint retains its shape and adds readable agent/profile labels,
assignment state, provider version numbers, freshness policy, and a stale flag.
The existing consumerMatrix convergence calculation is shared with summary reads.
Its read predicate additionally requires evidence for the management period's current
immutable identity and an active period/group, preventing an old fingerprint's success
from becoming verification for a replacement certificate. Distribution execution,
approvals, writes, and reconciliation were not changed.

A summary batch uses at most two SQL queries, independent of consumer count. The UI
batches only visible certificate links (chunks of 200 IDs), refreshes summaries every
30 seconds, and cancels/ignores obsolete requests. Consumers and versions load only
when details open and a distribution registration is selected. No domain matching is
used. Existing workspace/RBAC guards are unchanged, including the existing manager
restriction on distribution reads. No private material, credentials, or claim secrets
were added to responses or the UI.

## Modified files

API:
- apps/api/routes/certops.js
- apps/api/services/certops/materialDistribution.js
- apps/api/services/certops/distributionRead.js (new)

Dashboard wiring and shared details:
- apps/dashboard/src/App.jsx
- apps/dashboard/src/components/AssetInventoryTable.jsx
- apps/dashboard/src/components/certops/CertificateDetailsModal.jsx
- apps/dashboard/src/components/certops/CertificateIdentityDetailModal.jsx
- apps/dashboard/src/components/certops/CertificateDeployments.jsx (new)
- apps/dashboard/src/components/certops/DeploymentBadge.jsx (new)
- apps/dashboard/src/components/certops/distributionFormat.js (new)
- apps/dashboard/src/components/certops/useDistributionSummaries.js (new)
- apps/dashboard/src/components/certops/DistributionGroupsPanel.jsx (removed)
- apps/dashboard/src/components/certops/certopsApi.js
- apps/dashboard/src/components/certops/certopsFormat.js
- apps/dashboard/src/components/certops/useCertOps.js
- apps/dashboard/src/pages/certops/CertOpsCertificates.jsx
- apps/dashboard/src/pages/certops/CertOpsRenewals.jsx

Contracts and tests:
- packages/contracts/openapi/openapi.yaml
- contracts.manifest.json (OpenAPI digests)
- tests/unit/certops-distribution-read.test.js (new)
- apps/dashboard/tests/unit/CertificateDeployments.test.jsx (new)
- apps/dashboard/tests/unit/useDistributionSummaries.test.jsx (new)
- apps/dashboard/tests/unit/AssetInventoryTable.identity.test.jsx
- apps/dashboard/tests/unit/CertOpsCertificates.test.jsx
- apps/dashboard/tests/unit/CertOpsRenewals.test.jsx
- apps/dashboard/tests/unit/CertificateDetailsModal.test.jsx
- apps/dashboard/tests/unit/CertificateIdentityDetailModal.test.jsx
- apps/dashboard/tests/unit/certopsMultiCert.test.js
- apps/dashboard/tests/unit/certopsTokenResolution.test.js
- apps/dashboard/tests/unit/useCertOps.test.jsx
- .github/maintainers/certops/unified-distribution-ui.md (this report)

## Validation

- pnpm install --frozen-lockfile: passed; lockfile unchanged.
- pnpm run test:unit: 2,541 passed, zero skipped. Includes deployment-state/count and 50-certificate/500-consumer batch tests.
- Focused dashboard selection/navigation checks: passed. After the complete sweep, final identity-boundary rechecks passed (39 tests, followed by 9 tests covering the final managed-registration filter).
- pnpm run test:contracts with CONTRACT_API_REQUIRED=0: 42 passed.
- Dashboard/API lint: passed with existing repository warnings; changed feature components lint without warnings.
- Dashboard type-check, production build, and source Prettier check: passed (existing large-bundle warnings).
- API build, check:contracts, check:contracts:integrity, check:lockfile-overrides, check:secret-logging, and git diff --check: passed.
- Chromium smoke of the real shared modal with explicit local test fixtures: passed at 1440x1000 and 390x844; checked publication separation, consumer rendering, evidence links, and contained horizontal scrolling. This was not a live distribution execution test.
- Latest-main CI run 39118483843: Docker Build & Security Scan passed. The overall run failed in Windows Agent Quality Checks before this branch's changes.

Full dashboard suite: 905 tests passed across 93 files with --maxWorkers=4. Earlier sweeps exposed legacy expectations of automatic same-fingerprint selection; those expectations were updated and revalidated. The final source adjustments also passed their focused identity-boundary rechecks.

## Exact manual UI checks

Use a deployment of this branch with CertOps enabled and an existing workspace manager
session. Reuse existing scenarios; these inspection steps need no renewal, rollout,
approval, assignment, or lab reset. Include a distributed certificate, an undistributed
certificate, a shared token with multiple registrations, and an ended or rotated identity.

1. Open Tokens and filter to Certificates. Confirm a distributed linked token has an inline verified/total indicator; an undistributed token has none. Switch to another asset category and confirm no Deployment column or distribution status appears.
2. Open a certificate token using Details. For a single registration, inspect its renewal facts and Deployments. For multiple registrations, confirm no certificate is automatically chosen; select each option in Certificate to inspect and confirm certificate facts, consumers, versions, and jobs follow that registration. Reopen and confirm a new explicit choice is required. Verify a token without managed links retains ordinary asset details/editing and alert settings.
3. Open CertOps > Certificates. Inspect Deployment for distributed and undistributed identities. Click a deployment summary and confirm the same shared modal opens at Deployments for that identity. For multiple management registrations, select the required registration. Compare the same selected managed certificate with the token entry point; renewal facts and consumer evidence should agree.
4. In Deployments, inspect Vault store and published material separately from consumer verification. Select a distribution management period if needed. Confirm desired/observed provider versions, agent/profile names, verification timestamps/method, and deployed expiry. Check current, partial, pending, stale, failed, and uncertain existing scenarios. Historical job success must not turn stale or uncertain consumers green. Inspect a publication attempt failure without losing visibility of an earlier published version.
5. Expand Technical details and publication history; confirm diagnostics are available there. Click View job and evidence and confirm the Jobs page opens the specified job in the same workspace, with its existing execution evidence. Inspect an ended period or an older rotated identity: it must not inherit a replacement certificate's current consumers or current verification. Also inspect a certificate without a linked token.
6. With over 20 consumers, use Next consumers/Previous consumers and verify totals and rows. Test certificate page filters and 20/50/100 page sizes; network requests should be batched summary reads rather than one read per certificate. At a narrow viewport, scroll the consumer table horizontally inside the modal. Switch workspaces while a request is pending; no old workspace result should appear. Simulate a failed read in browser tooling, then use Refresh deployments to recover.
7. Open CertOps > Renewals and confirm only profiles and issuers remain. Confirm existing renewal setup, certificate retirement, token editing, alert settings, and viewer restrictions behave as before.

## Limits and follow-up

Docker Desktop's Linux engine was unavailable, and no existing API/lab listener was
present on the checked development ports. No compatible PR #329 lab could be smoke-tested;
none was modified. Live PostgreSQL integration, live consumer deployment/evidence, and
real database latency/EXPLAIN checks remain to be run in that lab before merge. The batch
unit test proves query count and aggregation, not production latency. Full Docker/Helm
CI parity and coverage collection were outside this focused validation run.

Distribution reads keep their previous manager-only authorization. Publication version
history keeps the existing endpoint's 1,000-record limit. Latest failed or uncertain deployment attempts take precedence over earlier successful evidence. Detailed verification is a
snapshot refreshed with Refresh deployments; the table summaries refresh every 30 seconds.
