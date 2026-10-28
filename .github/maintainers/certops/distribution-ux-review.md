# Certificate distribution UX review — 2026-10-19

Branch: `feat/certops-unified-distribution-ui`. This review covers the compact inventory, refresh handling, and final Deployments terminology and diagnostics improvements. No PR creation or merge is part of this task.

## Component changes and before/after

| Component | Before | After |
| --- | --- | --- |
| `useDistributionSummaries` / new `useDistributionRead` | Every poll emptied groups and hid existing badges; requests could overlap. | Last successful snapshot stays visible during revalidation; one in-flight read per scope, cancellation and late-response guards, background error state, hidden-tab polling pause. |
| `DeploymentBadge` | Long wrapping status badge and a different loading label. | Fixed 20px indicator with a small icon and count, accessible full description and tooltip; unavailable and last-known states use a neutral/warning presentation. |
| `AssetInventoryTable` | Deployment and Vault chips stacked under the name. | Count beside the existing subtitle on desktop and type on mobile. Names, CN/domain, owner, expiration and lifecycle remain. No new column; linked rows reserve the initial indicator footprint. |
| `CertOpsCertificates` | Large Deployment column badge. | Compact clickable count; manual Refresh also refreshes summaries. |
| `CertificateDeployments` | Repeated totals, five wide columns, raw JSON diagnostics. | Publication summary, one verified count, four compact columns, readable expandable destination details, consumer Advanced diagnostics, and one publication/configuration Technical information panel. Tables and expanded details survive ordinary refreshes. |
| `CertificateDetailsModal` / dashboard wrapper | Managed UUID and fingerprint always visible; inventory indicator did not focus deployments. | Certificate identifiers move into advanced certificate diagnostics; clicking an inventory deployment indicator opens and focuses the shared Deployments section. Shared-token certificate selection stays explicit. |

## Refresh correctness

The snapshot is tied to workspace and certificate selection. A new scope cannot read the previous scope's data. Ordinary refreshes preserve the snapshot, selection, table, and expanded rows. Initial reads alone show placeholders. Offline/server errors retain data with an explicit last-known/unconfirmed indication; HTTP 401/403/404 clears cached metadata. Manual and automatic requests coalesce, polling waits for completion, and hidden tabs resume revalidation on return.

The summary API adds only `evaluated_at` and per-verified-consumer `verification_expirations`. Each deadline is the earlier of evidence freshness expiry and certificate expiry. These reuse the existing convergence query and add no database reads or migrations. A conservative server/client clock offset accounts for request latency. Local timers wake at deadlines and only reduce verified counts; they never infer convergence from a successful job. Older servers without deadline metadata lose a current/green presentation after one poll window if revalidation cannot complete. A modal registration's identity, generation and active state also scope its snapshot.

## Operator semantics

- Publication means material was stored in the customer Vault, not verified service use.
- Provider revision labels explicitly say **Vault provider revision**. Comparisons use immutable TokenTimer material IDs, independently of rollout generations.
- Uncertain external effects show **Unknown** for current version. Historical confirmation remains available in Details.
- Details explain the expected version, last confirmed version, verification window, current state, failure reason and job evidence. UUIDs, hashes, generation/revision numbers and raw codes remain behind Advanced diagnostics.
- Failed, expired and uncertain states give contextual next steps. There are no execution/retry buttons; investigation, local reconciliation, signed retry and approval remain required.

## Final terminology and diagnostics polish

- Refresh status is a compact icon beside the Deployments heading. Its tooltip explicitly says it reloads TokenTimer's recorded status and evidence without triggering deployment or verification.
- Technical information contains Certificate publication and Distribution configuration. Consumer-specific Advanced diagnostics stays inside Details; Publication history has no nested diagnostics and excludes the latest attempt already shown in the summary.
- Latest publication failures or uncertain outcomes stay visible, alongside the last successful publication when relevant. All previous publication records, timestamps, evidence links, fingerprints and copyable IDs remain available.
- Field help supports hover, keyboard focus, Escape and an explicit tap toggle. Expected version, last confirmation, verification freshness, policy, required destinations, material IDs, Vault revisions and rollout generations have contextual explanations.
- Accepted verification methods distinguish served/fingerprint checks from TLS trust checks. Execution outcomes separately translate served_verified and trust_validated, retaining raw codes in consumer diagnostics.
- Verification freshness displays the policy window independently of certificate expiry. A configured 86400-second window displays as 24 hours; its copy control preserves the exact raw seconds.

## Validation

- Full dashboard unit suite: 941 passed across 95 files; the final focused checks below cover subsequent terminology refinements.
- Final focused frontend suite: 113 passed across five files, covering refresh/error/race/scope/freshness/access/rollout-generation regressions, field help, terminology, diagnostics, certificate modal behavior, history, selection and navigation. Inventory checks also passed (6 tests).
- Backend unit suite: 2,542 passed, zero skipped, including expiry metadata and the 50-certificate/500-consumer two-query bound.
- Contract tests: 42 passed; contract manifest/integrity, OpenAPI runtime coverage, lockfile overrides and secret logging checks passed.
- Dashboard lint, formatting, type check and production build passed. Changed UI files have no lint warnings. Repository-wide lint and build retain existing warnings (including chunk sizes).
- Latest main CI Docker Build & Security Scan passed (run 39172342766); this is not a claim of full local Docker/CI parity.
- Existing local review database and dataset were preserved. Browser checks covered 50 Certificates rows, 50 Assets rows, stable row heights over polling/manual refresh, shared-token selection, uncertain-state guidance, linked job evidence, light/dark themes, and a 375px mobile viewport with contained table scrolling. The final Refresh status smoke test preserved every consumer row height, and the technical panel appeared once with both expected subsections.

## Limits

The lab uses synthetic publication and deployment evidence. It does not validate live Vault or agent execution. Profile labels use readable references supplied by the existing API; UUID-like references stay in diagnostics. On narrow screens the four-column destination table scrolls horizontally inside the modal. No execution logic, database schema, RBAC guard or approval workflow was changed.

## Files included in this task

- `apps/api/routes/certops.js`
- `apps/api/services/certops/distributionRead.js`
- `apps/dashboard/src/components/AssetInventoryTable.jsx`
- `apps/dashboard/src/components/DashboardDetailsSection.jsx`
- `apps/dashboard/src/components/DashboardTokenDetailModal.jsx`
- `apps/dashboard/src/components/certops/CertificateDeployments.jsx`
- `apps/dashboard/src/components/certops/CertificateDetailsModal.jsx`
- `apps/dashboard/src/components/certops/DeploymentBadge.jsx`
- `apps/dashboard/src/components/certops/distributionFormat.js`
- `apps/dashboard/src/components/certops/useDistributionSummaries.js`
- `apps/dashboard/src/pages/certops/CertOpsCertificates.jsx`
- `apps/dashboard/tests/unit/AssetInventoryTable.identity.test.jsx`
- `apps/dashboard/tests/unit/CertOpsCertificates.test.jsx`
- `apps/dashboard/tests/unit/CertificateDeployments.test.jsx`
- `apps/dashboard/tests/unit/useDistributionSummaries.test.jsx`
- `contracts.manifest.json`
- `packages/contracts/openapi/openapi.yaml`
- `tests/unit/certops-distribution-read.test.js`
- `apps/dashboard/src/components/certops/DeploymentHelp.jsx`
- `apps/dashboard/src/components/certops/useDistributionRead.js`
- `apps/dashboard/tests/unit/DeploymentBadge.test.jsx`
- `apps/dashboard/tests/unit/DeploymentHelp.test.jsx`
- `.github/maintainers/certops/distribution-ux-review.md`
