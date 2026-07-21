# Changelog

All notable changes to TokenTimer Core are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [0.10.0] - 2026-07-21

### Added

- **GitLab pipeline trigger token discovery** — the GitLab integration scan can now inventory CI/CD pipeline trigger tokens (`GET /projects/:id/triggers`, paginated) behind a new opt-in `includeTriggerTokens` filter (checkbox "Pipeline Trigger Tokens" in the import modal). Requires Maintainer role or above on the project. Trigger tokens never expire, so they are imported as perpetual entries with owner/project metadata.
- **Import filter rules (#69)** — ordered include/exclude rules (exact or regex match on token name or description) can be defined in the import modal, are applied server-side to every integration scan (Vault, GitLab, GitHub, AWS, Azure, GCP, Azure AD) and to the shared import endpoint, and persist in auto-sync `scan_params` so scheduled syncs honor them. The preview table gets a one-click "exclude this token" action that appends an exact-match exclude rule, and scan responses report matched/excluded counts. Regex patterns use JavaScript (ECMAScript) syntax, are statically checked for catastrophic-backtracking (ReDoS) shapes such as `(a+)+` before a scan runs, and are matched against input capped at 2000 characters. The "description" field falls back to the item's name when a token type (e.g. GitLab PATs, project/group/deploy tokens) has no separate description metadata.
- **Obsolete-token cleanup on import and auto-sync** — new opt-in "Remove previously imported tokens no longer found at the source" checkbox for GitLab and GitHub imports (persisted as `cleanupObsolete` in auto-sync `scan_params`). Deletes previously imported tokens of the token types scanned that no longer appear anywhere in the scan's results, regardless of which items are selected for import; token types not scanned are never affected. Matching tokens are hard-deleted with a `TOKEN_DELETED` audit event (`reason: "import_cleanup"` / `"auto_sync_cleanup"`); linked alert-queue entries and endpoint monitors are removed with them. A scan that returns zero items never triggers deletion.
- **Control Center perpetual assets and scopes/privileges now load incrementally** — the "Never expires" and "Scopes & privileges" lists are backed by two new paginated endpoints (`GET /control-center/never-expires`, `GET /control-center/privilege-highlights`) and scroll-to-load-more in the dashboard instead of being capped at a small preview; the headline counts reflect the true workspace-wide totals regardless of how many rows have been loaded.

### Changed

- **GitLab PAT exclusion keeps admin PATs** — the "exclude user PATs" scan filter now retains PATs owned by GitLab administrators in addition to service-account-like users; only regular-user PATs are filtered out. The modal label reads "Exclude regular-user PATs (keep admin and service accounts)".

### Fixed

- **Control Center perpetual asset count** — the "never expires" stat no longer shows the length of the 5-item preview list when the aggregated bucket count is available; the aggregated count now takes precedence.
- **Control Center scoped-credentials count undercounted** — the "Scoped credentials" headline stat used to fall back to the length of a small capped preview list instead of the true workspace-wide total; it now always reflects the aggregate count, with a "Loaded N of M, scroll to load more" hint while the paginated list is still loading.
- **GitLab pipeline trigger token scan returning 0 results** — `listProjects` no longer passes `owned: true` alongside `membership`/`min_access_level`, since GitLab's `ProjectsFinder` short-circuits to literally-owned projects when `owned` is set, silently excluding group/subgroup projects where the caller only has Maintainer access. `listPipelineTriggers` now paginates (was first-page-only) and propagates 401/403/404 instead of always returning an empty array, so a systemic permission problem is distinguishable from projects that truly have no triggers.
- **Import filter rules never matched on the "description" field** — most token types (GitLab PATs, project/group/deploy tokens, GitHub secrets, etc.) carry no separate description metadata, so a description rule always compared against an empty string. `description` rules now fall back to the item's `name` when no description/notes value is present.
- **Bell notification false "alerts will not reach anyone"** — contact groups whose only destination is a webhook (`webhook_names` / `webhook_name`) are now recognized as reachable, so assigning such a group no longer raises the unreachable-alerts warning.

### Security

- **Import filter rules hardened against ReDoS** — regex patterns are rejected at validation time when they contain a classic catastrophic-backtracking shape (nested quantifiers such as `(a+)+`, `(a*)*`) or exceed 10 quantifiers/groups, both server-side and in the modal's live validation. Matched field values are capped at 2000 characters before `.test()` runs, bounding worst-case backtracking cost regardless of input length. The regex is confirmed used only with `.test()` (never `.exec`, `.replace`, `eval`, or any shell/SQL/file-path sink) anywhere in the codebase.

## [0.9.1] - 2026-07-20

### Added

- **Machine-token expiration monitoring opt-in** — the CertOps machine API token creation modal now offers a checkbox (checked by default) that, on confirm, creates a linked TokenTimer token so the machine token's expiry is tracked and alerted on like any other credential.
- **CertOps audit metadata coverage** — all 11 `CERTOPS_*` audit actions (certificate register/import/retire, key-material and evidence rejection, evidence/executor-event acceptance, generic-secret redaction) now render human-readable metadata on the Audit page and are selectable in the action-type filter; previously only 3 of 11 types were formatted.

### Changed

- **`pnpm docker:up` rebuilds stale images automatically** — added `--build` to the compose `up` command so a dashboard/API/worker image left over from a branch switch is rebuilt before the stack starts (cache hit is a no-op when nothing changed); `pnpm dev:help` text updated to match.
- **Dashboard token list refreshes after machine-token monitoring is added** — creating the linked TokenTimer token now dispatches the same `tt:tokens-updated` event used by the import/endpoint flows, so the new entry (and its plaintext reveal) shows up without a manual page refresh.
- **`brace-expansion` override bumped to 2.1.2** — closes a high-severity ReDoS advisory (GHSA-3jxr-9vmj-r5cp) pulled in transitively via `swagger-jsdoc` and `react-query`'s dependency tree.
- **`js-yaml` override bumped to 4.3.0** — closes a high-severity ReDoS advisory (GHSA-52cp-r559-cp3m) reached transitively via `swagger-jsdoc` and directly by the dashboard.

### Fixed

- **CertOps machine tokens can no longer be created already expired** — both the create-token form (disabled submit, `min` datetime, inline helper text) and `POST /api/v1/workspaces/:id/certops/tokens` (400 `CERTOPS_API_TOKEN_INVALID`) reject an `expiresAt` in the past.
- **Revoking a CertOps machine token now deletes its linked TokenTimer monitoring token** — prevents stale alerts firing for a credential that no longer works; recorded as a `TOKEN_DELETED` audit event with `reason: "certops_api_token_revoked"`.
- **CloudNativePG TLS verification during migrations** — `DB_SSL=require` now sets `rejectUnauthorized` from `NODE_ENV=production` in `migrate.js`, matching the runtime API's connection pool instead of always disabling certificate verification.
- **Self-hosted 404 page and footer** — dropped the stale Twitter/Instagram links in favor of Discord, LinkedIn, and GitHub, and fixed the "view pricing" and "read the docs" links that pointed at localhost / outdated destinations.

## [0.9.0] - 2026-07-19

### Added

- **CertOps M0–M2 (self-hosted)** — gated certificate operations broker under `/api/v1/workspaces/:id/certops/*`, enabled with `CERTOPS_ENABLED=true`. TokenTimer remains zero-custody: private-key material is rejected at the API boundary and never persisted, logged, or returned.
- **Managed certificate inventory (M1)** — `managed_certificates`, `certificate_targets`, and `certificate_instances` persistence; public PEM import/upsert by fingerprint; inventory list/detail/retire APIs; endpoint/domain-monitor observation bridge; retire-first lifecycle (`revoked` / `decommissioned`) with status mirrored onto the linked token.
- **Dashboard CertOps surfaces (M1/M2)** — token-detail enrichment (key locality, observation history, retire modal), Import tokens PEM path, Control Center / preferences entry to Certificate operations, and `/certops/operations` for machine API tokens, jobs, and evidence timelines.
- **Machine executor API (M2)** — workspace-bound CertOps API tokens with scopes `certops:read`, `certops:jobs:read`, `certops:events:write`, `certops:evidence:write`; bearer auth; CSRF exemption on machine routes; dedicated machine-token rate limiting; job/log/evidence persistence; aggregate and per-job executor event ingestion with idempotent replay and monotonic lifecycle transitions.
- **Manual job creation (M2 amendment)** — `POST /api/v1/workspaces/:id/certops/jobs` (session-authenticated, manager+) plus dashboard "Create manual job" for the pre-scheduler / break-glass path; jobs are always recorded with `source: "api"`.
- **Contracts and docs** — OpenAPI CertOps paths/schemas, route-compat and evidence/executor-event contracts, enablement docs, and ADR/CONTEXT updates for the CertOps broker model.

### Changed

- **Dashboard shell header alignment** — shared fixed `DASHBOARD_SHELL_HEADER_HEIGHT` so sidebar logo row and header bottom borders stay level.
- **Worker image module resolution** — compose/dev worker Dockerfiles symlink `apps/api/node_modules` to the worker install tree so copied CertOps bridge modules resolve `pg` / logging deps at runtime.
- **Version metadata bumped to 0.9.0** across package manifests, contract files, OpenAPI, and Helm chart `version` / `appVersion` / image tags.

### Fixed

- **Private-key rejection hardening** — JKS magic-header detection; key-rejection precedence before plan/role gates on write routes; fail-closed Unicode / mixed-script identity validation on certificate CN/SAN.
- **Retire and shared-token lifecycle** — retire-first delete gate for managed-backed tokens; terminal status mirrored onto a shared token only when no active sibling managed certificate remains; re-import and monitor observations never revive `revoked` / `decommissioned` rows.
- **Dashboard isolation and UX** — workspace-switch guards for CertOps loads; audit deep-link scope; show-once token reveal reset on workspace change; fail-closed delete while management status is unresolved; certificate-location empty vs 404 vs server-error states distinguished.

### Security

- **Zero-custody CertOps boundary** — private-key and keystore material rejected with audited `PRIVATE_KEY_MATERIAL_REJECTED`; generic secrets redacted from evidence/executor payloads before persistence; machine tokens never returned after one-time reveal.

## [0.8.3] - 2026-07-16

### Added

- **`WEBHOOK_ALLOW_PRIVATE_IPS` (#63)** — new opt-in env var for self-hosted deployments that allows webhook delivery to private/reserved IP ranges (RFC1918, loopback, link-local, CGN). Defaults to `false` (SSRF protection unchanged). Applies to worker alert delivery, the `/api/test-webhook` endpoint, and save-time webhook validation. Exposed in `docker-compose.yml` for the api, worker-delivery, and worker-weekly-digest services and documented in `docs/CONFIGURATION.md` and `deploy/compose/.env.example`. Note: in production (`NODE_ENV=production`) webhook URLs must still be HTTPS; the flag only lifts the private/reserved-IP block.
- **`WEBHOOK_ENFORCE_PRIVATE_IP_CHECK`** — test-infrastructure env var that forces the private-IP check even when `NODE_ENV=test`; set on the API service in `docker-compose.test.yml` so the integration suite exercises the SSRF guard (new `webhook-private-ip-blocking.test.js` plus unit coverage in `webhook-private-ip-gate.test.js`).

### Fixed

- **Webhook Test vs delivery parity (#63)** — the Test button and alert-settings save-time validation now run the same private/reserved-IP check as actual alert delivery (shared helpers in `apps/api/utils/webhookSafety.js`), so a webhook that would be blocked at delivery time fails fast with a clear error (`WEBHOOK_PRIVATE_IP_BLOCKED`) instead of a misleading successful test. Blocked-delivery errors now mention the `WEBHOOK_ALLOW_PRIVATE_IPS` remedy.

### Changed

- **Version metadata bumped to 0.8.3** across package manifests, contract files, OpenAPI, and Helm chart `version` / `appVersion` / image tags.

## [0.8.2] - 2026-07-15

### Fixed

- **GitLab auto-sync (#63)** — `ImportGitLabForm.getCredentials()` now maps `includePATs` / `includeSSHKeys` into `scanParams.filters` (matching the scan endpoint's expected shape) instead of the unused `scanParams.include`; auto-sync filter selections for PATs and SSH keys are honored again.
- **Auto-sync "Save changes"** — filter changes (`scan_params`) are now sent on every save, even when the PAT/token field is left blank; only `credentials` remain gated behind re-entering a secret, since filters never contain sensitive data.
- **Auto-sync worker status** — a run is now recorded as `partial` (with a descriptive `last_sync_error`) instead of `success` when items were scanned but none were actually imported, or when the import step reports per-item errors; the dashboard surfaces this via a warning banner and toast instead of a silent success message.

### Changed

- **pnpm 11.13.0** — upgraded from 10.33.4 so `pnpm audit` uses npm's bulk advisories endpoint after the legacy audit API was retired (HTTP 410); migrated `onlyBuiltDependencies` to `allowBuilds` for pnpm 11 build-script policy.
- **Docker builds** — `apps/api` and `apps/dashboard` Dockerfiles now require repo-root build context (same pattern as worker/compose) so they copy the canonical `pnpm-workspace.yaml` `allowBuilds` allowlist; compose test/dev contexts, coverage flush-hook path, and V8 coverage path remaps updated accordingly.
- **Base images** — Node `22.22.2` → `22.23.0` and Go `1.26.4` → `1.26.5` across Dockerfiles to clear Grype high/fixed CVEs in the image binaries.
- **Version metadata bumped to 0.8.2** across package manifests, contract files, OpenAPI, and Helm chart `version` / `appVersion` / image tags.

## [0.8.1] - 2026-06-22

### Added

- **Password reset + 2FA** — `POST /auth/reset-password` accepts optional `resetTwoFactor: true` to clear authenticator 2FA when completing a reset; Reset Password page adds a matching checkbox.
- **OpenAPI** — documented `since` / `until` audit filter query params on list and export routes.
- **Integration test** — `workspace-notifications.test.js` covers workspace operational notifications API.

### Changed

- **Dashboard shell** — notification bell action hints name Control Center, Preferences, and Import targets; deferred-alert notification href points to `/control-center` instead of legacy `/usage`.
- **Workspace context** — keeps `?workspace=` in the URL when navigating between dashboard routes; excludes frozen workspaces from auto-selection; resets normalization on pathname change.
- **Control Center** — auto-selects the first eligible workspace and syncs the URL query param on load.
- **Legacy Usage page** — reduced to a stub (`/usage` redirects to Control Center in `App.jsx`); removed unused `Navigation.jsx`.
- **Version metadata bumped to 0.8.1** across package manifests, contract files, OpenAPI, and Helm chart `version` / `appVersion` / image tags.

### Fixed

- **Audit filters** — date/time range filters convert browser local time to UTC ISO bounds before querying (fixes off-by-timezone filtering).
- **2FA setup modal** — Confirm & Enable footer no longer clips on narrow viewports; dialog footer layout stacks on mobile.
- **Alert preferences** — contact add, edit, and delete guarded when no workspace is selected; Add contact button disabled without a workspace.

## [0.8.0] - 2026-06-22

### Added

- **Control Center** — new `/control-center` route (replaces `/usage`) with expiry health buckets, needs-attention list, asset-source panels, perpetual-asset and privilege-highlight insight panels, and auto-sync health rows with deep links into token detail and Import manage.
- **`GET /api/v1/workspaces/:id/control-center/stats`** — workspace admin / manager RBAC; returns aggregated stats via `controlCenterStats.js` and shared `expiryBuckets` / `controlCenterStatsHelpers`.
- **Dashboard shell** — shared collapsible sidebar/topbar (`DashboardShell`), page layout primitives (`DashboardPageLayout`, `SettingsPageShell`), and inventory URL state sync (`useInventoryUrlState`).
- **Category-aware asset inventory** — `AssetFilters` + `AssetInventoryTable` with per-category columns, contact-group column, editable key/secret privileges, and multi-section OR filter semantics (API uses PostgreSQL `&&` overlap).
- **ThresholdDaysEditor** — chip-based alert threshold editing for workspace defaults and contact-group overrides; shared `alertThresholds.js` parse/validate helpers.
- **User preferences route** — `/preferences` for theme and display options.
- **Integration tests** — `control-center-stats`, `control-center-stats-rbac`, extended `audit-filtering`; suites registered in `core.txt` and `cloud-compatible.txt`.
- **Docs assets** — updated dashboard GIFs and new Control Center, workspace preferences, and system settings screenshots.

### Changed

- **Dashboard IA** — slimmed `/dashboard` to filters + inventory table; audit page full-width redesign; Help page removed; product tour and navigation updated for new routes.
- **Modal and toast UX** — centralized modal styling in `theme.js` via `useDashboardModalProps`; toasts moved bottom-right; Import modal light-theme parity and full-card source clicks.
- **Auto-sync worker schedule** — default cron aligned to `*/1 * * * *` across Compose, Helm, and worker runner (was hourly).
- **Dashboard XLSX dependency** — `xlsx` aliased to patched `@e965/xlsx@0.20.3` for import/export flows.
- **Docker images** — dashboard nginx Alpine pin updated to `1.28.3-r4` (CVE-2026-9256 / CVE-2026-49975; Alpine 3.23 patched revision).
- **Version metadata bumped to 0.8.0** across package manifests, contract files, OpenAPI, and Helm chart `version` / `appVersion` / image tags.

### Fixed

- **Settings UX** — sticky auth footers, disabled-button tooltips, workspace delete confirmation, duplicate webhook test toast removed, 2FA success toast with session refresh, contact groups mobile formatting.
- **Control Center deep links** — token modal via `?token-id=` supports string IDs; auto-sync rows open Import manage tab via `?import=&autoSyncManage=1`.
- **Inventory reload** — 100 ms debounced token reload on filter changes; prior rows kept visible until new data arrives.

### Security

- **SheetJS / xlsx** — dashboard import/export uses `@e965/xlsx@0.20.3` via pnpm alias (addresses GHSA-4r6h-8v6p-xvw6 and GHSA-5pgg-2g8v-p4x9 in legacy `xlsx@0.18.5`).

## [0.7.2] - 2026-06-15

### Added

- **WhatsApp template sanitization** — shared `apps/worker/src/shared/whatsappTemplateVars.js` strips invalid characters and enforces placeholder contracts before Twilio `ContentVariables` are sent.
- **CI supply-chain checks** — `check:lockfile-overrides` verifies security override pins in `pnpm-lock.yaml`; `check:secret-logging` blocks credential leakage in log statements.
- **Dev command map** — `pnpm dev:help` prints the local development command reference (`scripts/dev-help.js`).

### Changed

- **Root package scripts** — reorganized `package.json` scripts into labelled sections; contract and CI check scripts grouped under `// --- CI / contract checks ---`.
- **Docker images** — `COPY --chown` shrinks layers; Corepack pnpm caches are reusable in dev containers; dashboard Compose image pins nginx `1.28.3-r3` and routes nginx logs to stdout/stderr for non-root startup.
- **CI** — Grype action pinned by checksum; security override pins enforced at lockfile level.
- **Logger redaction** — API and worker loggers sanitize tokens, passwords, and connection strings before output.
- **Version metadata bumped to 0.7.2** across package manifests, contract files, OpenAPI, and Helm chart `version` / `appVersion` / image tags.

### Fixed

- **WhatsApp alert delivery** — delivery worker sends only the six EXPIRES/EXPIRED placeholders and sanitizes values (removes extra keys like `expiration_date_iso` that Twilio rejects).
- **WhatsApp weekly digest** — weekly digest worker uses the shared sanitizer; `tokens_list` keeps all tokens on one line without a 250-character cap.
- **API runtime** — PostgreSQL server identity verified in production when `DB_SSL=require`; `testConnection` pool leaks closed; `User.update` no longer wipes omitted fields.
- **Domain checker** — `binaryRunner` reliably kills child process trees after scans complete.
- **Prometheus metrics** — API route labels bound to matched Express patterns instead of raw URLs.
- **Dashboard import deep-links** — unknown provider query params no longer open the import modal on an invalid tab.
- **Dashboard Compose nginx** — non-root container creates `/var/lib/nginx/logs` and symlinks access/error logs for reliable startup.

### Security

- **Dependency patches** — `nodemailer` bumped to `8.0.11` (GHSA-wqvq-jvpq-h66f, GHSA-r7g4-qg5f-qqm2, GHSA-268h-hp4c-crq3); `js-yaml` bumped to `4.2.0` (GHSA-h67p-54hq-rp68); `vite` bumped to `6.4.3`; `form-data` workspace override pinned to `4.0.6` (GHSA-hmw2-7cc7-3qxx); worker `ajv@6` aligned to `6.15.0` via workspace overrides.
- **Grype exclusions** — `.grype.yaml` updated for known false positives after image hardening.

## [0.7.1] - 2026-06-03

### Added

- **Worker runner** — `apps/worker/src/runner.js` long-running scheduler for local development and Docker Compose; reuses one-shot job functions with cron mode aligned to Kubernetes Helm defaults.
- **Cross-platform dev scripts** — `scripts/dev.js`, `scripts/run-with-env.js`, and `scripts/process-utils.js` make `pnpm run dev` and `pnpm run migrate` work on Windows, WSL, Linux, and macOS.
- **Zero-config local dev** — `pnpm dev` starts PostgreSQL via `deploy/compose/docker-compose.postgres.yml`, applies local defaults when no root `.env` exists, and runs DB migrations on API startup.
- **Dev helpers** — `pnpm dev:noDB`, `pnpm dev:postgres`, and `pnpm dev:ports:check` (detects port conflicts with `tokentimer-enterprise` `demo:local` / `dev-mock-api`).
- **Root `.env.example`** — documents minimum local development variables.
- **Unit tests** — worker runner, CLI entrypoint detection (`is-node-entrypoint.js`), root env loading, and dev port checks.

### Changed

- **Docker Compose workers** — each worker service runs `runner.js` instead of one-shot scripts in restart loops; cron schedules match Helm (`*/5`, `1/5`, hourly auto-sync, etc.).
- **Worker Compose env** — `TZ=UTC` on all worker services; `WORKER_*_INTERVAL_MS` wired through with empty defaults (cron default; set `*_CRON=interval` to opt in).
- **pnpm overrides** — moved from root `package.json` to `pnpm-workspace.yaml`.
- **Worker default startup** — `pnpm start` / Dockerfile CMD use `runner.js`; one-shot commands remain for tests, CI, and Kubernetes CronJobs.
- **Integration credential copy** — README and AWS import form clarify that scan credentials are discarded after one-off imports and stored encrypted when auto-sync is enabled.
- **Version metadata bumped to 0.7.1** across package manifests, contract files, OpenAPI, and Helm chart `version` / `appVersion` / image tags.

### Fixed

- **Windows dev shutdown** — `dev.js` and `run-with-env.js` terminate child process trees (`taskkill /t`) with bounded graceful and hard stop timeouts.
- **Windows worker entrypoints** — `is-node-entrypoint.js` fixes `import.meta.url` main-module detection across path formats.
- **Root env parsing** — quoted values with inline comments parse correctly in `scripts/load-root-env.js`.
- **Worker entrypoint races** — auto-sync and endpoint-check scripts use async IIFE + try/catch instead of `.catch().then()` exit races.
- **Runner cron validation** — `validateCronFeasibility()` rejects impossible expressions; cron lookahead capped to 35 days; 30s shutdown timeout for in-flight runs.
- **Runner lazy loading** — worker job modules load on first scheduled run, not at process start.
- **Local dev DB credentials** — Postgres Compose defaults and app env defaults stay in sync when no `.env` is present.
- **Dashboard Compose nginx** — non-root container can start on nginx 1.28+ by routing temp paths to writable `/var/cache/nginx/*` directories.

## [0.7.0] - 2026-05-26

### Added

- **Operational notifications API** — `GET /api/v1/workspaces/:id/notifications` returns dashboard bell items for workspace admins and managers: failed auto-sync configs (with API error text) and alerts waiting for the delivery window (`OUT_OF_WINDOW`).
- **Auto-sync failure pipeline** — worker `formatAutoSyncError()` surfaces integration API error bodies in `last_sync_error`; `recordAutoSyncFailure()` writes `AUTO_SYNC_FAILED` audit events on the first transition into failed state (no hourly duplicates).
- **Manage auto-sync tab** — Import modal sub-tabs **Scan & Import** | **Manage auto-sync** when auto-sync is enabled: view failure status, edit schedule, update credentials, disable without separate modals.
- **Dashboard bell** — Navigation loads operational notifications alongside alert-settings warnings; auto-sync failure items deep-link into Import tokens on the **Manage auto-sync** tab (`?import={provider}&autoSyncManage=1`); deferred alerts link to Usage.
- **Bell refresh hook** — Navigation listens for `tt:notifications-refresh` so the bell can reload without a full page refresh.
- **Audit UI** — labels and colours for `AUTO_SYNC_*` actions including `AUTO_SYNC_FAILED`.
- **Unit tests** — `auto-sync-failure.unit.test.js`, `rbac-require-not-viewer.test.js`.

### Changed

- **Import modal deep-link** — `ImportTokensButton` reads dashboard query params and opens the modal on the correct provider and Manage auto-sync tab when arriving from a bell notification.
- **Import GitHub/GitLab forms** — `autoSyncManageMode` hides scan UI on the Manage tab while keeping credentials and sync filters visible.
- **Auto-sync worker** — delegates failure persistence to shared `apps/worker/src/shared/autoSyncFailure.js`.
- **RBAC** — `requireNotViewer` bypasses viewer check for authenticated worker API calls (`req.isWorkerCall`).
- **Version metadata bumped to 0.7.0** across package manifests, contract files, OpenAPI, and Helm chart `version` / `appVersion` / image tags.

### Fixed

- **Import modal footer** — import action buttons no longer appear on the Manage auto-sync tab.
- **Import modal reset** — closing the modal resets the integration sub-tab to Scan & Import.
- **Bell notification UX** — auto-sync failure subtext matches deep-link behaviour; `openRequest` is cleared after the modal consumes it; Manage tab deep-link no longer sticks when auto-sync is not configured for the provider.

## [0.6.2] - 2026-05-25

### Added

- **Core auto-sync provider allowlist** — `apps/worker/src/auto-sync-providers.js` hardcodes GitHub and GitLab for the OSS worker; enterprise editions replace this module via file override.
- **Regression tests** — system-admin preserve-admin unit coverage; auto-sync provider allowlist and AWS integration tests.

### Changed

- **Auto-sync worker** — rejects providers outside the core allowlist with a clear failure metric instead of env-based edition flags.
- **Dashboard AWS import** — `ImportAWSForm` and `ImportTokensModal` build auto-sync payloads compatible with the all-regions scan API.
- **Plugin context contract** — documents that `setAutoSyncProviders` is reserved; enterprise enforces provider policy via file overrides in 0.6.x.
- **Version metadata bumped to 0.6.2** across package manifests, contract files, OpenAPI, and Helm chart `version` / `appVersion` / image tags.

### Fixed

- **System-admin workspace expansion** — `ensureSystemAdminWorkspaceAccess()` no longer downgrades existing workspace `admin` memberships to `workspace_manager`; it inserts missing rows and upgrades `viewer` only. Preserves workspace-owner RBAC for creators who are also system admins.
- **AWS auto-sync region detection** — `detectAWSRegions()` uses per-region timeouts, batched parallel probes, and IAM key caps so all-regions scans cannot hang indefinitely.
- **Auto-sync worker AWS payload** — worker builds correct all-regions scan requests instead of passing `region: "all-regions"` to the API.

## [0.6.1] - 2026-05-25

### Added

- **System-admin organization audit** — users with `users.is_admin` can view and export the full organization audit log (not limited to workspaces where they hold `admin`); Audit UI shows SSO login and membership-sync metadata.
- **System-admin workspace sync on local login** — `POST /auth/login` and `POST /auth/verify-2fa` call `ensureInitialWorkspaceForUser`, which upserts `workspace_manager` on every workspace for system admins (adds missing rows and upgrades existing `viewer` memberships; existing workspace `admin` memberships are preserved).
- **Integration tests** — `audit-system-admin-org-scope.test.js`, `csrf-worker-exemption.test.js`.

### Changed

- **Dashboard audit access** — Audit nav and `/audit` route allow system admins (`session.isAdmin`) in addition to workspace admins and managers.
- **Test WhatsApp authorization** — `POST /api/test-whatsapp` now requires `whatsapp.test` (minimum role `workspace_manager`) instead of `workspace.update` (`admin`), matching 0.6.0 role semantics.
- **Version metadata bumped to 0.6.1** across package manifests, contract files, OpenAPI, and Helm chart `version` / `appVersion` / image tags.

### Fixed

- **Auto-sync and worker API calls blocked by CSRF** — recent CSRF hardening required a token on all `/api` mutations; background worker requests (e.g. auto-sync import via `Authorization: Bearer WORKER_API_KEY`) had no session cookie and were rejected. Shared `internal-worker-auth` and `csrf-exempt` middleware restore the authenticated worker bypass; `requireAuth` accepts the same bearer.
- **Test WhatsApp 403 for workspace managers** — managers and workspace managers on the shared Default workspace were denied because the route required workspace `admin`.
- **Audit authorization fail-closed** — role-check errors on audit list/export now return **503** instead of continuing with a partial filter.
- **System-admin workspace sync skipped** — `ensureInitialWorkspaceForUser` no longer returns early when the user already has memberships, so system-admin workspace upserts run on every login.
- **Integration test suite (0.6.0 alignment)** — dedicated test workspaces for isolation on shared Default installs; audit cleanup respects immutable `audit_events`; import expiration assertions use PostgreSQL `::text` cast (avoids JS timezone drift on `DATE`); alert queue tests seed email contact groups required by queue-manager.

## [0.6.0] - 2026-05-23

### Added

- **System admin management** — system admins can grant or revoke installation-wide admin (`users.is_admin`) from **Workspaces → Members** via `PATCH /api/admin/users/:userId/system-admin`; session exposes `user.isAdmin`.
- **Unit tests** — `ensure-default-workspace.test.js` and `bootstrap-default-workspace.test.js` for shared Default workspace provisioning.
- **Regression tests** — `ensure-default-workspace.test.js` asserts system admins joining existing Default get `workspace_manager` (never `admin`); `admin-system-settings.test.js` asserts system admin with Default `workspace_manager` can still reach `GET /api/admin/system-settings`.

### Changed

- **Default workspace provisioning** — bootstrap and first-login provisioning use a shared **Default workspace** instead of per-user personal workspaces (`{name}'s workspace`). New users without membership join the existing default (or the sole workspace on legacy installs); existing personal workspaces are unchanged on upgrade.
- **Workspace member roles** — Members tab manages viewer/manager only; system admin is a separate toggle (not workspace-scoped `admin` promotion).
- **Dashboard navigation** — the **System Settings** entry (desktop and mobile) and the SMTP-not-configured notification link are now gated on `session.user.isAdmin` instead of workspace `admin` role, matching the API's `requireSystemAdmin` check on `/api/admin/system-settings`.
- **`docs/AUTHENTICATION.md`** — documents Default workspace behavior and system admin vs workspace roles.
- **Version metadata bumped to 0.6.0** across package manifests, contract files, OpenAPI, and Helm chart `version` / `appVersion` / image tags.

### Fixed

- **System Settings nav visibility for SSO admins.** Dashboard previously hid the System Settings link whenever the session user lacked a workspace `admin` membership, even though `users.is_admin = TRUE` already authorised the API endpoint. The link is now driven by the session `isAdmin` flag and the SMTP warning routes there only for system admins (non-admins see read-only guidance to contact a system administrator).
- **Integration test suite** — login rate limiting no longer exhausts the IP bucket during long runs; `auto-sync-import` expiration assertion handles Postgres date types.
- **Account deletion vs last system admin.** `DELETE /api/account` blocks when the caller is the last active system administrator, clears `is_admin` during GDPR anonymization, and counts only live admins (excluding tombstoned `@example.invalid` accounts). System-admin demotion uses the same active-admin definition under a shared Postgres advisory lock to prevent concurrent delete/demote races from leaving zero active admins.
- **Release test path** — `pnpm run test:unit` runs `tests/unit/` via `scripts/run-unit-tests.js` (Node 24 CI cannot use `node --test tests/unit` as a directory); `test:ci` and `scripts/run-tests.sh` run unit tests before the integration suite; CI backend quality job runs unit tests on every push.

### Security

- **Default-workspace privilege-escalation hardening (pre-release).** `apps/api/services/workspace.js#resolveJoinRole` no longer reads `users.is_admin` when deciding the join role for the shared Default workspace; every automatic join after the workspace exists is `workspace_manager`. This prevents `users.is_admin = TRUE` (including the SSO bootstrap-admin group path) from being silently promoted to a workspace `admin` membership on the shared Default workspace during first-login provisioning. The first user who creates the Default workspace is still its workspace admin (creator branch unchanged), and bootstrap still seeds the bootstrap admin as workspace admin on the workspace it creates. No repair migration is shipped because 0.6.0 has not been released yet.

## [0.5.4] - 2026-05-23

### Added

- **`session-cookie-options.js`** — shared session/CSRF cookie and CORS origin resolution for split `APP_URL` / `API_URL` (`SameSite`, `Secure`, `SESSION_COOKIE_DOMAIN`, localhost override, logout `clearCookie` parity).
- **`runtime-labels.js`** — API log and rate-limit labels from `TT_MODE` / `.tokentimer-variant` (enterprise vs core) with optional env overrides.
- **Dashboard `resolveApiBaseUrl.js`** — local dev rewrites configured `localhost` API URLs to the page hostname (`127.0.0.1` vs `localhost`).
- **Tests** — Mocha unit suites for session cookies and runtime labels (in core integration suite); Vitest for `resolveApiBaseUrl`; integration logout asserts matching `sessionId` clear-cookie attributes.

### Fixed

- **Docker Compose login on localhost** — split HTTP ports (`5173` + `4000`, or Helm port-forward `8080` + `4000`) stay `SameSite=Lax` instead of `SameSite=None; Secure` (blocked as third-party cookies in strict browsers).
- **Logout and account deletion** — `clearCookie("sessionId")` matches express-session options (`sameSite`, `secure`, `domain`); no hard-coded `SameSite=Strict`.
- **`API_URL` fallback in cookie/CORS logic** — missing `API_URL` falls back to `APP_URL`, aligned with `constants.js` and Helm same-origin installs.
- **`__Host-` CSRF cookie** — disabled when `SESSION_COOKIE_DOMAIN` is set (Host-prefix cookies cannot include `Domain`).
- **`SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE`** — honored only when both `APP_URL` and `API_URL` are local HTTP; ignored on public HTTPS even if the flag is set.
- **Production CORS** — localhost dev origins omitted unless `ALLOW_LOCAL_DEV_CORS=true`; OPTIONS preflight uses the same CORS options as other routes.
- **Dashboard `resolveApiBaseUrl`** — classifies local API hosts via URL hostname, not substring match (avoids query-string false positives).
- **Integration test drift** — `auto-sync-import.test.js` expects HTTP `201` on `POST /api/v1/integrations/import` and uses the test stack `SESSION_SECRET` for worker bearer auth (was mismatched hard-coded secret).

### Changed

- **API logger and rate limiter** use `getRuntimeLabels()` instead of hard-coded `tokentimer-core-api` / `oss`.
- **Compose** — dashboard service receives `API_URL` for runtime `env.js`; **Helm** — `API_URL` defaults to `baseUrl` when `apiUrl` is omitted.
- **`docs/CONFIGURATION.md`** — split-host cookies, optional `SESSION_COOKIE_DOMAIN`, `ALLOW_LOCAL_DEV_CORS`, localhost override guard, Helm vs Compose vs runtime URL table.
- **Domain checker UI** — removed outdated Pro/Team badge copy from the SSL monitor modal.
- **Version metadata bumped to 0.5.4** across package manifests, contract files, OpenAPI, and Helm chart `version` / `appVersion` / image tags.

### Security

- **pnpm override `qs@6.15.2`** — addresses [GHSA-q8mj-m7cp-5q26](https://github.com/advisories/GHSA-q8mj-m7cp-5q26) (moderate DoS in `qs.stringify` via Express).

## [0.5.3] - 2026-05-19

### Changed

- **Helm chart rollouts on `helm upgrade`.** API, dashboard, and worker Deployments (and CronJob pod templates) now carry `checksum/config` and `checksum/secret` annotations derived from rendered ConfigMap data and stable secret inputs, so pods restart when `tokentimer.config`, SMTP, Twilio, or DB-related values change. Dashboard also checksums `dashboard.env`.
- **`checksum/helm-release-revision`** on API, dashboard, and workers so umbrella charts (for example enterprise SSO env from a parent ConfigMap) trigger a rollout on every upgrade when subchart Deployments cannot see parent-only resources.
- **Helm README** documents automatic rollout behavior and notes that env vars are read only at pod start.
- **Version metadata bumped to 0.5.3** across package manifests, contract files, OpenAPI, and Helm chart `version` / `appVersion` / image tags.

## [0.5.2] - 2026-05-18

### Fixed

- **Dashboard nginx on port 8080** in compose-built images and Helm (`containerPort: 8080`, Service still exposes port 80). Fixes `bind() to 0.0.0.0:80 failed (13: Permission denied)` when Kubernetes drops all capabilities (`securityContext.capabilities.drop: [ALL]`).

### Changed

- **CloudNativePG Cluster template** exposes optional CNPG spec fields with sane defaults (`maxSyncReplicas: 2`, `minSyncReplicas: 1`, 10Gi storage, 512Mi-1Gi resources). Power users can pass any other `Cluster` spec field via `postgresql.cloudnative.parameters` or `postgresql.cloudnative.extraSpec`.
- **Version metadata bumped to 0.5.2** across package manifests, contract files, OpenAPI, and Helm chart `version` / `appVersion` / image tags.

## [0.5.1] - 2026-05-18

### Added

- **Helm tpl support for `api.envFrom`, `worker.envFrom`, and `extraVolumes`.** `configMapRef.name`, `secretRef.name`, and `secret.secretName` values may use Helm `tpl` (for example `{{ .Release.Name }}-overlay-env`) so umbrella charts can wire release-scoped ConfigMaps and Secrets without hard-coded names.
- **`helm-template-verify` default-values scenario and CNPG SSL assertion.** The script now templates chart `values.yaml` and fails if `DB_SSL: require` is missing when CloudNativePG is enabled.

### Fixed

- **CloudNativePG installs rejected non-SSL database connections.** The chart ConfigMap now sets `DB_SSL: require` whenever `postgresql.cloudnative.enabled` is true, matching the default `pg_hba` rules (`hostssl` + `hostnossl reject`) and fixing API startup errors such as `pg_hba.conf rejects connection ... no encryption`.

### Changed

- **Version metadata bumped to 0.5.1** across package manifests, contract files, OpenAPI, and Helm chart `version` / `appVersion` / image tags.

## [0.5.0] - 2026-05-18

### Added

- **Plugin-ready system settings JSONB column registry.** `systemSettings.js` now exposes `registerJsonColumn(columnName, options)` so enterprise and plugin layers can add encrypted JSONB columns to `system_settings` at startup without touching core. Each column participates in the existing env > DB > default precedence and supports per-column `featureGate(req)` predicates to enforce entitlement boundaries at the API layer.
- **System settings GET/PUT surface registered JSONB columns.** `GET /api/admin/system-settings` merges registered plugin columns (subject to their feature gates) into the response alongside `smtp` and `whatsapp`. `PUT` accepts and persists plugin column payloads alongside core fields.
- **`TRUST_PROXY_HOPS` env var** lets operators control the number of trusted reverse-proxy hops in front of the API (`0` = no proxy, `1` = single ingress, `2` = LB + ingress, default). Affects `req.ip` and `req.protocol` resolution used for rate-limit keys and SSO callback URL generation. Documented in `docs/CONFIGURATION.md`, `.env.example`, Helm `values.yaml`, and `configmap.yaml`.
- **`disableAdminBootstrap` Helm value** (`config.disableAdminBootstrap: false`). Set to `true` to skip automatic admin account creation on first boot — useful when all users are managed via SSO. Propagated through `configmap.yaml` as `DISABLE_ADMIN_BOOTSTRAP=true`.
- **SMTP TLS knobs: `SMTP_SECURE` and `SMTP_REQUIRE_TLS`.** Force SSL (`secure`) or require STARTTLS (`requireTls`) without relying on auto-detection. Available via env vars, `docker-compose.yml`, and Helm `smtp.secure` / `smtp.requireTls` values.
- **Configurable NetworkPolicy egress CIDRs.** `networkPolicy.egress.smtpCidrs` and `networkPolicy.egress.httpsCidrs` in `values.yaml` replace the hard-coded `0.0.0.0/0` catch-all. Default to `[0.0.0.0/0]` to preserve existing behaviour; operators can narrow to known relays or provider IP ranges.
- **`alerts_delivery_last_success_unix` Prometheus gauge.** Set by the delivery worker after each run to the DB timestamp of the most recent successful delivery. Powers time-based alerting on stale alert queues.
- **`weekly_digest_last_sent_unix` Prometheus gauge.** Set by the weekly-digest worker to the DB timestamp of the most recent digest send. Powers `WeeklyDigestNoSendsWeek`-style alerts.
- **`requireAnyAdmin` middleware caching.** Result is stored on `req._adminCheckResult` and the session-deserialized `req.user.is_admin` is trusted directly, saving a DB round-trip per admin API call.
- **`compose_validation` CI job.** New GitHub Actions job validates `docker-compose.yml`, `docker-compose.images.yml` overlay, and `docker-compose.dev.yml` with `docker compose config -q` on every push, catching env-variable and YAML errors before they reach production.
- **`helm:lint` and `helm:template` root scripts.** Added to `package.json` for developer convenience.
- **Healthchecks for `api` and `dashboard` services** in `docker-compose.yml`. The API uses a native `node -e` HTTP probe (no curl required in Alpine); the dashboard uses `wget`.
- **Unit tests for `systemSettings` JSON column registry** (`tests/integration/system-settings.unit.test.js`). Covers `registerJsonColumn` validation, `getJsonColumn`, `setJsonColumn`, secret-field encryption, env-var override, and feature-gate logic.

### Changed

- **`ADMIN_EMAIL` is no longer required when `config.disableAdminBootstrap` is true.** The `required` guard in `configmap.yaml` is skipped, removing a Helm install blocker for SSO-only deployments.
- **`docker-compose.yml` env var coverage extended.** `WORKER_API_KEY`, `ALERT_THRESHOLDS`, `ALERT_MAX_ATTEMPTS`, `ALERT_RETRY_DELAY_MS`, `DELIVERY_WINDOW_*`, `ENABLE_METRICS`, `PUSHGATEWAY_URL`, and `ENVIRONMENT_SUFFIX` are now forwarded to the relevant worker containers, removing the need for manual `docker-compose.override.yml` stubs.
- **`docker-compose.dev.yml` parity.** `SMTP_SECURE`, `SMTP_REQUIRE_TLS`, `ENABLE_METRICS`, and `ENVIRONMENT_SUFFIX` forwarded to the dev API service.
- **Helm `values.schema.json` extended.** Added schemas for `config.adminName`, `config.disableAdminBootstrap`, `config.nodeEnv`, `config.trustProxyHops`, `networkPolicy.ingressNamespace`, `networkPolicy.monitoringNamespace`, and the new `networkPolicy.egress` object.

### Fixed

- **Repeated `system_settings` table-missing log noise suppressed.** Boot sequences (and tests without the schema seeded) no longer flood logs — the warning fires once (`42P01`), then drops to debug-level for subsequent misses.
- **`whatsapp-webhook-status` test stability fix.** Corrected an assertion that was timing-sensitive in CI.
- **`.gitignore` extended** to exclude `/AGENTS.md`, `/docs/agents/`, and `/.scratch/` (local agent-skill scaffolding artifacts).

## [0.4.0] - 2026-05-09

### Added

- **Bulk token section assignment via a single API call.** New `PUT /api/tokens/bulk` endpoint accepts up to 500 token IDs and a `section` value, applies the update in one SQL statement, and returns per-token success/failure detail. The dashboard's multi-select section workflow now uses this endpoint instead of N individual requests, and the new endpoint is fully documented in OpenAPI.
- **`EndpointSslMonitorModal` extracted to its own component file.** The endpoint monitor and SSL certificate modal is now a standalone `apps/dashboard/src/components/EndpointSslMonitorModal.jsx`, making the file smaller and the component independently testable.
- **Domain utilities extracted.** `domainStatusColor`, `domainSslBadge`, `domainFormatUrl`, and `domainValueToUrl` are now in `apps/dashboard/src/utils/domains.jsx`, shared across components without duplication.
- **Auto-sync Prometheus metrics.** Three new metrics pushed to Pushgateway after every worker run: `auto_sync_runs_total{provider,status}` (counter), `auto_sync_items_imported_total{provider}` (counter), and `auto_sync_last_run_timestamp{provider,status}` (gauge). Two ready-to-use PrometheusRule alert definitions (`AutoSyncProviderFailures`, `AutoSyncNotRunning`) added to `deploy/helm/examples/values-full-test.yaml`.
- **Server-side credential validation for auto-sync configs.** The `POST` and `PUT /api/v1/workspaces/:id/auto-sync` endpoints now validate that required credential fields (e.g. `token` for GitHub/GitLab, `accessKeyId`+`secretAccessKey` for AWS) are present and non-empty before encrypting and storing. Returns HTTP 400 with a descriptive error instead of silently storing unusable credentials.

### Fixed

- **Auto-sync rework and credential decryption fix.** Reworked the auto-sync worker to delegate token import to the existing `POST /api/v1/integrations/import` endpoint (the same one the dashboard uses) for all providers, so deduplication, sanitization, and audit logging are identical to a manual import. Fixed a credential decryption bug where the worker used a SHA-256-derived key while the API encrypts with `scryptSync`; the legacy SHA-256 path is kept as a fallback for older records.
- **Auto-sync `API_URL` hardcoded in Docker Compose and Kubernetes CronJob.** The worker service in `docker-compose.yml` previously derived `API_URL` from the user-facing `.env` variable, which defaults to `http://localhost:4000`. Since `localhost` inside a container resolves to the container itself, every scan request failed with a network error. `API_URL` is now hardcoded to `http://api:4000` in the Compose service definition. The Helm CronJob template applies the same fix by injecting `http://<release>-api:<port>` directly, overriding whatever `config.apiUrl` is in the ConfigMap.
- **Kubernetes NetworkPolicy updated for auto-sync.** The worker egress policy was missing a rule for port 4000 to the API pod, and the API ingress policy did not allow traffic from the `auto-sync` component. With NetworkPolicy enabled, every HTTP call from the auto-sync CronJob was silently dropped. Both policies are now updated.
- **Auto-sync credential reading fixed in the import modal.** All integration form components (`ImportGitHubForm`, `ImportGitLabForm`, `ImportAWSForm`, `ImportAzureForm`, `ImportGCPForm`, `ImportVaultForm`) now expose a `getCredentials()` method via `useImperativeHandle`. The parent `ImportTokensModal` reads live form state through these refs instead of stale parent-scope state variables that were never updated, which caused every auto-sync save to silently store an empty token.
- **Auto-sync worker pre-flight credential validation.** The worker now checks required credential fields immediately after decryption and throws a descriptive error (`token (empty)` vs `token (absent)`) before attempting any HTTP call, replacing a confusing HTTP 400 from the downstream scan endpoint.

### Changed

- **System color mode enabled by default.** The dashboard now follows the OS light/dark preference (`useSystemColorMode: true`, `initialColorMode: "system"`). Previously the dashboard was always light.
- **Modal animations disabled for `ImportTokensModal`.** Added `motionPreset="none"` to remove the open/close animation, which was causing visual jank on slower machines.
- **Backdrop blur removed from Chakra dialog containers.** Removed `backdropFilter: blur(10px)` from both light and dark dialog theme overrides to avoid a GPU compositing layer on every modal open.
- **`CreateTokenNotesField` memoized with `flushSync`.** The notes textarea in the create/duplicate token forms is now a memoized component; `flushSync` ensures uncommitted note input is flushed to state before form submission.
- **Bulk section assignment error messages surfaced.** The dashboard now shows the API-returned error string on failure instead of a generic "Failed to assign section" toast.
- Updated pnpm from **10.33.0** to **10.33.4** across `package.json`, all three Dockerfiles, and CI.
- Updated release metadata from **0.3.2** to **0.4.0** across all package and contract version files.

### Security

- Upgraded `axios` from **1.15.0** to **1.16.0** in all three packages (`api`, `dashboard`, `worker`) — fixes multiple prototype-pollution and SSRF advisories (GHSA-pmwg-cvhr-8vh7, GHSA-q8qp-cvcw-x6jj, GHSA-pf86-5x62-jrwf, GHSA-6chq-wfr3-2hj9, and others).
- Upgraded `express-rate-limit` from **8.3.1** to **8.5.1** in `api`.
- Upgraded `@aws-sdk/client-acm/iam/secrets-manager/sts` from **3.990.0** to **3.1045.0** in `api`.
- Added `fast-xml-builder@1.2.0` and upgraded `fast-xml-parser` override from **5.7.2** to **5.7.3** to resolve GHSA-5wm8-gmm8-39j9 in the AWS SDK transitive chain.
- Upgraded Grype from **v0.111.0** to **v0.112.0** in CI.
- Updated the Go builder stage in `Dockerfile.api` from `golang:1.26.2-alpine3.23` to `golang:1.26.3-alpine3.23` to resolve stdlib CVEs in the subfinder binary.

## [0.3.2] - 2026-05-04

### Changed

- **Removed embedded docs from the self-hosted dashboard.** The in-app `/docs` route and all bundled documentation pages (Intro, Teams, Tokens, Alerts, Audit, Usage, API) have been removed from the dashboard bundle. Every docs link in the dashboard — Navigation bar, mobile nav, Footer, Help page, NotFound page, WelcomeModal, ProductTour, ImportTokensModal, and all import provider forms — now opens `https://tokentimer.ch/docs/self-hosted` in a new tab. This reduces the dashboard bundle size and ensures self-hosted users always read the latest documentation.
- Updated `COMMERCIAL_TERMS.md` and `README.md` docs references to point to `https://tokentimer.ch/docs/self-hosted`.
- Updated release metadata from **0.3.1** to **0.3.2** across package and contract version files.

### Fixed

- Fixed `docker-compose.yml` healthcheck for the `api` service: the compose-level override used `curl`, which is not present in the Alpine Node image, causing the container to report `unhealthy` despite the API being fully operational. The override is removed; Docker now falls back to the `HEALTHCHECK` instruction baked into the Dockerfile, which uses `node -e` and includes a 10 s start-period grace window.

## [0.3.1] - 2026-04-30

### Fixed

- Fixed account deletion for users that already had audit events, so right-to-be-forgotten cleanup no longer fails on those audit references.

### Changed

- Refined README wording to explicitly mention public subdomain discovery, SSL certificate imports, and HTTPS endpoint checks.
- Updated release metadata from **0.3.0** to **0.3.1** across package and contract version files.
- Updated licensing metadata to use the registered company name **Tokentimer Sàrl, Switzerland**.

## [0.3.0] - 2026-04-27

### Added

- **Domain Checker.** Discover publicly known subdomains for a root domain with subfinder's default passive discovery behavior, review results in the dashboard, and import selected live SSL certificates as tokens in a single click. Domain Checker does not scan private DNS or internal network records.
- **Bulk endpoint monitor creation from Domain Checker.** When importing discovered hostnames, optionally create an endpoint monitor for each hostname in one step, with the same settings as the Add endpoint form (health check, check interval, alert after failures, contact group). Hostnames that already have a monitor are skipped automatically.
- **New audit events for Domain Checker.** Every lookup and import now emits a dedicated audit event (`DOMAIN_CHECKER_LOOKUP`, `DOMAIN_CHECKER_IMPORT`) with rich metadata (domain, counts of imported / skipped / duplicate / invalid certificates, and, when applicable, the monitor settings used). Both events are filterable in the audit log and documented in `/docs/audit`.
- **Resilient self-hosted discovery.** Domain Checker runs subfinder with process timeouts, safe argument handling, configurable result/import limits, and clear warning text when discovery is unavailable or capped.
- **Rate limiting for Domain Checker.** Certificate discovery is limited to one lookup per workspace every 60 seconds (configurable). Rate limit responses include a standard `Retry-After` header so clients can back off cleanly.
- **Domain Checker REST API.** Two new endpoints let integrations trigger discovery and import programmatically:
  - `POST /api/v1/workspaces/{id}/domain-checker/lookup`
  - `POST /api/v1/workspaces/{id}/domain-checker/import`

### Changed

- Renamed the dashboard **"Monitor Endpoint"** action to **"Endpoint & SSL monitor"** (button and modal title), since the same place now covers both single-URL endpoint (SSL) monitoring and domain-wide SSL discovery via the Domain Checker. Matching updates in `/docs/tokens` and in the `Endpoint & SSL monitoring` solutions page.
- Refined the dashboard UX for Endpoint & SSL monitoring and token management: endpoint tables now support column-header sorting, health and interval filters, full multi-line URLs, clickable token domain links, bulk section assignment, and a compact non-persisted **Last import summary** after Domain Checker imports.
- Added build scripts for the API and worker packages so the root build can syntax-check backend entry points during release verification.
- Bumped TokenTimer Core from **0.2.0** to **0.3.0**.

### Fixed

- Fixed Audit Log pagination so **Load More** appends the next page without immediately collapsing back to the first page.
- Fixed Domain Checker import refresh behavior so the discovered-results table clears after a successful import while the endpoint monitor table and import summary remain visible.
- Fixed manual endpoint health checks so clicking **Run health check now** refreshes monitor data without moving the modal scroll position.

### Security

- Build `subfinder` v2.13.0 from source in the API Docker images instead of downloading a bundled binary, and remove unnecessary runtime packages from the production image.

### Dependencies

- Updated security-related dependency pins and overrides, including `uuid` 14.0.0, `fast-xml-parser` 5.7.2, and `postcss` 8.5.12.

## [0.2.0] - 2026-04-22

### Added

- **Workspace invitation management (two new HTTP endpoints),** documented in OpenAPI and covered by integration tests:
  - **`GET /api/v1/workspaces/{id}/invitations`** lists **pending** invitations (`accepted_at IS NULL`) with pagination (`limit`, `offset`). The invite **`token`** is never returned in the JSON payload.
  - **`DELETE /api/v1/workspaces/{id}/invitations/{invitationId}`** cancels a **pending** invitation only (`accepted_at IS NULL`), emits an **`INVITATION_CANCELLED`** audit event, and increments the invite-cancelled metric. Unknown IDs or invitations that are already accepted return **404** (no row deleted, no audit for spurious cancel on accepted rows).
- **Prometheus metric** `tokentimer_invite_cancelled_total` (counter) on successful pending-invitation cancellation (`apps/api/utils/metrics.js`, wired from `apps/api/routes/workspaces.js`).

### Fixed

- **Dashboard session UX on unknown routes.** The API client only treats **401** as “session expired” with redirect to `/login` after the app has observed a logged-in session (`hasObservedLoggedInSession`), so anonymous users on non-app URLs (for example a client-side **404**) no longer see a spurious expiry toast or forced redirect.

### Changed

- Align contract and spec versions with the app version. The following files are bumped from **0.1.3** to **0.2.0** so consumers can pin on a single release:
  - `contracts.manifest.json`
  - `packages/contracts/openapi/openapi.yaml`
  - `packages/contracts/api/auth-route-compat.contract.json`
  - `packages/contracts/runtime-extensions/plugin-context.contract.json`
  - `packages/contracts/runtime-extensions/plugin-context.example.json`

### Dependencies

- **No dependency or lockfile changes** are part of this release; `pnpm-lock.yaml` and root `pnpm.overrides` are unchanged from **0.1.3**.

## [0.1.3] - 2026-04-18

### Security

- **Session invalidation on password change.** `POST /api/account/change-password` now deletes every other session for the acting user from the `connect-pg-simple` `session` table and rotates the acting session id via `req.session.regenerate` + `req.login`, so other browsers and devices are logged out immediately. Mitigates OWASP **ASVS 3.3.1** and the attacker-persistence-after-password-change scenario.
- **Session invalidation on password reset.** `POST /auth/reset-password` (token-based, unauthenticated) now deletes all sessions belonging to the reset user, so any live attacker session is revoked when the legitimate user completes a reset from an email link.
- **Session invalidation on 2FA enable.** `POST /api/account/2fa/enable` now deletes every other session for the acting user and rotates the acting session id. A concurrent session that pre-dates the 2FA enrollment no longer skips the new second factor.
- **Session invalidation on 2FA disable.** `POST /api/account/2fa/disable` (password-gated) now deletes every other session for the acting user and rotates the acting session id, so a 2FA downgrade cannot silently leave other devices authenticated.
- Revocation is transactional to the request but wrapped in a best-effort `try/catch` so a transient `session` store error cannot block the credential or 2FA update itself; the audit entry (`PASSWORD_CHANGED`, `PASSWORD_RESET_COMPLETED`, `TWO_FACTOR_ENABLED`, `TWO_FACTOR_DISABLED`) is still emitted.

### Added

- Integration suite `tests/integration/auth-session-invalidation.integration.test.js` asserting, for every covered flow: acting session survives, every other session row for the user is deleted, `Set-Cookie` is emitted (session rotation), old credentials are rejected, new credentials work, other users are unaffected, and `reset-password` wipes every session for the target account only. New describe blocks cover `POST /api/account/2fa/enable` and `POST /api/account/2fa/disable`, driving real TOTP tokens through `otplib` against the live `/api/account/2fa/setup` + `/auth/verify-2fa` endpoints.

### Changed

- Align contract and spec versions with the app version. The following files are bumped from **0.1.0** to **0.1.3** so consumers can pin on a single release:
  - `contracts.manifest.json`
  - `packages/contracts/openapi/openapi.yaml`
  - `packages/contracts/api/auth-route-compat.contract.json`
  - `packages/contracts/runtime-extensions/plugin-context.contract.json`
  - `packages/contracts/runtime-extensions/plugin-context.example.json`

## [0.1.2] - 2026-04-14

### Security

- Bump direct **axios** dependencies to **1.15.0** and add a root **pnpm** override so **follow-redirects** resolves to **1.16.0** (regenerated lockfile).
- Bump Grype in CI to [v0.111.0](https://github.com/anchore/grype/releases/tag/v0.111.0) (same pinned `install.sh` pattern as before).
- On Alpine-based production and dev Docker stages, run `apk update && apk upgrade --no-cache` so `libcrypto3`, `libssl3`, and `musl` pick up fixes from the current Alpine 3.23 package index (keeps Grype `--fail-on high --only-fixed` passing when base image layers lag mirrors).

### Changed

- Remove explicit **libpng** `apk` installs from Alpine-based Dockerfiles; rely on official **nginx** and **node** Alpine images instead of brittle version pins.

## [0.1.1] - 2026-04-08

### Security

- Patch transitive `ajv` ReDoS vulnerability by overriding `ajv@6` to `6.14.0`
- Patch transitive `lodash` code injection and prototype pollution by overriding to `4.18.1`
- Pin all GitHub Actions to immutable SHA digests across CI, release, publish, and performance workflows to prevent supply-chain attacks through tag manipulation
- Gate Grype container image scans with `--fail-on high --only-fixed` so the pipeline fails on fixable high/critical vulnerabilities
- Pin Grype to v0.110.0 and Helm to v3.20.1 in CI workflows to eliminate unpinned `curl | bash` supply-chain risk
- Pin all Docker base images to exact versions: `node:22.22.2-slim`, `node:22.22.2-alpine3.23`, `nginx:1.28.3-alpine3.23`
- Add `.grype.yaml` ignore list for 10 false positives caused by Grype's stale vulnerability database (picomatch, brace-expansion, Node 22.22.2 CVEs, zlib)
- Patch `nodemailer` SMTP command injection (GHSA-vvjj-xcjg-gr5g) by bumping to `8.0.5`

---

## [0.1.0] - 2026-04-01

First public release. Complete extraction of the self-hosted core from the
tokentimer-cloud SaaS codebase into a standalone, variant-agnostic repository.

### Added

#### Architecture

- Standalone monorepo (apps/api, apps/worker, apps/dashboard, packages/config, packages/contracts)
- Variant composition model: cloud and enterprise overlay on core without forking
- Contract catalog (contracts.manifest.json) with API surface, queue schemas, and DB baseline validation
- Shared config package with environment-driven settings for all components
- OpenAPI 3.0 specification with optional Swagger UI (/api-docs)

#### Token management

- Full token lifecycle: create, read, update, delete, bulk operations
- Rich metadata model (certificates, API keys, licenses, secrets, custom categories)
- Workspace-scoped tokens with configurable expiration thresholds
- Import from external providers (HashiCorp Vault, GitHub, GitLab, AWS, Azure, GCP, Azure AD)
- Scheduled auto-sync for continuous provider imports

#### Alert system

- Five-stage pipeline: discovery, queuing, delivery, retry, and audit
- Multi-channel delivery: email (SMTP), WhatsApp (Twilio), webhooks (Slack, Discord, Microsoft Teams, PagerDuty, generic)
- Configurable delivery windows with timezone support
- Backoff, cooldown, and retry logic with per-alert tracking
- Contact groups with channel routing and fallback chains
- Weekly digest emails for token expiration summaries

#### Endpoint monitoring

- SSL certificate and HTTP health checks on domain monitors
- Automated alerting for certificate expiry, endpoint downtime, and recovery

#### Workspaces and collaboration

- Multi-workspace support with per-workspace settings and token isolation
- RBAC roles: admin, workspace_manager, viewer
- Email-based workspace invitations with token-gated registration
- Workspace token transfer between workspaces

#### Auth and security

- Local email/password authentication with bcrypt hashing
- TOTP two-factor authentication (setup, enable, disable, verify)
- Email verification and password reset flows
- Session management with PostgreSQL-backed store
- CSRF double-submit cookie protection
- Tiered rate limiting (global, login, password reset, API)
- Webhook SSRF protection (private IP blocking, DNS validation, host allowlists)
- Helmet CSP, HSTS, CORS with strict origin allowlist
- Immutable audit log with trigger-enforced integrity

#### Admin and compliance

- Global admin system settings (SMTP, Twilio configuration via UI)
- GDPR/SOC2 data export and right-to-be-forgotten (account deletion)
- Audit event log with workspace-scoped filtering and CSV export

#### Deployment

- Helm chart on GHCR OCI registry with CloudNativePG, ingress, HPA, PDB, ServiceMonitor, PrometheusRules, and per-component network policies
- Docker Compose stacks for development, production, and testing
- Production Dockerfiles with non-root user, read-only root filesystem, and security contexts
- Prometheus metrics endpoint with counters/histograms for HTTP, auth, delivery, DB, and SMTP
- Health endpoint with database connectivity check

#### Testing and CI

- 530 integration tests covering auth, tokens, workspaces, alerts, webhooks, endpoints, integrations, and security
- Contract tests for API endpoint coverage, OpenAPI conformance, and queue schema validation
- GitHub Actions CI/CD: lint, audit, contract checks, integration tests, Docker builds, Helm chart publishing

### Security

#### Application layer

- CSRF double-submit cookie protection on all state-changing endpoints
- Tiered rate limiting: global, per-IP login, per-email login, password reset, email verification, API
- Slowdown middleware in production for brute-force mitigation
- Helmet CSP, HSTS, X-Frame-Options DENY, referrer policy, XSS filter
- CORS with strict credential-bearing origin allowlist
- Session cookies: httpOnly, secure, sameSite strict, PostgreSQL-backed store
- bcrypt password hashing with minimum complexity requirements
- TOTP two-factor authentication
- Webhook SSRF protection: private/reserved IP blocking, DNS validation, provider host allowlists
- Vault scan address allowlist (VAULT_ADDRESS_ALLOWLIST)
- JSON request body size limits (10 MB)
- Suspicious request logging (path traversal, SQL injection patterns, anomalous user agents)
- Immutable audit log enforced by database trigger

#### Infrastructure layer

- Non-root containers across all Dockerfiles (UID 1001/1000)
- Read-only root filesystem with explicit tmpfs mounts
- Pod security contexts: runAsNonRoot, seccompProfile RuntimeDefault, drop ALL capabilities
- Per-component Kubernetes network policies: default-deny baseline, scoped ingress/egress per workload
- CNPG database egress locked to cluster pods when CloudNativePG is enabled
- pnpm audit enforced at moderate severity in CI

### Not included in Core

- Google OAuth / SAML / OIDC (enterprise variant)
- Billing, plan limits, usage quotas (cloud variant)
- Marketing pages, analytics (cloud variant)

---

[0.3.1]: https://github.com/tokentimerch/tokentimer-core/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/tokentimerch/tokentimer-core/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tokentimerch/tokentimer-core/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/tokentimerch/tokentimer-core/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/tokentimerch/tokentimer-core/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/tokentimerch/tokentimer-core/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/tokentimerch/tokentimer-core/releases/tag/v0.1.0
