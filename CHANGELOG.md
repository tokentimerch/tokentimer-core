# Changelog

All notable changes to TokenTimer Core are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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
