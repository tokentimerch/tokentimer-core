# Changelog

All notable changes to TokenTimer Core are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.1] - 2026-04-04

### Security

- Patch transitive `ajv` ReDoS vulnerability by overriding `ajv@6` to `6.14.0`
- Patch transitive `lodash` code injection and prototype pollution by overriding to `4.18.1`
- Pin all GitHub Actions to immutable SHA digests across CI, release, publish, and performance workflows to prevent supply-chain attacks through tag manipulation
- Gate Grype container image scans with `--fail-on high --only-fixed` so the pipeline fails on fixable high/critical vulnerabilities

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

[0.1.1]: https://github.com/tokentimerch/tokentimer-core/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/tokentimerch/tokentimer-core/releases/tag/v0.1.0
