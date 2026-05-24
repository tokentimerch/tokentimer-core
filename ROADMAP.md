# TokenTimer Core -- Codebase Roadmap

Engineering health and quality targets, tracked alongside the
[feature roadmap](https://tokentimer.featurebase.app/en/roadmap).
These items are worked on in parallel with feature development and may
ship in any release -- version numbers below are targets, not hard gates.

Last updated: 2026-05-23

---

## v0.1.0 (March 2026) -- Foundation release

### Architecture

- [x] Full extraction from tokentimer-cloud into standalone, agnostic core
- [x] Variant composition model (core -> cloud / enterprise overlay via staging)
- [x] Contract catalog and integrity checks (contracts.manifest.json, packages/contracts)
- [x] Shared config package (packages/config) for cross-component settings
- [x] OpenAPI 3.0 specification with Swagger UI

### Deployment

- [x] Helm chart published to GHCR OCI registry (minimal, full-test, external-db examples)
- [x] Docker Compose stacks for development, production, and testing
- [x] CloudNativePG integration with auto-generated credentials and backup support
- [x] Per-component network policies, ServiceMonitor, and PrometheusRules
- [x] Production-hardened Dockerfiles (non-root, read-only root filesystem)

### Core features

- [x] Token lifecycle with multi-provider imports (Vault, GitHub, GitLab, AWS, Azure, GCP, Azure AD)
- [x] Five-stage alert pipeline with multi-channel delivery (email, WhatsApp, Slack, Discord, Teams, PagerDuty, generic webhooks)
- [x] Endpoint SSL/HTTP monitoring with automated alerting
- [x] Multi-workspace RBAC (admin, workspace_manager, viewer) with invitation system
- [x] Local auth with TOTP 2FA, email verification, and password reset
- [x] Admin system settings UI for SMTP and Twilio configuration
- [x] Audit log with GDPR data export and right-to-be-forgotten

### Testing and CI

- [x] 530 integration tests passing (100% on Docker Compose and on live k8s)
- [x] Contract tests for API surface, OpenAPI conformance, and schema validation
- [x] GitHub Actions pipeline: lint, audit, test, build, publish (Docker + Helm)

---

## Near-term

### Testing

- [ ] Frontend line coverage from 10% to 25% (apiClient.js, Workspaces.jsx, Account.jsx)
- [x] Unit tests for `emailService.js` (`tests/integration/email-service.unit.test.js`)
- [x] Contract / unit coverage for `planLimits.js` (`tests/contract/limits-policy.test.js`, `core-services.unit.test.js`)
- [ ] Unit tests for `rbac.js`
- [ ] Unit tests for worker shared logic (`thresholds.js`, `contactGroups.js`)
- [ ] Helm test hook for post-install smoke test (GET /health)
- [ ] Make frontend coverage job fail CI (currently continue-on-error: true)
- [ ] Relocate `*.unit.test.js` files from `tests/integration/` into `tests/unit/` (in progress: 2 files moved; 18 `*.unit.test.js` still under `tests/integration/`)

### CI / supply chain

- [x] Restore container image scanning with Grype (Trivy remains disabled; CI pins Grype v0.112.0, `--fail-on high --only-fixed`, `.grype.yaml` ignore list)
- [ ] Upload SARIF results to GitHub Code Scanning when GHAS is available (Grype emits SARIF and CI uploads scan artifacts today; Security tab upload still commented pending GHAS)

### Observability

- [ ] Request correlation ID middleware (x-request-id in Winston logs)

### Backend

- [ ] Wire offline mode / outbound allowlist into API and workers (scaffolded in packages/config but not consumed)
- [ ] Consolidate webhook allowlist logic (constants.js inline vs packages/config/network.js)

### Frontend

- [ ] Replace swallowed catch blocks with toast errors or logging (30+ instances)

### Documentation

- [x] CONTRIBUTING.md with contributor workflow and local dev setup

---

## Mid-term

### Infrastructure

- [ ] Split squashed migrations into numbered files (001_initial.sql, 002_alert_queue.sql, ...)
- [ ] Enable CodeQL / SAST scanning in CI
- [ ] Expand Artillery performance tests (more endpoints, scheduled runs, regression budgets)

### Code quality

- [ ] Migrate react-query to @tanstack/react-query v5
- [ ] Standardize ESLint to flat config across all packages
- [ ] Add Prettier config for API and Worker code (dashboard-only today)
- [ ] Separate co-located unit tests from tests/integration/ into tests/unit/ (in progress; see Near-term Testing)
- [ ] Progressively enable jsx-a11y rules (currently disabled in dashboard eslint config)

---

## Long-term

### Type safety

- [ ] Gradual TypeScript: @ts-check on critical API services (rbac, planLimits, emailService)
- [ ] Convert packages/config to TypeScript

### Supply chain / security

- [ ] Container image signing (Cosign) in release workflow
- [ ] OpenAPI versioning policy for v2 API paths

### Frontend

- [ ] Structured frontend logging with error boundary context
- [ ] Internationalization (i18n) support (currently hardcoded to en-US)

---

## v1.0.0 -- RBAC and role model cleanup

Target release for breaking or structural RBAC changes deferred from the 0.6.x
shared Default workspace work. See also `docs/AUTHENTICATION.md` (system admin vs
workspace owner).

### Workspace roles

- [ ] **Multiple workspace owners** -- allow more than one `admin` membership per
  workspace (promote/demote co-owners from **Workspaces → Members**, demote or
  transfer ownership safely, sole-owner guards on account deletion). Today only
  the workspace creator gets `admin`; the API rejects invites and role changes
  to `admin`.
- [ ] `is_installation_default` column on workspaces (explicit Default workspace
  marker instead of name matching).
- [ ] Remove `created_by` implicit-owner fallbacks in `rbac.js` once co-owner
  management exists.

### Attribution and APIs

- [ ] Alert, usage, audit, transfer-tokens, and weekly-digest attribution aligned
  with the cleaned role model (system admin vs workspace owner vs manager).
- [ ] OpenAPI role model cleanup (`admin` vs system admin naming, documented
  grants).

---

## Metrics

| Metric | Current | Near-term target | Long-term target |
|---|---|---|---|
| Backend line coverage | ~50% | 55% | 65% |
| Frontend line coverage | 10.9% | 25% | 40% |
| API unit test files | 20 (`tests/unit/` + `tests/integration/*.unit.test.js`) | 5+ (done) | 10+ |
| Swallowed catches (frontend) | 30+ | 10 | 0 |
| Integration tests (Docker + k8s) | 530/530 | 530/530 | 530/530 |
| Helm chart examples validated | 3/3 | 3/3 | 3/3 |
| jsx-a11y rules enabled | 0 | 5+ | all |
