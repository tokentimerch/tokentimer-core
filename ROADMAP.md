# TokenTimer Core -- Roadmap

Last reviewed: 2026-11-06 against main 2f508142 (v0.19.1) and PR #498’s scope. Other
certificate testing expansion remains follow-up work under [#354](https://github.com/tokentimerch/tokentimer-core/issues/354).

This page is the repository milestone index: what Core takes next, what must
land before v1.0.0 so that release is a stable product, what ships in 0.x
without gating v1.0.0, and what v1.0.0 itself changes for compatibility. Public feature cards and voting
live on the [public feature roadmap](https://tokentimer.featurebase.app/en/roadmap).
Release history lives in [CHANGELOG.md](CHANGELOG.md). Owners, acceptance
criteria, and evidence live in the linked GitHub issues.

**Before v1.0.0** is 0.x work asked by pilot operators; it is a prerequisite
for calling v1.0.0 stable, not a substitute for the RBAC contract below.
**v1.0.0** is the compatibility-stable major: explicit ownership plus
compatible upgrades.
Review this page in each release PR; move shipped outcomes into the
changelog.

Certificate Lifecycle Management (CLM) keeps zero control-plane private-key custody (CI-enforced) and does
not change the role model. Inventory, executor reporting, the Kubernetes
controller, agent renewal, signed dispatch, Windows/IIS execution, and
trust-anchor reconciliation have shipped. CLM 0.17.0 groups
certificates by fingerprint and separates lifecycle, management periods and
observed locations; see [CHANGELOG.md](CHANGELOG.md)
and `docs/adr/`. Remaining Core CLM release gates are listed under Before
v1.0.0; additional capabilities below follow their own schedules.
Airgap operator packages, proxy-agents, appliance connectors, and
compliance reporting are not deliverables of this repository.

---

## Before v1.0.0 -- operator-stable product

These are the remaining pilot asks. They ship in 0.x. v1.0.0 is not
called stable while they are open.

- **CLM destinations: store issued material and distribute it**
  ([#248](https://github.com/tokentimerch/tokentimer-core/issues/248)).
  Name filesystem, IIS, or Vault locations on a certificate.
  One issuance can deploy to those destinations. The control plane
  never stores private keys. Shared-key Vault mode is explicit opt-in.
  [PR #329](https://github.com/tokentimerch/tokentimer-core/pull/329) adds
  publication through your Vault and independent consumer rollouts for any shared
  certificate, including ordinary and wildcard certificates, shipped in 0.18.0
  (see [CHANGELOG.md](CHANGELOG.md)); the remaining destination scope stays
  open on the issue.
  [PR #460](https://github.com/tokentimerch/tokentimer-core/pull/460) is merged:
  explicit OpenBao KV v2, Azure Key Vault Secrets exact versions and Windows/IIS
  shared-material execution exist. [PR #498](https://github.com/tokentimerch/tokentimer-core/pull/498)
  integrates that code with consumer management, exact-version independent
  approvals, reviewed automation, canary waves, maintenance calendars, supported
  activation, recurring verification/drift incidents, durable recovery/PagerDuty,
  preflight and retention management. These #498 increments are implemented,
  unreleased work, not missing future connectors. See the
  [completion and evidence matrix](docs/certops/pr498-merge-readiness-20261103.md).
  OpenBao distribution is supported. Azure storage, shared Windows/IIS material
  deployment, independent Linux preparation/staging and exact-version Vault/OpenBao
  cleanup exist but remain absent from the production qualification manifest.
  Their exact artifact/native evidence must pass the existing protected gates
  before promotion. The [2026-11-03 qualification record](docs/certops/pr498-production-qualification-20261103.md)
  records two complete packaged baseline journeys and each remaining native or
  authorization dependency; no extension capability was promoted.
  Retention preview remains report-only by default; publication,
  staging and approval are not proof of installation or live service use.
  Broader Windows connectors and unsupported activation methods remain later
  work under #504/#366/#369/#376; they are not new merge requirements for #498.
- **Shared outbound policy**
  ([#233](https://github.com/tokentimerch/tokentimer-core/issues/233)).
  Wire offline mode and outbound allowlists into API and worker egress.
  Independent of the already-shipped integration redirect and pagination
  checks. Issuer CA/ACME/DNS egress in #246 must reuse this policy.
- **CLM issuer connectors and revocation jobs**
  ([#246](https://github.com/tokentimerch/tokentimer-core/issues/246)).
  Core ACME, step-ca, and webhook issuers. CA-backed revoke,
  replace-compromised, decommission, and verify-revocation. Encrypted
  issuer credentials fail closed if the key is missing.
- **Operational diagnostics**
  ([#232](https://github.com/tokentimerch/tokentimer-core/issues/232)).
  Correlation identifiers across API and workers; production error
  reporting with secret scrubbing.
  API request logs now share a generated `correlationId`, returned as
  `X-Request-Id`, which dashboard API errors display as a request reference.
  Worker propagation and production error-boundary reporting remain open.

---

## Alongside 0.x -- does not gate v1.0.0

Accepted work that ships in 0.x stages on its own schedule. v1.0.0 can be
called stable while it is open.

- **MCP operator interface**
  ([#502](https://github.com/tokentimerch/tokentimer-core/issues/502),
  implementation [PR #406](https://github.com/tokentimerch/tokentimer-core/pull/406)).
  Scoped inventory queries and updates, contact and invitation actions,
  remote sign-in, and ACME issuance and renewal requests ship in 0.19.0.
  Deletes and provider-side actions remain follow-on work.

---

## v1.0.0 -- RBAC and role model cleanup

Target release for breaking or structural authorization changes
deferred from 0.x, after the Before v1.0.0 product work above. See
[docs/AUTHENTICATION.md](docs/AUTHENTICATION.md) (system admin vs
workspace owner). Completion is a safe, explicit ownership contract plus
compatible upgrades. It is not a coverage percentage, a TypeScript
rewrite, or internationalization.

Per-user personal default already exists. v1.0.0 adds a separate
**installation-default** marker. Do not conflate the two.

- **Multiple workspace owners** with a transactional final-owner
  invariant
  ([#239](https://github.com/tokentimerch/tokentimer-core/issues/239)).
- **Explicit installation-default workspace marker**
  ([#240](https://github.com/tokentimerch/tokentimer-core/issues/240)).
- **Remove implicit creator-based authorization** after memberships are
  backfilled
  ([#241](https://github.com/tokentimerch/tokentimer-core/issues/241)).
- **Align alert, usage, audit, transfer, and digest attribution**
  ([#242](https://github.com/tokentimerch/tokentimer-core/issues/242)).
- **Publish a permission matrix** and update OpenAPI, UI terminology,
  and auth docs together
  ([#243](https://github.com/tokentimerch/tokentimer-core/issues/243)).
- **Prove fresh install and supported 0.x upgrades**, including recovery
  limits and overlay consumers
  ([#244](https://github.com/tokentimerch/tokentimer-core/issues/244)).

---

## Later -- evaluate against a concrete need

These themes make queued requests and follow-ons discoverable. Inclusion
does not promise a version or add a v1.0.0 gate.

- **Incident response and escalation**
  ([#503](https://github.com/tokentimerch/tokentimer-core/issues/503)):
  owner/backup thresholds, acknowledgement, delivery fallback and external
  incident lifecycle are distinct outcomes.
  PagerDuty expiration incidents ([PR #496](https://github.com/tokentimerch/tokentimer-core/pull/496))
  with resolution after verified renewal or confirmed certificate retirement
  and audited manager ACK/Resolve actions, alongside distribution incidents ([PR #498](https://github.com/tokentimerch/tokentimer-core/pull/498))
  are active increments, not completion of the entire umbrella.
- **Windows service certificates beyond IIS**
  ([#504](https://github.com/tokentimerch/tokentimer-core/issues/504)):
  service discovery, typed connectors, controlled activation and fleet
  operations build on shipped Windows/IIS and AD CS support.
  #498 provides stable consumer discovery/contract groundwork and supported
  lifecycle controls; merged #460 covers Windows/IIS shared material under #248,
  with its production capability still gated. SQL Server (#374), Exchange (#371),
  RDP/WinRM (#368), RDS (#367), NPS (#372), LDAPS (#375) and AD FS/WAP (#373)
  remain backlog. Windows independent staging and unsupported restart/refresh
  stay under #376/#366; no additional executor is required to merge #498.
- **Workspace readiness and actionable recovery**
  ([#505](https://github.com/tokentimerch/tokentimer-core/issues/505)):
  persistent readiness, safe diagnostics, verified recipes and contributor
  setup extend completed wizards; coordinate error reporting with #232.
- **Discovery and provider expansion**
  ([#506](https://github.com/tokentimerch/tokentimer-core/issues/506)):
  Bitbucket, registrar discovery and additional secret inventories need
  explicit provider and edition scope.
- **Telegram notifications**
  ([#507](https://github.com/tokentimerch/tokentimer-core/issues/507)):
  reuse recipient routing and delivery controls with documented transport.
- **API-triggered token renewal**
  ([#508](https://github.com/tokentimerch/tokentimer-core/issues/508)) and
  [CI/CD templates](https://github.com/tokentimerch/tokentimer-core/issues/308):
  provider credential rotation is separate from auto-sync inventory refresh
  and certificate renewal.
- **Certificate operator controls and recovery**:
  [native alerts #360](https://github.com/tokentimerch/tokentimer-core/issues/360),
  [cancellation #344](https://github.com/tokentimerch/tokentimer-core/issues/344),
  [manual evidence #341](https://github.com/tokentimerch/tokentimer-core/issues/341)
  and [restore decommissioned identities #410](https://github.com/tokentimerch/tokentimer-core/issues/410).
  Scope each against the released lifecycle before implementation.
- **Release provenance**
  ([#300](https://github.com/tokentimerch/tokentimer-core/issues/300)).

Performance tests with regression budgets
([#235](https://github.com/tokentimerch/tokentimer-core/issues/235));
targeted dashboard and test maintainability
([#238](https://github.com/tokentimerch/tokentimer-core/issues/238)).
TanStack Query v5; incremental type checking on changed security-critical
services and the shared config package; internationalization; an API v2
compatibility policy before any v2 paths. CLM follow-ons such as CT
log discovery and orphaned-certificate detection need a scoped issue and
a concrete operator need before they are scheduled.
