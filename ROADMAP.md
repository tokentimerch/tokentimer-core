# TokenTimer Core -- Roadmap

Last reviewed: 2026-10-28 against main 9b65f3c6 (v0.18.2). Other
certificate testing expansion remains follow-up work under [#354](https://github.com/tokentimerch/tokentimer-core/issues/354).

This page is the repository milestone index: what Core takes next, what must
land before v1.0.0 so that release is a stable product, what ships in 0.x
without gating v1.0.0, and what v1.0.0 itself changes for compatibility. Customer-facing feature cards and voting
live on the [public feature roadmap](https://tokentimer.featurebase.app/en/roadmap).
Release history lives in [CHANGELOG.md](CHANGELOG.md). Owners, acceptance
criteria, and evidence live in the linked GitHub issues.

**Before v1.0.0** is 0.x work asked by pilot operators; it is a prerequisite
for calling v1.0.0 stable, not a substitute for the RBAC contract below.
**v1.0.0** is the compatibility-stable major: explicit ownership plus
compatible upgrades.
Review this page in each release PR; move shipped outcomes into the
changelog.
The [maintenance process](docs/ROADMAP_PROCESS.md) defines scope, edition and
status reconciliation. The [outcome index](docs/roadmap/outcomes.json) powers
a read-only drift check; issue acceptance criteria remain authoritative.

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
  Name filesystem, IIS, or customer Vault locations on a certificate.
  One issuance can deploy to those destinations. The control plane
  never stores private keys. Shared-key Vault mode is explicit opt-in.
  [PR #329](https://github.com/tokentimerch/tokentimer-core/pull/329) adds
  customer Vault publication and independent consumer rollouts for any shared
  certificate, including ordinary and wildcard certificates, shipped in 0.18.0
  (see [CHANGELOG.md](CHANGELOG.md)); the remaining destination scope stays
  open on the issue.
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
  `X-Request-Id`. Worker propagation and frontend reporting remain open.

---

## Alongside 0.x -- does not gate v1.0.0

Accepted work that ships in 0.x stages on its own schedule. v1.0.0 can be
called stable while it is open.

- **MCP operator interface**
  ([#502](https://github.com/tokentimerch/tokentimer-core/issues/502),
  implementation [PR #406](https://github.com/tokentimerch/tokentimer-core/pull/406)).
  Workspace-scoped queries, secure enrollment and approval-gated renewal
  requests are in development, not released. General token CRUD and
  text-to-token extraction are later follow-ons. Cloud and Enterprise
  adoption is separate.

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
- **Windows service certificates beyond IIS**
  ([#504](https://github.com/tokentimerch/tokentimer-core/issues/504)):
  service discovery, typed connectors, controlled activation and fleet
  operations build on shipped Windows/IIS and AD CS support.
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
- **Release confidence and qualification**:
  [remaining host coverage #354](https://github.com/tokentimerch/tokentimer-core/issues/354)
  and [release provenance #300](https://github.com/tokentimerch/tokentimer-core/issues/300).
  Keep published AD CS baseline support separate from testing expansion.

Performance tests with regression budgets
([#235](https://github.com/tokentimerch/tokentimer-core/issues/235));
targeted dashboard and test maintainability
([#238](https://github.com/tokentimerch/tokentimer-core/issues/238)).
TanStack Query v5; incremental type checking on changed security-critical
services and the shared config package; internationalization; an API v2
compatibility policy before any v2 paths. CLM follow-ons such as CT
log discovery and orphaned-certificate detection need a scoped issue and
a concrete operator need before they are scheduled.
