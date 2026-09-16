# TokenTimer Core -- Roadmap

Last reviewed: 2026-09-16 against main `7c7b2197` (post-0.15.0 tip).

This page is the repository milestone index: what Core takes next, what must
land before v1.0.0 so that release is a stable product, and what v1.0.0
itself changes for compatibility. Customer-facing feature cards and voting
live on the [public feature roadmap](https://tokentimer.featurebase.app/en/roadmap).
Release history lives in [CHANGELOG.md](CHANGELOG.md). Owners, acceptance
criteria, and evidence live in the linked GitHub issues.

**Now** is the next release-candidate scope. **Before v1.0.0** is 0.x work
asked by pilot operators; it is a prerequisite for calling v1.0.0 stable,
not a substitute for the RBAC contract below. **v1.0.0** is the
compatibility-stable major: explicit ownership plus compatible upgrades.
Review this page in each release PR; move shipped outcomes into the
changelog.

CertOps keeps zero control-plane private-key custody (CI-enforced) and does
not change the role model. Inventory, executor reporting, the Kubernetes
controller, agent renewal, signed dispatch, Windows/IIS execution, and
trust-anchor reconciliation have shipped; see [CHANGELOG.md](CHANGELOG.md)
and `docs/adr/`. Remaining Core CertOps work is listed under Before v1.0.0.
Airgap operator packages, proxy-agents, appliance connectors, and
compliance reporting are not deliverables of this repository.

---

## Now -- next release candidate

- **Make existing CI quality gates dependable**
  ([#227](https://github.com/tokentimerch/tokentimer-core/issues/227)).
  No contributor PR-triggered Actions. Tighten the existing
  push/dispatch pipeline. Post-merge CI is not a pre-merge gate;
  document how maintainers verify before merge, and require successful
  CI on the release commit before publishing.

---

## Before v1.0.0 -- operator-stable product

These are the remaining pilot asks. They ship in 0.x. v1.0.0 is not
called stable while they are open.

- **Multiple auto-sync configurations per provider in a workspace**
  ([#71](https://github.com/tokentimerch/tokentimer-core/issues/71)).
  Two GitLab instances (or two Vaults) in one workspace, without a
  major-version requirement unless an API break is identified. Existing
  single-config workspaces must keep working. One configuration's
  failure or cleanup must not affect another's assets.
- **Optional notification for already-expired imports**
  ([#231](https://github.com/tokentimerch/tokentimer-core/issues/231)).
  Quiet historical imports remain the default.
- **CertOps CSR import and signed-certificate import**
  ([#245](https://github.com/tokentimerch/tokentimer-core/issues/245)).
  Public CSR/PEM and metadata only. Private-key packages stay rejected.
- **CertOps destinations: store issued material and distribute it**
  ([#248](https://github.com/tokentimerch/tokentimer-core/issues/248)).
  Name filesystem, IIS, or customer Vault locations on a certificate.
  One issuance can deploy to those destinations. The control plane
  never stores private keys. Shared-key Vault mode is explicit opt-in.
- **Shared outbound policy**
  ([#233](https://github.com/tokentimerch/tokentimer-core/issues/233)).
  Wire offline mode and outbound allowlists into API and worker egress.
  Independent of the already-shipped integration redirect and pagination
  checks. Issuer CA/ACME/DNS egress in #246 must reuse this policy.
- **CertOps issuer connectors and revocation jobs**
  ([#246](https://github.com/tokentimerch/tokentimer-core/issues/246)).
  Core ACME, step-ca, and webhook issuers. CA-backed revoke,
  replace-compromised, decommission, and verify-revocation. Encrypted
  issuer credentials fail closed if the key is missing.
- **Operational diagnostics**
  ([#232](https://github.com/tokentimerch/tokentimer-core/issues/232)).
  Correlation identifiers across API and workers; production error
  reporting with secret scrubbing.

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
  Helm post-install smoke
  ([#234](https://github.com/tokentimerch/tokentimer-core/issues/234))
  is part of this proof, not a separate product feature.

---

## Later -- evaluate against a concrete need

Performance tests with regression budgets
([#235](https://github.com/tokentimerch/tokentimer-core/issues/235));
SAST and verified SARIF ingestion
([#236](https://github.com/tokentimerch/tokentimer-core/issues/236));
release image signing and verification instructions
([#237](https://github.com/tokentimerch/tokentimer-core/issues/237));
targeted dashboard and test maintainability
([#238](https://github.com/tokentimerch/tokentimer-core/issues/238)).
TanStack Query v5; incremental type checking on changed security-critical
services and the shared config package; internationalization; an API v2
compatibility policy before any v2 paths. CertOps follow-ons such as CT
log discovery and orphaned-certificate detection need a scoped issue and
a concrete operator need before they are scheduled.
