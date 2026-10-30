# Maintainer documentation

Repository maintenance workflows and their metadata live here, separate
from end-user installation, configuration and operations documentation.

- [Roadmap maintenance](roadmap.md) and [outcome index](roadmap-outcomes.json):
  scope, status and release reconciliation.
- Engineering references: [auto-sync internals](AUTO_SYNC_INTERNALS.md),
  [distribution UI implementation](certops/unified-distribution-ui.md) and
  [UX review](certops/distribution-ux-review.md), [CLM domain context](certops/CONTEXT.md)
  and [agent protocol](certops/agent/protocol.md).
- Qualification: [AD CS](certops/qualification/adcs/README.md) and
  [certificate distribution](certops/qualification/distribution/README.md),
  [suite catalog](certops/qualification-suites.json) and
  [generated skip inventory](certops/skip-inventory.generated.md).
- Release records: [preparation](release/0.18.0-release-preparation.md),
  [change ledger](release/0.18.0-core-change-ledger.md),
  [remediation](release/0.18.0-remediation.md) and
  [evidence](release/evidence/0.18.0/README.md).
- [Product media capture and verification](MEDIA.md).

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for contribution and pre-merge
guidance, [DEVELOPMENT.md](../../DEVELOPMENT.md) for local development, and
`docs/` for operator guides. Architecture decisions retain their established
`docs/adr/` location.
