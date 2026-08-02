# Architecture Decision Records

One ADR per significant, hard-to-reverse decision. Numbering is `000N-kebab-slug.md`.
Sections: Status, Context, Decision, Alternatives considered, Consequences.

Status values: Proposed, Accepted, Superseded, Deprecated. Date each status change.

## CertOps decision status

CertOps is maintained as a living architecture baseline until GA. The baseline is
stable enough for parallel Core, Cloud, Enterprise, and Agent implementation, but
it is not immutable. Domain vocabulary for the program lives in
[`docs/certops/CONTEXT.md`](../certops/CONTEXT.md) (purgeable when CertOps
graduates).

We distinguish:

- **Hard invariants**: security and custody rules that require a major architecture
  review to change (zero private-key custody, control plane vs execution plane,
  agent-local policy wins, outbound-only agent model).
- **Accepted decisions**: current implementation direction, amendable through ADRs
  before GA (tracked design decisions pending before GA).
- **Flexible implementation details**: phase-level details that may change in PRs
  as long as they do not violate hard invariants or published contracts (UI copy,
  exact column names, PR pairing, quota numbers, agent packaging location).

**Contract surfaces are stricter than planning text.** Once an API route, protocol
schema, migration, or route-compat contract is consumed by another repo or
release, changes require an ADR or explicit compatibility note. Examples of
change-controlled artifacts:

- Route namespace shape once downstream depends on it.
- Protocol envelope fields once agents, cloud, or enterprise implement them.
- Zero-custody rejection codes (`PRIVATE_KEY_MATERIAL_REJECTED`).
- Contract schemas after a version bump.
- Migration shape after release.

Architecture decisions are accepted but amendable before GA through ADRs.

## Index

### CertOps

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-certops-zero-custody-enforcement.md) | CertOps zero private-key custody enforcement | Proposed |
| [0002](0002-certops-agent-protocol.md) | CertOps agent protocol and agent-local policy | Proposed |
| [0003](0003-certops-job-signing-and-replay-protection.md) | CertOps job signing and replay protection | Proposed |
| [0004](0004-certops-certmanager-secret-handling.md) | CertOps Kubernetes cert-manager Secret handling | Proposed |
| [0005](0005-certops-threat-model.md) | CertOps threat model | Proposed |
| [0006](0006-certops-dashboard-ux-split.md) | CertOps dashboard UX split | Accepted |
| [0007](0007-certops-certificate-removal-lifecycle.md) | CertOps certificate removal and lifecycle model | Accepted |
| [0008](0008-certops-upfront-issuance.md) | CertOps upfront issuance and provisioning lifecycle | Accepted, amended 2026-07-26 |
| [0009](0009-certops-durable-side-effects-and-alert-policy.md) | CertOps durable side effects and renewal alert policy | Accepted |
| [0010](0010-certops-derived-renewal-profiles.md) | CertOps renewal profiles are derived at issuance | Accepted, amended 2026-07-26 |
| [0011](0011-certops-machine-initiated-audit-events.md) | CertOps machine-initiated lifecycle events are audited | Accepted |
| [0012](0012-certops-windows-execution-surface-and-trust-anchors.md) | Windows execution surface, trust-anchor operations, and CNG-vs-PFX custody | Proposed |

ADR-0001 through ADR-0005 were authored as early skeletons to unblock
parallel inventory and executor work. They remain `Proposed` until ratification moves them to
`Accepted` and their TODO markers are resolved. ADR-0006 and ADR-0007 record the
dashboard UX split and the removal/lifecycle model and are `Accepted` as of
2026-06-28. ADR-0008 records upfront issuance and is `Accepted` as of 2026-07-26;
it extends the ADR-0007
lifecycle model with a `provisioning` pre-active status and establishes the
control-plane `operation` versus agent-facing `action` distinction relative to
ADR-0002.

ADR-0009 and ADR-0010 record what live testing of `issue` changed, and both
amend ADR-0008 rather than superseding it: the upfront-issuance decision stands,
four of its decision points do not. ADR-0008 carries the amendment inline
(Amendment 1) with pointers to these two records. ADR-0009 replaces point 8 and
owns durable side effects and the alerting rule. ADR-0010 revises point 4 and
owns renewal profile derivation. Neither record rewrites the original decision
text; where amendment and original disagree, the amendment is authoritative and
says so.

ADR-0010 carries its own Amendment 1, added the same day, for the same reason the
others exist: derivation made automatic renewal live, which turned "what may an
operator change about a renewal" from a theoretical question into a shipping one.
It owns the profile-level off switch, the immutability boundary on deployment
details, and why there is no create route.

ADR-0011 closes the third consequence of the same change. Derivation turned
promotion, scheduled renewal, and profile creation into live unattended paths, and
none of them were audited: a certificate TokenTimer issued and now renews by
itself had a one-row trail. ADR-0011 owns which machine-initiated events are
written, that they commit with the state change they describe, and why job
successes and replays deliberately produce nothing.

ADR-0012 decides the trust-job schema shape, CNG-native-vs-PFX key custody on
Windows, and the Windows agent privilege model, three questions that blocked
the Windows execution-surface and trust-anchor work from starting
implementation.

Changing a published contract or an accepted invariant is a new or updated ADR,
not a silent code edit.
