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
  before GA (D1-D4, D6, D7 in `tokentimer-canvas/plans/TOKENTIMER_CERTOPS_PLAN.md`).
- **Flexible implementation details**: milestone-level details that may change in PRs
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
| [0006](0006-certops-dashboard-ux-split.md) | CertOps dashboard UX split (D6) | Accepted |
| [0007](0007-certops-certificate-removal-lifecycle.md) | CertOps certificate removal and lifecycle model (D7) | Accepted |

ADR-0001 through ADR-0005 were authored as Phase 0 skeletons to unblock M1/M2
parallel work. They remain `Proposed` until M0 ratification moves them to
`Accepted` and their TODO markers are resolved. ADR-0006 and ADR-0007 record
plan decisions D6 and D7 and are `Accepted` as of 2026-06-28.

Changing a published contract or an accepted invariant is a new or updated ADR,
not a silent code edit.
