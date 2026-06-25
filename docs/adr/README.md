# Architecture Decision Records

One ADR per significant, hard-to-reverse decision. Numbering is `000N-kebab-slug.md`.
Sections: Status, Context, Decision, Alternatives considered, Consequences.

Status values: Proposed, Accepted, Superseded, Deprecated. Date each status change.

## Index

### CertOps (Phase 0 skeletons, to be finalized in M0)

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-certops-zero-custody-enforcement.md) | CertOps zero private-key custody enforcement | Proposed |
| [0002](0002-certops-agent-protocol.md) | CertOps agent protocol and agent-local policy | Proposed |
| [0003](0003-certops-job-signing-and-replay-protection.md) | CertOps job signing and replay protection | Proposed |
| [0004](0004-certops-certmanager-secret-handling.md) | CertOps Kubernetes cert-manager Secret handling | Proposed |
| [0005](0005-certops-threat-model.md) | CertOps threat model | Proposed |

These skeletons freeze direction so M1/M2 can proceed in parallel. Each carries
TODO markers for the content that is finalized during M0.
