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

Two things are frozen at different strengths, on purpose:

- The **contract surface** (route namespaces, auth model, JSON schemas, OpenAPI
  skeletons) is frozen now (`status: frozen-skeleton`) so cloud, enterprise, the
  executor, and the agent build against a stable shape without route churn.
- The **ADR decisions** stay `Proposed` until **M0 ratification**, when they move
  to `Accepted` and their TODOs are resolved. From M0 onward, changing a frozen
  decision is a new/updated ADR, not a silent code edit.

In short: Phase 0 is a pre-M0 scaffold that freezes the wire/contract shape while
the rationale is still being ratified.
