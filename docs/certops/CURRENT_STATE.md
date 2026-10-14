# CertOps current state

Short index for operators and engineers.

## Current system behavior

- Domain language and product invariants: [CONTEXT.md](CONTEXT.md).
- Dashboard: Certificate operations tabs are Jobs, Certificates, Renewals, Agents, and Settings. AD CS issuers, preflight, pinning, enrollment status, and AD CS renewal profiles live under **Renewals**.
- Microsoft AD CS operator guide (states, allowlists, troubleshooting): [agent/adcs.md](agent/adcs.md).
- Agent task index: [agent.md](agent.md).

## Accepted architecture

- AD CS issuer model, async enrollment, pin and allowlist rules: [ADR-0014](../adr/0014-certops-adcs-issuer-and-async-enrollment.md).
- Broader CertOps ADRs: [docs/adr/README.md](../adr/README.md).

## Enrollment prerequisites

These are runtime requirements for an AD CS renewal, not a separate product mode:

- Local enrollment rule names the exact CA config and template.
- Confirmed CA public-key pin and a fresh safe preflight on the enrolling agent (24-hour freshness).
- Attached renewal profile with automation on, inside the lead time.
- Online Windows agent that declares the certificate DNS name and a fresh `adcs-enroll-v1`.
- Creating an issuer or profile alone does not issue a certificate.

## Historical records

Internal planning records that are not part of this public repository may hold older acceptance evidence. Public truth for readers of this repo is this file, [CONTEXT.md](CONTEXT.md), [agent/adcs.md](agent/adcs.md), and the ADRs.
