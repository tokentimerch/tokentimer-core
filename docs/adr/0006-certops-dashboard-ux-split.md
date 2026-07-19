# ADR-0006: CertOps dashboard UX split

## Status

Accepted (2026-06-28). Plan decision D6 (v1.3).

## Context

Certificates are already first-class assets in the TokenTimer dashboard. The
`tokens` table carries the `cert` category (`ssl_cert`, `tls_cert`,
`code_signing`, `client_cert`) with issuer, serial, subject, domains, and
validity columns. The Tokens list, Control Center, and token detail modal
already render them.

CertOps M1 adds managed-certificate metadata (key locality, registration
source, deployment/instance history, extended x509 fields) without changing
where operators look for certificate inventory. Shipping a parallel CertOps
inventory page would duplicate the same certificates and confuse operators about
which surface is authoritative.

The CertOps program also introduces genuinely new operational surfaces (agents,
jobs, evidence, approvals) that do not map onto existing token views. Those
belong in a dedicated CertOps section, introduced when there is orchestration
work to do (M2+ jobs/evidence, M4+ agents).

## Decision

1. **No standalone M1 CertOps inventory page or nav entry.** Certificate
   visibility is delivered by enriching existing dashboard surfaces:
   - Tokens list: key-locality badge, managed status, retired filtering.
   - Control Center: CertOps summary widgets when applicable.
   - Token detail: CertOps enrichment panel (managed fields, deployments).
2. **Public PEM import uses the existing Import tokens flow**, not a CertOps-only
   route or modal. The import card appears when `certops.enabled` is on for the
   workspace.
3. **Dedicated CertOps pages are orchestration-only**, mounted under a single
   `/certops/*` splat route when milestones add agents, jobs, evidence, or
   approvals (M2+/M4+). They do not replace token-based certificate visibility.

Dashboard code lives in `apps/dashboard/src/components/certops/` and is consumed
by existing surfaces (`ImportTokensModal`, `TokenDetailModal`, `App.jsx` asset
list). Minimal wiring edits only.

## Alternatives considered

- Standalone CertOps inventory list in M1 - rejected: redundant with the token
  asset model; operators would not know which list to trust.
- CertOps-only PEM import route - rejected: splits import UX and hides cert
  registration behind a feature silo operators may never find.

## Consequences

- M1 dashboard work (PR #48 and follow-ups) enriches tokens; it does not add
  `apps/dashboard/src/pages/certops/` inventory pages.
- Cloud and Enterprise overlays mirror the same enrichment pattern on their
  token surfaces.
- Reviewers should treat token-surface enrichment as aligned with D6 even when
  it lands before backend endpoints are complete, provided contracts and paired
  backend PRs are tracked (see ADR-0007 for retire UI pairing).
- M2 implementation note: the first orchestration page is
  `/certops/operations` (executor jobs, evidence timelines, machine API
  tokens), mounted via the `/certops/*` splat route behind the manager route
  guard. There is still no nav entry; discovery is contextual only - a footer
  link on the Control Center certificate-operations panel and a Workspace
  Preferences entry rendered as the last section when `certops.enabled` is on.
  Control Center itself stays read-only: the executor jobs list and token
  management live exclusively on the orchestration page.
