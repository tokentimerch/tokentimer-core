# ADR-0004: CertOps Kubernetes cert-manager Secret handling

## Status

Proposed (2026-06-25). Phase 0 skeleton; finalize in M0, detail in M8.

## Context

In Kubernetes, cert-manager stores issued certificates as `Secret` objects that
contain both `tls.crt` (public) and `tls.key` (private). A TokenTimer Kubernetes
controller that watches certificate state must not become a private-key custody
path, or it would break the zero-custody invariant.

## Decision

- The TokenTimer Kubernetes controller observes `Certificate` /
  `CertificateRequest` status and reads `tls.crt` only. It never reads, copies,
  or transmits `tls.key`.
- The controller reports public material and status as evidence to the control
  plane; key material stays in the cluster.
- The controller ships the first Helm RBAC templates, scoped to the minimum
  verbs needed. Note the platform limitation: Kubernetes RBAC cannot restrict
  access to individual data keys inside a `Secret`, so a controller able to
  `get` a Secret can technically read both `tls.crt` and `tls.key`. RBAC
  minimizes Secret access; it cannot prove per-key denial.
- Per-key non-access is therefore enforced by a strict read hierarchy (prefer
  Certificate/CertificateRequest status, then annotations, then `tls.crt` only),
  by code-level enforcement that never reads/deserializes/logs/transmits
  `tls.key`, by tests asserting that, and by the shared detector scanning
  everything the controller reports upstream.

## Alternatives considered

- Read whole Secrets for convenience - rejected: that is private-key custody.
- Mutate cert-manager Secrets - rejected: out of scope and custody-bearing.

## Consequences

- RBAC narrows but cannot prove per-key denial; the load-bearing proof is the
  test suite showing controller code never reads/deserializes/logs/transmits
  `tls.key`, plus detector scanning of all upstream reports.
- TODO (M8): exact RBAC verbs/resources, controller reconcile model, Helm chart
  layout, and how status maps to CertOps evidence.
