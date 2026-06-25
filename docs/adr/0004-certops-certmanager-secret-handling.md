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
- The controller ships the first Helm RBAC templates and is scoped to the
  minimum verbs needed (no blanket Secret read).

## Alternatives considered

- Read whole Secrets for convenience - rejected: that is private-key custody.
- Mutate cert-manager Secrets - rejected: out of scope and custody-bearing.

## Consequences

- RBAC must be narrow enough to prove the controller cannot read `tls.key`.
- TODO (M8): exact RBAC verbs/resources, controller reconcile model, Helm chart
  layout, and how status maps to CertOps evidence.
