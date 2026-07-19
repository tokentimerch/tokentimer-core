# ADR-0007: CertOps certificate removal and lifecycle model

## Status

Accepted (2026-06-28). Plan decision D7 (v1.5).

## Context

CertOps tracks certificates as `managed_certificates` rows linked 1:1 to cert-
category `tokens` via `token_id`. The token is the dashboard anchor; the managed
certificate is the lifecycle system of record. Discovery, endpoint-monitor bridge,
and PEM import can create managed rows that must not disappear silently when an
operator deletes a token from the asset list.

Today there is no product path to remove a managed certificate without row
deletion. Hard-deleting tokens that reference managed certificates would orphan
inventory (`ON DELETE SET NULL` on `token_id`) and destroy audit visibility.

M1 adds a **retire-first** removal model: status transitions instead of FK
cascade deletes, with restricted hard purge for manually created cert tokens
only.

## Decision

1. **Retire (soft, default).** Operators remove tracked certificates via
   `POST /api/v1/workspaces/:id/certops/certificates/:certId/retire` with body
   `{ status: "revoked" | "decommissioned", reason? }`. This is a status
   transition, not a row delete (`DELETE` is intentionally avoided because
   nothing is purged).
   - `managed_certificates.status` becomes `revoked` or `decommissioned`.
   - A matching lifecycle status is mirrored onto the linked token in the same
     transaction.
   - `certificate_instances`, evidence, and audit history are preserved.
2. **Token surface gating.** A token linked to a `managed_certificate` cannot be
   hard-deleted from the dashboard. Delete affordances route to **Retire**
   instead. Bulk delete skips managed-backed cert tokens.
3. **Hard purge (restricted).** Only a manually created cert-category token that
   is **not** backed by a `managed_certificate` may use the existing
   `DELETE /api/tokens/:id` path. Managed-backed certificates are never row-
   deleted from the product in M1; a gated retention/decommission purge belongs
   to a later milestone (M7 `decommission`, enterprise retention policy).
4. **Reverse direction via status sync, not cascade.** Retiring a managed
   certificate retires its linked token. The FK stays `ON DELETE SET NULL` so an
   accidental token row delete still cannot destroy the certificate record.
5. **Dashboard defaults.** Retired certificates (`revoked`, `decommissioned`)
   are hidden from the asset list by default with a "Retired" filter toggle.
6. **Audit.** Retire writes a `CERTOPS_CERTIFICATE_RETIRED` audit row (exact
   code name is flexible pre-GA; see plan section 0.3) with optional reason in
   metadata. Reason is not required in M1 UI display.

### Schema implication

The `tokens` table gains an additive, nullable lifecycle status column
(cert-relevant; `NULL` for non-cert tokens), written in the same transaction as
the certificate status change. Exact column name is an implementation detail.

### Paired delivery

Frontend retire UI (dashboard PR #48) may land ahead of the backend retire
endpoint (see PR #47). That is acceptable under D7 when:
- OpenAPI, route-compat contract, migration, token status column, audit row, and
  tests are tracked in the paired backend PR or an immediately following one.
- Callers handle 404 on the retire route until the backend ships.

## Alternatives considered

- `DELETE /certops/certificates/:id` with FK cascade - rejected: loses evidence
  and breaks the system-of-record model; discovery imports could vanish silently.
- Hard delete token clears managed row - rejected: `ON DELETE SET NULL` orphans
  inventory with no dashboard path to the certificate.
- Defer all retire UI until backend exists - rejected: frontend contract and
  operator UX can proceed in parallel when paired backend work is explicit.

## Consequences

- Dashboard ships `RetireCertificateModal`, retire gating on managed certs, and
  retired filtering (aligned with v1.5 / this ADR).
- Backend must implement the retire route, token status sync, and audit event
  before GA; until then UI degrades gracefully on 404.
- Hard purge of managed-backed certificates remains out of M1 scope.
