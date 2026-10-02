# ADR-0007: CertOps certificate removal and lifecycle model

## Status

Accepted (2026-06-28).

## Context

CertOps tracks certificates as `managed_certificates` rows linked 1:1 to cert-
category `tokens` via `token_id`. The token is the dashboard anchor; the managed
certificate is the lifecycle system of record. Discovery, endpoint-monitor bridge,
and PEM import can create managed rows that must not disappear silently when an
operator deletes a token from the asset list.

Today there is no product path to remove a managed certificate without row
deletion. Hard-deleting tokens that reference managed certificates would orphan
inventory (`ON DELETE SET NULL` on `token_id`) and destroy audit visibility.

This ADR adds a **retire-first** removal model: status transitions instead of FK
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
   deleted from the product today; a gated retention/decommission purge belongs
   to a later phase (`decommission`, enterprise retention policy).
4. **Reverse direction via status sync, not cascade.** Retiring a managed
   certificate retires its linked token. The FK stays `ON DELETE SET NULL` so an
   accidental token row delete still cannot destroy the certificate record.
5. **Dashboard defaults.** Retired certificates (`revoked`, `decommissioned`)
   are hidden from the asset list by default with a "Retired" filter toggle.
6. **Audit.** Retire writes a `CERTOPS_CERTIFICATE_RETIRED` audit row (exact
   code name is flexible pre-GA) with optional reason in
   metadata. Reason is not required in the initial UI display.

### Schema implication

The `tokens` table gains an additive, nullable lifecycle status column
(cert-relevant; `NULL` for non-cert tokens), written in the same transaction as
the certificate status change. Exact column name is an implementation detail.

### Paired delivery

Frontend retire UI (dashboard PR #48) may land ahead of the backend retire
endpoint (see PR #47). That is acceptable under this decision when:

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
  retired filtering (aligned with this ADR).
- Backend must implement the retire route, token status sync, and audit event
  before GA; until then UI degrades gracefully on 404.
- Hard purge of managed-backed certificates remains out of scope for now.
- Addendum (2026-07-26): [ADR-0008](0008-certops-upfront-issuance.md) adds a
  `provisioning` pre-active status to this lifecycle model for upfront agent
  issuance. It is non-terminal and subject to the same retire-first rules as any
  other non-terminal status: it retires to `revoked` or `decommissioned` through
  the retire route with token status mirroring, is never row-deleted, and counts
  as active for quota.

## Addendum: fingerprint identity and management periods (2026-10-01)

This addendum supersedes the 1:1 source-row lifecycle and default retired
visibility rules above. A certificate is identified by its normalized SHA-256
fingerprint within a workspace. `managed_certificates` remains a historical
source record. An open `certops_management_periods` row denotes current
management; rotation changes its current certificate association without
moving lifecycle from A to B. Closing a period is terminal. Re-adding a source
starts another period, and observations cannot reopen management.

The grouped inventory displays one fingerprint once, with its source history
and location evidence. Fingerprintless provisioning rows stay separate until
identified. Lifecycle changes target `certops_certificate_identities` and
require the expected fingerprint; the legacy record route requires the same
precondition. Revocation records CertOps state and does not contact the CA.
Decommission is an operator declaration made with the best available evidence:
fresh confirmed service use blocks it; stored copies or unknown visibility
require a reason and explicit acknowledgment. Subsequent observations leave
lifecycle unchanged and show the conflict. Revoked/decommissioned certificates
with fresh presence remain visible by default.

Historical source provenance comes from the management period's `source` and
`source_ref` snapshots and survives physical source deletion or workspace
transfer. Current source fields such as `tokenId` are hydrated only when the
source and period belong to the same workspace; otherwise they are null.
Observation matching normalizes legacy instance fingerprints on reads with
`certops_normalize_fingerprint`, including the decommission safety check.
Slot and unmanaged observations enforce canonical fingerprints with database
constraints. The same normalizer checks job targets before permitting a
replacement operation to bypass retirement restrictions.

Grouped list and detail responses return at most 20 locations, with a full
`locationCount`. PostgreSQL computes `visibilityUnknown` over all matching
distinct locations using their effective presence and freshness rules before applying
the display limit. No observations means unknown visibility; fresh confirmed
absence is known visibility.

Lifecycle does not end management and does not release quota. Quota consumes
one unit per distinct fingerprint with an open period, plus one per open
fingerprintless source. Closing the last period releases the unit. Token status
and alert suppression must respect other active fingerprints sharing a token.
Historical source records, jobs, observations, and audit rows remain intact.

Certificate detail layout is shared with dashboard token details. Both use the
same validity, expiry, renewal, key-locality, Notes and alert sections. CertOps
adds column-based observed locations and management periods beneath Notes;
dashboard token details omit those location tables. Source actions remain tied
to a specific management period, and evidence state is separate from evidence
type. Edition overlays retain this shared layout; hosted Cloud excludes
auto-sync provenance because that feature and its schema are not available.

The UI calls the source-period section **Certificate management** and explains
registrations separately from deployment evidence. Current and restartable
registrations appear by default; **Show ended periods** reveals earlier periods
and associations. **Start managing again** opens a new period with explicitly
selected renewal settings, never a second fingerprint entry. See
[Certificate details](../certops/certificate-details.md).

Repeated endpoint monitor records are grouped by their exact endpoint URL before
location counts and pagination. Prefer a surviving monitor over ended monitors,
then its latest captured evidence. Previous monitor records remain immutable;
responses include their count and at most 20 historical summaries per location.
Historical summaries contain no deployment paths or source references. Genuine
current visibility gaps are retained; the lifecycle action continues checking
all raw evidence independently of the display projection. Other observation
slots are not merged merely because two hosts use the same file path.

Existing open management periods may rotate to a different fingerprint even when other sources retain the old certificate and quota usage temporarily exceeds the limit. New period enrollment still requires admission; joining an already managed fingerprint adds no unit. Core migration 64 (Cloud migration 82) repairs the earlier admission function without rewriting historical migrations or management history.
