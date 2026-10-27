# ADR-0015: PagerDuty expiration incident lifecycle

## Status

Accepted (2026-10-27). Amends ADR-0013's webhook destination identity for
PagerDuty; applies ADR-0009's durable side-effect and owner-fencing principles.

## Context

Expiration triggers had no Events v2 correlation key. URL-only webhook identity
merged different PagerDuty integrations, and partial webhook success removed
the failed channel from retries. Permanent per-threshold queue keys also
prevented later expiration cycles, except where CertOps explicitly archived
them. Expiration writes originate in multiple APIs and workers.

## Decision

1. Keep the existing PagerDuty webhook configuration and HTTP safety layer.
   PagerDuty destination identity is SHA-256 over a versioned tuple of workspace,
   endpoint and routing key. Other webhook kinds still dedupe by URL. Raw keys
   and URLs are not copied into the lifecycle table or delivery evidence.
2. Migration 79 adds `pagerduty_incidents`, a minimal ledger and durable outbox.
   It holds an episode UUID, workspace/asset identity, destination digest, opaque
   `dedup_key`, original expiration/authority, risk-window boundary, delivery
   evidence, retries, timestamps and leased claims. One partial unique index
   permits at most one pending/open episode per workspace/asset/destination.
   Resolve-pending episodes may coexist with a newer active episode, using
   distinct keys. No legacy incident is inferred or backfilled.
3. Enqueue intent before sending. Persist explicit provider acceptance together
   with its delivery evidence in a short transaction after HTTP. Session advisory
   locks serialize dispatch for an episode across lease expiry, while claim IDs
   fence every completion. Never hold a transaction across network calls.
4. Drain indexed, bounded batches from the existing delivery schedule, even when
   the ordinary queue is empty. Re-read committed facts and configuration before
   dispatch. Retry bounded transient failures with exponential backoff; park
   permanent/exhausted failures and allow existing authorized requeue to retry.
5. Recovery requires a later valid expiration outside the wider of the recorded
   and current destination windows. Preserve provider/certificate/monitor fact
   ownership. Do not treat edits remaining inside the window, disabled alerts,
   missing groups, deleted assets or missing evidence as renewal. An immutable
   resolve intent can only reference a successfully accepted trigger.
6. Find credentials by exact original destination fingerprint in current
   workspace configuration. Renames work; removed/rotated integrations remain
   unresolved and observable. Never resolve a replacement integration.
7. A database expiry-write hook extends the existing CertOps archival convention
   to every asset writer. Preserve successful logs, revoke stale queue claims,
   archive old threshold keys, and wake active lifecycle records atomically with
   expiration changes. Freeze each queue row's expiration snapshot at insert.
8. If a renewed asset's earlier trigger acceptance is uncertain after a network
   failure/crash, retain that uncertainty for operator reconciliation. Never
   manufacture acceptance, send a stale trigger, or issue an unproven resolve.

## Alternatives considered

- Per-threshold dedup keys: produce separate incidents and let an earlier resolve
  target the wrong cycle.
- Current group membership as delivery evidence: cannot prove historical receipt
  and can silently send resolves to another integration.
- API-specific recovery hooks: miss provider imports and direct worker writes.
- PagerDuty REST polling/inbound ACK synchronization: adds credentials and
  infrastructure outside expiration lifecycle scope.
- Exactly-once HTTP: cannot be guaranteed across an external send and local
  commit. Provider correlation plus explicit uncertainty is the honest boundary.

## Consequences

The existing Compose and Helm delivery paths support automatic recovery without
new services or permissions. ACK remains in PagerDuty. Missing original
credentials and unprovable acceptance require operator action. Event
Orchestration must route minimal resolves consistently with triggers. See
[PagerDuty operations and compatibility](../PAGERDUTY.md) for deployment, retries,
state semantics and edition integration points.
