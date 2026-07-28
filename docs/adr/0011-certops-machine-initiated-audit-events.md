# ADR-0011: CertOps machine-initiated lifecycle events are audited

## Status

Accepted (2026-07-26).

## Context

A certificate that TokenTimer issued and now renews on its own left an audit trail
of exactly one row: `CERTOPS_JOB_CREATED_MANUAL`, from the request that started
it. Between that row and the certificate's eventual retirement, the system had
ordered a certificate from a public CA, written a private key and a certificate to
a host, reloaded a service, promoted the certificate to `active`, and granted
itself a renewal profile authorising it to repeat all of that indefinitely. None
of it was audited. A scheduled renewal produced no row at all.

This was found the way such things are found: a certificate existed, and searching
the audit log by its id returned the job that asked for it and nothing else.

The gap was not a deliberate scoping decision. Two pieces of the existing design
say so plainly. The event that did exist is named `CERTOPS_JOB_CREATED_MANUAL`,
which only means something in contrast to an automatic counterpart that was never
written. And the bootstrap-token catalog entry told readers that a consumed token
produces no revocation event, so they should "look for the agent's own
registration instead" - a registration event that did not exist either.

The reason the gap survived is that until [ADR-0010](0010-certops-derived-renewal-profiles.md)
none of these paths could actually run. Nothing populated renewal profiles, so
nothing was promoted by a scheduler, so the only real audit surface was the
operator-facing routes, which were audited. Derivation turned three dormant code
paths into live, unattended, host-mutating ones on the same day. The audit
coverage question moved with them and was not asked.

The general commitment ("every mutation audited") predates this record. This ADR
records which machine-initiated events discharge it, and
which deliberately produce nothing.

## Decision

1. **Five events are added, all of them machine-initiated.**

   | Event | Written at | Records |
   |---|---|---|
   | `CERTOPS_CERTIFICATE_ISSUED` | promotion of `provisioning` to `active` | the certificate coming into existence |
   | `CERTOPS_CERTIFICATE_ISSUANCE_UNRECONCILED` | refused promotion after a succeeded job | a certificate that is not usable and will not renew |
   | `CERTOPS_RENEWAL_PROFILE_DERIVED` | derivation, per ADR-0010 point 1 | the grant of recurring authority |
   | `CERTOPS_JOB_CREATED_AUTOMATIC` | renewal scheduler job creation | a job nobody asked for |
   | `CERTOPS_AGENT_REGISTERED` | enrollment | a new machine principal gaining command rights |

2. **Each event is written on the transaction that performs the state change.**
   Not after it, and not on the pool. A certificate cannot become `active`, a
   profile cannot come into existence, a renewal cannot be queued, and an agent
   cannot enroll while its audit row rolls back. This is asserted in
   `tests/unit/certops-audit-coverage.test.js` by routing the real `writeAudit`
   through the mock transaction client: a stubbed writer would pass even if
   production code used the pool.

   The converse also holds and is intended: an audit write that fails aborts the
   operation. An unaudited promotion is worse than a failed one, because the
   failed one is visible and retried.

3. **There is no user actor on any of them.** `audit_events.actor_user_id` is a
   `users` foreign key, and the actor here is an agent, a scheduler sweep, or a
   reconciliation path. Attributing a scheduled renewal to whoever last touched
   the certificate would be a fabrication. The acting machine is identified in
   metadata (`agentId`), consistently with the existing executor and controller
   events. Both audit catalogs now state this property up front, because an empty
   actor column otherwise reads as missing data.

4. **UUID subjects live in metadata, not `target_id`.** `target_id` is an
   `INTEGER` column and `writeAudit` silently coerces a non-integer to `NULL`.
   CertOps identifies everything by UUID, so `managedCertificateId`, `jobId` and
   `profileId` are metadata fields and the catalogs say to search there. Widening
   the column is the better long-term fix and is out of scope here; what is not
   acceptable is events whose subject is unrecoverable.

5. **Job success is not audited; terminal failure is.**
   `CERTOPS_JOB_FAILED` covers `failed`, `rejected`, `cancelled` and
   `orphaned_unknown_effect`. Successes are covered by
   `CERTOPS_CERTIFICATE_ISSUED`, which records the outcome that changed state.

   A row per successful renewal per certificate would grow with fleet size times
   renewal frequency and would bury the failures in the same log, which is the
   opposite of what an audit log is for. Failures earn a row for two specific
   reasons: `certificate_jobs` keeps only the *latest* error, so a job that failed
   and was retried loses its own history; and `orphaned_unknown_effect` is the one
   outcome where the real-world state is genuinely unknown and a human must
   intervene.

6. **Nothing is audited for a no-op or a replay.** An already-active certificate
   reconciling again, an idempotent renewal that created no job, a certificate
   that already links to an operator's own profile, and a replayed registration
   returning the original response all produce no event. Each of them would
   otherwise read as a second issuance, a second renewal, or a second agent.

7. **Error text is scrubbed before it is stored.** `errorMessage` on
   `CERTOPS_JOB_FAILED` passes through the same private-key and generic-secret
   redaction as the rest of the agent result path. The audit log is broadly
   readable and exportable, so it is the last place key material may appear.

## Alternatives considered

- **Audit every job status transition, including success** - rejected: volume
  scales with the fleet, and the failures are what a reader is looking for. The
  job row and its log already carry the per-transition detail for anyone
  investigating one job.
- **Emit these events from the outbox after commit** - rejected. The outbox
  ([ADR-0009](0009-certops-durable-side-effects-and-alert-policy.md)) exists for
  side effects with external dependencies that must survive retries. An audit
  write is a local insert on a transaction that is already open, and deferring it
  would create a window where a certificate is active and unaudited. That window
  is exactly the defect this ADR closes.
- **Attribute machine events to a synthetic system user** - rejected: it puts a
  fictional principal in a compliance artifact, and it would make "who did this"
  answerable with a name that cannot be held responsible. A null actor with the
  agent named in metadata is honest and already the established pattern.
- **Log to the application log instead** - rejected: derivation failures were
  already log-only, and the consequences section of ADR-0010 recorded that as a
  shortcoming. Application logs have different retention, no workspace scoping, no
  export path, and are not what an auditor is shown.
- **Reuse `CERTOPS_JOB_CREATED_MANUAL` with `source: "automation"`** - rejected:
  the event name would then contradict its own payload, and every existing query
  filtering on the manual event would silently start matching unattended activity.
- **Defer to a later release** - rejected. The paths went live with ADR-0010, so
  the untraceable window is open now, and an audit gap cannot be backfilled: the
  events that were never written are gone.

## Consequences

- A certificate's full lifecycle is now reconstructable from the audit log by
  searching its id in metadata: creation of the job, derivation of its profile,
  issuance, later automatic renewals, failures, and retirement.
- `audit_events` grows at roughly one row per issuance plus one per scheduled
  renewal plus one per failure, per certificate. Retention policy is unchanged;
  deployments with a strict retention budget should note the new floor.
- An audit-write failure now fails the operation it accompanies. This is intended
  (point 2) and means a database problem that would previously have produced an
  unaudited promotion produces a visible, retryable failure instead.
- Two catalog entries that pointed at events which did not exist are now
  accurate: the bootstrap-token entry's "look for the agent's own registration"
  and the runbook reference to `CERTOPS_RENEWAL_PROFILE_UPDATED`, which was
  itself missing from both catalogs.
- Certificates issued before this change keep their thin trail. The events are
  not backfilled, and no synthetic history is invented for them.
- Cloud and Enterprise inherit all five through the shared services when they
  re-pin core. No migration is required: `audit_events` predates this ADR and no
  column changes.
- `target_id` remains an `INTEGER` while CertOps identifies by UUID. Point 4 works
  around this rather than fixing it, and the workaround is now depended on by the
  catalogs and by the reconciliation runbook.
