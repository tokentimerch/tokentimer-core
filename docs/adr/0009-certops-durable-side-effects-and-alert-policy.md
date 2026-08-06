# ADR-0009: CertOps durable side effects and renewal alert policy

## Status

Accepted (2026-07-26). Amends [ADR-0008](0008-certops-upfront-issuance.md)
decision point 8, which is replaced by
[Amendment 1, section A1.4](0008-certops-upfront-issuance.md#a14-alerting-is-not-unchanged-a-failed-issuance-does-not-alert-replaces-8)
of that record.

## Context

Two separate defects, both silent, produced the same operator experience: a
failed renewal that emailed nobody, and a failed issuance that emailed nobody,
with no way to tell which cause applied.

**The rule had two homes.** `agentDispatch.js` carried its own set of
alert-worthy operations, `{renew, issue}`, while `renewalFailureAlerts.js`
hard-rejected anything other than `renew`. A failed issuance was therefore
dispatched into an alert path that discarded it and returned a reason nobody
read. The duplication was not carelessness: the dispatcher already required the
resolver, so the set could not live in the dispatcher and be imported back
without a require cycle. The set had a unit test; the resolver was never run
against it, so the test proved the two halves agreed with themselves rather than
with each other.

**Alerting was best-effort by construction.** Contact resolution and the
`alert_queue` insert ran inline inside the result-ingestion transaction, wrapped
in a savepoint specifically so an alert failure could never abort ingestion.
That made the two guarantees mutually exclusive. Ingestion always survived,
which is right, and the price was that the intent to alert was lost to a single
`log.warn` on any error: no retry, no record, nothing for an operator to find
afterwards. A transient failure in contact resolution or in `alert_queue` was
indistinguishable from a deliberate decision not to alert.

**Status alone cannot decide whether to alert.** `RESULT_STATUS_TO_JOB_STATUS`
maps agent-reported results onto `rejected` and `blocked`, which are the same
statuses the human approval flow produces. An agent refusing a job on
agent-local policy grounds (ADR-0002) is actionable and the operator needs to
know. A human rejecting their own job in the approval UI is that human's
deliberate act, and emailing them about it is noise. The job's creation source
cannot separate the two either, because an API-created job can later be
terminated by either.

## Decision

1. **One module owns the alerting vocabulary.**
   `apps/api/services/certops/renewalAlertPolicy.js` is dependency-free and is
   imported by both the dispatcher and the resolver, so "does this job alert?"
   has exactly one answer. Being dependency-free is the point: it is what breaks
   the cycle that caused the duplication, and it must stay that way.
2. **`issue` is deliberately excluded from alerting.**
   `RENEWAL_ALERTING_OPERATIONS` is `{renew}`. A failed issuance has no
   certificate identity worth alerting on: no linked token to anchor contact
   routing (linking happens at successful reconciliation, ADR-0008 A1.3), and
   nothing in the inventory the operator was already relying on. Its record is
   the visible `provisioning` row with the failed job and evidence attached.
   Once issued and active, that certificate's renewals alert like any other's.
3. **Classification is by origin, not status alone.** A terminal transition is
   classified by `(operation, status, origin)` through
   `classifyTerminalTransition`, where origin describes what caused the
   transition (`agent_result`, `executor_event`, `approval_rejection`,
   `operator_cancel`, `lease_reaper`, `stale_agent`, `forced_retirement`) and is
   distinct from `certificate_jobs.source`, which describes how the job was
   created. `executor_event` covers the machine-token lane (a bring-your-own
   executor driving the API directly with a machine credential, or the
   Kubernetes controller): it shares `certificate_jobs` with the agent lane but
   holds no lease, and its terminal reports were the last path that recorded a
   renewal failure with no alert at all — added alongside `forced_retirement`
   actually enqueuing its own intent for the same reason: a transition origin
   existing in this enum is necessary but not sufficient, every call site that
   produces a terminal transition has to invoke the classifier itself. Human
   decision origins never alert. Dry runs never alert, because a dry run changes
   nothing on the host by construction. `orphaned_unknown_effect` always alerts
   at high priority, because it is the one case where side effects may have
   landed and cannot be proven either way.
4. **Every classification records its reason, including the skips.** A skip that
   cannot explain itself is indistinguishable from the bug this replaces.
5. **The deciding transaction records intent, not delivery.** A new
   `certops_outbox` table holds intents. The enqueue is a plain local INSERT
   inside the caller's transaction, with no savepoint and no best-effort
   swallow, so "the job reached its terminal status" and "the side effect was
   decided" commit together or not at all. If the enqueue fails, the terminal
   transition fails. That is the honest outcome: refusing to record a state
   change we cannot alert on is better than recording one we have silently
   dropped the alert for.
6. **Delivery moves to a drain sweep.** A new `outbox-drain` sweep in the
   CertOps maintenance worker claims due rows under an owner-scoped lease,
   resolves contacts, and inserts into `alert_queue`, with attempt counting and
   backoff. Every terminal write is conditional on the sweep's own `claim_id`,
   mirroring the `alert_queue.delivery_claim_id` convention from migration 17,
   so a second worker that takes over an expired lease turns the first one's
   late writes into no-ops.
7. **The drain separates structural skips from transient errors.** An intent
   whose answer cannot change (no linked token, no deliverable channel) goes
   terminal as `skipped` with its reason preserved, because retrying it forever
   would bury real failures. A thrown error is treated as transient and retried
   until `max_attempts`, then parked as `failed` for an operator. An event type
   with no registered handler **defers** rather than being consumed: recording
   intent is pointless if the drain silently discards what it cannot yet handle.
8. **The table is generic and typed, not alert-specific.** Event type is a
   CHECK-constrained enum and each type has an allowlisted payload field set.
   Payloads carry ids and frozen codes only, validated per event type and run
   through the same key-material detector as every other CertOps
   `public_metadata` sink, so an outbox row can never become an exfiltration
   path for job payload contents. Unknown payload keys are rejected rather than
   dropped, because a caller passing something unexpected is a bug worth
   surfacing.
9. **Idempotency is `(workspace_id, event_type, dedupe_key)`.** A retried caller
   transaction enqueues the same side effect once. `enqueued: false` on conflict
   is a success, not an error. Renewal alerting therefore has two independent
   layers of duplicate suppression: this uniqueness, and the resolver's existing
   check for an already-queued alert for the same job.

### Schema implication

Migration v35 adds `certops_outbox`: `workspace_id`, `event_type`,
`dedupe_key`, `payload`, `status` (`pending`, `succeeded`, `skipped`,
`failed`), `outcome_reason`, `attempt_count`, `max_attempts`, `next_retry_at`,
`last_error`, `claim_id`, `claimed_until`. A unique index on
`(workspace_id, event_type, dedupe_key)` provides the idempotency, and a partial
index on `next_retry_at WHERE status = 'pending'` is the drain scan path.

`event_type` is CHECK-constrained to `renewal_alert_requested` and
`profile_derivation_requested`. The second value was reserved for
[ADR-0010](0010-certops-derived-renewal-profiles.md); that work then landed
inline in the reconciliation transaction instead, so the value is currently
enqueued by nothing. It is intentionally kept rather than removed: it costs a
CHECK entry, decision 7 makes an unhandled type defer rather than be lost, and
narrowing a CHECK constraint after release is more expensive than leaving an
unused enum value in place.

### Operational implication

Alerting now depends on the CertOps maintenance worker running. If the
`outbox-drain` sweep is disabled or the worker is not deployed, intents
accumulate as `pending` rather than being lost, which is a recoverable state
and strictly better than the previous behaviour, but the operator hears nothing
in the meantime. Deployment documentation must state that the sweep is not
optional for anyone relying on renewal-failure notifications.

## Alternatives considered

- **Keep alerting inline and retry in-process** - rejected: the retry state
  lives only in memory, so a worker restart or a process kill loses it, which
  is the same defect with extra steps.
- **Keep the inline savepoint and log more loudly** - rejected: a log line is
  not a record an operator can act on later, and it cannot be retried.
- **Make the code match ADR-0008 point 8 and alert on failed issuance** -
  rejected. There is no deadline (nothing is expiring), no linked token to route
  through, and the `provisioning` row is already a better record than a
  notification. See ADR-0008 A1.4.
- **A bespoke `certops_pending_alerts` table** - rejected: profile derivation
  needed the same decided-here-executed-later property, and a second table
  would duplicate the claim, lease, and backoff logic. Typing the event instead
  costs one enum.
- **Reuse `alert_queue` directly as the outbox** - rejected: `alert_queue` rows
  require a resolved recipient, and resolution is exactly the part that must not
  run in the deciding transaction. It also has no notion of an intent that
  legitimately resolves to no recipient.
- **Decide alerting from job status alone** - rejected: agent-reported
  rejections and human approval rejections share statuses, so the two would be
  indistinguishable and one of them is pure noise.
- **Store the full job payload in the outbox row for debuggability** - rejected:
  outbox rows are operator-visible and payloads contain CA and deployment
  detail. Ids are enough to re-read the job under the caller's own
  authorization.

## Consequences

- The CertOps maintenance worker becomes load-bearing for notifications, not
  just for housekeeping. Cloud and Enterprise must run the `outbox-drain` sweep
  when they re-pin core.
- A failed `issue` job produces no notification by design. Operator-facing
  documentation must direct people to `provisioning` certificates and their
  `reconciliation_reason` for issuance problems, and to alerts for renewal
  problems.
- Alert delivery gains latency equal to at most one sweep interval. This is an
  accepted trade for durability; renewal windows are measured in days.
- `renewalAlertPolicy.js` must stay dependency-free. Importing anything that
  transitively reaches `agentDispatch.js` or `renewalFailureAlerts.js`
  reintroduces the cycle and, with it, the pressure to duplicate the rule.
- Adding an alert-worthy operation is now a one-line change in one file, and
  both call sites inherit it. Adding one without adding a resolver path is
  visible as `pending` outbox rows for an unhandled type rather than as silence.
- `certops_outbox` rows are retained after reaching a terminal status so the
  reason survives for audit. No retention policy ships with this ADR; growth is
  bounded by terminal job transitions and can be pruned later without a
  contract change.
