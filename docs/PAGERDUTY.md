# PagerDuty expiration incidents

Configure a named PagerDuty webhook in workspace alert preferences using the
Events API v2 endpoint and the service's existing integration routing key. Select
that webhook in the asset's contact group(s). No PagerDuty REST token, inbound
webhook, browser session or additional worker is required.

## Trigger, acknowledge and recover

The first expiration notification creates a durable incident episode. Its
`dedup_key` is an opaque digest of workspace, asset, destination and episode
identity. Retries and later threshold notifications reuse that episode; they do
not open another incident. A successfully accepted trigger is not sent again for
each threshold, preserving the responder's workflow and acknowledgment.

Acknowledge incidents inside PagerDuty. ACK is not synchronized into TokenTimer,
and TokenTimer does not send acknowledge events. The delivery worker periodically
reevaluates active incidents, including when its ordinary alert queue is empty.
When recovery is established, it sends:

```json
{
  "routing_key": "<the original integration routing key>",
  "event_action": "resolve",
  "dedup_key": "<the original episode key>"
}
```

`open` and `resolved` in the local ledger mean the corresponding Events API
request was accepted. They do not mirror PagerDuty's remote incident status. The
existing shared HTTP client validates provider acceptance and retains HTTPS,
host validation, SSRF protection, redirect restrictions and timeouts. See
[PagerDuty's alert event documentation](https://docs.pagerduty.com/developer/send-alert-event).

## What counts as recovery

An expiry change alone is insufficient. The new date must be later than the
episode's original expiration and outside the entire effective threshold window
for that destination. TokenTimer uses the wider of the window recorded during
the episode and the currently assigned groups' window. Shrinking thresholds or
removing a group cannot manufacture recovery. An expired asset remains at risk
until recovery is established, even if there are no negative-day thresholds.

For example, with a 30-day PagerDuty window:

| Expiration change                            | Result                                    |
| -------------------------------------------- | ----------------------------------------- |
| Tomorrow → six months away                   | Resolve after validating the new fact     |
| Tomorrow → five days away                    | Keep the same incident open               |
| Unchanged, earlier, missing or invalid       | Keep the incident unresolved              |
| New risk after a resolved/recovering episode | Create a new episode with a different key |

An authorized expiry edit is authoritative for a manually managed asset.
Provider-managed assets require available provider evidence; recovery requires
a newer source observation than the one recorded at trigger time. A provider's
unknown-expiry `2099-12-31` fallback does not prove recovery. Managed certificates
must match their current certificate inventory facts. Monitored TLS assets must
match an observed TLS expiration and fingerprint. Removing the monitor or
inventory owner does not turn a manual edit into verified renewal. The manual
asset API returns `409 VERIFIED_CERTIFICATE_EXPIRY_REQUIRED` when an edit would
replace provider/certificate/monitor-owned certificate expiration facts.

Expiry changes archive existing threshold queue keys using the established
`:previous_expiration:` convention. Historical queue rows and delivery logs are
preserved, pending queue claims are revoked, and a new expiration cycle can
notify again. This covers manual edits, integration imports, automatic sync,
endpoint monitoring and CertOps reconciliation, including direct SQL writers.
The PagerDuty episode remains open across changes that still leave it at risk.

## Groups, destinations and configuration changes

Plural contact-group routing and existing eligibility/RBAC rules continue to
apply. The same PagerDuty endpoint and routing key selected through several
groups receives one incident; its risk window includes all those groups'
thresholds. Different routing keys at the same Events endpoint represent
independent destinations and receive separate incidents. Other webhooks keep
their existing URL-based destination deduplication. Partial webhook success
leaves failed destinations retryable and skips destinations that already
succeeded.

Historical accepted-trigger evidence anchors resolution. Current membership is
used for new triggers and current threshold validation, never as proof that a
destination received an earlier trigger. Removing a group's webhook selection
stops an unattempted trigger to that destination; renaming a group or webhook
does not change destination identity. Disabling delivery or removing groups is
not renewal. Existing channel-setting semantics are unchanged: PagerDuty uses
the effective groups' named webhook selections; the legacy workspace webhook
flag is not a new lifecycle switch. A verified recovery can still resolve a
historically triggered destination after its groups are removed.

The ledger stores a workspace-scoped fingerprint of the original endpoint and
routing key, never another plaintext copy of credentials. At dispatch it finds
that exact destination in the workspace's current webhook configuration. A
renamed configuration with the same endpoint/key works. A removed configuration,
changed URL, or rotated key leaves `original_destination_unavailable`; the
worker never substitutes another integration. Restore the original valid
destination if it is still usable, or reconcile the old incident in PagerDuty.
Deleting an asset, revoking a certificate or stopping monitoring does not prove
renewal and does not send a resolve. Deleted assets retain a historical anchor
and `asset_unavailable`. Workspace deletion erases its lifecycle records.

Incidents triggered before the PagerDuty lifecycle migration have no recoverable correlation key.
They are not backfilled and are not automatically resolved. Resolve those
historical incidents in PagerDuty. New tracked episodes do not adopt them.

An unsent queue row can still contain a successful pre-upgrade webhook log with
only `metadata.urlHash`. That evidence cannot identify the original routing key,
even with one current integration or several aliases of the same key. Replacing
an integration at the same URL must never turn old acceptance into proof that
the replacement received a notification. Only successful evidence with the exact
workspace/endpoint/routing-key `destination_id` establishes delivery.

URL-only PagerDuty success therefore remains ambiguous. The worker neither marks
that destination delivered nor sends a new correlated trigger that could duplicate
the historical notification. It retains an observable failure with the sanitized
code `pagerduty_legacy_destination_ambiguous`, subject to the normal queue retry
budget and eventual blocking. Older unaccepted outbox intents with this history
are parked without spending network-attempt budget. Parent reconciliation cannot
use ambiguous evidence to mark a channel complete or clear its failure warning.
Exact modern successes remain authoritative, and independently pending endpoints
can still proceed. Non-PagerDuty URL deduplication is unchanged.

Operators must inspect and reconcile historical incidents in PagerDuty; ordinary
requeue preserves the history and does not establish the missing routing identity.
No automated history-adoption mechanism is provided. Keep the original evidence;
never assign it a guessed destination or historical `dedup_key`. No incident or
automatic resolve is fabricated from a URL-only record.

For a legacy asset with no direct workspace, routing uses its owner's sole
workspace, or, when none is owned, its sole admin/manager membership. Multiple
candidates at either preferred level, or no authorized candidate, fail delivery
instead of silently succeeding. This resolution does not change asset ownership
or grant workspace access. Modern assets retain their direct workspace scope.

## Retries and operations

The existing delivery schedule drains at most 100 due lifecycle records per
pass. Active rows have an indexed next-attempt timestamp and a five-minute
recheck interval. Expiry writes wake affected records. Compose's runner and
Helm's delivery CronJob both execute this workflow without deployment changes.

HTTP 429, 408, 425, 5xx and transport failures retry with exponential backoff
starting at one minute and capped at one hour, up to eight attempts per action.
Other rejected responses park the action immediately. A network failure never
marks an incident resolved. Missing credentials are polled without consuming
network-attempt budget. Actual acceptance and its safe delivery-log entry commit
together. Each episode uses a leased, owner-fenced claim plus a session advisory
lock; no transaction spans HTTP. A dead process is reclaimable after a minute.

After background trigger acceptance, the worker also reconciles the original
queue row from persisted delivery logs. A channel completes only when every
current destination or recipient has success evidence. Other failed channels
remain pending in the row; a blocked row stays blocked while another failure
remains. Otherwise a failed row can become partial, or fully delivered rows
become sent and their delivery failure notifications clear. No synthetic success
logs are added. Active queue claims, locked rows, archived expiration cycles and
changed configuration fence this repair; open-incident sweeps retry skipped
repairs. A deleted source row does not prevent independent incident processing.

The API's existing authorized alert-requeue operation also retries exhausted
PagerDuty actions in its scope, preserving keys and cumulative attempt/history
counts. A manually requeued exhausted action gets a fresh bounded retry budget.
Its API count continues to describe ordinary queue rows.
Restoring the same removed destination resumes non-exhausted resolution on a
later sweep. Inspect the ledger without reading credentials:

```sql
SELECT id, workspace_id, token_id_snapshot, destination_id, state,
       trigger_accepted_at, resolve_requested_at, resolved_at,
       trigger_attempts, resolve_attempts, retry_exhausted,
       last_attempt_at, next_attempt_at, last_error
FROM pagerduty_incidents
WHERE workspace_id = '<workspace UUID>'
ORDER BY created_at DESC;
```

Events API sends are at least once across a send/commit crash. While still at
risk, retries use the same key to recover acceptance. If the asset becomes safe
after an ambiguous timeout/5xx/crash and no trigger acceptance was recorded, the
row stays `trigger_pending` with `trigger_acceptance_unknown`. TokenTimer cannot
prove a successful trigger without additional PagerDuty read permissions. It
does not send a stale trigger to establish acceptance, invent a resolve, or
claim recovery. Operators must reconcile that case in PagerDuty. A definite
rejection followed by recovery can be safely cancelled. A renewal during a
successful in-flight trigger is reconciled after that acceptance is persisted.

Once recorded, a resolve intent belongs permanently to its episode. Later risk
uses a different key, so an old delayed resolve cannot close the replacement.
Reconciliation samples committed facts on scheduled sweeps; a transient safe
date reverted entirely between sweeps is not treated as an observed recovery.

## PagerDuty Event Orchestration

Prefer an Events API v2 integration tied directly to the intended service. If
using Event Orchestration, ensure trigger and resolve events route to that same
service and preserve `dedup_key`. A resolve event has only routing key, action
and correlation key; rules depending on trigger-only summary/custom details
must explicitly accommodate it. Rules that rewrite event actions, suppress
triggers, change correlation keys or route resolves elsewhere can prevent
recovery even when Events API accepts the request. See
[PagerDuty's routing and deduplication guidance](https://docs.pagerduty.com/ai-automation/aiops/event-orchestration).

## Edition compatibility

This implementation is Core agnostic and adds no plan conditionals or schema
changes to webhook configuration. Cloud/Enterprise rebases must carry migration
81, the new worker modules, delivery-worker's lifecycle dispatch/drain hooks,
the shared legacy-workspace and delivery-evidence helpers, operational notification
reconciliation, and alertQueue's scoped retry CTEs into any overridden counterparts.
Apply API migrations before upgraded workers start. Preserve edition-owned entitlement,
freeze and dispatch guards when composing overrides; this change does not
automatically update independently pinned edition repositories.

## Migration 81 and preview-version compatibility

PagerDuty uses `apps/api/migrations/081-pagerduty-incident-lifecycle.sql`.
Released migration 79 is `auto_sync_provider_stats`; migration 80 is
`auto_sync_run_metrics`. Their names, versions and SQL are unchanged. The
PagerDuty SQL is unchanged from its unpublished v79 preview; only its registry
slot and filename moved. Fresh installations and databases at v78 or canonical
v80 run the normal migration command and reach v81 without special handling.

The PR's earlier v79 migration was executable, so preview/dev/staging databases
may already have recorded `79 / pagerduty_incident_lifecycle`. Its use outside
the disposable validation databases is not known. Inspect each deployment's
history before upgrading; never infer its state from the application version:

```sql
SELECT version, name, executed_at FROM migrations ORDER BY version;
```

The normal runner deliberately rejects the colliding preview history. It does
not treat PagerDuty as an alias of the released auto-sync migration, overwrite
the ledger, or replay PagerDuty SQL. Do not delete the v79 row or manually mark
auto-sync SQL executed. Use this explicit procedure only for that exact preview:

1. Stop all API/worker nodes and migration runners. Take and verify a restorable
   database backup. Retain a copy of the original migration history, incident
   ledger, delivery logs and schema. Rehearse recovery on a restored copy first.
2. Use the merged Core checkout and the same database/TLS environment as normal
   migrations. The tool requires the standard `public` Core schema and sufficient
   migration privileges. Run `node scripts/reconcile-pagerduty-v79.cjs --check`.
   It requires a complete validated v1-v78 prefix plus exactly PagerDuty v79,
   no v80/v81/future history, and no unrecorded auto-sync telemetry schema.
   It compares the full PagerDuty ledger columns, defaults, constraints and
   indexes, expiration snapshot column, function bodies/attributes and both
   enabled triggers with temporary reference DDL. Persistent state is unchanged.
3. After successful preflight, run
   `node scripts/reconcile-pagerduty-v79.cjs --apply`. This explicit maintenance
   operation locks migration history and repeats validation. In one transaction
   it relocates only the proven PagerDuty entry to v81, retaining its name and
   original execution timestamp, and executes/registers the released auto-sync
   migrations at v79 and v80. Strict history validation runs before commit.
   Any failure rolls back both ledger edits and telemetry DDL. PagerDuty data,
   keys, claims, queue state, delivery history, functions and triggers are not
   rewritten. PagerDuty SQL is never rerun.
4. Run `node apps/api/migrations/migrate.js`, then verify the final slots below.
   Compare the preserved records and original PagerDuty execution timestamp with
   the backup. Restart matching components only after normal migrations succeed.

```sql
SELECT version, name, executed_at FROM migrations WHERE version >= 79 ORDER BY version;
-- 79 auto_sync_provider_stats
-- 80 auto_sync_run_metrics
-- 81 pagerduty_incident_lifecycle (original preview timestamp if reconciled)
SELECT id, destination_id, dedup_key, state, trigger_accepted_at,
       trigger_attempts, resolve_attempts, claim_id FROM pagerduty_incidents;
```

The tool fails closed on unexpected histories, partial/unrecorded telemetry,
schema drift, missing or disabled triggers, and repeat application after recovery.
It prints only a sanitized failure code; DB specialists can compare the saved
history/schema with the shipped SQL to investigate. Do not bypass these checks.
For customized schemas or other mixed histories, retain the backup and obtain an
installation-specific reviewed recovery procedure. This is an opt-in preview
repair, not an automatic production migration or a general migration renumberer.
