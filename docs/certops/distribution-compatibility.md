# Distribution lifecycle integration and migration compatibility

PR #498 integrates main through `d2f7dbd4` and compares these unmerged sources:

| PR | Inspected head | Shared boundary |
| --- | --- | --- |
| #460 | `66f94086eb01b6cdd81727899defb300eedf4319` | Provider identity, version pins, provider schema and its two earlier preview orders |
| #461 | `b8c506425e30017ea6470665cd34460e7347a07c` | Recipient-verification and digest-claim schemas at independent 81/82 |
| #496 | `99101c108fcc8f71950103379255d71d13c9d391` | PagerDuty schema at independent 81 and earlier preview 79 |

Only additive compatibility SQL and #460's shared public provider helper are
imported. This does not merge those PRs' runtime features, environment policies,
trust exceptions or production capabilities. Their runtime integration must use
the shared registry by migration name instead of registering duplicate numbers.

## Migration ordering

Use the normal migration runner. SQL filenames from earlier previews are retained;
the composed plan determines numbers. On a fresh install, main owns 79–81:

| Fresh version | Identity |
| --- | --- |
| 79 | `auto_sync_provider_stats` |
| 80 | `auto_sync_run_metrics` |
| 81 | `auto_sync_metric_labels` |
| 82–86 | Lifecycle, incident delivery, discovery, cleanup, consumer verification outcomes |
| 87 | `certops_material_providers` |
| 88 | `recipient_channel_verification` |
| 89 | `weekly_digest_recipient_claim_token` |
| 90 | `pagerduty_incident_lifecycle` |
| 91 | `certops_distribution_resolution_delivery` |

Applied `(version,name,executed_at)` rows are never changed. Their SQL is not
replayed. Only missing identities append after the applied extension tail. For
example, #498's applied 81–85 stay at 81–85 and missing main metric labels append
at 86; a main installation with metric labels already at 81 uses fresh 82–91.
The provider previews at 78/79/81, recipient/digest at 81/82 and PagerDuty at 79/81
are recognized, as are combinations produced by this composer. Do not run an old
standalone preview renumbering tool against this integrated registry.

The existing four historical 70–76 orders and immutable SQL are retained.
Unknown names, duplicate names/versions, gaps and incomplete known dependencies
fail before SQL executes. Unrecognized or manually altered schemas require manual
review; never invent ledger records to bypass validation. Migration execution is
serialized with a database advisory lock, including initial table creation and
history validation. Deploy matching API/workers only after migration completion.

The isolated PostgreSQL runner executes the historical SQL, preserves original
ledger timestamps and counters, upgrades all nine extension layouts, tests two
concurrent runners and repeats migration execution. It also replays the existing
six histories and tests verification/recovery backfills. Compatibility DDL alone
does not enable recipient enforcement or PagerDuty expiration reconciliation.

## Cleanup operation and provider contract

New signed cleanup intents use `operation: "soft-delete"` and
`provider: "vault-kv2"`. They have no operation-valued `type`, so #460's shared
`providerOf` and local adapter resolve the correct provider. Only Vault KV v2 is
accepted for this cleanup capability; OpenBao/Azure requests are rejected before
an API cleanup fence is created. Provider version and customer scope validation
remain required.

Previously approved `type: "vault-kv2-soft-delete"` intents remain valid. The
shared cleanup helper normalizes a separate adapter copy, preserving the original
signed payload, approval hash and local journal identity. A failed fenced cleanup
can retry the original signed job or request fresh independent review after its
authority expires or changes. Neither path releases the material reuse fence.

Vault's `deletion_time` is effective only when valid and at or before the current
time. A future scheduled deletion cannot bypass retention or count as a completed
delete. Both pre-delete reconciliation and post-delete readback enforce that
rule. Ineffective/missing/invalid post-delete evidence produces uncertainty and
no successful cleanup receipt; the original-intent retry remains available.

## Incident recovery and navigation

Health resolution and delivery are separate durable obligations. Resolution sets
`resolution_delivery_pending` transactionally. Monitoring drains older pending
resolutions before new alerts, within the existing 20-entry hourly workspace
quota. Enqueue and clearing the flag commit together. The stable incident revision
and unique queue key prevent duplicate recovery events under retries/concurrency.
Migration 91 backfills previously resolved incidents without an existing matching
resolution queue event. The existing worker keeps PagerDuty trigger/resolve
correlation and delivery retry behavior.

Cleanup Jobs links carry the active workspace through `jobsLink`; onboarding uses
the shared `onboardingPath`. Explicit URL scope wins over another tab's saved
workspace. Tests exercise both workspaces with real workspace context and two tabs.

## Qualification and rollout limits

Cleanup remains disabled/report-only by default. Runtime/group/customer opt-ins,
independent approval and a separately qualified native capability are all needed.
The release manifest still omits `material-cleanup-vault-kv2-v1`; this integration
does not enable it. Exact-version Vault soft deletion does not authorize data
reads, destroy, metadata/all-version deletion, purge or Azure individual-version
deletion. Full real-fleet/operator acceptance and protected artifact qualification
remain outstanding. #460's production Windows/Azure gates and administrator-owned
environment cleanup remain its separate release/merge requirements.
