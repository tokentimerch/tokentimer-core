# Distribution lifecycle integration and migration compatibility

PR #498 integrates the merged provider (#460), recipient-verification (#461)
and PagerDuty (#496) runtimes. Their earlier preview databases retain their applied
migration identities. Normal feature capability gates remain authoritative; no
temporary qualification trust exception is imported.

The [PR #498 scope and merge matrix](pr498-merge-readiness-20261103.md) records
supported behavior separately from optional capability promotion. No production
manifest gate is opened by migration composition or by the finalization work.

## Migration ordering

Use the normal migration runner. SQL filenames from earlier previews are retained;
the composed plan determines numbers. Fresh installations preserve main 79–82,
then use provider 83, recipient/digest 84–85, lifecycle 86–90, recovery delivery 91
and PagerDuty 92–95, followed by additive consumer preparation at 96 and durable
review-authority epochs at 97. Migration 97 invalidates existing distribution
authorizations once: obtain fresh independent review after upgrading. Removing
and restoring a reviewer or changing workspace ownership cannot revive an old
review. Stored approvals and permanent material fences remain intact.
Independent registered tails may leave reservations absent;
never fill them with no-op SQL. Applied version/name/timestamp rows and their SQL
remain unchanged. Recognized previews retain their original assignments, while
missing definitions are placed without collisions. Use the normal runner and
preserve a restorable backup; do not run an old standalone renumbering tool.

The existing four historical 70–76 orders and immutable SQL are retained.
Unknown names, duplicate names/versions, noncanonical gaps and incomplete known dependencies
fail before SQL executes. Unrecognized or manually altered schemas require manual
review; never invent ledger records to bypass validation. Migration execution is
serialized with a database advisory lock, including initial table creation and
history validation. Deploy matching API/workers only after migration completion.

The isolated PostgreSQL runner executes the historical SQL, preserves original
ledger timestamps and counters, upgrades released, independent and historical extension layouts, tests two
concurrent runners and repeats migration execution. It also replays the existing
six histories and tests verification/recovery backfills. Recipient enforcement and PagerDuty reconciliation use their normal runtime settings.

## Cleanup operation and provider contract

New signed cleanup intents use `operation: "soft-delete"` and
`provider: "vault-kv2"` or `provider: "openbao-kv2"`. They have no operation-valued
`type`, so the shared `providerOf` and local adapter resolve the correct provider.
Each provider requires its own separately qualified cleanup capability and its
matching material-store capability. Azure cleanup is rejected before an API fence
is created. Provider version and customer scope validation remain required. The
new OpenBao cleanup capability is absent from the released qualification manifest.

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
remain outstanding. Azure and shared Windows/IIS retain their separate protected
artifact qualification requirements; OpenBao distribution is supported.
