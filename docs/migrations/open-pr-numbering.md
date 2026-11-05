# Migration integration for PRs 460, 461, 496 and 498

Main at `93b29305c7b7739957152da7342d15d584605575` owns migrations 78–82.
Do not rename, replace or reinterpret released rows. These canonical numbers
are enforced by `apps/api/migrations/migration-reservations.cjs`; missing PRs
are reservations, not no-op migrations. They do not install another feature.

| Version | Canonical name | Owner / integration action |
|---|---|---|
| 78 | certops_installed_file_distribution | Released main; unchanged |
| 79 | auto_sync_provider_stats | Released main; unchanged |
| 80 | auto_sync_run_metrics | Released main; unchanged |
| 81 | auto_sync_metric_labels | Released main (#513); unchanged |
| 82 | auto_sync_system_metrics | Released main (#516); unchanged |
| 83 | certops_material_providers | #460, moved from unapplied 82 |
| 84 | recipient_channel_verification | #461 must move unapplied 81 |
| 85 | weekly_digest_recipient_claim_token | #461 must move unapplied 82 |
| 86 | certops_distribution_lifecycle | Unapplied lifecycle schema |
| 87 | certops_distribution_incident_delivery | Unapplied incident delivery |
| 88 | certops_stable_consumer_discovery | Unapplied consumer discovery |
| 89 | certops_material_cleanup | Unapplied retention cleanup |
| 90 | certops_consumer_verification_failures | Unapplied verification outcomes |
| 91 | certops_distribution_resolution_delivery | Unapplied recovery delivery |
| 92 | pagerduty_incident_lifecycle | Independent PagerDuty tail |
| 96 | agent_credential_rotations | Credential rotation preparation and receipt |
| 97 | agent_credential_rotation_ack | Credential rotation acknowledgement |

Use the normal runner with these canonical identities. Independent feature tails
may leave unapplied reservations absent; never install no-op SQL to fill them.
Recognized applied previews retain their names, numbers, SQL and timestamps.
Only missing definitions are assigned; duplicate feature definitions must be
removed when composing branches. Unknown, conflicting or unrecognized histories
fail before DDL and require reviewed recovery. Database compatibility does not
qualify the corresponding runtime feature or production artifact.

## Applied history and supported previews

The runner serializes concurrent migrations before reading history. Fresh
installs and released main through 78, 79, 80, 81 or 82 append provider schema at 83.
The same unmodified provider SQL is used for known #460 preview histories:

- Providers at 78, then installed assurance at 79: append stats at 80,
  run metrics at 81, metric labels at 82 and system metrics at 83.
- Installed assurance at 78, providers at 79: append stats at 80,
  run metrics at 81, metric labels at 82 and system metrics at 83.
- Installed assurance at 78, stats at 79, run metrics at 80, providers at 81
  (including #460 `66f94086`): append metric labels at 82 and system metrics at 83.
- Installed assurance at 78, stats at 79, run metrics at 80, metric labels at 81,
  providers at 82 (#460 `6d685f95`): append system metrics at 83.

Partial recognized prefixes and the older distribution/enrollment preview
histories remain supported. Never update recorded names, execution timestamps,
SQL or customer records to make the ledger look canonical. The upgrade tests
run historical SQL through the executor, preserve retained material and counter
evidence, and replay concurrent/restarted runners.

A ledger containing another PR's former 81 is not a provider alias. Unknown or conflicting histories fail before migration DDL. Do not manually edit them.
In particular #496's earlier PagerDuty-at-79 preview requires its explicit
backup/check/apply recovery procedure, using its independent reservation 92; this build
does not silently relabel it. Any deployed #461/#498 preview needs a separately
reviewed history-aware recovery before integrating the associated feature.

## Cleanup contract handoff to #498

Use separate `operation` and `provider` identities from the shared
`packages/contracts/certops/material-provider.cjs`. Legacy cleanup `type` is
accepted only for the exact Vault soft-delete operation and cannot override
provider identity. Canonical `operation: "soft-delete"` is supported alongside
the earlier explicit `operation: "vault-kv2-soft-delete"`; normalization never
rewrites a signed intent. A future Vault `deletion_time` is a readable scheduled
version, not completed deletion; retention and metadata readback still apply.
#498 must preserve its independent approval, exact-version
reference fence, local cleanup credential/retention checks and claim-bound
receipt admission when consuming the shared adapter. Its contract schemas and
intent producer must accept the explicit operation/provider shape together;
never alter already signed jobs to migrate the wire shape.

Windows/IIS and Azure production capability gates remain disabled. Database
compatibility or local protocol tests do not qualify either production artifact.
