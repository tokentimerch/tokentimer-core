# Migration integration for PRs 460, 461, 496 and 498

Main at `d2f7dbd498e5c257859427562db0888d7879cdff` owns migrations 78–81.
Do not rename, replace or reinterpret released rows. These canonical numbers
are enforced by `apps/api/migrations/migration-reservations.cjs`; missing PRs
are reservations, not no-op migrations. They do not install another feature.

| Version | Canonical name | Owner / integration action |
|---|---|---|
| 78 | certops_installed_file_distribution | Released main; unchanged |
| 79 | auto_sync_provider_stats | Released main; unchanged |
| 80 | auto_sync_run_metrics | Released main; unchanged |
| 81 | auto_sync_metric_labels | Released main (#513); unchanged |
| 82 | certops_material_providers | #460, moved from unapplied 81 |
| 83 | recipient_channel_verification | #461 must move unapplied 81 |
| 84 | weekly_digest_recipient_claim_token | #461 must move unapplied 82 |
| 85 | pagerduty_incident_lifecycle | #496 must move unapplied 81 |
| 86 | certops_distribution_lifecycle | #498 must move unapplied 81 |
| 87 | certops_distribution_incident_delivery | #498 must move unapplied 82 |
| 88 | certops_stable_consumer_discovery | #498 must move unapplied 83 |
| 89 | certops_material_cleanup | #498 must move unapplied 84 |
| 90 | certops_consumer_verification_failures | #498 must move unapplied 85 |

This change updates only #460. Related heads inspected: #461 `b8c50642`,
#496 `99101c10`, #498 `e758dd0f`. Their maintainers must adopt these reservations
in SQL filenames/registries, fixtures, recovery tooling and documentation before
integration. Do not merge their old 81 registrations or reuse reserved numbers.
No dependency on those unmerged features is introduced into #460.
With the current contiguous-history runner, integrate the canonical blocks in
order: #460, #461, #496, then #498. Do not ship a gapped ledger by merging a
later block first. A different merge order requires a separately reviewed
history-composition change; reservations must not be filled with no-op SQL.

## Applied history and supported previews

The runner serializes concurrent migrations before reading history. Fresh
installs and released main through 78, 79, 80 or 81 append provider schema at 82.
The same unmodified provider SQL is used for known #460 preview histories:

- Providers at 78, then installed assurance at 79: append stats at 80,
  run metrics at 81 and metric labels at 82.
- Installed assurance at 78, providers at 79: append stats at 80,
  run metrics at 81 and metric labels at 82.
- Installed assurance at 78, stats at 79, run metrics at 80, providers at 81
  (including #460 `66f94086`): append metric labels at 82.

Partial recognized prefixes and the older distribution/enrollment preview
histories remain supported. Never update recorded names, execution timestamps,
SQL or customer records to make the ledger look canonical. The upgrade tests
run historical SQL through the executor, preserve retained material and counter
evidence, and replay concurrent/restarted runners.

A ledger containing another PR's former 81 is not a provider alias. Unknown,
gapped or mixed histories fail before migration DDL. Do not manually edit them.
In particular #496's earlier PagerDuty-at-79 preview requires its explicit
backup/check/apply recovery procedure, updated for reservation 85; this build
does not silently relabel it. Any deployed #461/#498 preview needs a separately
reviewed history-aware recovery before integrating the associated feature.

## Cleanup contract handoff to #498

Use separate `operation` and `provider` identities from the shared
`packages/contracts/certops/material-provider.cjs`. Legacy cleanup `type` is
accepted only for the exact Vault soft-delete operation and cannot override
provider identity. #498 must preserve its independent approval, exact-version
reference fence, local cleanup credential/retention checks and claim-bound
receipt admission when consuming the shared adapter. Its contract schemas and
intent producer must accept the explicit operation/provider shape together;
never alter already signed jobs to migrate the wire shape.

Windows/IIS and Azure production capability gates remain disabled. Database
compatibility or local protocol tests do not qualify either production artifact.
