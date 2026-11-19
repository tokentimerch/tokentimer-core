# Migration integration for PRs 406, 460, 461, 496 and 498

Main owns migrations 78–85, 92–95 and 98.
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
| 83 | certops_material_providers | Main; unchanged |
| 84 | recipient_channel_verification | Main; unchanged |
| 85 | weekly_digest_recipient_claim_token | Main; unchanged |
| 86 | certops_distribution_lifecycle | Unapplied lifecycle schema |
| 87 | certops_distribution_incident_delivery | Unapplied incident delivery |
| 88 | certops_stable_consumer_discovery | Unapplied consumer discovery |
| 89 | certops_material_cleanup | Unapplied retention cleanup |
| 90 | certops_consumer_verification_failures | Unapplied verification outcomes |
| 91 | certops_distribution_resolution_delivery | Unapplied recovery delivery |
| 92 | pagerduty_incident_lifecycle | Independent PagerDuty tail |
| 93 | pagerduty_resolution_reason | PagerDuty resolution context |
| 94 | pagerduty_operator_actions | Main; unchanged |
| 95 | remove_pagerduty_rest_lookup | Main; unchanged |
| 96 | certops_consumer_staging | Reserved consumer staging |
| 97 | certops_review_authority_epochs | Reserved review authority |
| 98 | certops_manual_rollout_authority | Main; unchanged |
| 99 | operator_connections | MCP scoped connections (#406) |
| 100 | operator_enrollment_grants | Optional local adapter enrollment (#406) |
| 101 | operator_action_requests | MCP renewal requests (#406) |
| 102 | operator_oauth | Remote MCP sign-in (#406) |
| 103 | operator_connection_lifetimes | MCP access duration (#406) |
| 104 | operator_inventory | MCP inventory metadata import (#406) |
| 105 | operator_oauth_retention | MCP token retention (#406) |
| 106 | operator_issuance | MCP certificate issuance (#406) |
| 109 | certops_period_creator_delete | Main; unchanged |
| 110 | recipient_member_verification | Reuse exact verified workspace-member email proof |
| 114 | distribution_pagerduty_recovery | Main; destination-bound incident delivery recovery |
| 115 | store_issuance_explicit_renewal_consent | Explicit Windows Store renewal consent |
| 116 | certops_acme_store_enrollment_identity | Agent-bound ACME Store enrollment identity |
| 117 | certops_adcs_expected_identity_receipts | Claim-bound AD CS expected identity |
| 118 | certops_windows_iis_consent | IIS binding consent |
| 119 | certops_material_adcs_operation_union | AD CS operation union |
| 120 | certops_iis_absence_proofs | IIS absence proofs |
| 121 | certops_enrollment_jobs_index | Enrollment job lookup |
| 122 | certops_observed_revocation | Observed revocation |
| 123 | agent_credential_rotations | Agent credential rotation |
| 124 | agent_credential_rotation_ack | Agent credential rotation acknowledgement |
| 125 | certops_adcs_preflight_lookup_index | AD CS preflight lookup |
| 126 | certops_adcs_receipt_deadline | Immutable AD CS receipt admission deadline |

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

The retirement preview at 109 also preserves either recovery-first or Store-first
append histories after 110–113, including partial Store prefixes. Missing definitions
are appended without changing applied rows. The receipt deadline uses canonical
126 on fresh main installations; these recognized previews record it at 117 or
118. Do not manually relabel them.

The MCP preview with mainline schemas through 82 and operator schemas at
83–85 keeps those applied rows. The runner appends missing provider, recipient
and PagerDuty schemas without reapplying MCP SQL. The later preview with MCP at
94–96 also retains its applied identities; missing mainline PagerDuty definitions
are appended after that tail. The later draft with MCP at 96–103 also keeps its
applied identities and appends missing authority work. Fresh installs use MCP 99–106. Do not manually
renumber an existing preview database.

A ledger containing another PR's former 81 is not a provider alias. Unknown or conflicting histories fail before migration DDL. Do not manually edit them.

An unrecognized Windows Store preview with Store migrations at 109–111 conflicts with released identities and is rejected before DDL. Preserve its ledger and use a separately reviewed recovery; do not manually relabel it.
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

Database compatibility and local protocol tests cover the migration and wire
contract. See [distribution availability](../certops/distribution-extensions.md)
for the production capability requirements.
