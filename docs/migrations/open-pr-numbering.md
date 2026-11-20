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
| 107 | certops_issuance_job_identity | Main; unchanged |
| 108 | certops_issuance_identity_transfer | Main; unchanged |
| 109 | certops_period_creator_delete | Main; unchanged |
| 110 | recipient_member_verification | Reuse exact verified workspace-member email proof |
| 112 | certops_retirement_dossiers | Distribution lifecycle on main |
| 113 | certops_material_reconciliation | Distribution lifecycle on main |
| 114 | distribution_pagerduty_recovery | PagerDuty distribution recovery on main |
| 115 | store_issuance_explicit_renewal_consent | Windows Store issuance consent |
| 116 | certops_acme_store_enrollment_identity | Windows Store ACME enrollment identity |
| 117 | certops_adcs_expected_identity_receipts | Windows Store AD CS identity receipts |
| 118 | certops_windows_iis_consent | Windows IIS reassociation consent |
| 119 | certops_material_adcs_operation_union | Preserve material and AD CS job operations |
| 120 | certops_iis_absence_proofs | Reconcile proven IIS observations |
| 121 | certops_enrollment_jobs_index | Index enrollment jobs |
| 122 | certops_observed_revocation | Observed certificate revocation (#541) |
| 126 | certops_adcs_receipt_deadline | Immutable AD CS receipt admission deadline |

The integrated Windows Store and IIS preview previously used 115 for observed revocation and 116–122 for Store and IIS. The runner preserves those recorded pairs and appends only missing definitions.
