# Distribution lifecycle implementation and qualification status

Updated 2026-11-03 for [PR #498](https://github.com/tokentimerch/tokentimer-core/pull/498) and issue #248. The branch integrates the merged provider (#460), recipient-verification (#461) and PagerDuty (#496) runtimes. Its increments are unreleased. Use the [operator guide](distribution-lifecycle.md), [migration compatibility guide](distribution-compatibility.md), [cleanup protocol](distribution-retention-cleanup.md) and [current scope/completion matrix](pr498-merge-readiness-20261103.md). Earlier acceptance attempts remain in the [historical record](pr498-completion-20261103.md).

## Available behavior

The [production qualification follow-up](pr498-production-qualification-20261103.md)
records fresh complete Vault and OpenBao packaged baseline journeys at `037a8d2c`
(15 strict phases and 41 product checks each). All five extension capabilities
remain unqualified and absent from the manifest. Independent implementation
review, trusted-main native campaigns and independent evidence acceptance remain
required; Azure spending opt-in is currently false.

- Manual publication is the default. Approval requests and reviewed automatic rollout require deliberate configuration and current independent authority.
- Consumer administration, bounded waves, calendars, recurring verification, drift incidents, durable recovery delivery, discovery and preflight reuse signed jobs and public evidence. Verification and incident policies start disabled.
- Retention is report-only by default. Exact-version Vault soft deletion requires administrator action, independent approval, runtime/group/customer opt-ins and a separately qualified cleanup artifact. Reuse fences survive uncertainty and cancellation.
- OpenBao distribution is supported. Azure, shared Windows/IIS and material cleanup retain their production qualification boundaries. Settings alone cannot bypass a compiled capability gate.
- Linux independent preparation has separate signed jobs, protected local staging and public preparation receipts. It requires explicit server policy, customer-local opt-in and the separately gated `material-consumer-staging-v1` capability. Preparation does not establish installation, service use or trust. Windows independent preparation remains unavailable.
- Exact manual rollout reviews recheck requester/reviewer membership before expansion and every claim or retry. Revocation after preparation pauses the rollout before activation. A committed cleanup acknowledgement accepts only its exact persisted receipt, including after an API restart or interrupted HTTP response.

## Upgrade and acceptance

Run the normal composed migration plan before starting matching API/workers. Fresh installations run through version 97 (`certops_review_authority_epochs`); recognized preview histories preserve applied rows and append missing identities. Version 97 requires fresh independent review for existing distribution authorizations and makes reviewer removal/restoration durably invalidate old reviews. Back up existing databases and allow time for outcome/recovery backfills. Upgrade agents before enabling calendars (`maintenance-calendar-v1`).

Automated regression coverage includes real PostgreSQL migration histories, independent approvals, recurring failure accounting, cleanup races, provider readback and durable notification recovery. Full candidate CI and at least one complete supported enrolled-agent journey are final merge-review evidence; broader real-fleet and live-provider acceptance retains its actual scope. Protected native qualification is required before promoting a gated capability or claiming a qualified release. The [merge-readiness record](pr498-merge-readiness-20261103.md) records the actual final decision and outstanding review; optional qualification and new connectors are not substituted for required supported-flow validation.

## Frozen and deferred scope

The existing lifecycle includes version-pinned publication/distribution, independent review, consumer management, canary waves, calendars, supported Linux activation, verification/monitoring, incident recovery and retention preview. Cleanup, shared IIS material activation, Azure storage and independent Linux staging exist in source but remain gated by the production manifest. Shipped baseline Windows store/IIS support is separate from shared-material IIS qualification.

SQL Server, Exchange, RDP/RDS, NPS/LDAPS and other Windows service connectors, Windows independent staging, unsupported restart/refresh methods, arbitrary commands, appliances, additional providers and full MSP ITSM integration are deferred. Keep #504, #366, #369, #376 and their service-specific follow-ups open; no extension is a new requirement for PR #498. See the matrix for exact backlog references.
