# Distribution lifecycle implementation and qualification status

Updated 2026-11-03 for [draft PR #498](https://github.com/tokentimerch/tokentimer-core/pull/498) and issue #248. The branch integrates the merged provider, recipient-verification and PagerDuty runtimes. It has not been released or production-qualified. Use the [operator guide](distribution-lifecycle.md), [migration compatibility guide](distribution-compatibility.md), [cleanup protocol](distribution-retention-cleanup.md) and [current acceptance record](pr498-completion-20261103.md).

## Available behavior

- Manual publication is the default. Approval requests and reviewed automatic rollout require deliberate configuration and current independent authority.
- Consumer administration, bounded waves, calendars, recurring verification, drift incidents, durable recovery delivery, discovery and preflight reuse signed jobs and public evidence. Verification and incident policies start disabled.
- Retention is report-only by default. Exact-version Vault soft deletion requires administrator action, independent approval, runtime/group/customer opt-ins and a separately qualified cleanup artifact. Reuse fences survive uncertainty and cancellation.
- OpenBao distribution is supported. Azure, shared Windows/IIS and material cleanup retain their production qualification boundaries. Settings alone cannot bypass a compiled capability gate.
- Linux independent preparation has separate signed jobs, protected local staging and public preparation receipts. It requires explicit server policy, customer-local opt-in and the separately gated `material-consumer-staging-v1` capability. Preparation does not establish installation, service use or trust. Windows independent preparation remains unavailable.
- Exact manual rollout reviews recheck requester/reviewer membership before expansion and every claim or retry. Revocation after preparation pauses the rollout before activation. A committed cleanup acknowledgement accepts only its exact persisted receipt, including after an API restart or interrupted HTTP response.

## Upgrade and acceptance

Run the normal composed migration plan before starting matching API/workers. Fresh installations run through version 97 (`certops_review_authority_epochs`); recognized preview histories preserve applied rows and append missing identities. Version 97 requires fresh independent review for existing distribution authorizations and makes reviewer removal/restoration durably invalidate old reviews. Back up existing databases and allow time for outcome/recovery backfills. Upgrade agents before enabling calendars (`maintenance-calendar-v1`).

Automated regression coverage includes real PostgreSQL migration histories, independent approvals, recurring failure accounting, cleanup races, provider readback and durable notification recovery. Those checks do not establish real-fleet acceptance. The current combined candidate still requires end-to-end operator testing of renewal, publication, activation, trust, drift, channel delivery, recovery and cleanup, with exact artifact provenance and retained evidence. Protected native qualification remains a separate release requirement. Keep the PR in draft until the required manual checks and current-head CI pass.
