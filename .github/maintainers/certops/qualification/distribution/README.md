# Certificate distribution qualification

Baseline Vault/OpenBao publication and Linux deployment are in the shipped
agent capability manifest. Azure, shared Windows/IIS material deployment,
independent staging and cleanup remain separately gated. Passing a
source-mounted lab is supporting E2E evidence, not production release approval.
Shared policy: [certificate lifecycle qualification](../../e2e-qualification.md).
Current implemented/future scope: [PR #498 merge review](../../../../../docs/certops/pr498-merge-readiness-20261103.md).
Current per-capability evidence and remaining approvals/native campaigns:
[2026-11-03 qualification record](../../../../../docs/certops/pr498-production-qualification-20261103.md).

Use the trusted workflow inputs to select disposable supporting runs. Core product CI remains separate.

## Reproduce the supporting runs

The operator journey exercises workspace approval off: a requester starts a
rollout, both enrolled consumers complete, and fresh strict TLS matches the
selected certificate version without a second user or an approval call.
Separate approval scenarios explicitly opt in with `requiresApproval: true`;
the PostgreSQL cohort also covers workspace-forced approval and deployment
children, forbidden self-approval, default-off execution and legacy requests.
Scheduled renewal follows that same workspace setting. These checks do not
claim that publication automatically schedules a consumer rollout.

Compose teardown runs even after failure. Do not reuse a test project's containers or credentials for a later run. Live infrastructure execution and cleanup still require CI qualification; local fixture tests alone do not prove delivery.
