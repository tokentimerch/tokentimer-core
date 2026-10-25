# Customer Vault distribution testing

Run `certops-distribution-qualification.yml` from trusted main. It uses disposable Docker services rather than Azure and covers ordinary, SAN and wildcard certificate distribution, PostgreSQL state/authorization, Vault delivery, browser journeys and privacy checks.

The workflow runs only through manual dispatch on main; pushes and pull requests do not start it. Core product CI remains separate.

A successful run must execute every required cohort with no missing prerequisites or hidden skips. Sanitized JSON reports identify the candidate and test counts; inspect failed cohort artifacts before rerunning. Private keys and credentials must stay out of console logs and uploaded artifacts.

The operator journey exercises workspace approval off: a requester starts a
rollout, both enrolled consumers complete, and fresh strict TLS matches the
selected certificate version without a second user or an approval call.
Separate approval scenarios explicitly opt in with `requiresApproval: true`;
the PostgreSQL cohort also covers workspace-forced approval and deployment
children, forbidden self-approval, default-off execution and legacy requests.
Scheduled renewal follows that same workspace setting. These checks do not
claim that publication automatically schedules a consumer rollout.

Compose teardown runs even after failure. Do not reuse a test project's containers or credentials for a later run. Live infrastructure execution and cleanup still require CI qualification; local fixture tests alone do not prove delivery.
