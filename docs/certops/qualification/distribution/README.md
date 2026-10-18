# Customer Vault distribution testing

Run `certops-distribution-qualification.yml` from trusted main. It uses disposable Docker services rather than Azure and covers ordinary, SAN and wildcard certificate distribution, PostgreSQL state/authorization, Vault delivery, browser journeys and privacy checks.

The workflow runs only through manual dispatch on main; pushes and pull requests do not start it. Core product CI remains separate.

A successful run must execute every required cohort with no missing prerequisites or hidden skips. Sanitized JSON reports identify the candidate and test counts; inspect failed cohort artifacts before rerunning. Private keys and credentials must stay out of console logs and uploaded artifacts.

Compose teardown runs even after failure. Do not reuse a test project's containers or credentials for a later run. Live infrastructure execution and cleanup still require CI qualification; local fixture tests alone do not prove delivery.
