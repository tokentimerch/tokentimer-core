# Renewal path topology qualification

The mandatory `renewal-health` supporting integration group executes fifteen existing production resolver cases against actual PostgreSQL. It covers pinned and open-claim execution paths, redundant executors, partial/all-location outage forecasts, retired agents, missing target/profile/custody, disabled profiles, retired certificates and dependency counts. No SQL query or resolver is mocked.

All fifteen cases passed focused execution through the strict inventory/report wrapper. Initial certificate/profile/agent/liveness rows are explicitly seeded database prerequisites, so the results prove query and eligibility semantics rather than an actual service outage or custody. The separate manual integration workflow executes the complete literal case inventory without skips and preserves source-bound sanitized reports. Native host recovery, public health presentation and full CI remain pending.
