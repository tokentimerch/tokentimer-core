# Fleet execution-log quota qualification

The `agent-log-quota-api` suite registers real fixture agents and claims real noop jobs through the authenticated API, then calls production log ingestion against PostgreSQL with a supplied 1000-byte daily budget. Public diagnostic lines and the supplied service environment are explicit fixtures; the suite does not change the shared API environment, fabricate quota records, or run an installed agent.

Six mandatory scenarios check two streams racing one workspace/day budget, cached acknowledgement replay without additional charges, independent workspace budgets, disabled storage without charges, telemetry finalization preserving claimed job state, and owned fixture cleanup. Database row counts, byte bounds and drop counters provide independent persistence oracles.

Run through `scripts/certops-api-qualification.js` on an explicitly disposable stack. The dedicated report uses `CERTOPS_LOG_QUOTA_REPORT`; strict verification requires all six named cases. Focused local execution passed against the actual API/PostgreSQL fixture and its independent report verifier. This supporting integration evidence does not qualify native fleet load, exhausted long retry budgets, retention over elapsed days, or browser/Windows console behavior.
