# Actual elapsed log abandonment and production worker retention

The manual `certops-log-maintenance-qualification.yml` workflow owns an exclusive disposable API/PostgreSQL stack. Its `agent-log-maintenance-worker` suite is separate from the standard API runner because retention purge has global scope. No push automatically starts the five-minute wait.

A genuinely registered protocol fixture claims a noop, submits two public diagnostic lines and posts its signed terminal success result. The database must record the production default upload grace as exactly 300,000 milliseconds. A separate Node child invokes the unchanged production `runCertOpsMaintenance` function with only the selected log sweep enabled; every other current sweep is disabled through its exported configuration. The child refuses foreign workspace log data and reports bounded counters over IPC. Raw worker output and credentials are excluded from artifacts.

Seven mandatory cases require:

- Real diagnostic persistence and terminal job success, without a final log batch.
- An actual worker pass before expiry that preserves both lines and the streaming state.
- At least five monotonic minutes after result ingestion, an independently expired PostgreSQL deadline, and another actual worker pass that abandons the stream while preserving its rows and the succeeded job.
- Refusal of a new late upload, without additional lines or a changed job result.
- The supported `CERTOPS_AGENT_LOG_RETENTION_DAYS=0` policy deleting both recently received lines through the production purge sweep. The abandoned stream tombstone remains during its additional retention window.
- A repeated worker purge deleting nothing further, with an empty public console response and unchanged job outcome.
- Confirmed owned child exits before fixture rows are removed. Cleanup failure fails qualification.

Host clocks, database timestamps, stream states and job outcomes are never rewritten by the fixture. Retention zero tests the supported storage-off policy; it does not claim that a full day of retention elapsed. The diagnostics and noop result come from a protocol client, not an installed native agent or certificate operation.

`CERTOPS_LOG_MAINTENANCE_EXCLUSIVE_STACK=1` and `CERTOPS_CSR_DISPOSABLE_STACK=1` are required. The report path is `CERTOPS_LOG_MAINTENANCE_REPORT`. `scripts/certops-log-maintenance-report.js` requires every named case, a matching candidate, current parent/helper/worker/service source hashes and bounded genuine elapsed-time evidence. The release matrix requires this report separately; a standard API-stack report cannot substitute for it.

Focused local execution passed all seven cases with no skips after 300.16 seconds of monotonic waiting. Independent report verification passed. The report records local worktree source and a baseline commit; hosted execution and release qualification remain pending.
