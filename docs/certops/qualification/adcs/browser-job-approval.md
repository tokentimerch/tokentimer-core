# Browser approval of native AD CS jobs

This journey exercises the existing Jobs page's control-plane approval gate. It does not approve a request at the certificate authority and does not claim a CA officer UI.

The existing capacity fixture supplies two genuine requested AD CS enrollments whose jobs are pending approval. A distinct owned workspace manager logs into the dashboard and searches the exact job ID. The real filtered API response and visible job details must identify that job. Opening the approval dialog and choosing Cancel must produce no CertOps mutation, approval decision or job change. Reopening it, entering a bounded reason and confirming must produce exactly one real public approval response with status 200; unrelated CertOps writes fail the scenario.

Each append-only decision must identify the real manager and independently match the production payload and canonical execution-intent hashes. One of the four remaining never-approved jobs is also rejected through its real Jobs dialog. Cancel has zero writes; confirmation has exactly one actual rejection response with status 200. The append-only rejection records the manager and reason and retains the product’s null payload/intent hash fields. Independent before/after hashes require the job’s execution intent to remain unchanged. The job must be rejected with zero claims or attempts, no CA request, no enrollment journal and no CNG key; the remaining three requests retain their public API cleanup.

The existing capacity fixture then independently verifies real CA issuance, native protected CNG custody, IIS/SNI and trusted TLS. The browser proof must bind both approved jobs and enrollment IDs to those same two native generations; database and production journal state must be installed. Browser and temporary trust ownership must drain.

This source and its pure report/decision tests do not constitute native browser qualification. Execution on the protected disposable Windows domain lane remains pending. No new CA request or additional preflight is needed beyond the two existing capacity installations. Requester self-approval and other job types remain separate coverage.

Implementation: `tests/e2e/helpers/certops-adcs-browser-job-approval.js`. Supporting pure checks: `scripts/certops-adcs-browser-job-approval.test.js`.
