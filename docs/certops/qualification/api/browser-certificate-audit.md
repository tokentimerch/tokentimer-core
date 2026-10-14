# Browser certificate audit qualification

`browser-certificate-audit` exercises the real `/audit` page in Chromium against an explicitly disposable API/PostgreSQL stack. It creates eleven public certificate retirements whose reasons contain a unique literal percent/underscore marker, one same-workspace wildcard decoy, and one retirement in a separate fixture workspace. OpenSSL creates actual public certificates; authenticated import and retirement routes create every audit event. No audit, job, observation or expiry rows are fabricated.

The six mandatory scenarios verify:

- Persisted actor, subject, workspace, retirement action, target type, identity ID, fingerprint, reason and lifecycle match the real public requests. Retirement target attribution is carried in metadata; the route legitimately stores a null generic target ID.
- Actual browser search treats percent and underscore literally and excludes the wildcard decoy. Visible retirement metadata includes the expected reason and fingerprint.
- The real action selector excludes unrelated import actions and restores retirement results.
- Next/Previous navigation shows ten then one matching events, without duplication or omission. Actual authenticated response IDs must equal independently ordered PostgreSQL event IDs. This is stable pagination over a completed fixture, not a concurrent-write snapshot guarantee.
- The visible workspace results exclude the foreign retirement, while both independent authenticated API requests and the browser's real cookie session receive HTTP 403 for that foreign workspace.
- Browser, fixture users/workspaces and generated private key files are removed. Temporary-file deletion requires the resolved direct temporary parent, exact generated directory name and a non-symlink root. Cleanup errors preserve the original failure.

Run `node scripts/certops-browser-audit.js` with `CERTOPS_CSR_API_URL`, `CERTOPS_BROWSER_URL`, `CERTOPS_CSR_DISPOSABLE_STACK=1`, test database connection variables and `CERTOPS_BROWSER_AUDIT_REPORT`. The trusted manual dashboard workflow supplies these prerequisites and separately verifies the strict named report. Source fingerprints bind the producer, fixture helpers, dashboard audit page, public audit route and retirement service. Reports contain bounded outcomes and source identity, never cookies, key bytes, raw audit rows or screenshots.

Dispatch **CertOps / Real certificate dashboard qualification** from trusted `main`. The audit stage follows navigation, console and retirement visibility, independently verifies `qualification-results/browser-audit.json`, and uploads only the sanitized reports. Its separate Ubuntu 24.04 host release slot requires all six cases and current source hashes. Changes to the exact shared audit page select cheap tooling; Chromium, PostgreSQL and Windows host execution remain deliberate manual operations.

All six cases passed in a focused local Windows Chromium/API/PostgreSQL execution. Its report is explicitly classified as local working-tree evidence against the baseline SHA. The Ubuntu hosted workflow remains unexecuted. This control-plane/browser qualification makes no native CA, Windows store, certificate removal or live deployment claim.
