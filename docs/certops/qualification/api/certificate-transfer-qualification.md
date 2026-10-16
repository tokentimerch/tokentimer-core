# Certificate transfer qualification

The central `scripts/certops-api-qualification.js` runner executes `tests/e2e/certops-certificate-transfer-e2e.test.js` against the explicitly disposable API/PostgreSQL stack. The `certificate-transfer-api` report requires every committed named scenario and the current test source digest. It is supporting control-plane integration evidence.

Actual public requests prove that a caller needs management authority in both workspaces, including refusal for a destination viewer. A destination certificate identity collision refuses the entire transfer. A successful transfer keeps the token and certificate identity together, removes source-workspace visibility and makes replay a zero-move operation.

The suite creates a real OpenSSL CSR, imports its matching public certificate and records public manual installation confirmation before transfer. The completed CSR, public material, fingerprints, target identity and confirmation fields must survive unchanged in the destination. The original workspace must refuse CSR retrieval. Manual confirmation creates no physical certificate instance; this case does not claim native deployment, target binding or key custody.

Historical CSR audit events stay unchanged in their original workspace. The destination audit API must expose the new transfer event with the correct source, destination and actor, without copying those historical events. A separate fixture seeds only a valid target-to-token association prerequisite: the public transfer must refuse a CSR dependency linked to a token outside the requested transfer and preserve its certificate, target and workflow rows atomically.

All ten named scenarios, including owned cleanup, passed a focused local run against a separately owned API and migrated PostgreSQL fixture. Reports identify this as local worktree source with a baseline SHA; hosted qualification and native certificate transfer behavior remain pending.
