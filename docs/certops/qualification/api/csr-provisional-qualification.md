# Shared CSR ownership and truthful installation evidence

`tests/e2e/certops-csr-provisional-e2e.test.js` runs eight mandatory supporting integration scenarios through an authenticated disposable API and PostgreSQL stack. It uses fresh, independently verified OpenSSL CSRs and public signed leaves. Local private keys remain in the owned fixture directory and are never submitted; unchanged file digests are a local integrity oracle, not proof of native key custody.

- Two workflows on distinct manual targets import the same public leaf and share one provisional certificate with no token or observed instance.
- Cancelling one preserves the other workflow's signed material and provisional owner. Cancelling the last removes only the unreferenced provisional certificate. Replays retain public workflow history and write no duplicate cancellation audit.
- Three pairs of concurrent public cancellation requests exercise the last-reference race without changing database clocks, directly deleting references, or weakening foreign keys.
- Manual installation confirmation creates an active identity and inventory token, records a manual completion audit, and leaves `observedInstanceId` null with zero physical instances. Cancelling a sibling preserves the active identity and token. Repeated confirmation is refused without another completion event.
- A real loopback TLS endpoint rotates to the shared public leaf. An independent TLS peer fingerprint agrees with the actual monitor scan. Both provisional workflow references move to the observed logical certificate; only the monitored target completes by observation. The other target remains pending with no invented observation, and its cancellation cannot remove the observed certificate.
- A different endpoint first establishes real ownership of a later leaf. When the selected target subsequently serves that leaf, its observation remains owned by the other certificate and records a CSR identity conflict. Acknowledging changed names cannot promote or transfer the selected identity, alter its token expiry, or create a completion audit. Reobservation retains that boundary without duplicate conflict audit.
- Cleanup closes both owned HTTPS listeners and removes only the fixture's users, workspaces and temporary public/private material.

The suite is registered as `csr-provisional-api` in the API qualification runner and required release matrix. `CERTOPS_CSR_PROVISIONAL_REPORT` selects its strict report path. Required capabilities are `api`, `postgres` and `openssl`; the report must include every mandatory scenario and the digest of the current harness source.

Use the standard disposable stack prerequisites described in the [qualification overview](../../e2e-qualification.md). For a focused run, set `CERTOPS_CSR_API_URL`, `CERTOPS_CSR_DISPOSABLE_STACK=1`, `CERTOPS_E2E_REQUIRED=1`, `CERTOPS_QUALIFICATION_STRICT=1`, the database connection variables and the candidate `GITHUB_SHA`, then run:

```powershell
$env:CERTOPS_CSR_PROVISIONAL_REPORT = "qualification-results/csr-provisional.json"
node --test tests/e2e/certops-csr-provisional-e2e.test.js
node scripts/certops-qualification-report.js $env:CERTOPS_CSR_PROVISIONAL_REPORT
```

Focused local execution passed all eight scenarios with no skips. This proves the public API, database ownership and real monitor-observation boundaries. The OpenSSL signer and direct TLS context replacement are owned fixture actions; the suite does not qualify a native CA, agent certificate deployment, Windows CNG custody, or a released package. Native host qualification remains separate.
