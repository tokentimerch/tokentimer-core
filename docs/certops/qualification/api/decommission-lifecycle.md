# Decommission acknowledgement and factual rediscovery

The `decommission-lifecycle-api` suite exercises the public API with real PostgreSQL, independently generated public certificates, the native public-file collector and a trusted loopback TLS endpoint. It does not seed observation rows or claim that an installed agent removed a certificate.

Seven mandatory scenarios cover:

- Public import creates an identity without inventing an observed location.
- Missing or false uncertainty acknowledgement returns `428 CERTOPS_VISIBILITY_ACK_REQUIRED`, preserving identity, token and retirement audit rows.
- Explicit acknowledgement records terminal decommissioning once, without inventing deployment evidence.
- Actual registered-protocol ingestion of a native filesystem scan produces a stored-copy location. Decommissioning still requires acknowledgement and preserves that observation.
- A later real TLS scan records factual use of the same public fingerprint while preserving the operator's terminal status, token projection and audit history.
- Three concurrent rescans advance observation freshness without duplicate fingerprint identities or source instances, reactivation, or additional retirement audits.
- Cleanup removes only the owned workspace, temporary files and TLS listener.

Run through the disposable API qualification runner, or run `node --test tests/e2e/certops-decommission-e2e.test.js` with its documented API/PostgreSQL fixture environment and `CERTOPS_DECOMMISSION_REPORT` set to a report path. Strict execution requires `CERTOPS_E2E_REQUIRED=1` and explicit `CERTOPS_CSR_DISPOSABLE_STACK=1` authorization. Reports bind the exact test source hash and candidate baseline; local worktree evidence does not qualify a hosted release slot.

Focused local execution passed all seven scenarios, including cleanup. The public-file scan ran on the local Windows filesystem; it does not prove Windows Certificate Store/CNG custody or native certificate removal. Hosted workflows, real enterprise infrastructure and full release qualification remain separate execution requirements.
