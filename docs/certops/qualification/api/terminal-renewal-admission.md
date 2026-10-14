# Terminal certificate renewal admission

`terminal-renewal-admission-api` checks actual public manual and bulk renewal after operator retirement and factual TLS rediscovery. Six mandatory scenarios exercise real authenticated API requests and PostgreSQL. Complete linked agent-local renewal profiles/key mode are explicitly seeded prerequisites; certificate material, initial identity and later observations come from genuine public imports and trusted loopback TLS. No jobs, certificate expiry or observations are seeded.

The active positive control first creates a real manual renewal awaiting approval for each of two certificates, then publicly rejects those jobs. The suite publicly retires one identity as revoked and the other as decommissioned. An independent TLS client trusts only the corresponding owned certificate and verifies its exact fingerprint before public domain scanning records factual use. This factual use preserves terminal lifecycle status.

Manual renewal must then return `409 CERTOPS_CERTIFICATE_NOT_RENEWABLE`, while the bulk route returns the same per-item code. Exact persisted jobs, outbox rows, token expiry/lifecycle, identities and audit history remain unchanged by each refusal. Cleanup removes the fixture workspace, temporary private files and owned TLS listeners.

This regression reproduced an actual admission difference: the old manual route accepted a fully profiled revoked certificate with HTTP201 after rediscovery, while bulk renewal already refused it. The shared manual/bulk materializer now checks persisted retirement before constructing its renewal profile. A public import without a profile is not used as false proof of that guard; the active positive control establishes that the complete prerequisite could otherwise admit the request.

Focused local execution passed all six cases using a separate candidate API process against an explicitly disposable database. These are control-plane admission assertions; no CA issuance, native key installation, hosted matrix or full release qualification is established by this report. Reports bind the current test, API fixture, jobs service and route source hashes.
