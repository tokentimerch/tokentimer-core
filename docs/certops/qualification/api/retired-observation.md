# Retirement and fresh observation qualification

The seven mandatory `retired-observation-lifecycle` cases run through the actual authenticated API and PostgreSQL with an owned HTTPS endpoint. OpenSSL generates two public leaves and their local private keys. An independent TLS client trusts only those fixture certificates and verifies the exact served fingerprint before each rotation.

Public monitor creation and update requests perform the certificate scan. The separate endpoint `/check` action checks health and is not used as evidence of a fresh certificate observation. The suite requires persisted capture time to advance, so a successful response with cached data cannot satisfy the rescan oracle.

Missing, empty, nonprintable and oversized retirement reasons must fail without changing identity or audit rows. After public retirement, three concurrent certificate rescans preserve exact lifecycle status, retirement reason/time, one identity and the original retirement audit. A genuine old/new/old served-leaf sequence preserves both observation histories and keeps the original identity revoked and excluded from the active-only inventory.

Focused local execution passed all seven cases and its strict source-bound report verifier. This qualifies public endpoint observation and control-plane lifecycle behavior; it does not prove Windows store removal, agent key custody or certificate replacement by an installed service.
