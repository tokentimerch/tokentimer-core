# Public CA capacity admission qualification

Six strict `ca-capacity-api` scenarios passed focused real API/PostgreSQL execution. Six simultaneous public issuance requests admit exactly five pending approval jobs under the default per-CA cap; the sixth receives the documented capacity conflict. Idempotency still resolves the existing job at capacity. Canonical endpoint variations cannot split one bucket, a different CA remains independently eligible, and an actual requester rejection releases capacity for another request. Failed reservations preserve job, certificate and outbox counts.

The suite uses genuine public admission and approval decisions with no CA requests, fake completed jobs or direct database business-state mutation. Its supporting integration classification does not claim manual/bulk renewal, scheduled waiting or native issuance completion. Those remain explicit catalog gaps. Hosted/full CI qualification remains pending.
