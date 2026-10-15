# Public renewal setup for an owned Linux certificate

This mandatory source exercises supported renewal re-setup for a genuinely owned
agent-local certificate. It does not import or adopt an unknown private key.
It runs in the existing Ubuntu24 certbot/noEAB journey after public bulk
renewal and is required by its release matrix cell. Native qualification
remains pending; offline proof checks do not replace actual execution.

The existing Ubuntu24 certbot/noEAB journey first owns two actual issued and
renewed certificates through its public bulk-renewal case, then stops their
management periods. The new producer selects the first exact certificate and
reopens management through public `sources/:id/readd` with no profile and
`automationEnabled:false`. No database row, journal, timestamp or custody fact
is fabricated.

A real signed `renewal-setup` dry run and its public idempotent replay must
complete as `dry_run_complete`, retain the same native certificate/key and
trusted serving TLS, leave the profile association empty and create no adoption
intent. A subsequent real public setup and replay must produce one new real job,
current claim, genuine CA leaf, changed serial/SPKI, matching local private key,
trusted TLS and claim-bound verification evidence.

Only after that genuine native success does the producer invoke the actual
production `drainCertOpsOutbox({dbPool, env:process.env})`. It supplies no clock,
resolver, derivation implementation or scheduling override. The real pending
outbox must contain exactly its own authentic adoption intent, and that exact
row must finish on its first attempt. Public certificate detail must show the
same setup job as configured. This is an explicit drain, not an unattended
worker qualification or a transient parked-intent retry.

Production may reuse the certificate-qualified derived profile row and replace
its derivation metadata. The oracle compares execution policy and the operator
fields production promises to preserve, rather than demanding unchanged
derivation timestamps. The manually reopened period remains manual: profile
configuration does not itself enable that period's automation. Its exact period
is publicly stopped afterward.

The original primary certificate's private bytes, trusted TLS and operator
profile remain independently unchanged. A retained in-process TLS listener and
all accepted/probe sockets must close before its guard is removed. Unknown
mutation, changed ownership or failed drainage leaves sticky ownership for the
parent to preserve database records and private files. Private key material and
private-key hashes are local-only and never enter the public proof.
