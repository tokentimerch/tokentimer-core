# Distribution extension merge validation — 2026-10-26

PR #460 merges main through `8ba7a118b08992855db697580697fed1cb3d9e31` into the
existing `feat/certops-distribution-extensions` branch, starting from clean PR head
`2ca3b2581ffbf3e140e3b05a864baedcb186e451`. The branch is not rebased or force
pushed, and the PR is not merged into main.
The first merge integrated `af0d826b`; a second preserves subsequent retirement
guards, timezone handling and dependency/action updates. Added PR jobs use the
same checkout pin as the updated main workflow. Both retirement regression
assertions are combined, including scoped parameters and retained source data.

## Conflict integration

Nine conflicted files were reconciled by combining their invariants:

- The agent lifecycle retains main's installed-file readback/no-reload path and
  the PR's multi-provider factory, mutation callbacks, Windows connector,
  cancellation, strict platform policy and uncertainty fencing.
- The consumer matrix combines policy-specific installed/served/trust proofs
  with the PR's immutable management-period constraint. The latter also follows
  the existing composite foreign key and does not block authorized retained
  rollback within the group.
- Test fixtures preserve both options-based installed cases and typed Windows
  seams; the trust receipt test uses the returned receipt ID, preserving main's
  concrete-store behavior. Main's Debian trust-store fresh revoke remains.
- Both migration test histories are retained and extended through 79. Vendored
  validators and skip inventory are regenerated with official scripts.

## Migration correctness

`078-certops-installed-file-distribution.sql` is byte-for-byte unchanged from
main. The provider SQL is moved unchanged to
`079-certops-material-providers.sql`; the canonical registry has unique,
sequential versions through 79.

The historical composer recognizes the named, unreleased provider-first 78
preview ledger and preserves its applied SQL/version. It adds only the missing
installed assurance as 79. Fresh and main-78 databases always use installed
assurance at 78 and providers at 79. Unknown or duplicate histories fail closed.
No ledger rows, timestamps or applied SQL definitions are rewritten.

Three competing migration runners reproduced catalog-creation and post-commit
DDL races. The executor now holds a per-database session advisory lock from
before ledger creation through all migrations and post-commit checks. Failed
unlocks discard the connection. A transaction lock would end too early at each
migration commit; see [PostgreSQL advisory lock semantics](https://www.postgresql.org/docs/current/explicit-locking.html#ADVISORY-LOCKS).

Eight real PostgreSQL histories cover fresh, older distribution/enrollment
orders, main's installed-78 and the provider-first preview. Fresh and both 78
histories run three independent CLI processes concurrently. Existing published
numeric pins, binding policy and accepted installed/served evidence are seeded
before upgrade and compared afterward. Both schema extensions must coexist.

## Distribution guarantees

Linux endpoints support installed/served/trust. Installed-only configurations
omit probes and reload hooks. Secure filesystem readback checks the leaf,
private-key association, SHA-256 fingerprint and every supplied chain
certificate. Served/trust retain listener identity and trust requirements.

Regression tests reproduced reconciliation clearing uncertainty after a chain
was truncated. New local journals retain only public chain proof. Older journals
recover that proof through an exact, read-only customer-store version fetch.
Reconciliation never installs, reloads, promotes control-plane state or clears
the marker after failed proof; retries still need the original approved intent
and live claim/lease. Private key bytes are never added to a journal.

Windows remains win32/windows-iis with `windows-material-iis-v1`, qualified RSA,
P-256/P-384 keys, non-exportable machine CNG custody, exact ACL/signature checks,
IIS binding and served TLS evidence. The agent refuses installed-only IIS
assurance before effects. API binding admission, receipt acceptance and read
projections also reject a Windows file-only downgrade.

Group/provider identity, exact numeric/opaque version pins, generation,
authorization revision, approval, retirement, transfer and rollback fences stay
in place. Main's retirement regression assertion is updated to prove that only
the retired identity's active periods close while source/association history is
retained; the corresponding real PostgreSQL tests remain enabled.

## Validation evidence

Focused Core tests: 222 passed, 0 failed/skipped. The full local Core unit run
passed 2,775 tests with no failures/skips. Focused agent/provider tests passed
60 tests; two live-provider fixtures are reserved for their dedicated CI jobs.
Real PostgreSQL migration/provider tests passed 11 scenarios, including all
eight histories and all three provider models. Azure model tests are offline.

Complete merged CI, native matrix and final diff audit will be recorded after
the candidate run. Earlier reports are historical supporting evidence rather
than exact-artifact qualification for this merged candidate.

## Qualification boundaries

PR merge validation is separate from production capability promotion. Windows
and Azure shared-material production gates remain disabled. Live Azure is
excluded because no subscription is available. Physical TPM/smart-card KSPs,
Server 2019, ARM64, coordinated multi-host Windows rollout and exact release
artifact promotion remain separate release qualification gates.
