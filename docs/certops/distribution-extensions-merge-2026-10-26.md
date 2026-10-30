# Distribution extension merge validation — 2026-10-26

PR #460 merges main through `8e9df7d0de9ff3b65e5f834e18815d7fe93e04cf` into the
existing `feat/certops-distribution-extensions` branch, starting from clean PR head
`2ca3b2581ffbf3e140e3b05a864baedcb186e451`. The branch is not rebased or force
pushed, and the PR is not merged into main.
The first merge integrated `af0d826b`; a second preserves subsequent retirement
guards, timezone handling and dependency/action updates. Added PR jobs use the
same checkout pin as the updated main workflow. Both retirement regression
assertions are combined, including scoped parameters and retained source data.
A subsequent refresh, `f08d9287`, integrates main's guided Vault recovery,
workspace-manager access, onboarding restart, nested Vault diagnostics and
scoped Linux reload-policy changes. That refresh started from clean, pushed
head `4d008af1` and preserves all previously confirmed Windows fixes.
Main subsequently landed its own manager-repair regression tests. The final
test-only refresh, `2fed37ad`, integrates those tests without changing any
application, agent, contract, script or workflow code from `f08d9287`.

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

The subsequent main refresh had one conflict in
`tests/wildcard-vault/ux-lab/qualification.cjs`. Its resolution keeps main's
convergence wait and the PR's explicit exact-version/accepted-generation and
removed-consumer assertions. Active retained identities in the same management
period remain eligible for an approved rollback; removed bindings cannot count
as converged. The auto-merged consumer matrix also retains main's distinct
rollout/request IDs and fallback job failure code alongside the PR's provider
references and policy-specific proof fences.

One stale qualification assertion was independently reproduced against the
actual authorization middleware: the lab expected manager profile repair to
return 403, but main deliberately admits workspace managers. The public
journey now proves idempotent manager repair, demotes that same authenticated
member to viewer through the public membership API, verifies 403, and restores
the manager role. The last refresh resolves the overlapping `journey.cjs`
conflict by preserving that role-change proof alongside main's owner/manager
success assertions. Main's additional viewer check after renewal is retained.
The real API integration suite uses main's dedicated manager-repair test and
viewer/missing-membership refusal cases; the earlier duplicate manager assertion
is removed. Product RBAC is not changed.

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

The tested merged product commit is
`2fed37ad7f07251e63940e83ca87010964908f91`.
[Core CI run 40404197128](https://github.com/tokentimerch/tokentimer-core/actions/runs/40404197128)
completed successfully: **all 35 jobs have successful final results**, with no
skipped jobs. One infrastructure bootstrap required an isolated retry, detailed
below. Separate CodeQL
Actions, Go and JavaScript/TypeScript analysis jobs also passed. Earlier reports
are historical supporting evidence, not exact-artifact qualification for this
merged candidate. Counts below overlap across full and focused runs and must
not be added together.

| Validation | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Core unit suite on merged CI candidate | 2,792 | 0 | 0 |
| Frontend suite on merged CI candidate | 2,745 | 0 | 0 |
| Contract suite | 47 | 0 | 0 |
| Integration suite against the Compose stack | 1,399 | 0 | 0 |
| Runtime API endpoint contracts | 8 | 0 | 0 |
| Focused Core regressions during the main refresh | 170 | 0 | 0 |
| Focused native Windows agent/provider regressions during the refresh | 78 | 0 | 0 |
| Focused frontend during the refresh, serial workers and original timeouts | 205 | 0 | 0 |
| Full recursive Linux agent suite in the local Debian/Node 24 container | 2,055 | 0 | 15 |
| Native Windows full recursive agent suite | 2,049 | 0 | 16 |
| Server 2022/2025 native custody/IIS matrix, 16 jobs | 144 | 0 | 0 |
| Real PostgreSQL immutable upgrade histories | 8 | 0 | 0 |
| PostgreSQL provider pinning/retained rollback models | 3 | 0 | 0 |
| PostgreSQL distribution governance/transfer regressions | 55 | 0 | 0 |
| Real OpenBao 2.3.2/2.4.1 and Vault 1.21.0 compatibility scenarios | 3 | 0 | 3 |
| Exact-candidate packaged OpenBao SAN lab, mandatory phases | 15 | 0 | 0 |

The focused Windows agent command also has an excluded Linux-only installer
suite; Node's final individual-test skip counter is zero. Full agent skips are
existing platform/environment restrictions. Each real-provider
job runs its KV scenario and excludes the live Azure scenario; all Azure
exact-version and ambiguous-write tests in ordinary suites use offline models.
No new skip was added to make validation pass.

Diagnostic local attempts are retained separately, not counted as green: the
initial concurrent Windows frontend run had 199 passed and six timeout failures;
a container run had 203 passed and two timeout failures. The final native
serial run passed the same 205 tests with unchanged assertions and deadlines.
The first fully concurrent recursive Linux agent run had 2,053 passed, two
ACME subprocess/readiness failures and 15 skips under the concurrent image-build
load. Those process cases passed all 11 tests in isolation, and the complete
recursive rerun with two workers passed all 2,055 eligible tests. Test bodies,
termination deadlines and assertions were not weakened. The new installer
permission smoke also passed in a disposable Debian container under umask 077.

The final CI's first attempt had 34 successful jobs and one failed fixture
bootstrap: Windows 2022/OpenBao/RSA job `121857615262` could not obtain an
initialized, unsealed OpenBao health response. No Node/certificate test started
in that failed job; the original VM's server diagnostic files are not retained
by this workflow, so a more specific startup cause is not asserted. A fresh
runner retried only that job, with no code, timeout or assertion changes.
Job `121866809708` passed all nine Node results, including all seven custody
cases, with zero failures/skips. The remaining 34 results were carried forward
into attempt 2; the overall run and all 35 unique jobs are successful.

Each native matrix job has seven custody subtests, their enclosing test and
one IIS scenario. Every log was checked for valid reuse, exportable key,
user key, incorrect ACL, private-key mismatch, CNG provider/custody policy and
legacy CSP rejection. This covers twelve supported RSA/P-256/P-384 IIS
campaigns and four P-521 rejection campaigns, using fixture and real OpenBao
transports. The Windows package suite also passed native PFX wrong-password
and MAC-tamper rejection.

Frozen pnpm 11.28.8 installation, contract manifest/runtime coverage/generated
integrity, all 13 CI guards, secret-logging and lockfile checks, formatting,
lint, types, builds, coverage, dependency audit, Compose and Helm passed.
All four API/dashboard/worker/controller image builds, startup probes and
Grype scans passed. The latest main run, 40401455506 on `8e9df7d0`, also passed;
its four image scans were inspected separately.

The exact-candidate lab, `tt-wildcard-ux-qual-pr460-mainfinal`, passed all 15
mandatory phases and 41 operator checks with three real Pebble DNS-01 orders.
It uses a checksum-verified package, unprivileged agents, actual OpenBao 2.4.1,
nginx/HAProxy listeners, real Chromium and public HTTP operations. Publication
and reload failures, credential rotation, read-only reconciliation, original
signed retries, retained rollback, drift, rollout controls, workspace-role
changes, corrupted signatures, replay rejection, custody audit and workspace
transfer all passed. The official report verifier accepted the result.

An earlier `f08d9287` packaged cohort independently passed the same 15 phases
and 41 checks. Both qualification labs are stopped with evidence/volumes
retained; the existing user review lab is untouched. These are development
artifacts with `qualificationStatus: not-qualified`, not production capability
promotion or exact release qualification.

## Security alert disposition

[CodeQL alert 140](https://github.com/tokentimerch/tokentimer-core/security/code-scanning/140)
at `packages/agent/src/windows-material/pkcs12.js:69` is a confirmed context
false positive. SHA-1 hashes public certificate DER solely into the
`localKeyId` bag-pairing attribute (OID `1.2.840.113549.1.9.21`), matching the
Windows thumbprint label. It is not used as a security proof. PKCS#12 bag
attributes carry identifiers separately from integrity protection; see
[RFC 7292 section 4.2](https://www.rfc-editor.org/rfc/rfc7292#section-4.2).

The PFX MAC is HMAC-SHA-256 and encrypted PKCS#8 uses AES-256. Bundle validation
pins SHA-256 and key association. `connector.ps1` invokes
`MaterialImport.Verify()` after import and before returning to activation;
it verifies the expected SHA-256 fingerprint, machine/non-exportable software
CNG custody, exact ACL and SHA-256 signing association. Served TLS also uses
the SHA-256 pin. An existing thumbprint match cannot bypass these proofs.

After reviewing this data flow and native evidence, only alert 140 was
dismissed as `false positive` with a scoped rationale. GitHub's CodeQL result
then reported success with no new alerts. No query exclusion, source
suppression, identifier replacement or weaker security check was introduced.

## Changed files and regressions

| Files | Purpose |
| --- | --- |
| `apps/api/migrations/{compose-migrations.js,migrate.js,079-certops-material-providers.sql}` | Unique canonical 78/79 sequence, explicit preview-history preservation and whole-executor concurrency fence |
| `packages/agent/src/material-store/lifecycle.js`, `packages/agent/src/index.js` | Combine installed readback with provider/Windows lifecycle, strict preflight and complete-chain reconciliation |
| `packages/agent/bin/reconcile-material-binding.js` | Supply customer-local stores for read-only recovery of older journals |
| `apps/api/services/certops/{materialDistribution,distributionOperations,distributionRead}.js` | Preserve policy-specific receipts/read models, immutable provider pins and authorization fences; refuse Windows installed-only downgrades |
| Agent lifecycle/platform tests and Core installed-assurance tests | Linux installed/served/trust, 19 qualified platform/mode cases, no-effect denials, full-chain truncation, legacy-journal recovery and Windows policy/receipt rejection |
| Migration unit, PostgreSQL and integration upgrade tests | Fresh and both version-78 histories, three competing CLI migrators, preserved ledger rows/data, both schema extensions and provider rollback |
| Retirement regression, vendored contracts, manifests and skip inventory | Preserve both branches' assertions and regenerate through official repository scripts |
| `tests/wildcard-vault/ux-lab/{qualification,journey}.cjs`, `tests/integration/certops-manager-access.test.js` | Combine retained-rollback proofs and keep manager/viewer qualification aligned with main's actual permission contract |
| Distribution/qualification/ADR documentation | Canonical migration numbers, supported policies, evidence and release boundaries |

The prior custody, association and SHA-1 review fixes remain unchanged in the
merged implementation. Azure adapter and local Windows CNG enrollment/rebind
files are unchanged from the starting PR head. Native matrix and provider
coverage confirm these paths still work within their stated qualification
boundaries.

## Final audit and recommendation

**NOT READY TO MERGE under the current repository policy; code and validation
are complete.** No confirmed product finding remains. The complete merged diff was
inspected against the latest fetched main, `8e9df7d0`. Main is an ancestor of
the candidate, there are no unmerged paths/conflict markers, `git diff --check`
passes, the registry has 79 unique versions and the renamed provider SQL is
byte-for-byte identical to its original PR definition. Both merge commits
(`ebacda31`, `54267caf`) and refresh merges (`f08d9287`, `2fed37ad`) were pushed
normally on the existing feature branch. GitHub reports the branch mergeable.
The final evidence-only documentation update does not change the tested
product, and its exact tracked source snapshot is checked with all 13 guards.
The PR is not merged automatically.

GitHub reports `mergeable: true`, `mergeable_state: blocked`, `draft: false` and
`merged: false`. The active
[Protect main ruleset 24130458](https://github.com/tokentimerch/tokentimer-core/rules/24130458)
includes a restriction on updating the default branch. The current account's
`current_user_can_bypass` is `never`; it has push access but no repository
administration permission. GitHub's
[ruleset documentation](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#restrict-updates)
explains that this restriction admits only actors with bypass permission.
The second active ruleset also requires signed commits and linear main history;
all PR commits are already verified. There is no outstanding required review
or failing check on the final evidence commit. An authorized maintainer must
handle the remaining merge-policy gate using the repository's permitted merge
process. Repository protections are not changed or bypassed by this work.

## Qualification boundaries

PR merge validation is separate from production capability promotion. Windows
and Azure shared-material production gates remain disabled. Live Azure is
excluded because no subscription is available. Physical TPM/smart-card KSPs,
Server 2019, ARM64, coordinated multi-host Windows rollout and exact release
artifact promotion remain separate release qualification gates.
