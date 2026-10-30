# Distribution extension review — PR #460

This report records the earlier review before the main-branch integration.
Current merge readiness, migration 78/79 reconciliation and final validation
are recorded in the [merged-candidate report](distribution-extensions-merge-2026-10-26.md).

Reviewed on 2026-10-26 after fetching `origin/main` and
`origin/feat/certops-distribution-extensions`. The existing branch was clean and
already matched remote commit `bac39ef10043414829c9350dee80564324ef3236`.
No new branch, rebase, schema change or merge into the PR was performed.

## Findings and fixes

### Windows target isolation — confirmed

The original binding policy accepted both `endpoint` and `windows-iis` without
checking the local platform. The dispatch gate permitted `deploy-from-store`
on a qualified Windows process. Consequently an endpoint binding could reach
the generic filesystem installer and reload path. The original lifecycle tests
reproduced that installation and reload path on this Windows workstation.

`resolveBindingPolicy()` now accepts only Linux/endpoint and Windows/windows-iis.
The existing Windows validator also requires `windows-material-iis-v1` and the
approved IIS configuration. Execution, verification-only operation and local
reconciliation apply that policy before locks, provider reads, staging, native
helpers or reload. Job dispatch shares the preflight between dry-run and real
execution. The internal platform injection is for deterministic tests; job or
configuration fields cannot override the running process's platform.

Regression tests exercise fully qualified Linux/Windows capability manifests
in isolated processes, both job modes, denied cross-platform combinations,
unsupported hosts, an untyped connector and untouched staging/destination
directories. Positive tests retain real Linux file installation/reload/TLS
verification and the typed Windows lifecycle and reconciliation paths.

### Existing Windows key custody — confirmed, with downstream mitigation

`MaterialImport.Install()` previously checked the existing key's ACL and
returned without `CheckCustody()`. An isolated diagnostic using a user-store
redirect of the unchanged implementation accepted a key which its own custody
check rejected. This workstation is not elevated; that diagnostic establishes
the existing-branch omission, not machine-store or IIS qualification.

The complete connector already called `Verify()` before activation, which
checks custody, SHA-256 identity, ACLs and signing association. That downstream
mitigation prevented an exportable key from becoming an accepted deployment,
but did not make the import helper's reuse contract correct.

Existing-key reuse now checks machine/non-ephemeral custody, the Microsoft
Software KSP, a non-exportable policy, the exact protected service ACL and a
fresh SHA-256 signing proof. Signing verification is shared with `Verify()`.
The existing branch never sets an ACL, reimports material or changes a key's
export policy to force adoption. Rejections retain fixed diagnostic stages;
the connector continues to expose only its bounded public failure code.

The native fixtures cover valid reuse, exportable keys, user keys, incorrect
ACLs, mismatched private keys, unsupported CNG custody/provider policy and a
real legacy CSP association. They compare key ACLs, export policy and store
membership before/after reuse or rejection. Only uniquely named fixture keys
and stores are cleaned up.

## SHA-1 / CodeQL analysis

The SHA-1 call in `windows-material/pkcs12.js` computes only the leaf bag's
`localKeyId` attribute (`1.2.840.113549.1.9.21`), copied onto the one encrypted
private-key bag. This is the implementation's Windows-thumbprint association
convention. PKCS#12 bag attributes are described in
[RFC 7292 section 4.2](https://www.rfc-editor.org/rfc/rfc7292.html#section-4.2);
these optional attributes assign identifiers to keys and other bag contents.
The digest bytes here are not used for authentication.

The security checks use separate inputs and algorithms:

- The key is encrypted as PKCS#8 with AES-256-CBC. PFX password integrity uses
  HMAC-SHA-256 and a SHA-256 password-integrity KDF, with a random salt and
  100,000 iterations.
- Provider bundle validation checks the SHA-256 certificate fingerprint and
  private/public key association against the pinned intent.
- The native helper checks the actual store certificate's SHA-256 fingerprint,
  custody and ACLs, then signs/verifies a fresh nonce with SHA-256.
- Windows thumbprints select store/binding entries; actual served TLS is
  compared with the pinned SHA-256 leaf fingerprint and configured trust policy.

No security-sensitive verification was found to rely on collision resistance
of this SHA-1 bag identifier. The identifier is retained, with a precise source
comment instead of a blanket CodeQL suppression. Native PKCS#12 tests now also
reject an incorrect password and tampered MAC salt while retaining successful
parsing and signing association. No alert was dismissed through GitHub.

## Validation

Product fix: `bffed7496e1234d53cb04ad47e31a4abf7d6c449`. The following native
fixture corrections through `3cb4095f5881351b5b9f3097811dcbd8745087e5` change
only tests. Current full CI:
[40325329387](https://github.com/tokentimerch/tokentimer-core/actions/runs/40325329387).
All 35 jobs passed. The subsequent documentation-only commit is checked
separately with the repository guards; it does not change the tested product.

| Check | Result |
| --- | --- |
| Core unit tests | 2,759 passed, 0 failed, 0 skipped |
| Contract tests and validation | 47 passed, 0 failed, 0 skipped; manifest/runtime coverage and generated contract integrity passed |
| Integration tests | 1,395 passed, 0 failed, 0 skipped |
| Full recursive Linux agent suite | 2,024 passed, 0 failed, 15 explicit platform/environment skips |
| Native Windows agent package | 2,020 passed, 0 failed, 15 explicit platform/environment skips |
| Server 2022/2025 IIS and custody matrix | All 16 jobs passed; 144 Node test results, 0 failures/skips |
| Real OpenBao 2.3.2/2.4.1 and Vault 1.21.0 | All three compatibility jobs passed; each has one passing real-provider scenario and one excluded live Azure scenario |
| Migration/provider pinning/governance | All six migration histories, three provider pin/rollback cases and 55 distribution governance regressions passed, with no failures/skips |
| Formatting, lint, builds and guards | Prettier, lint, type checks, API/worker/controller/dashboard builds and coverage, agent build/shipped-source validation and all 13 guards passed |
| Four image build/boot/security scans | All API, dashboard, worker and controller image builds, startup probes and Grype scans passed |

Each native matrix job reports nine passing Node tests: seven custody cases,
their enclosing test and one IIS scenario. This covers twelve supported-key IIS
campaigns and four pre-mutation P-521 rejection cases, across both Server
versions and fixture/real-OpenBao transports. Logs from every native job were
checked for all seven custody cases and zero skipped tests.

Early native diagnostic runs passed six custody scenarios but exposed an
incorrect fixture assumption: Windows presents a persisted legacy CSP key
through an `RSACng` wrapper under the legacy provider's name. Its safe rejection
correctly occurs at custody validation. The fixture now asserts actual provider
identity, machine/non-ephemeral state and non-exportability, so the unsupported
provider is isolated from the other rejection reasons. Passing counts refer to
the corrected run; earlier diagnostic runs are not presented as green.

The earlier six packaged operator cohorts are retained in the
[expanded lab report](distribution-extensions-lab-2026-10-26.md). They predate
these review fixes and are not exact-artifact evidence for the new candidate.

## Changed files

| File | Purpose |
| --- | --- |
| `packages/agent/src/material-store/lifecycle.js` | Central platform/target policy before deployment and reconciliation effects |
| `packages/agent/src/index.js` | Common dry-run/real binding preflight |
| `packages/agent/src/windows-material/MaterialImport.cs` | Custody and shared signing-association checks before existing-key reuse |
| `packages/agent/src/windows-material/pkcs12.js` | Explain the SHA-1 interoperability label without changing its bytes |
| `packages/agent/src/material-store/lifecycle.test.js`, `platform-policy.test.js` | Positive/negative platform, mode, connector and no-mutation regressions |
| `packages/agent/src/windows-material/pkcs12.test.js` | Wrong-password and MAC-tamper native regressions |
| `tests/e2e/windows-material-custody-real.test.js`, `fixtures/MaterialCustodyTests.cs` | Native machine-key/store reuse and rejection checks |
| `.github/workflows/ci.yml` | Run custody checks alongside the existing native IIS matrix |
| Qualification/review documentation and generated skip inventory | Record evidence, boundaries and the elevated native test prerequisite |

## Readiness and boundaries

Keep the PR draft until its conflicts with newer `main` work are resolved and
the combined revision is validated. A read-only `git merge-tree` check found
conflicts in distribution services/lifecycle/tests, migration tests, generated
contracts and the skip inventory. Those upstream changes were not overwritten.
The latest main CI also has an unrelated decommission unit-test failure and
therefore skipped its image scan; the last completed successful main scan was
inspected separately.

Vault/OpenBao adapters, Azure exact-version/ambiguous-write handling, Linux
deployment implementation, local Windows CNG enrollment and schemas are
unchanged. Linux's existing endpoint path remains supported.

Live Azure remains excluded because no subscription is available. Physical
TPM/smart-card KSP deployments are not provisioned; their provider policy is
tested without claiming hardware qualification. Windows and Azure production
capability gates remain disabled. Server 2019, ARM64, coordinated multi-host
Windows issuance/rollout and exact release artifact promotion remain separate
release gates. No merge or release is performed.
