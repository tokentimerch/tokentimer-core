# Core 0.18.0 evidence index

Read the [release preparation record](../../0.18.0-release-preparation.md) for
the completed disposition and scope. These JSON files preserve
observed receipts and reproducible source accounting; a passing unit test,
supporting lab, historical native job and formal qualification collector are
different kinds of evidence.

## Source identities

- Audited product baseline: `fcc681c19314b7c2432973ce99d517af36e10238`.
- Reviewed product fix: `b1b92cb36de0ef0d8647f1122d18b075d06c17ea`.
- Current normal-CI and distribution checkpoint: `fd4417653d40d4241f1cdecf310676a62e22fc55`.
- Original immutable image build: `69387d85231f242d00f653bbde94ead373fefe1e`.
- Rebuilt Go 1.26.10 agent source: `fcc681c19314b7c2432973ce99d517af36e10238`.
- Initial package build/verification workflow: `c77145b64012698e8d1d2c9a48a1cd05fe0137c0`.
- Successful upgrade fixture: `2a41f2089c0883d72f0fb2cb1d667f3ab65b25ec`.
- Successful focused Windows fixture: `edb0d829d1abea1e49736e8c74653e62d19020d3`.
- Current distribution/browser fixture: `fd4417653d40d4241f1cdecf310676a62e22fc55`.

Preparation fixtures have their own real source SHAs. Product/build-source
equivalence is checked explicitly; reports are not edited to give them an
earlier product source. The Windows helper regression overlays two unshipped
readiness fixtures, records their hashes, then restores the product checkout
before executing the actual packaged CMC binary.
The later browser-discovered workspace fix changes one production dashboard
file. The earlier dashboard image is superseded; carried agent/backend/chart
records retain their original source identities and explicit equality limits.

## Receipts and accounting

| File | Purpose |
|---|---|
| [release-status.json](release-status.json) | Current overall disposition, completed and pending gates, exact source/package identities and publication boundary. |
| [SHA256SUMS](SHA256SUMS) | Checksums of every other file in this evidence directory, including all six retained owner-redo screenshots. |
| [source-accounting.json](source-accounting.json) | Every product commit/parent/tree identity, aggregate path counts, nine-commit addendum and final path modes since v0.17.3. |
| [preparation-source-accounting.json](preparation-source-accounting.json) | The preparation code checkpoint and the purpose of every change beyond the product source. |
| [source-impact.json](source-impact.json) | Native/helper/package footprints and relevant runtime changes since the earlier successful qualification sources. |
| [native-reconciliation.json](native-reconciliation.json) | Original native jobs, source/package identities, 169-scenario mapping, fixture and ZIP integrity checks, and original formal-scope distinctions. |
| [current-delta-ci.json](current-delta-ci.json) | Current normal CI and focused Windows execution mapped to the changed runtime boundaries. |
| [corrected-normal-ci.json](corrected-normal-ci.json) | All 16 current-source CI jobs, exact Windows skips, frontend regression, separate backend/integration counts, disposable Kind smoke, and four fresh image/security results with residual findings. |
| [auto-sync-fcc-equivalence.json](auto-sync-fcc-equivalence.json) | Dedicated real-PostgreSQL auto-sync execution and exact relevant-source equality. |
| [candidate-artifacts.json](candidate-artifacts.json) | Agent/chart/image identities, signing/scan evidence, replacement archive and rejected earlier archive. |
| [artifact-carry-forward.json](artifact-carry-forward.json) | Exact current packaged-agent/chart/controller equality and the two non-runtime API/worker copied-context test-file exceptions; excludes the old dashboard. |
| [corrected-dashboard-verification.json](corrected-dashboard-verification.json) | Actual unpublished Docker archive, all 14 layers/config, production configuration, served asset bytes, exact fixed-page source map and hosted scan binding. |
| [corrected-dashboard-hosted-job.json](corrected-dashboard-hosted-job.json) | Successful actual-source production dashboard build, owned-container smoke, scan and archive preservation steps. |
| [agent-verification.json](agent-verification.json) | Independent checks of the actual rebuilt archive and its security gate. |
| [agent-native-provenance.json](agent-native-provenance.json) | Per-binary PE, Go build/module settings and byte hashes, plus packaged source inventory. |
| [helm-verification.json](helm-verification.json) | Durable hosted stable chart and content/mode equality with the earlier local package. |
| [image-scan-summary.json](image-scan-summary.json) | Unfiltered image/old-agent scan counts, selected child manifests, database identity and report hashes. The replacement agent has its own verification receipt. |
| [security-analysis.md](security-analysis.md) | Rejected/replacement package decision, image policy results, primary advisory references and residual applicability limits. |
| [core-upgrade.json](core-upgrade.json) | Exact downloaded successful 13-check package-upgrade receipt, including cleanup and explicit scope exclusions. |
| [core-upgrade-verification.json](core-upgrade-verification.json) | ZIP/receipt verification and independently reconstructed image source manifests. |
| [api-runtime-source-manifest.json](api-runtime-source-manifest.json) | 311 actual API image runtime file hashes. |
| [worker-runtime-source-manifest.json](worker-runtime-source-manifest.json) | 248 actual worker image runtime file hashes. |
| [windows-helpers-receipt.json](windows-helpers-receipt.json) | Four passing Go suites, exact test-fixture provenance and actual packaged amd64 CMC controls. |
| [windows-boundaries-receipt.json](windows-boundaries-receipt.json) | Actual packaged IIS rebind, SAN-only store discovery, evidence construction and owned cleanup. |
| [followup-source-equivalence.json](followup-source-equivalence.json) | Earlier `4ce098be` fixture versus trusted product-source equality and the exact two unshipped test exclusions. |
| [followup-postgres-vault-receipt.json](followup-postgres-vault-receipt.json) | Earlier `4ce098be` PostgreSQL/Vault execution, no-skip checks, fixture hashes and cleanup. |
| [followup-corrected-source-equivalence.json](followup-corrected-source-equivalence.json) | Reviewed workspace fix versus audited baseline and the current acceptance checkpoint, with exact current archive/chart matches and carried runtime boundaries. |
| [followup-corrected-postgres-vault-receipt.json](followup-corrected-postgres-vault-receipt.json) | Corrected-candidate 13 guard, 50 PostgreSQL and nine actual Vault adapter passes, zero skips/todos, exact source hashes and owned cleanup. |
| [followup-corrected-seven-cohort-receipt.json](followup-corrected-seven-cohort-receipt.json) | Passed seven supporting cohorts and three separate operator-package modes; six real browser redo receipts, exact source/hash chains, counts and cleanup limits. |
| [distribution-functional-summary.json](distribution-functional-summary.json) | Exact downloaded canonical aggregate, retaining its functional-support and unqualified-native labels. |
| [prep-distribution-initial-attempt.json](prep-distribution-initial-attempt.json) | The original failed private-fixture scanner attempt and its preceding actual passes. |
| [followup-distribution-initial-attempt.json](followup-distribution-initial-attempt.json) | The next attempt's 12 runtime passes per mode and the new browser fixture's active-versus-removed inventory assertion failure; no owner UI or package acceptance is claimed. |
| [followup-vault-readiness-initial-attempt.json](followup-vault-readiness-initial-attempt.json) | The earlier `67a085fa` attempt's 13 guard and 50 PostgreSQL passes, followed by owned Vault startup failure before any adapter execution; cleanup passed and the cause remains unestablished. |
| [followup-workspace-navigation-failure.json](followup-workspace-navigation-failure.json) | Three real browser failures after first reuse and reset succeeded, diagnosed as loss of the reset workspace during navigation. |
| [workspace-reset-regression.json](workspace-reset-regression.json) | Same-test red/green proof against the exact previous source and the fixed page/router/provider; 27 fixed workspace tests passed. |
| [workspace-reset-baseline-red.log](workspace-reset-baseline-red.log), [workspace-reset-fixed-green.log](workspace-reset-fixed-green.log) | Complete bounded local regression logs, including the actual wrong-workspace assertion. |
| [prep-postgres-vault-receipt.json](prep-postgres-vault-receipt.json) | The earlier successful support job from the initial preparation run. |

Historical snapshots retain what was known when they were produced. Their
initial unresolved fields may be closed by later receipts listed here; they
are not silently rewritten as earlier successes. Relative acquisition paths
inside original receipts describe the producer's workspace. Original artifact
ZIPs remain linked through their recorded GitHub run/artifact IDs; bounded
verified results are preserved here beyond Actions artifact retention.

## Distribution receipts

Original public qualification, privacy, owner-redo and owner-redo screenshot bytes are
preserved in each directory below. Package directories also include the
qualification-only artifact identity. These are receipt bundles, not copies
of that qualification-only tgz. The final downloaded release-agent archive
has its separate identity and verification above.
Other distribution-status screenshots remain in their original Actions
artifacts; this bounded repository bundle preserves the owner-redo images.

| Certificate mode | Source lab | Operator-package lab |
|---|---|---|
| Ordinary | [Receipt](distribution/ordinary/source/qualification.json), [owner redo](distribution/ordinary/source/onboarding-redo.json), [screenshot](distribution/ordinary/source/distribution-onboarding-redo.png) | [Receipt](distribution/ordinary/package/qualification.json), [owner redo](distribution/ordinary/package/onboarding-redo.json), [screenshot](distribution/ordinary/package/distribution-onboarding-redo.png) |
| SAN | [Receipt](distribution/san/source/qualification.json), [owner redo](distribution/san/source/onboarding-redo.json), [screenshot](distribution/san/source/distribution-onboarding-redo.png) | [Receipt](distribution/san/package/qualification.json), [owner redo](distribution/san/package/onboarding-redo.json), [screenshot](distribution/san/package/distribution-onboarding-redo.png) |
| Wildcard | [Receipt](distribution/wildcard/source/qualification.json), [owner redo](distribution/wildcard/source/onboarding-redo.json), [screenshot](distribution/wildcard/source/distribution-onboarding-redo.png) | [Receipt](distribution/wildcard/package/qualification.json), [owner redo](distribution/wildcard/package/onboarding-redo.json), [screenshot](distribution/wildcard/package/distribution-onboarding-redo.png) |

## Reproduction

The exact nonpublishing workflow definitions are preserved in the immutable
preparation commits and Actions runs. Temporary workflows pinned to this
candidate are removed from the final PR head after acceptance, so a later
release cannot accidentally test this old product SHA. The reusable package
verifier, upgrade runner, Windows boundary runner and distribution fixture
remain in the repository.
The temporary exact-preparation-branch normal-CI trigger is also restored to
its original main/master scope at the final evidence commit.

The new production `pack-agent` release gate verifies and scans the **freshly
built publication archive**. A later build has its own observed checksum; the
prepared archive checksum must not be copied onto different bytes. No tag,
registry publication, Helm deployment or production rollout is authorized by
this evidence record.
