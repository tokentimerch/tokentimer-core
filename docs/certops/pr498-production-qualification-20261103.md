# PR #498 production qualification — 2026-11-03

All five extension capabilities remain **unqualified and disabled**. As of
12 November, their promotion is outside this implementation review; Azure
infrastructure fencing is separate work. Original-job reconciliation, the
operator journey and NAT qualification are covered by the current PR checks.
The following is the historical 3 November qualification record. Two fresh,
complete packaged-agent journeys passed against the current implementation,
strengthening merge-review evidence. They do not establish native release
qualification for the five disabled operations. It does not authorize promotion
or deployment.

Implementation candidate: `037a8d2cebcb37dac281ca3c3478fe0c94604d8b`.
Trusted main at inspection: `ece47164344a6908a29820909c634e5b2d451b67`.
The [bounded evidence](evidence/2026-11-03/production-qualification/summary.json)
contains exact package, source, dependency, scenario, host and screenshot hashes.
The [merge-review record](pr498-merge-readiness-20261103.md) retains earlier
failed attempts and their narrower evidence boundaries.

## Acceptance matrix

| Capability | Source tests | Real provider/host | Signed E2E | Exact artifact | Protected CI | Qualified | Enabled |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `material-store-azure-key-vault-v1` | Current adapter/identity/ambiguity fixtures | Historical real Azure, 18/18 at `a53d0634` | Historical packaged agent/PG integration with fixture CA; current full HTTP/operator journey missing | Historical development package only; no current enabled release artifact | Main-only environments configured; spending opt-in **false** | No | No |
| `windows-material-iis-v1` | Current source and custody tests | Current Server 2022/2025: 16 cohorts, 9 tests each, zero skips | Native local/OpenBao execution; installed signed control-plane/separate-host composition missing | Current native source tests do not use the installed release package | Current source CI passed; required trusted-main native package evidence absent | No | No |
| `material-consumer-staging-v1` | Agent integrity/calendar and real-PG preparation/activation tests | Supporting Linux filesystem/PG evidence | Separate signed preparation/activation supporting cases; complete packaged failure matrix missing | Fresh baseline package is verified, but staging stays disabled | No dedicated capability-native producer/accepted report | No | No |
| `material-cleanup-vault-kv2-v1` | Current hosted real-provider cohort, 15/15 | Vault 1.21 + PG 16 | Signed service/API/source executor, with seeded public setup; installed daemon/worker journey missing | Fresh baseline package is verified, but cleanup stays disabled | Supporting CI artifact only; native release acceptance missing | No | No |
| `material-cleanup-openbao-kv2-v1` | Current hosted real-provider cohort, 15/15 | OpenBao 2.4.1 + PG 16 | Signed service/API/source executor, with seeded public setup; installed daemon/worker journey missing | Fresh baseline package is verified, but cleanup stays disabled | Supporting CI artifact only; native release acceptance missing | No | No |

## A. Changes and provenance

This qualification follow-up adds documentation and bounded evidence to
[Core #498](https://github.com/tokentimerch/tokentimer-core/pull/498). Product
code, dependencies, capability manifests, generated modules, migrations,
workflow protections and edition pins are unchanged. The optional-consumer
retry fix remains `e66add8559733bfd8bd6d753b1ce6db604b7bfbb`; the complete
tested repository candidate is `037a8d2c`. The PR records the subsequent
documentation commit and its CI result without claiming it was the tested
artifact's source.

Before starting new tests, the audit compared the policies, ADR-0012 decision
14, ADR-0015, Azure runbook, existing reports, package builders, dedicated
workflows, suite inventory and release collector. The committed inventory has
191 source slot definitions expanding into **271 mandatory environment cells**;
the scenario catalog has 217 specifications. `standard-hosted` selects 241 cells
and exposes 30 omitted cells. None supplies a dedicated native release producer
and acceptance contract for these five operations. Distribution lab slots are
explicitly experimental. No separate `qualification-matrix.json` exists.

The pre-test audit and all raw attempts remain in the ignored
`.tmp/pr498-production-qualification/` directory. Earlier evidence and the
unrelated original workstation checkout were preserved.

## B. Campaigns and artifacts

| Campaign | Candidate/environment | Actual result |
| --- | --- | --- |
| Fresh Vault packaged operator journey | `037a8d2c`; Debian 12 container, Node 24.22.2 x64, UID 10001; PG 17.11, Vault 1.21.0, Pebble DNS-01, nginx 1.22.1, HAProxy 2.6.12 | **15/15 strict phases**, **41/41 product checks**, zero missing/skipped phases, 3 genuine ACME orders; no database injection |
| Fresh OpenBao packaged operator journey | Same source, package and consumer environment; independent PG/provider/issuer/agent stack, OpenBao 2.4.1 | **15/15 strict phases**, **41/41 product checks**, zero missing/skipped phases, 3 genuine ACME orders; no database injection |
| Actual package inspection | Agent 0.18.2 built independently twice with canonical packager, Node 24.11.1/pnpm 11.28.8/Go 1.27.3 on Windows | Byte-identical archives; six Windows amd64/arm64 PE helpers passed pinned Go/module/architecture/hash inspection; extracted installed files unchanged |
| Current hosted Vault/OpenBao cleanup | [CI 41666895504](https://github.com/tokentimerch/tokentimer-core/actions/runs/41666895504), exact `037a8d2c` | **15/15 each**, zero failed/skipped/cancelled, both owned fixture teardowns passed; explicitly source functional support |
| Current Windows native source matrix | Same CI, Server 2022/2025 × fixture/OpenBao × RSA/P-256/P-384/P-521 | All **16 actual executor cohorts** ran; **9/9 tests each**, zero failed/cancelled/skipped. P-521 is expected pre-mutation refusal, not supported activation |
| Hosted qualification tooling | Same CI; Ubuntu 24.04 and Server 2025 | Ubuntu **1,325 passed / 3 platform skips**; Windows **1,351 passed / 3 platform skips**, zero failures; official Actions schema checks passed |
| Local `pnpm test:certops:qualification` | Unelevated Windows 11, Node 24.11.1 | **1,346 passed, 5 failed, 3 skipped**, zero cancelled. Retained as failed; missing Python/Actionlint, LocalMachine elevation prerequisite and a junction-cleanup failure prevent a local green claim |
| Catalog/profile planner | Documented `check:certops:catalog` and `certops-qualification-start.js --profiles` | Catalog/profile validation passed; 217 specifications, 10 implemented and 207 partial mappings; planner does not execute campaigns |
| Release collector refusal | `certops-release-qualification.js --profile standard-hosted <full candidate SHA> <two hosted supporting cleanup summaries>` | Expected **exit 1**: 241 required environment artifacts missing. Supporting cleanup summaries cannot fill native release slots |

Both new archives have SHA-256:
`7c26d2546fe051375822c6f519f82ee82f4db9e09b4c1d5b09b7ad6e12d67139`.
They are **qualification-only-not-release** packages with the existing eight-entry
manifest. The packager SHA-256 and all six embedded executable hashes are in
the bounded evidence. Reproducibility does not make these a published release.
The exact archive is retained locally; no package or private fixture is uploaded
as public evidence.

The hosted cleanup artifact is
[13245458632](https://github.com/tokentimerch/tokentimer-core/actions/runs/41666895504/artifacts/13245458632).
Native Windows and hosted tooling job IDs/counts are recorded individually in
the bounded evidence. The historical Azure
[18/18 campaign](https://github.com/tokentimerch/tokentimer-core/actions/runs/40486274037)
is retained for its original source/package only and was not needlessly repeated
while the current spending opt-in was false.

Both newly owned stacks were stopped, and their specifically labelled containers,
networks and volumes were removed and independently checked absent. The teardown
receipt records exact counts. Unrelated labs were untouched. Ignored local raw
evidence/private fixture files and the tested package are retained; none enters
the public evidence directory.

## C. Observed customer flows

Each fresh journey used normal bootstrap/invitation, three enrolled packaged
agents and the real API/worker/outbox. Actual DNS-01 issuance published a pinned
SAN certificate to the selected provider. Two consumer agents installed and
served it through nginx/HAProxy; independent strict TLS probes checked leaf
identity and trust. Seven Vault Agent/AppRole credential rotations per cohort
used separate scoped roles, sinks and UID 10001 processes.

The completed journeys covered approval-off execution, independent review and
self-review refusal, canary/offline catch-up, frozen waves, optional reload
failure, read-only reconciliation, retry of the original job, retained rollback
and restore, verification-only drift refusal and approved repair. Lost provider
responses recovered without another ACME order. Signature/pin/foreign-agent/replay
attacks failed. Workspace pause required fresh independent review after clearing.
Actual reload hooks serialized at `maxParallel=1` and overlapped at 2.

Real manager/viewer browser flows, onboarding Start over/reuse and public
cross-workspace transfer passed. Each cohort scanned 8 private keys, 25 credentials,
9 historical provider credentials and 3 historical provider versions against
Core DB/logs and customer-agent logs; scans passed without exporting needles.
DNS credential coverage remains expressly unqualified.

Screenshots show the actual fixture application:
[Vault converged](evidence/2026-11-03/production-qualification/vault-converged.png),
[Vault partial failure](evidence/2026-11-03/production-qualification/vault-optional-failure.png),
[Vault pause](evidence/2026-11-03/production-qualification/vault-workspace-paused.png),
[OpenBao converged](evidence/2026-11-03/production-qualification/bao-converged.png),
[OpenBao partial failure](evidence/2026-11-03/production-qualification/bao-optional-failure.png),
[OpenBao pause](evidence/2026-11-03/production-qualification/bao-workspace-paused.png).
The UI's existing custody badge says Vault; the OpenBao provider identity is
established by its real service, configuration and signed package journey.

These new journeys test shipped baseline publication/deployment. They do **not**
exercise enabled staging, cleanup, Azure or Windows shared-material operations.
The 15/15 cleanup cohorts separately prove source-level provider deletion and
receipt recovery, not a packaged cleanup agent. No synthetic receipt is counted
as native acceptance, and no cause is asserted for the inaccessible historical
valid-receipt exception. No current valid-receipt 500 was reproduced.

## D. Security and teardown

The new runs used isolated disposable fixtures, loopback-published ports,
separate provider processes and verified candidate images. No customer keys,
production stores, Azure resources, privileged roles or protection changes were
used. Tests checked current authority, tenant isolation, independent approvals,
signed pin/agent binding, replay refusal, scoped credentials and customer-local
key custody. Existing source cleanup tests retain metadata/exact-version soft
delete only, denied bundle-read/destroy/metadata-delete access, one deletion,
one successful audit and permanent reuse fences.

The production manifests and runtime gates stayed immutable. Only bounded
allowlisted metadata and synthetic application screenshots are committed.
Private sessions, JWTs, bundle values, raw provider/DB logs and private fixture
files remain outside committed artifacts. See the teardown receipt in the
bounded summary for removal of the two newly owned stacks.

## E. Activation and artifact boundaries

For **each of the five capability strings** in the acceptance matrix:

- The source manifest and generated module still omit it.
- The actual extracted package runtime refuses to advertise it, including when
  the obsolete runtime environment variable names all five.
- Authenticated public API reads confirmed its absence from **all six enrolled
  packaged agents** across both completed cohorts.
- The extracted Linux package refused Azure publication, independent staging
  and each provider's cleanup at the execution gate before mutation. Windows
  package inspection also refused unsupported material work; this Windows 11
  observation is gate evidence only, not Server/IIS qualification.
- Existing API claim/dispatch capability and current-authority checks remain
  enforced by the unchanged source and exact-head CI. No enabled installed
  execution of any new gate is claimed, and no production manifest edit or
  generated-file override was made.

The eight existing manifest capabilities remain unchanged. ADR-0012's exact
artifact discipline still applies: obtain independent qualification acceptance
for the intended candidate bytes, then use the reviewed promotion process.
A different rebuilt artifact cannot inherit these observations as native
qualification. Existing qualification-only builders are not release promotion
mechanisms.

## F. CI, review, merge and editions

[CI 41666895504](https://github.com/tokentimerch/tokentimer-core/actions/runs/41666895504)
passed **37/37 jobs and 41/41 checks** at implementation `037a8d2c`.
Latest inspected main [CI 41622867685](https://github.com/tokentimerch/tokentimer-core/actions/runs/41622867685)
passed image boot and all four Grype scans. Subsequent documentation-only CI
and its exact SHA belong in the live PR disposition; neither run qualifies a
future native artifact.

PR #498 remains open and ready for review, with **no submitted independent
review** at the latest inspection. `tokentimerch` is requested. The authenticated
author cannot supply that review. The user authorized normal protected merge
after required independent approval; no bypass or self-approval is permitted.
Keep all five gates disabled through that implementation merge.

Cloud #218 and Enterprise #193
still compose preview `4a5dedca`. No edition pin, compatibility claim, merge or
deployment is advanced before accepted Core main and actual qualification.
Their normal composition, migrations, governance and full CI remain required.

## G. Remaining dependencies and acceptance work

**External authorization:**

1. An independent maintainer must review/approve PR #498 and the repository must
   permit its normal protected merge. Main-only workflows cannot run this PR's
   source by pretending it is trusted main.
2. An authorized Azure administrator must explicitly authorize current lab
   spending and set `CERTOPS_AZURE_KEYVAULT_LAB_ENABLED=true` only for that approved
   campaign. It is currently `false` and was not changed. The lab and separate
   cleanup environments both have exactly the `main` branch rule and no tags;
   the lab has required reviewers and `prevent_self_review=true`; UUID variable
   names are present and the independent cleanup janitor is active. Azure role
   grants/OIDC trust still need actual preflight, and the protected lab job needs
   independent environment approval. No missing role is invented from an unrun
   preflight, and no subscription/identity values are published.
3. Independent release evidence acceptance and ordinary review are required
   before any separate capability promotion PR can merge.

**Qualification implementation/evidence gaps, separate from product defects:**

- Azure needs a current exact release-candidate input and full signed HTTP/
  operator/native-installation/privacy/TLS journey in addition to the dedicated
  18-case workflow. Its existing development report excludes real IMDS and
  natural access-token expiry; these cannot be silently claimed as covered.
- Shared IIS needs the exact installed package on Server 2022/2025, complete
  signed store/API/worker/agent execution and separate actual hosts/offline
  consumer coverage. Retain the existing native CNG/ACL/algorithm evidence,
  then add restart, lease/import/activation interruption/failure, current binding/
  ownership refusal, read-only reconciliation/original retry and retained rollback
  against those bytes. Two bindings on one VM cannot fill the host requirement.
- Staging needs a dedicated native packaged producer/accepted report covering
  preparation without mutation/proof, protected exact bytes, separate activation,
  API/worker/agent restarts, lost acknowledgement, cancellation/supersession,
  local policy/authorization/reviewer changes, modified/missing bytes, live lease,
  closing windows/blackouts/stale canaries, actual TLS, partial failure/retry and
  retained rollback. Windows staging stays out of scope.
- Each cleanup provider needs an installed-agent public API/worker campaign
  using genuinely published eligible versions. Complete least-privilege metadata/
  exact deletion, retention/reference protection, independent review, current
  signature/scope, soft-delete readback and atomic receipt/audit/fence checks.
  Include denied/restored ACL, missing/already-deleted/malformed/future metadata,
  malformed/wrong-scope/provider/version receipts, stale/revoked review, lease and
  process interruptions, duplicate/concurrent cleanup/rollout/rollback, uncertain
  effects, original reconciliation and re-review refusal, without a second delete
  or success audit. Source 15/15 is reusable supporting evidence only.
- Add the capability-specific mandatory inventory, hosted provenance, teardown
  and collector acceptance contracts without weakening the existing 271 cells.
  A general green profile does not fill an absent capability-native producer.

No new supported product defect was demonstrated by these campaigns. The local
tooling failures remain recorded; the unchanged hosted Windows/Ubuntu tooling
passed. They are not relabelled as passing local tests. Source/runtime gates
are preserved while the native evidence gaps remain open.

## H. Individual verdicts

| Capability | Verdict |
| --- | --- |
| Azure Key Vault | **BLOCKED — EXTERNAL AUTHORIZATION REQUIRED**; current spending opt-in and subsequent independent approval are outstanding; exact native release evidence also remains |
| Shared IIS | **FUNCTIONALLY VERIFIED — NATIVE QUALIFICATION PENDING** |
| Linux staging | **FUNCTIONALLY VERIFIED — NATIVE QUALIFICATION PENDING** |
| Vault cleanup | **FUNCTIONALLY VERIFIED — NATIVE QUALIFICATION PENDING** |
| OpenBao cleanup | **FUNCTIONALLY VERIFIED — NATIVE QUALIFICATION PENDING** |

No capability is `QUALIFIED — PROMOTION PENDING` or `QUALIFIED AND ENABLED`.
The next permitted release sequence is independent implementation review,
protected merge with gates closed, reviewed trusted-main qualification work and
exact candidate campaigns, independent evidence acceptance, narrowly scoped
promotion review/CI, then verification of the promoted artifact's advertisement,
dispatch and actual native execution. Production deployment remains outside this
task's authorization.
