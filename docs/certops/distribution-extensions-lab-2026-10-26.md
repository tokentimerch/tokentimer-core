# Distribution extension lab — 2026-10-26

Product/CI candidate: `6245c3a473553b7e366198cd87b360aca28c4455`.
Operator lab candidate: `33260e8f02240a80a3a4b136551ad80e291b3e55`.
The Vault wildcard replay uses the CI candidate. Product sources match across
both candidates; later commits improve the tests.
Live Azure testing is excluded: no subscription or usable test identity is available.
All services are isolated lab instances using synthetic, customer-side credentials.

## Native Windows campaign

The [expanded CI run](https://github.com/tokentimerch/tokentimer-core/actions/runs/40288838220)
executes native IIS on independent Windows Server 2022 and 2025 VMs. Each OS
uses both the local HTTP transport fixture and a real, checksum-verified
OpenBao 2.4.1 process with a scoped read-only consumer token.

| Key | Server 2022 | Server 2025 | Meaning |
| --- | --- | --- | --- |
| RSA 2048 | Passed with both transports | Passed with both transports | Full deployment campaign |
| EC P-256 | Passed with both transports | Passed with both transports | Full deployment campaign |
| EC P-384 | Passed with both transports | Passed with both transports | Full deployment campaign |
| EC P-521 | Safe rejection with both transports | Safe rejection with both transports | Rejected before import, native helper invocation, binding mutation or uncertainty journaling |

The twelve positive campaigns exercise two SNI consumers, non-exportable machine
CNG keys, protected key ACLs, actual NetworkService signing, exact IIS/HTTP.sys
and served TLS, idempotent retry, verification-only execution, lease interruption,
uncertainty fencing, read-only reconciliation, original-intent retry, new material,
retained rollback, and stale/unauthorized/CA-material rejection.

The replacement case interrupts after a different certificate is imported,
proves the old binding remains intact, and refuses reconciliation while it is
stale. A typed customer-side repair activates the intended leaf; read-only
reconciliation and the original approved retry then restore the consumer.

Expanded testing found that P-521 could pass CNG parsing/signing but fail IIS
activation on both tested Server versions. Shared IIS consumers now reject it
before mutation with `material_windows_algorithm_unsupported`. Provider storage
and Linux algorithm support are unchanged. The UI explains the supported IIS
algorithms. Native ephemeral PKCS#12/signature checks passed for all three EC
curves on the Windows workstation.

## Other completed checks

| Check | Result |
| --- | --- |
| Core unit tests | 2,759 passed |
| Contract tests | 47 passed |
| Integration tests | 1,395 passed |
| Recursive Linux agent suite, Debian/Node 24 | 2,012 passed, 15 explicit platform/environment skips |
| Native Windows agent package suite | 2,008 passed, 15 explicit platform/environment skips |
| Real provider compatibility | OpenBao 2.3.2 / 2.4.1 and Vault 1.21.0 passed |
| Full CI | All 35 jobs passed, including all four image build/boot/Grype scans |
| Distribution database campaign | 55 PostgreSQL scenarios passed; all six migration histories and three provider pin/rollback cases also passed in CI |

Provider compatibility includes scoped AppRole access, revocation/rotation, CAS,
exact version reads after a privileged later write, delete/undelete/destroy,
and recovery after a committed write loses its response. API/database tests
also cover all six migration histories, immutable provider authority and version
pins, approvals, concurrency, retained rollback, transfer and retirement fences.

The recursive Linux suite runs with the frozen workspace dependencies and an
init process to reap deliberately orphaned subprocesses. It exposed a test that
looked up a Linux ownership receipt using its portable wire label; the test now
reads the persisted receipt by the returned receipt ID.

## Operator lab campaign

| Real store | Ordinary | SAN | Wildcard |
| --- | --- | --- | --- |
| OpenBao 2.4.1 | Passed | Passed | Passed |
| Vault 1.21.0 | Passed | Passed | Passed |

All six cohorts passed all fifteen mandatory phases without skips: ninety
mandatory phases in total. Each cohort completed three real Pebble DNS-01
orders, forty operator checks (forty-one for SAN), and its custody audit.
The passing cohorts needed no transport rereads.

Sanitized JSON reports, package manifests, screenshot evidence and their
SHA-256 hashes are collected locally in
`qualification-results/distribution-extensions-20261026/summary.json` and
`qualification-results/distribution-extensions-20261026.zip`. The archive
excludes local credentials, browser sessions, private keys and database dumps.

The lab uses the real API/worker/PostgreSQL, Pebble DNS-01 CA, authenticated
dashboard and Chromium, scoped AppRoles managed by Vault Agent, and unprivileged
packaged agents controlling actual nginx and HAProxy TLS listeners. Product
state changes go through HTTP and signed jobs. The harness does not insert
certificates, fabricate receipts or write product database rows.

The initial runs corrected stale rollback/receipt assertions and added the
P-521 safety restriction. One Vault wildcard browser cohort timed out during a
shared dashboard rebuild; its fresh replay passed with the dashboard build
held fixed. Failed development attempts remain in the ignored local lab
directories and are excluded from passing-cohort totals.

## Running review lab

Dashboard: <http://127.0.0.1:61401>. Inbox: <http://127.0.0.1:61403>.
Synthetic owner: `owner@wildcard.test` / `LabOwner-2026!Only`.
Project: `tt-wildcard-ux-review-extensions-20261026`.

This separate OpenBao SAN lab retains its active workspace and two verified
nginx/HAProxy consumers. Genuine agent filesystem discovery and trusted TLS
handshakes match the published identity. It uses a source-based qualification
artifact for inspection; the six acceptance cohorts use packaged agents.

Select **Shared Certificate UX Lab 585be1df** in the workspace picker and open
**CertOps → Certificates → the active certificate showing 2/2 deployments →
Deployments**. Jobs and renewal history show signed publication, approvals,
fault recovery and per-consumer evidence. The review lab deliberately omits the
final workspace transfer.

Discovery merges filesystem registrations into the certificate identity, so
the inventory's representative source can show **Agent-local** and **No
auto-renewal**. The Deployments view still opens the expected OpenBao group and
both verified consumers; the issuer registration retains its renewal profile.
Post-discovery browser inspection checked the actual visible identity row
against those group and consumer IDs. A separate provisioning row is an
expected rejected-before-claim fixture.

From the implementation checkout, stop only this lab with:

```powershell
./tests/wildcard-vault/ux-lab/run.ps1 -Action Stop `
  -Project tt-wildcard-ux-review-extensions-20261026
```

## Reproduce a packaged operator lab

From the candidate checkout with Node 24, pnpm 11.13.0, Go and Docker available:

```powershell
$project = 'tt-wildcard-ux-qual-my-openbao-run'
./tests/wildcard-vault/ux-lab/run.ps1 -Action Up -Project $project `
  -BasePort 60800 -CertificateMode san -MaterialProvider openbao-kv2 `
  -BuildImages -PackageAcceptance
./tests/wildcard-vault/ux-lab/run.ps1 -Action Test -Project $project
node scripts/certops-distribution-report.js ".scratch/$project/qualification.json"
./tests/wildcard-vault/ux-lab/run.ps1 -Action Stop -Project $project
```

Repeat with a fresh project for `ordinary` and `wildcard`, and with
`-MaterialProvider vault-kv2`. Ports bind only to loopback. `Stop` targets only
that named lab and retains its evidence/volumes. Store dev mode is volatile;
always use a new project for a new run.

## Production qualification boundaries

These are development qualification artifacts. OpenBao is in the candidate
manifest; Windows shared import and Azure production capabilities remain off.
Windows Server 2019, ARM64, a coordinated multi-host Windows signed
issuance-to-rollout campaign, and exact release artifact promotion remain
separate release gates. Cloud/Enterprise adoption is not part of this Core lab.
The local Docker/QEMU Windows disk is retained stopped; passing native evidence
comes from the Server CI VMs. No live Azure request, production deployment,
release tag or edition pin update is performed.
