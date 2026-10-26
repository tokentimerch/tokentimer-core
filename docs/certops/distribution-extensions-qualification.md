# Distribution extension qualification

The [2026-10-26 expanded lab report](distribution-extensions-lab-2026-10-26.md)
records the current non-Azure campaign, including Server 2022/2025 and the
pre-mutation P-521 restriction. The initial implementation evidence below is
retained for provenance.

Implementation evidence recorded on 2026-10-25. These are development checks,
not an exact-artifact production release campaign. See [ADR-0015](../adr/0015-certops-material-providers-and-windows-consumers.md)
and the [operator runbook](distribution-extensions.md).

## Evidence and release gates

| Surface | Infrastructure actually exercised | Result / boundary |
| --- | --- | --- |
| OpenBao KV v2 | Real OpenBao 2.3.2 and 2.4.1 Docker services, from native Windows Node and Linux Node 24 | Publication, CAS=0, immutable version 1, exact reads after a privileged version 2 write, AppRole login, ACL denial, token rotation/revocation, delete/undelete/destroy, and recovery after a real committed write loses its HTTP response passed. The adapter is shared with Vault. |
| HashiCorp Vault regression | Real Vault 1.21.0 Docker service | The same KV v2 compatibility scenarios passed. Existing Vault configuration and numeric wire references remain valid. |
| Provider orchestration | Real PostgreSQL 17 | All three provider types passed claim-bound publication, immutable provider authority, numeric/opaque version constraints, public reads, approval snapshots, exact deployment pins, failure evidence, and a retained-version rollback while the source has a newer identity. |
| Existing distribution governance | Real PostgreSQL 17, unchanged distribution regression suites | 55 tests passed across publication/renewal, approvals, frozen waves, retirement, concurrency, late receipts, transfer containment, required/optional failures and rollback. |
| Windows PKCS#12 and key handles | Native Windows 11 CryptoAPI/CNG | Encrypted PKCS#12 parsing, private-key signing association, independent CNG handle lifetime, and effective ACL mask comparison passed. The parser test creates no persisted production key. |
| Windows shared consumer | Real Windows Server 2022 GitHub Actions VM with IIS installed | The native campaign passed: two distinct IIS SNI consumers, non-exportable machine CNG import, exact protected ACLs, actual key use as NetworkService, exact IIS/HTTP.sys and served TLS, idempotent retry, read-only verify, lease interruption after import, reconciliation/original retry, stale/unauthorized rejection, CA-material rejection before mutation, new leaf activation and retained rollback. The material-store transport in this cohort is a local fixture. |
| Azure Key Vault | Local bounded HTTP fixtures and injected identity transport | Token sink rotation/expiry, workload federation renewal, fixed IMDS scope/headers, authorization denial, opaque pins, ambiguous writes, no blind PUT retry, conflicting versions, hostile paging, metadata-only material and unsupported configuration rejection passed. **No real Azure vault was tested.** |
| Linux consumers | Existing agent suite plus real local TLS listener fixtures | Existing file deployment, listener verification, journals, fencing and reconciliation remain covered. This run does not replace the separate containerized nginx/Apache/HAProxy release campaign. |

The real Windows campaign passed against implementation commit
`2de2a6a50f22a2716720a6ba269b3fe10797e0c5` in
[the Server/IIS CI job](https://github.com/tokentimerch/tokentimer-core/actions/runs/40233848306/job/121291185028).
The test ran without skips. It exposed and fixed a CNG ACL comparison bug:
the Microsoft Software KSP returns generic rights alongside expanded file
rights. Verification now compares effective rights and still rejects extra
rights/principals, inherited ACEs and missing ACL protection. The service-account
probe proves the configured read grant permits actual key use without export.

The candidate manifest includes OpenBao compatibility. Azure
`material-store-azure-key-vault-v1` and Windows `windows-material-iis-v1` remain
absent from the shipped qualified manifest. API/contract availability does not
grant those capabilities. Dispatch requires a fresh provider-specific
declaration; the agent checks the build manifest again before execution.

The workstation's Azure service-principal credential was expired and no
dedicated customer-local test identity/vault was available. Do not enable the
Azure gate on mock evidence. Real identity renewal, least-privilege issuer and
consumer roles, denied/missing/disabled versions, network interruption and
audited cleanup/retention still need qualification in a dedicated customer
environment.

For Windows, two bindings on one VM do not establish two-host/offline-agent
qualification, a signed control-plane issuance-to-rollout journey, or support
across all advertised Server versions. Complete those campaigns against the
exact candidate artifact before promoting the Windows capability. Preserve
the existing [ADR-0012 decision 14 promotion discipline](../adr/0012-certops-windows-execution-surface-and-trust-anchors.md#14-new-operations-actions-capability-gate-and-rbac).

Other completed checks include 2,759 Core unit tests, 47 contract tests,
all six supported migration-history paths through migration 78, dashboard
distribution tests, agent tests on Linux and native Windows, contract/integrity
and secret-logging checks, lint/build/type checks, dependency audit, Compose
validation, and the CI Helm 3.20.1 template verification. Existing lint warnings
and frontend chunk-size warnings remain. A successful main CI Docker/security
scan was inspected; this change does not modify Dockerfiles. See the PR for
final suite totals and any execution-specific caveats.

The [implementation CI run](https://github.com/tokentimerch/tokentimer-core/actions/runs/40233848306)
also passed 1,395 integration tests and the full native Windows agent package
suite (2,007 passed, 15 explicit platform/environment skips), backend/frontend
coverage, and Helm smoke testing. The local Node 24 Linux run includes every
recursive source test (1,943 passed, 26 explicit skips). Production capabilities
remain subject to the separate release gates above.
All 20 jobs in that implementation run passed, including Docker image build,
boot verification and Grype security scans. This evidence-report update changes
documentation only; it does not change the tested implementation.

## Repeat the real provider compatibility tests

Use disposable services; the root token below is a synthetic fixture, never a
customer credential. Ports are bound only to loopback. No API/worker process
or `.env` file is needed. From the repository root in PowerShell:

```powershell
docker run --detach --name tt-openbao-qualification --cap-add IPC_LOCK `
  --publish 127.0.0.1:58207:8200 `
  --env BAO_DEV_ROOT_TOKEN_ID=isolated-openbao-fixture-only `
  --env BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200 openbao/openbao:2.3.2
$env:TT_REAL_KV = '1'
$env:TT_REAL_KV_PROVIDER = 'openbao-kv2'
$env:TT_REAL_KV_ADDRESS = 'http://127.0.0.1:58207'
$env:TT_REAL_KV_TOKEN = 'isolated-openbao-fixture-only'
node --test tests/e2e/material-providers-real.test.js
docker rm --force tt-openbao-qualification
```

Wait until the service reports ready before running the test. Repeat with
`openbao/openbao:2.4.1`. For Vault, use `hashicorp/vault:1.21.0`, the equivalent
`VAULT_DEV_*` environment variables and `TT_REAL_KV_PROVIDER=vault-kv2`.
The `material_store_compatibility` CI matrix runs these three services with a
health check. Both cases in the test file are individually gated: a skipped
Azure case is not Azure evidence.

For a Linux client, mount this checkout into a Node 24 container and use the
provider container's network namespace. Pass the same `TT_REAL_KV_*` values,
with address `http://127.0.0.1:8200`, then run the same test. The adapter and
fixture use Node builtins and require no secret-store SDK.

## Repeat real Azure tests

Prepare a dedicated public-cloud vault and a protected local JSON store
configuration using the [documented auth and permissions](distribution-extensions.md#azure-key-vault).
The test supplies its own unique workspace/group/material identifiers; the
file supplies provider, address and auth. It deliberately retains the unique
secret names because the issuer needs no delete/purge permission. Dispose of
the dedicated vault using the customer's normal retention procedure.

```powershell
$env:TT_REAL_AZURE = '1'
$env:TT_REAL_AZURE_CONFIG = 'C:\ProgramData\TokenTimer\qualification-store.json'
node --test tests/e2e/material-providers-real.test.js
```

The gated real test currently proves actual publish, exact retrieval,
idempotent recovery and missing-version rejection. The broader Azure release
campaign must also exercise independent read-only consumer access, denial,
revocation/renewal and a lost provider response. The local fixture tests prove
those protocol boundaries but do not substitute for the live campaign.

## Repeat native Windows/IIS tests

Use an elevated disposable Windows Server with Node 24 and IIS
`Web-Server`, `Web-Mgmt-Tools`, `Web-Scripting-Tools` installed. Run the checked-out
test inside the VM; keep all fixture keys and protected staging there.

```powershell
$env:TT_WINDOWS_MATERIAL_REAL = '1'
node --test tests/e2e/windows-material-real.test.js
```

Manual dispatch of `ci.yml` also runs this test in its
`windows_material_qualification` matrix on ephemeral Windows Server 2022 and
2025 runners with real IIS installed. Each OS covers RSA, P-256, P-384 and
P-521 with both a local HTTP fixture and a real checksum-verified OpenBao
2.4.1 process. The OpenBao consumer uses a scoped read-only token. P-521 cases
require rejection before native mutation; the twelve supported-key cases run
the complete native campaign, including a different-leaf import interruption,
typed local repair and read-only reconciliation. Push runs leave that external
qualification job gated off. The ordinary native Windows agent unit suite
remains separate. See the workflow for its per-case environment and provider
setup when reproducing the matrix locally.

The test reserves port 45443, uses uniquely named IIS sites and a unique
machine personal store, and removes only its own sites/certificates/keys.
It also owns a temporary NetworkService scheduled task and a separate directory
containing only public helper files and an output marker; it never grants that
identity access to PFX, token or bundle staging.
Its material-store transport is a local fixture: the **store import,
private-key permissions, IIS metadata, HTTP.sys and TLS handshakes are native**.
It does not claim a live CA order or a signed server/worker journey.

For a Linux-engine Docker workstation, a Windows **VM** is required; a Linux
container cannot supply Windows CNG or IIS. The development lab used
`dockurr/windows:5.14`, `VERSION=2022`, `RAM_SIZE=3G`, `CPU_CORES=2`,
`DISK_SIZE=40G`, `KVM=N`, `NETWORK=user`, and a dedicated named storage volume.
The evaluation ISO is downloaded by that image. Hardware KVM can be used when
available; software emulation is substantially slower. Do not change the
workstation's virtualization settings or restart it to run this test.
The local software-emulated VM reached first-boot setup during this development
run; no passing IIS result is attributed to that Docker VM. The passing native
evidence above comes from the separate Server 2022 CI VM.

Mount a dedicated OEM directory at `/oem` containing `node.exe`, the agent's
`src`/`vendor` trees and this test at their repository-relative paths. Its
`install.bat` can invoke a fixed `setup.ps1` to install the IIS features, then
run the command above from `C:\OEM\repository`. A dedicated `/shared` bind
mount is available in the guest as `\\host.lan\Data` for public test results.
Use a local copy for execution, since protected staging must not live on SMB.
Publish any console/management port only on `127.0.0.1`, keep credentials
synthetic and confined to this disposable lab, and stop/remove only the lab's
own containers/volume when finished. Never upload fixture PFX files, identity
tokens or customer key material as CI artifacts.

## Edition adoption

Core owns the implementation. Enterprise composes the base CertOps services;
Cloud has an older Core pin and an independent migration/route overlay.
Adopt migration 78, widened contracts, provider-aware services and agent
capabilities together when those editions update their Core pin. Review
Cloud's migration ordering and route composition and rerun each edition's
RBAC/governance suite. No sibling release pin or customer environment was
changed, and no complete Cloud/Enterprise qualification is claimed here.
