# Certificate distribution qualification

This extends PR #358 after merging main's PR #329 (`6fc0c44a`). Existing
qualification suites and their obligations remain mandatory. Distribution is
still outside the shipped agent capability manifest. Passing a source-mounted
lab is supporting E2E evidence, not a production capability release approval.

## Reproduce the supporting runs

Use Node 24, locked pnpm dependencies, Docker and Chromium. Run from this checkout:

```powershell
pnpm install --frozen-lockfile
pnpm exec playwright install chromium
node scripts/certops-distribution-postgres.js
node scripts/certops-distribution-vault.js

# Choose a NEW name and unused ports for each cohort: ordinary, san, wildcard.
$project = 'tt-wildcard-ux-qual-your-unique-run'
./tests/wildcard-vault/ux-lab/run.ps1 -Action Up -Project $project -BasePort 60800 -CertificateMode san -BuildImages
$env:CERTOPS_DISTRIBUTION_QUALIFICATION = '1'
./tests/wildcard-vault/ux-lab/run.ps1 -Action Test -Project $project
node scripts/certops-distribution-report.js ".scratch/$project/qualification.json"
./tests/wildcard-vault/ux-lab/run.ps1 -Action Stop -Project $project
```

Linux CI uses the same PowerShell controller; install Chromium with
`pnpm exec playwright install --with-deps chromium`. The dedicated
[workflow](../../../../.github/workflows/certops-distribution-qualification.yml)
runs on affected trusted main pushes and manual dispatch on main. No customer,
production, shared-audit or live DNS-provider credentials are consumed.

PostgreSQL runs use a randomly named container and three fresh randomly named
databases, each migrated by the actual candidate executor. A dynamically bound
loopback port and explicit fixture opt-in replace historical fixed addresses.
The inherited fixed-port fences remain unchanged for their original callers.
Vault adapter tests share a network namespace with their own temporary Vault;
no Vault port is exposed. Both controllers remove only their owned container.
The lab controller refuses reused projects/evidence and occupied ports. It
stops only the selected Compose project and retains its evidence/volumes.
Never use global Docker cleanup. On local interruption, stop the exact named
lab; hosted workflow cleanup runs independently with `always()`.

## Evidence and scope

The `distribution-agent-lab` suite requires all thirteen phases. It cannot
resume a partial run or reuse a completed state. Missing Chromium, a candidate
identity, a phase, a required capability, or fresh ownership fails the strict
report. Report verification also binds all causal fixture sources by SHA-256.
Each certificate mode has a separate release-matrix obligation. All three
PostgreSQL fixture inventories and the real Vault adapter inventory are
separate supporting release cells. Renamed or omitted fixture tests fail the
inventory guard. Existing skip sites now explicitly route both real Vault
tests to this workflow; no skip is described as executed by the static map.

The API journey enrolls three actual CLI processes and uses real signing,
nonces, claims, leases, outbox, approval and result ingestion. nginx and HAProxy
load real certificates from Vault. External probes use ordinary Node TLS from
outside the customer container, a public CA root and SNI, independently of
agent receipts. Real Chromium reads the dashboard and its live API responses;
there are no route mocks. Group administration remains API-first.

The isolated Vault grants separate scoped issuer create/read and consumer read
tokens. A deliberately revoked issuer token tests same-job recovery after
customer-local rotation. The separate generic Vault scanner uses its own
synthetic lab root token: that existing inventory API explicitly accepts a
Vault credential and is **not** the certificate distribution credential path.
The final read-only privacy auditor streams the owned Core database dump and
API/worker logs to the customer container. Customer private-key fragments and
execution credentials stay there; only scan counts and verdicts return. No
database rows or agent receipts are injected by the direct journey/auditor.
The extended auditor also reads every published historical version through the
customer's scoped Vault adapter and scans retained rotated/revoked credentials
and protected local backups. Only public version IDs cross the controller
boundary. Missing/duplicated version inventories fail before any lab access;
private needles and historical credential files never become CI artifacts.
Pebble has no secret DNS-provider credential, so the privacy report explicitly
sets `dnsCredentialQualification: false`.

Only `qualification.json`, the public privacy verdict and dashboard images are
uploaded. Session files, runtime secrets, customer volumes, raw database dumps,
journey state and raw process logs must not be uploaded. Database evidence
uses the existing bounded Node reporter, which omits assertion/error payloads.

Reports carry `experimental: true`, `qualificationStatus: not-qualified`,
`allFeaturesQualified: false` and the source-mounted lab scope. Removing these
fields fails verification. The existing release collector refuses experimental
reports, even after every functional assertion passes. This intentionally keeps
release qualification blocked until actual candidate artifact/native evidence
exists; source-only declarations cannot enable capabilities.
Supplying credentials alone cannot make this experimental suite qualify a
release: a reviewed native runner/collector contract must replace these blocked
obligations with exact artifact evidence. Remaining native campaign source and
execution gaps are explicitly listed in the feature matrix.

## Remaining native obligations

See [the feature matrix](coverage-matrix.md). The lab has independent agents and
TLS processes on one disposable container host. It does not qualify separate
native VMs, a released package, customer ACME/Vault AppRole/DNS providers,
default lease/grace crash timing, retention elapsed windows, or all security
and transfer races through native processes. Existing PostgreSQL tests inject
receipts/rows to verify transactions; those results are integration evidence
and cannot substitute for the enrolled-agent journey.

Native qualification requires protected, explicitly owned issuer and consumer
hosts, exact candidate archives and hashes, a customer-controlled Vault KV v2,
an authorized ACME/DNS zone, real nginx/HAProxy, independent external probes,
and cleanup/reconciliation evidence. These prerequisites were not available in
this task. No workflow provisions or spends on such infrastructure implicitly.

The additional mandatory `security` and `runtime-controls` phases exercise
revoked consumer credentials, genuinely signed dispatch replay/misdelivery and
tampering, workspace pause, actual service-hook serialization/overlap, and
customer filesystem replacement followed by verification-only refusal and
approved repair. They do not manufacture receipts or modify the Core database.
Execution is recorded separately; adding runnable source is not qualification.

| Native blocker | Exact missing evidence or prerequisite |
|---|---|
| Artifact provenance | All distribution cohorts still enable capabilities in a volume-local source copy. No immutable packaged candidate with recorded archive/binary digests has executed these distribution phases. |
| Independent host deployment | The issuer and both consumers use separate agent processes on one owned container host. No owned independent issuer/NGINX/HAProxy hosts, installation receipts, reboot/cleanup campaign or external host probe records were supplied. |
| Native runner/collector contract | The lab producer is intentionally experimental and rejected by the release collector. A reviewed artifact-bound native distribution producer and corresponding collector obligations are still missing; credentials alone cannot satisfy this. |
| Customer trust and credentials | Pebble and dev Vault are real isolated services but do not validate customer CA trust, AppRole login/rotation, a secret DNS provider, customer ACL configuration or external logging sinks. No production secrets are used. |
| Default crash and freshness windows | No exact-artifact host-death, lease-expiry, late-outbox and default freshness-expiry campaign has run. SQL and bounded fault fixtures remain supporting evidence. |
| Retention | Live Vault deletion/undelete/destroy controls have runnable adapter checks. Elapsed customer retention windows, policy exhaustion and native rollback denial for an unavailable object remain separate obligations. |
| Freeze variants | Core exposes its workspace pause incident control. Billing/license freeze behavior belongs to variants and is not exposed as a Core API; no invented freeze endpoint is tested. |

## Tooling execution budget

`pnpm run test:certops:qualification` discovers the entire tooling inventory,
limits workers to four by default (or a validated `TEST_CONCURRENCY` from 1 to
16), and retains a twelve-minute subprocess timeout. The measured Windows
inventory exceeded the former five-minute limit. The CI tooling job allows
thirty minutes for dependencies, that inventory, collectors and guards.
Timeouts, signals, empty inventories and failed tests return failure; none
count as qualification evidence. Subprocess regressions exercise real failure
and timeout behavior, including isolation from a parent Node test context.

## Defect reproduced by the real journey

A genuine failed reload produced an agent outbox result with public nonce
`OMuMIxYIpFYikkNjwQ-eEldCLnuFEPc_`. Its decoded prefix resembles a zlib
container, so the unchanged private-material detector rejects it. The agent's
actual result POST returned `PRIVATE_KEY_MATERIAL_REJECTED`, leaving the Core
job running while the real reload had already failed. Reproduce deterministically:

```powershell
node --test tests/unit/certops-distribution-nonce.test.js
```

The narrow fix resamples only generated public dispatch nonces rejected by the
same detector, with a finite attempt bound. It preserves 24-byte cryptographic
randomness, signing, nonce ownership/replay and the custody rejection policy.
The failed source-mounted run remains failed; it is never rewritten as a pass.

A second real journey reproduced dispatch starvation after retiring an
unstarted rollback: with `maxJobs=1`, the old pending deployment repeatedly
occupied the SQL selection limit, then failed authoritative intent validation;
the newer approved verification job was never selected. The narrow SQL
prefilter now excludes paused/retired/superseded distribution rollouts before
the limit, while retaining the locked authoritative check. It does not mutate
historical jobs or receipts. A real PostgreSQL regression in
`pr329-review.test.cjs` reproduces two approved rollouts and proves that the
newer signed claim is returned without rewriting the old pending job. The
enrolled-agent retirement/recovery journey tests the complete execution path.

Main integration also needed both renewal-schema `allOf` conditions combined:
Windows key-reuse refusal and publication-only deployment-target rules. The
distribution contract generator now preserves unrelated existing conditions.
The scheduler's Windows test fixture now requests its required fresh key.
