# Installed Windows agent qualification

The manual `certops-windows-e2e.yml` workflow runs only on the trusted main reference in disposable GitHub-hosted Windows Server 2022 and 2025 environments. It initializes a separate loopback native PostgreSQL instance, applies migrations, and starts native Pebble and its DNS challenge server. Tools include pinned Pebble 2.8.0 and acme.sh 3.1.2; the PostgreSQL binaries are provided by the hosted runner image and their version is recorded by initialization.

Select `key_profile` to qualify RSA 2048, 3072, or 4096, or EC P-256 or P-384.
The default runs RSA 2048; `all` expands to five isolated runner jobs with
separate execution reports. Each profile runs the complete installed-agent
issuance, renewal, restart, and crash-reconciliation journey. The supporting
native host suite separately exercises all five algorithms in both My and
WebHosting. These are implemented qualification cases awaiting opted-in CI
execution.

Select `windows_server=all` together with `key_profile=all` for all ten actual
server/algorithm combinations. At most two runner jobs execute concurrently.
Individual selections qualify only their selected environments; the complete
release matrix requires reports from every server/algorithm combination.

Initial issuance uses the authenticated public workspace jobs endpoint. A separate
owned fixture login first receives viewer membership: anonymous and viewer POSTs
must fail without creating any job or issuance inventory identity. The same login
then receives `workspace_manager` membership and submits the real issue request;
its identical replay must return the same job and certificate. PostgreSQL checks
independently require `source=api`, the actual requesting user, and server-derived
`os-store-managed` key custody. Fixture SQL provisions users/memberships only;
it does not create issuance jobs or bypass approval settings. The existing signed
installed-agent execution, CNG, IIS and authenticated TLS oracles remain mandatory.
The parent journey report retains only bounded admission and cleanup facts and
requires the current helper source hashes. Supporting public API checks have run
for all five profiles; the Windows native journey remains pending.

Each selected job also produces `windows-output-privacy-<key-profile>.json`.
An owned command-profile launcher emits generated test-only password, bearer
and private-key-shaped sentinels to actual child stdout and stderr, then
delegates the unchanged real ACME executable, arguments and environment.
Receipts must prove LocalSystem identity, emission and successful delegation;
the parent still independently requires actual CNG/IIS issuance and trusted TLS.
The production agent withholds captured child output. A bounded loopback observer
and independent PostgreSQL/SCM-log reads must find no sentinels while the genuine
ACME success marker remains available. This proves child-output confidentiality,
not live forwarding of subprocess output. Only counts, booleans, source digests
and public environment facts enter the report. All ten server/key-profile cells
require both the parent journey and this strict privacy evidence. Native
execution remains pending.

The fixture polls every two seconds and sends heartbeats and Windows discovery
updates every five seconds, preserving headroom under the unchanged production
machine-token rate limit. Slower fixture traffic does not relax server policy.

The default `historical_upgrade=true` runs the RSA-2048 source-upgrade lane
on each selected Server version; choose `windows_server=all` for the two
mandatory release slots. Other key profiles retain the ordinary candidate
journey. Set the option false only for a partial run: its missing upgrade
report cannot satisfy the full release matrix.

The predecessor is genuine `v0.17.2` source at immutable commit
`6c902405c7b5d229e2f47b4d5436d780e91c5e17`. GitHub must verify its signed
tag object before both native helper architectures are compiled exclusively
from that checkout and packed with its original JavaScript and installer.
The actual historical SYSTEM service registers, reports its historical
version, and completes a genuine scheduled dry-run noop. The candidate
installer must preserve that completed job, exact credential/configuration/
signing-pin bytes, same registered identity, and independently measured
non-exportable machine CNG key, IIS binding and authenticated TLS endpoint.
That certificate is an explicitly owned operator fixture, not a claim that
the historical agent performed native issuance. Candidate helper bytes and
a newer authenticated candidate-version heartbeat prove activation. Existing
legacy WER policy must remain unchanged; this does not prove dump suppression.

`windows-source-upgrade.json` is a strict independently required report
with `provenance=historical-source-build`, source/package/helper digests,
and verified owned fixture cleanup. Its two OS slots qualify distinct-version
source migration only when actually executed. Native execution remains pending.

The latest published [v0.17.3 release](https://github.com/tokentimerch/tokentimer-core/releases/tag/v0.17.3)
archive has verified SHA-256
`ec74ed8e1026b7a76b50e0ddc843ee8dc42d1283923ff01be11603069f94c6bb`,
matching both GitHub asset metadata and its public checksum sidecar. Actual
archive inspection on 2026-10-14 found neither native service-host executable,
although its Windows installer requires them. The manual
`certops-windows-published-baseline.yml` preflight therefore fails before
any lab installation and retains a public blocked report. A genuinely complete
published predecessor is still required for published-package upgrade
qualification; rebuilding that source or adding candidate helpers cannot
satisfy it. This blocked packaging prerequisite is separate from the executable
source-upgrade matrix slots.
The preflight also requires the exact public release ID, asset ID, asset name,
size, download URL and GitHub-reported digest before inspecting the archive.
Missing, duplicated or changed release metadata fails; matching metadata does
not qualify a cryptographic release signature or execute an upgrade. The local
read-only inspection confirms this blocked prerequisite and never substitutes
candidate executables into the published archive.
Current candidate package tests freshly build both helpers and require their
presence and architectures. Archive checksums and a signed source tag do
not establish a signed executable or release-asset attestation.

The journey freshly builds the product release archive, verifies its checksum and native helper architecture, then executes its PowerShell product installer with only the fixed install-root selector redirected to an owned temporary directory. The actual installed service host and agent run under LocalSystem from those checked candidate bytes. Bootstrap registration and authenticated signed job dispatch use the real API. The API issuance service creates a Windows IIS target job; the agent generates its non-exportable CNG key, completes DNS01 issuance through acme.sh, accepts the certificate in My, and deploys its IIS SNI binding. Independent trusted TLS confirms the served certificate and SAN; Windows store and netsh observations confirm deployment, and the database must contain agent evidence for the completed job. Unmodified fixed-root installation and externally authenticated signed release provenance remain separate qualification cases.

After issuance, the installer runs again through its actual staging/activation
and service upgrade path. The SCM host PID must change, operator configuration
and the registered credential must remain byte-identical, and a fresh
authenticated heartbeat must arrive. A native SYSTEM ReadData denial on one
owned public candidate file then forces the real copy stage to fail. An
independent Node read must actually be denied first; afterward the running
service PID, installed binary, configuration and credential remain unchanged.
The original file ACL is restored and the fixture removed in `finally`.
Another attempt deliberately replaces
only the disposable extracted candidate's native service executable with an
unloadable file. The actual installer must fail its health check and restore
the exact previous executable, configuration and registered credential;
the restored service must send a fresh authenticated heartbeat. Candidate
source bytes are repaired in `finally`. This proves native loader-failure
rollback, while distinct-version migration and atomic-rename failure remain
separate qualification cases.
At the end, the candidate's actual uninstaller must remove service/application
resources and preserve its registered credential and configuration.
Before uninstall, the actual API agent identity is retired. A newly logged
native host retirement exit 86 must correspond to SCM's clean exit status,
and no service process may appear over five explicitly configured recovery
intervals, despite failure recovery being enabled.
The fixture records the previous node.exe WER policy before installation.
Candidate installation must preserve it; a historical predecessor's policy
change is restored only after the owned service has been removed. Recovery is disabled before deliberate
startup and hard-crash cases so native observations cannot race an automatic
restart.

Dump suppression is not qualified: Microsoft defines [`DumpType=0` as a
custom dump](https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps),
so observing that registry value does not prove suppression. The optional
`wer_probe` workflow input is an experimental positive control. It copies the
native Node binary under a unique executable name, verifies identical bytes,
sets an explicit custom-dump policy in an owned WER key and output folder, and
aborts only a fresh benign child with a minimal environment. It must observe
a nonempty custom dump, then delete all dump bytes and its key. No agent,
API, database, bootstrap, DNS or job configuration is passed to that child;
the real node.exe dump sink is never redirected. An absent dump is
inconclusive and fails the diagnostic. After that positive control, an
experimental native debugger helper runs the same benign binary through
handled exceptions, exit 17, exit 86 and an abort. Normal exit codes must
survive; a last-chance fault must be terminated, and no new dump may appear
in the previously proven sink. The helper pins its event loop to the creating
Windows thread and never reads child memory. This is a prototype of the
[native debugger contract](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling),
not a change to the product service host. Its source compiles, but the probe
has not run on the native qualification hosts and does not establish a
supported suppression fix.

The qualification harness itself runs as SYSTEM through a temporary, uniquely named Scheduled Task with a bounded execution limit. This lets its independent filesystem observations read the agent's restricted state without granting broader access to agent credentials or weakening trusted-owner checks. Prepared config and DNS credentials use the production restrictive ACL helper. The task, scoped environment launcher, and public exit receipt are removed afterward. Git trust is scoped to this checkout through process environment variables.

After issuance, the persisted profile must describe the exact IIS target, ACME command, CA, and DNS provider, and its management period must enable automation. Pebble's short-lived leaf must naturally fall inside the profile renewal window; the fixture does not rewrite certificate expiry or manufacture a profile. The real maintenance worker function runs its renewal scheduler from persisted state. The installed agent must complete that scheduler-created renewal, and fresh trusted TLS plus netsh must observe a different served certificate while the superseded certificate survives its rollback window. This exercises the actual scheduler function and installed-agent renewal, rather than a separately deployed worker daemon.

Before renewal, the real service is stopped and its owned configuration is temporarily malformed. A second startup removes only the configured agent identity while retaining its actual credential. Starting the packaged CLI must produce the corresponding new parse or inconsistent-identity failure in the host log and leave SCM stopped, the registered credential unchanged, and the deployed native binding intact. Database reads require exactly one existing registered identity after each refusal. The exact original configuration is restored in a `finally` block, then the service starts again. A fresh authenticated heartbeat must arrive using the unchanged persisted credential after its bootstrap registry values have been scrubbed; trusted TLS must still serve the previous certificate. These configuration repairs occur between jobs and do not prove credential replacement through a fresh re-registration or package-version upgrade recovery. Native execution of the added identity case remains pending.

A further scheduler-created renewal is interrupted after native key generation. An owned loopback DNS proxy holds its next real mutation request, allowing the test to observe the actual CNG key and durable job journal before killing only the owned service child process tree. The fixture advances only that job's lease deadline and runs the real reaper with a short offline threshold: the running attempt must become `orphaned_unknown_effect`, require operator reconciliation, and consume no extra retry. After service restart, startup reconciliation must remove that orphaned key and mark its journal, while fresh trusted IIS TLS must still serve the previous certificate. The attempt count must remain unchanged. This proves native key reconciliation and safe lease handling after a hard crash; it does not claim safe replay after a completed certificate cutover.

The actual agent log transport must persist rows for the issuance job. Those rows must contain neither its bootstrap token nor private PEM material. This checks real streaming and persistence; it does not inject a secret into native ACME stdout or claim every redaction pattern was exercised.

The workflow verifies that the named journey and all required protocol tests ran through the JSONL report verifier. It does not qualify enterprise AD CS or browser navigation. Initial job creation uses the actual API service transaction, rather than an authenticated browser or user REST request. Those are separate qualification scenarios.

The allowlisted `windows-candidate-<profile>.json` artifact contains only the
verified package version, archive/native-helper digests, native execution
architecture and unsigned candidate/root-adapter provenance. It is package
identity evidence; the named JSONL test report establishes execution. No
state, bootstrap environment, ownership receipts or dump bytes are uploaded.

Only disposable hosts may run this journey. It refuses an existing TokenTimerAgent service or existing fixture CA roots. Teardown stops and removes the owned service, removes the unique site/binding and issued certificate/key receipts, removes the newly imported Pebble trust anchors, and deletes its job/certificate rows and temporary files. The outer protocol fixture owns the workspace, agent registration, and bootstrap rows. Uploaded artifacts are limited to the sanitized execution report; agent credentials, logs, keys, and database files are excluded.

After actual service retirement, a fresh protected state directory exercises
replacement registration through the installed candidate CLI. Reusing the
retired identity must exit with code1 and report HTTP409; an independent public
protocol request confirms `CERTOPS_AGENT_REGISTRATION_CONFLICT`. No credential
may be written, the failed transaction must preserve the bootstrap token, and
failure logs must redact it. A different identity with fresh bootstrap
authorization must create its own credential and subsequently heartbeat with
its declared selectors. The predecessor remains retired with an unchanged
credential hash and job state. The parent journey independently checks its
original credential bytes and trusted served certificate remain unchanged.

A focused local Windows run passed the protocol/process assertions against
the real API and PostgreSQL. The installed-service and IIS preservation checks
remain pending in the native lane. This case does not automatically migrate
management profiles or certificate custody to the replacement identity, and
the replacement runs as a bounded CLI process under the fixture identity.
Fatal CLI startup errors now allow pending native teardown to finish before
exiting with code1; the old immediate exit reproduced a native Windows abort
during the registration conflict.

Run `node scripts/certops-windows-e2e.js` only after provisioning those prerequisites and setting `CERTOPS_WINDOWS_BASH` and `CERTOPS_WINDOWS_ACMESH`. This implementation has not yet undergone an opted-in hosted execution; syntax and contract checks do not prove the real-host journey passes.

### Native child output privacy

The qualification command profile delegates the actual Git Bash/acme.sh client
through an owned launcher that emits random test-only bearer/password and PEM
sentinels to both real child streams. Native identity/emission/exit receipts stay
inside protected temporary paths. The actual client still performs its real
ACME order; existing CNG custody, issued-leaf and trusted IIS TLS checks remain
mandatory.

Successful ACME child output is captured and intentionally withheld, rather
than streamed as individual console lines. The fixture requires the genuine
agent ACME-success marker, checks a transparent literal-loopback machine upload
observer, and independently scans persisted job logs/evidence/results and SCM
console files for sentinel absence. It makes no claim that child stream lines
were uploaded. The observer admits only exact POST machine routes and bounded
machine headers, forwards original bodies, refuses URL/path escapes and drains
only its owned sockets during cleanup.

Every key-profile/Server slot must also produce and verify
`windows-output-privacy-<key-profile>.json`; missing proof cannot be hidden by a
successful parent test. Reports contain measured Server/SYSTEM identity, source
hashes, bounded counts and boolean privacy observations, never the recipe,
stream contents or credentials. Portable process/socket tests cover fixture
behavior; actual installed SCM/ACME privacy execution remains pending until the
protected Windows workflow runs.
