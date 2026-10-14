# Windows host qualification

Run `node --test packages/agent/scripts/host/windows-host.test.js` from the repository root with `CERTOPS_HOST_TESTS=1` and `CERTOPS_QUALIFICATION_STRICT=1` on an elevated disposable Windows host with Go installed. Set `CERTOPS_QUALIFICATION_REPORT` to a JSON artifact path and `CERTOPS_HOST_ARTIFACTS` to a diagnostic artifact directory.

The manual `certops-windows-arm64-host.yml` workflow uses GitHub's hosted `windows-11-arm` desktop image. It requires actual ARM64 CPU evidence, native ARM64 Node and Go, and enabled desktop IIS without a pending restart. It executes the same mandatory host cases, including native CNG, CryptoAPI, IIS, retention and SCM operations. The service host and chain helper execute the build selected for the real process architecture; packaging both architectures alone does not satisfy execution. Git/OpenSSL and other ancillary image tools may use Windows emulation and are not claimed as native ARM64 product binaries. See [GitHub's runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) and [the Windows ARM image inventory](https://github.com/actions/runner-images/blob/main/images/windows/Windows11-Arm64-Readme.md).

The resulting report records the measured desktop build and ARM64 process architecture. It cannot satisfy a Windows Server 2022 or 2025 release-matrix slot. This supporting lane does not qualify the installed-agent/API/Pebble journey on ARM64: that separate lane still needs a verified disposable PostgreSQL provisioning path because the ARM desktop image does not ship the native PostgreSQL tools used by the Server workflow. ARM64 execution remains unqualified until the new workflow actually passes.

This suite creates a uniquely identified certificate in LocalMachine/My, exercises real discovery, independently exports and hashes certificate bytes with certutil, generates RSA and EC CNG CSRs, checks KSP container existence and absence of private key exports, and executes all four Go modules (service host, AD CS chain, AD CS CMC, and verifier). Required verdicts and cleanup are recorded independently of Node's test summary. Fixture certificates, private keys, and generated CNG containers are deleted in a finally block; every owned host resource gets a cleanup attempt even if another removal fails. Workspace logs can be copied before temporary files are removed.

The CNG scenario signs each public CSR using a disposable OpenSSL CA, accepts the issued certificate through certreq, and independently checks the associated private key name and non-exportable policy through .NET. The temporary CA private key stays in the local temporary directory and is excluded from artifact uploads. OpenSSL must be on PATH. This local signer validates Windows key custody and acceptance without claiming domain AD CS issuance coverage.

While that owned signer is trusted, the native chain scenario compiles and invokes the actual Windows chain helper. It requires an explicit revocation-unavailable verdict for a leaf without distribution points, rejects a different pinned issuer public key, and preserves the pin verdict when the actual signer reissues its CA certificate over the same key. Real PEM and DER inputs must agree, while malformed or absent public input must fail. Independently signed, genuinely expired and not-yet-valid leaves must fail with CryptoAPI's actual time-invalid trust bit; best-effort revocation cannot accept the expired leaf. Public verdicts alone are uploaded; this supporting native check does not qualify enterprise distribution points, revoked certificates, or two-tier AD CS chains.

The IIS scenario creates an isolated website on an ephemeral loopback port and replaces its certificate through the product deployment module. Independent TLS handshakes prove the served certificate before and after replacement. A certificate absent from the store forces a binding or verification failure, and a fresh TLS handshake plus netsh confirms rollback. All fixture sites, SSL bindings, and certificates are removed afterward. The host needs Web-Server and Web-Scripting-Tools without a pending reboot.

The retention durability scenario writes its own ledger in one process and loads it in a fresh process to check eligibility and persistence. It does not claim crash injection or real certificate deletion evidence.

The owned retention scenario uses the CNG-issued fixture certificates, checks that cleanup does not run inside the retention window, then removes the old certificate/key through the product cleanup function and verifies the replacement survives. Time and eligibility context are supplied by the test; this is supporting host integration, not a full served-TLS retention journey.

The elapsed expiry-grace scenario separately signs a genuinely short-lived public leaf for a new owned non-exportable CNG key. Trusted TLS must serve it while still valid, then the real deployment module replaces its IIS binding. With the unchanged 24-hour policy, the product's earlier deadline is the actual native certificate expiry plus its fixed 300-second grace. The fixture waits that real wall-clock deadline (roughly seven minutes), then calls the actual native retention collector and verifies the old certificate/key are absent, the persisted ledger says removed, and independent trusted TLS still serves the replacement. No clock, native query, TLS or eligibility context is injected. This supporting host case qualifies actual elapsed expiry-grace cleanup; it explicitly does not qualify an elapsed full 24-hour window or installed-agent issuance.

The SNI variant uses hostnameport bindings and validates that IIS sslFlags remain enabled through replacement and rollback. Root trust qualification distributes the disposable CA certificate through the product, verifies receipt replay makes no mutation, revokes it, and independently checks Root store presence. Any partial failure triggers removal of only the newly owned anchor.

Both IIS variants also keep an unrelated HTTPS binding live and independently prove it remains unchanged. Trust qualification separately installs an unmanaged fixture anchor and confirms product revocation refuses to remove it without ownership receipts. CNG custody includes overwrite refusal, malformed input rejection, SAN preservation, and WebHosting acceptance with no duplicate left in My.

The cross-store mutex scenario launches independent Node processes. A WebHosting operation must block a simultaneous My operation through their shared real filesystem lock, and My must become available after release. This supporting concurrency check does not claim concurrent certificate deployment coverage.

The SCM scenario builds the product service host with a temporary Go source overlay changing only its dispatcher label, then installs a uniquely named disposable service around a fixture child. Its executable/state path contains spaces. It verifies RUNNING/STOPPED/restart and bootstrap-token registry scrubbing, then checks real SCM recovery after child exit 17 and absence of recovery after retired exit 86. A caller with a foreign config path may only query; the real environment must remain unchanged. Its owning caller removes token/token-id values while preserving unrelated values, including a literal backslash-zero PATH entry. The scrub helper uses its existing spawn seam to redirect only the fixed registry-key argument to the owned unique service; all operations/results come from real reg.exe. Released configuration stays fixed, and the installed-agent E2E lane separately verifies the released registry target. Teardown only removes a service this test successfully created. Windows [documents the OWN_PROCESS dispatcher-name behavior](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_table_entrya).

This suite does not qualify domain AD CS enrollment or registration of an installed production agent against a server. Domain CA template drivers remain separate lab procedures. Go unit test evidence is labeled separately from real host operation evidence.

Each of the four Go modules runs with `go test -json`. Qualification rejects
any skipped selected test or subtest, any failure, empty execution, and any
started test which lacks a passing completion. Uploaded Go evidence contains
counts rather than raw test output. Packages without test files contribute no
test evidence. All five supported key algorithms have native CSR/accept and
key-custody scenarios in both My and WebHosting.

IIS supporting fixtures also verify same-certificate replay avoids mutation,
sequential shared-certificate rollout across two real bindings, and rollback
after a valid SNI rebind fails TLS verification because an owned concrete-IP
binding serves a different certificate. The latter uses actual HTTP.sys
precedence and a real TLS connection, with no fabricated verification result.
These supporting cases remain unexecuted until an opted-in host run.

An owned CurrentUser certificate proves the machine-store query does not
cross the user/machine boundary. Missing PowerShell and a real incompatible
native runtime must fail both store and HTTP.sys queries instead of reporting
empty inventories. IIS deployment also verifies that a missing query tool
fails before mutation. An owned endpoint's persisted HTTP.sys metadata is
temporarily given an unknown setting, unknown flag bit, and incomplete CTL
pair; product discovery/deployment must refuse these settings while the
independent native hash and served certificate stay unchanged. Teardown
restores the modified metadata and removes only owned resources.

The native retention guard fixture seeds a supporting ledger from actual
CNG-issued fixture certificates. The product collector reads real HTTP.sys
bindings, store/key associations, and replacement TLS with the real clock.
A still-bound predecessor blocks deletion. A second public certificate issued
for the original CSR is repaired to the same real KSP container; that surviving
shared key association also blocks deletion. Removing only this public copy
leaves the original private key intact, and a fresh 24-hour retention window
still blocks cleanup. This fixture does not claim that a full production
24-hour cutover interval elapsed in CI.

The unique SCM fixture also invokes the product PowerShell uninstaller with
only its fixed install-root and service-name selectors mapped to owned fixture
resources. It verifies actual service/app removal, state-marker preservation,
and idempotent uninstall replay. This supporting check uses a state marker;
qualification of a registered credential through the exact released Windows
installer remains a separate case.

The package fixture uses the product release packer, independently checks its
archive against both the checksum sidecar and native SHA256, parses both
shipped PE architectures, and imports the extracted runtime outside the
checkout without dependencies. An altered archive must fail checksum
verification. The shipped entrypoint must promptly reject malformed JSON and
array configuration without changing existing state-marker bytes; repaired
configuration must load. This is unsigned candidate package validation.
It does not prove signed release provenance, execution on arm64, or an upgrade
through the exact released installer.

The SCM fixture also launches the shipped CLI against malformed configuration
and requires a stopped service plus its explicit parse failure in the real
host log. Recovery is disabled during this negative case. Repairing the
configuration then starts a child through the real configuration loader and
reaches Running while preserving existing state-marker bytes. The repaired
child is the bounded supporting fixture; this does not prove registration or
credential-preserving package upgrades.

The unsupported-target fixture invokes the product executors against the real
owned IIS fixture. Standalone Windows IIS deployment and a renewal containing
two SNI targets must fail before mutation. Independent native snapshots verify
unchanged bindings, certificate-store membership, private-key associations,
exact CNG containers and export policies, while the owned HTTPS endpoint keeps
serving its predecessor certificate. This mandatory host case is source-ready;
its result requires execution in a qualified Windows environment.

The SNI fixture also removes its owned predecessor's public store copy while
preserving the separately recorded CNG key. A real concrete-IP shadow binding
forces verification to fail after deployment, and the native restore attempts
to reference the now-absent predecessor. The required rollback-failure case
must report failure, `rolledBack: false`, and a restore diagnostic. Independent
TLS and native reads measure the live shadow and unaffected unrelated endpoint.
Teardown removes the owned site, both endpoint types, and all recorded keys.
This executor integration case does not prove API job reconciliation; native
execution remains pending.

The store-lock worker-death fixture acquires the production store lock over
actual IPC, proves a simultaneous contender is refused, and starts a real
owned Node subprocess. Terminating the actual lock Worker must propagate
`STORE_LOCK_LOST`, abort and drain that subprocess, and permit a successor to
acquire the released IPC endpoint. Releasing the stale owner must preserve the
successor's actual ownership marker. No lock state, heartbeat or clock is
rewritten. A focused local Windows run passed these assertions; the mandatory
qualified Windows lane remains pending. This supporting case performs no
certificate operation and does not establish lease recovery.

The separate mandatory drain-timeout case deliberately keeps its benign owned
subprocess alive after the real abort signal. The production five-second drain
window must elapse before returning `STORE_LOCK_LOST`; the caller must observe
failure while a successor acquires the freed IPC endpoint. The fixture then
kills and drains its own child in teardown. A focused local Windows run passed.
This case measures the non-cooperative boundary; it does not claim that lock
loss forcibly stops an arbitrary native mutation subprocess.

The owner-process death case uses a separate real Node process to hold the
production store lock. Its independently read diagnostic marker must match
that child's PID and remain byte-identical after an abrupt kill of only that
owned process. A real contender must then acquire the freed IPC endpoint
without rewriting the stale marker or changing time, and publish its own
observed PID and owner token. A focused local Windows run passed; the qualified
server lane remains pending. This case proves lock recovery after process
death, with no certificate effects or fabricated lease expiry.

All three lock fault cases also passed against production Linux abstract IPC
in the pinned Node24 Debian container, with networking disabled and source
mounted read-only. The owner child loads only the production lock module.
This portability check proves actual IPC/subprocess behavior on both platforms;
it does not qualify CNG, IIS or a physical Linux service deployment.

The installer floor case runs the exact production build guard and failure
function extracted through PowerShell's AST parser. It checks three refused
numeric builds and four accepted boundary/server builds without invoking the
installer or evaluating its other statements. All seven focused local Windows
checks passed. This is a source guard regression, classified as unit evidence;
it does not boot an unsupported OS, prove its installer behavior, or qualify an
advertised SKU. Real supported SKU and architecture lanes remain separate.
