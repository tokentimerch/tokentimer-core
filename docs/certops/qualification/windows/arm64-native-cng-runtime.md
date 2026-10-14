# Windows 11 ARM64 native CNG runtime

The manual **CertOps / Windows ARM64 native CNG runtime** workflow runs only the
trusted `main` reference on a fresh GitHub-hosted `windows-11-arm` machine. The
[runner label is documented by GitHub](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
This bounded desktop suite is separate from the broader ARM64 Windows host
workflow. Neither desktop lane qualifies a Windows Server slot.

The six mandatory scenarios require actual execution of native ARM64 Node,
PowerShell, Go and a freshly built current-source chain/store-query helper. The
producer independently measures the desktop OS product type, processor
architecture, runtime architectures and PE machine headers. Missing capabilities
fail the strict report. ARM64EC and ARM64X inbox executables retain their distinct
measured machine values; this initial lane refuses them rather than treating them
as wholly ARM64 executable evidence. An unsigned ARM64 cross-compiled helper alone
cannot satisfy this runtime suite.

## Native certificate cases

Production `generateCsrViaCng` and `acceptCertificateViaCng` create and accept
RSA-2048 and ECDSA P-256 machine keys in `LocalMachine\My`. An ephemeral local
test CA signs each real PKCS#10 request using the native .NET request loader,
which verifies the signature. An actually corrupted signature must be rejected.
Independent public-key, DNS SAN, exact key-usage and public certificate signature
checks bind each leaf to its request. The CA private key remains in one process's
memory and is disposed; it is never exported or written.

The accepted leaf's public DER and thumbprint must match its exact native CNG
container, unique key identity, provider, machine context and nonexportable policy.
The existing CNG export fixture supplies real signatures before and after an
actual private-export refusal and an exportable control of the same profile.
Private export buffers remain in memory and are cleared; only public signatures,
bounded HRESULTs and boolean observations leave that process.

The fresh ARM64 helper must execute real CryptoAPI chain and machine-store
operations: a trusted local signer without CDP produces `revocation_unknown`, a
wrong issuer public-key pin produces `ca_key_changed`, and a malformed public
certificate produces `invalid`. A complete machine-store scan must find the
accepted key reference; excluding that exact store/thumbprint must remove the
only reference. No successful revocation, network CA issuance or domain AD CS
claim follows from this local public fixture.

## Ownership, cleanup and artifacts

Before any key creation or public store mutation, a durable private receipt
records the fresh absent container or exact public certificate identity. Each
mutation also writes an active-operation guard before starting a native child.
Only an observed child `close` permits the guard to clear. Cleanup refuses an
active or incomplete guard, an existing producer PID, unknown key identity,
different public DER/native key association, a surviving machine-store reference,
changed helper bytes, or a linked/out-of-bounds work directory. It never kills or
adopts a process or key. An interrupted creation whose exact key identity was
never observed is preserved and fails qualification.

Normal cleanup and the independent `always()` workflow step remove only exact
receipt-owned public leaves, controls, CNG containers and public root trust. A
failed safety check preserves the private receipt and owned temporary files; the
disposable hosted machine supplies the final containment boundary. This is not a
claim that arbitrary process interruption can always yield a passing cleanup
report. No permanent machine, service, cloud lab or self-hosted runner is created.

Only `qualification-results/windows-arm64-cng-runtime.json` is uploaded. The
private receipt, public fixture files, raw machine inventory and work directory
are excluded. The public report requires every named case, exact current source
hashes, measured desktop identity and successful cleanup. Source/proof tests may
run on other architectures, but they do not qualify native ARM64 execution.

Native execution remains pending until this workflow is run successfully. This
suite deliberately makes no IIS, Windows service lifecycle, Windows Server,
domain AD CS, installed agent or published package qualification claim.
