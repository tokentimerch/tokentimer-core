# Canonical-root Windows installer lifecycle

The dedicated manual `certops-windows-fixed-root.yml` workflow uses fresh hosted
Windows Server 2022 and 2025 machines. It refuses any existing `TokenTimerAgent`
service or `C:\ProgramData\TokenTimerAgent` directory. It runs the packed
candidate's original `install-agent.ps1` CLI byte for byte, without replacing the
installation root or extracting production functions.

Seven mandatory cases establish ownership, install the actual candidate service
host, observe authenticated registration and bootstrap-registry scrubbing,
restart the LocalSystem service with a changed PID and fresh heartbeat, reapply
the same candidate while preserving configuration, credential and signing pin,
and execute the original uninstaller. Service/application absence and exact
preservation of operator state are asserted before final fixture cleanup.

Before installation, private internal and external receipts record a unique run
token and the canonical directory's native file ID. Normal cleanup and the
independent `always()` safeguard require matching receipts, unchanged directory
identity, an exact canonical resolved path, and no remaining service. If a
service survives a failed producer, cleanup first verifies its binary path
belongs to the owned canonical app. Foreign paths, redirected directories,
changed identities or missing ownership evidence fail closed. Private receipts,
configuration and process arguments are excluded from artifacts.

The public sidecar contains only seventeen mandatory booleans and an explicit
scope. The release collector projects these bounded facts; the verifier rejects
missing or false facts and stale producer/installer/builder source hashes.
The workflow also requires the disposable API/protocol suite to pass.

Implementation and supporting proof/cleanup tests are not native execution
evidence. The two Server lanes remain unrun. Same-version candidate
reapplication does not qualify a distinct-version or published-artifact upgrade.
The separate root-redirected ACME/CNG/IIS journey remains necessary for certificate
capabilities. The separate [full installer CLI second-rename source](installer-cli-second-rename.md)
now runs as a mandatory sidecar in this same fresh-host lane; its native
execution remains pending. The activation-function harness qualifies only its
supporting mechanics. This lane does not claim dump containment or ARM64
service qualification.
