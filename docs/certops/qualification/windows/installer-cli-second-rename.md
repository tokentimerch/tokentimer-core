# Full installer CLI second-rename refusal

The manual canonical-root workflow runs three mandatory scenarios on fresh
Windows Server 2022 and 2025 hosts after genuine candidate installation and
service restart, before same-version candidate reapplication and uninstall:

- `windows-cli-second-rename-owned-fixture`
- `windows-cli-second-rename-preserves-installed-service`
- `windows-cli-second-rename-owned-cleanup`

The original packed installer is invoked byte for byte with its actual CLI and
canonical root. An external test-only launcher waits before invoking product
code in that same measured PowerShell process. The independent holder first
registers the exact process identity and retains its native process handle.
Only its acknowledgement permits the launcher to invoke the installer. A real
source-file oplock then holds the production staging copy until the holder has
opened the actual staging directory without delete sharing. No installer code
is rewritten or instrumented, and no watcher timing is used to seize staging.

Actual native rename events must show the predecessor moving aside and being
restored after staging activation fails. The installer must explicitly report
incomplete staging cleanup while the handle remains held. Directory identity,
installed bytes, original service PID/creation time/executable/path, protected
configuration/credential/signing pin and a fresh authenticated heartbeat must
remain unchanged. Releasing the handle then removes the exact owned staging
directory and drains both measured children.

The operator-created fixture uses a unique non-exportable machine RSA CNG key,
self-signed public certificate and exact loopback IIS/HTTP.sys endpoint. Trusted
TLS, native binding and protected key observations prove preservation. This is
an installer rollback control; it does not claim agent-issued certificates or
CA integration. Native cleanup rechecks endpoint hash/store/application ID,
site path/binding coordinates and the certificate's actual RSA CNG association.
Missing, changed or unreadable ownership preserves custody and fails the case.

Both canonical root and working directory carry an active cleanup guard before
children start. Installer close and actual process absence must be proven
before holder release; both children must be closed and absent before guards
become drained. Parent uninstall, service cleanup, recursive deletion and the
independent always-run root cleanup refuse active or incomplete guards. On
parent death, the holder stops its retained exact installer process before
releasing handles. If the ten-second stop observation budget expires, the
custodian retains its handles and guard until that exact process exits. It does
not release a live installer on a timeout or kill processes by name.

IIS installation must complete without requiring reboot; missing capabilities
fail qualification. The inner journey, producer and task have separate bounded
deadlines, followed by independent cleanup. Public artifacts include the strict
three-case `windows-cli-second-rename.json` sidecar with bounded facts and exact
source hashes. Private process receipts, raw inventories and credentials are
excluded.

Actual temporary-public-file supporting execution verifies interception and
restoration mechanics only. The complete installed-service/native certificate
scenario remains unexecuted until this protected workflow runs. Published
artifact upgrades, native ARM64 and dump containment remain separate work.
