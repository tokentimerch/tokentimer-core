# Second-rename activation-function restoration

`windows-activation-second-rename` is a separate RSA-2048 qualification in the
installed Windows Server 2022/2025 journey. It tests the actual candidate
`Copy-PackageTree` and `Activate-StagedPackage` functions against that journey's
owned installation. It does **not** execute the full installer CLI, provision a
service, or claim that first-rename refusal proves predecessor restoration.

The driver waits for a run-bound go signal. Before authorizing it, the parent
independently measures its PID, parent, Windows PowerShell executable, command
arguments and creation time. Receipt parsing never supplies process ownership.
Only the two named functions are extracted through the PowerShell AST; installer
top-level service and registry code is not evaluated. Actual package copy creates
the exact current-PID staging directory. A genuine `GENERIC_READ` directory
handle permits read/write sharing and excludes delete sharing on **staging**.

An independent native `FileSystemWatcher` observes the owned parent directory.
Its notifications must show exactly `app → app.previous.<PID> → app`, in order,
with no staging activation or overflow. Native volume/file IDs independently
require the original predecessor directory to be restored and the staged
directory to remain the same held object. Original application file hashes must
match. This distinguishes the second rename from a first rename that never moved
the predecessor.

The staging handle also prevents immediate deletion. The expected product error
is explicitly **recovery incomplete because staging cleanup failed**, while the
predecessor has already been restored. The fixture must not call that complete
rollback or pretend staging disappeared while its handle remains held. The
parent releases the verified child; only then does the driver close its handle,
remove its exact PID-owned staging directory, publish an atomic closed receipt
and exit. Cleanup uncertainty fails qualification; process termination is fenced
by independently measured identity, and uncertain state is retained for the
disposable environment's teardown.

The installed-only checks additionally require the same running SCM PID,
unchanged configuration and credential bytes, unchanged actual non-exportable
CNG certificate/key identity, unchanged HTTP.sys binding and independently
authenticated TLS. A strictly newer authenticated heartbeat must arrive after
restoration is independently observed. These checks run only in the opted-in
hosted journey, never as a workstation service test. The bounded sidecar is
`qualification-results/windows-second-rename-activation.json`; it contains
boolean oracles, source fingerprints and the explicit activation-function scope,
not configuration, credential contents, private material or raw process commands.

The nonprivileged supporting regression is invoked by:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/certops-installer-swap.test.ps1
```

It uses the same gated driver on an exclusively created temporary app/package.
Actual Windows PowerShell 5.1 execution has verified native rename notifications,
file identity restoration, explicit held-staging cleanup failure and clean child/
staging removal. It does not query or alter services or certificate stores. The
selective Windows job already runs this supporting command. Portable report
contract regressions reject missing/false custody, heartbeat or cleanup oracles
and any assertion of full installer CLI coverage. Full installed-service cases
remain pending their hosted native runs; no Windows qualification pass is implied
by these supporting checks.
