# Windows runtime reference

Advanced reference for CNG custody, IIS binding behavior, crash recovery, and retention. Begin with [Install on Windows](install-windows.md) for a first deployment.

<a id="8-windows-notes"></a>

## Windows notes

The agent supports native Windows service installation. Its runtime differs from Linux in the following areas:

- Windows state uses validated ACLs through `icacls`; POSIX-mode assertions do not apply. See [Windows installation](install-windows.md) for the permission model.
- Directory fsync after the deploy rename is skipped on win32 (opening a
  directory for fsync fails there); the file-content fsync before rename
  still runs on every platform.
- Symlink-dependent tests are skipped where symlink creation requires
  privileges; the realpath containment check itself still runs.
- The default config directory is `%APPDATA%\tokentimer-agent`.
- Absolute-path detection accepts POSIX (`/...`), Windows drive (`C:\...`),
  and UNC (`\\...`) forms.
- **Windows service host.** `install-agent.ps1` does not point the
  `TokenTimerAgent` service's `binPath` directly at `node.exe`: a plain Node
  process never calls `StartServiceCtrlDispatcher`, so the Service Control
  Manager fails the start (error 1053) and the configured failure/restart
  policy turns that into a restart loop. `binPath` instead points at a small
  native host, `packages/agent/windows-service-host` (Go, cross-compiled for
  both supported architectures by `build:windows-service-host`, shipped in
  the package's own `bin/`), which answers the SCM's start/stop/interrogate
  protocol on the agent's behalf, launches `node.exe` plus the agent entry
  point as its child process, and translates a stop/shutdown request into a
  graceful `CTRL_BREAK_EVENT` with a bounded wait before force-killing the
  child. See ADR-0012 decision 11.
- **Windows build-number floor.** `install-agent.ps1` fails closed before
  doing anything else if `[System.Environment]::OSVersion.Version.Build` is
  below 14393 (Windows Server 2016 / Windows 10 1607), the first widely-
  deployed release with both WDAC (ADR-0012 decision 8's documented
  hardened PowerShell-trust alternative) and CNG non-exportable key custody
  (decision 1) generally available. This is a preflight check only; it does
  not change what the agent itself requires at runtime.
- **Registry-persisted bootstrap token is cleared after registration.** The
  installer writes the bootstrap token into the service's own
  `HKLM:\SYSTEM\CurrentControlSet\Services\TokenTimerAgent\Environment`
  value so the service process inherits it as an environment variable, then
  deletes the on-disk `bootstrap.env` file. The agent itself rewrites that
  registry value (dropping the token, keeping the config-dir entry) once
  registration succeeds, so the secret does not outlive its single-use
  purpose by lingering in the registry after a successful exchange.
- **A `windows-iis` target's `store` field is honored, not just validated.**
  `certreq -accept` has no switch that targets a store other than `My` for a
  machine-keyset request, so a non-default `store` (e.g. `WebHosting`) is
  reached by mirroring the accepted certificate into it afterward
  (`certutil -addstore` + `-repairstore`, then `-delstore My` to remove the
  original copy, then a closing `certutil -store <store> <thumbprint>` query
  that independently confirms the certificate is actually retrievable from
  the target store rather than trusting the prior exit codes alone).
  Requesting `store: "My"` (the common case) touches only `certreq`, with no
  `certutil` call. Real-host verification so far has only exercised the
  default `My` store; the non-default-store mirror path is unit-tested
  (including the closing confirmation query) against a stubbed `certutil`
  but not yet independently proven against a real Windows host. See
  ADR-0012 decision 9.
- **A CNG key container abandoned by a crash between `certreq -new` and
  `certreq -accept` is freed automatically at the next agent startup, not
  left behind indefinitely.** The container name is journaled the instant
  `certreq -new` succeeds; a startup reconciliation pass checks each
  unresolved entry against the live machine store and deletes
  (`certutil -delkey`) only a container still enrolled to no certificate,
  leaving alone (and marking reconciled, so it is not re-checked forever)
  any container a later attempt or an operator has since legitimately
  enrolled. For a non-default target store (e.g. `WebHosting`), this check
  queries **both** the default `My` store and the recorded target store,
  never the target store alone: `certreq -accept` itself always lands in
  `My` first, with the mirror into a non-default store happening as a
  separate, later step (see the store-targeting bullet above), so a crash
  between those two steps leaves a live certificate in `My` that a
  target-store-only check would miss, incorrectly freeing a key still in
  use. A store-query failure fails closed (deferred, never deleted). See
  ADR-0012 decision 9.
- **Normal (non-crash-recovery) execution against a non-default target
  store locks both stores for the duration of the operation, not just the
  target store.** `certreq -accept` always mutates the default `My` store
  first regardless of the requested target, with a non-default store (e.g.
  `WebHosting`) reached only by a separate, later mirror step (see the
  store-targeting bullet above) -- a `WebHosting`-targeted renewal that
  locked only `WebHosting` would leave `My` itself unprotected for that
  entire window, letting an unrelated `My`-targeted job's own concurrent
  `certreq -accept` (or this same job's later `-delstore My`) race it. A PR
  review found (2026-08-07) that execution's own lock scope did not match
  the crash-reconciliation sweep's already-correct dual-store scope; both
  now share one helper that locks the deduplicated set (one lock for the
  common `store: "My"` case) in the same deterministic order, so the two
  paths can never deadlock against each other.
- **Superseded-certificate retention now requires a persisted issuance
  record proving the *specific certificate* was installed by this agent,
  not just a container-naming match or a bare record of container
  creation, before treating a predecessor's CNG key container as this
  agent's own to delete.** A name matching the agent's own container-naming
  convention is necessary but not sufficient; a durable record written at
  the moment the agent itself created that exact container (carrying the
  originating job and certificate id) must also exist; and that record
  must further have been upgraded, immediately after a successful
  `certreq -accept`, to carry the actual accepted certificate's thumbprint,
  which must match the predecessor certificate being evaluated. This third
  requirement closes a gap where an operator (or an unrelated later
  attempt) enrolling a different certificate into an agent-created
  container -- one the crash-reconciliation sweep above found already
  enrolled and correctly left alone -- could otherwise inherit
  `tokentimer_installed` provenance for that unrelated certificate. A human
  operator's own `certreq` enrollment or a tool like IIS's
  self-signed-certificate generator is correctly recorded `preexisting` and
  never auto-deleted, whether for missing any of the three signals or for a
  mismatched thumbprint. See ADR-0012 decision 18.
- **The mandatory delete-then-add IIS rebind (decision 13) preserves the
  outgoing binding's other settings instead of silently resetting them to
  `netsh`'s defaults.** `netsh http add sslcert` only ever applies the flags
  a given call explicitly passes it, and a rebind must delete the existing
  binding before re-adding it (`add` refuses to overwrite one in place), so
  every renewal previously reset any operator-configured
  revocation-checking, CTL-issuer-restriction, DS-mapper, and
  client-certificate-negotiation setting back to default. The agent now
  reads the outgoing binding's settings back via `netsh http show sslcert`
  before deleting it and reapplies every one it can positively parse on the
  new binding, including the newer Windows Server 2019+ per-connection
  policy flags (`reject`, `disablehttp2`, `disablequic`, `disablelegacytls`,
  `disabletls12`, `disabletls13`, `disableocspstapling`,
  `enabletokenbinding`, `logextendedevents`, `enablesessionticket`,
  `disablesessionid`). A setting `netsh` reports as its own "Not Set"
  tri-state default is never forced either way, matching pre-fix behavior
  for that one field. `disableLegacyTls` specifically is parsed against a
  *different* vocabulary than every other per-connection flag above:
  Microsoft's own documentation reports this one field as `Set`/`Not Set`,
  not `Enabled`/`Disabled`/`Not Set` -- a PR review found (2026-08-07) that
  the shared Enabled/Disabled/Not-Set parser never matched a bare `Set`, so
  an outgoing binding with legacy TLS genuinely disabled had that
  restriction silently dropped, not merely reset, on every renewal. The
  parser now recognizes both vocabularies (defensively accepting
  `Enabled`/`Disabled` too, should a future Windows build ever report this
  field the same way as its siblings), with a regression test built from
  Microsoft's own documented `netsh http show sslcert` output shape.
- **A non-SNI binding on the same port always takes precedence over an SNI
  binding, and a deploy to an SNI binding now warns when one exists.** This
  is `http.sys`'s own dispatch rule, not something either binding's
  configuration can override: a client connecting to an address with its
  own `ipport=` binding gets that certificate regardless of the SNI
  hostname it sent. After a successful SNI (`hostnameport=`) deploy, the
  agent checks for a shadowing `ipport=` binding on the same port -- the
  IPv4 wildcard (`0.0.0.0`), the IPv6 wildcard (`[::]`), and any other
  concrete IP -- and surfaces a non-fatal `precedenceWarning` in the
  deploy-succeeded evidence when one is found, rather than staying silent
  about a real, non-obvious gotcha. This is detection only: the agent
  cannot change `http.sys`'s own precedence rule, only warn about it.

## Related

[Agent overview](../agent.md) · [Configuration](configuration.md) · [Operations](operations.md)
