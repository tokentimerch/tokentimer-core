# Installed Linux agent qualification

The manual `certops-linux-systemd.yml` workflow runs on trusted main in fresh
GitHub-hosted Ubuntu 22.04 and 24.04 runners. It provisions a disposable
migrated PostgreSQL/API stack, then runs the real protocol suite and a named
installer/systemd journey. No permanent runner or Windows/Azure lab is needed.

The journey invokes the product `install-agent.sh` against the local candidate
package with a real single-use API bootstrap token. It independently checks
registration, removal of `bootstrap.env`, persisted configuration and credential
ownership/modes, the actual non-root service UID, and both soft and hard core
limits in `/proc/<MainPID>/limits`. A qualification drop-in points `ExecStart`
at the exact Node binary selected by the workflow; the product unit's sandbox
and restart policy stay active.

The installer also receives an actual `--write-path` for one unique owned
`/var/lib` directory. A bounded benign Node `ExecStartPre` probe runs under the
installed service's user and mount namespace; the main `ExecStart` remains the
candidate agent. The allowed path must accept a marker. A sibling directory
with the same mode-0777 discretionary permissions must reject its marker with
`EROFS`, while an independent host-namespace `runuser` check proves that the
same account can write both paths outside the unit. Native `systemctl show`
must report `ProtectSystem=strict`, the allowed `ReadWritePaths`, and no grant
for the denied peer. This qualifies the effective service sandbox through a
fixture probe; it does not claim that an agent certificate operation wrote
the markers. The separate strict `linux-systemd-writepath.json` report requires
both the native boundary and exact owned cleanup. Receipt validation binds
the unique directory, peers, probe source hash and main fixture source hash.
An actual systemd restart must preserve the credential and advance the API's
authenticated heartbeat. SIGKILL of the measured main PID must trigger a fresh
systemd process which authenticates again. The real `retireAgent` service then
retires the identity; the native agent must exit 86, and systemd must suppress
restart across more than two configured restart intervals. The product
uninstaller must remove the app and service while preserving credential/state.
The harness subsequently removes only the fixture-owned preserved resources.

Running requires root, `GITHUB_ACTIONS=true`,
`CERTOPS_LINUX_SYSTEMD_DISPOSABLE_HOST=1`,
`CERTOPS_PROTOCOL_DISPOSABLE_STACK=1`, a live systemd manager, and no existing
agent account/group, install directory, unit, drop-in, or polkit rule. The
workflow runs `node scripts/certops-linux-systemd.js` as root with a scoped test
environment. A root-owned mode-0600 ownership receipt is written before
installation. An independent always-run cleanup validates that receipt and
the fixture source digest before retrying product uninstall and deleting
exact owned paths/account/group. It refuses to remove state while a service
still runs. Runner disposal provides a final interruption safeguard.

Uploaded evidence is the sanitized JSONL execution report and strict native write-path report. Bootstrap tokens,
credentials, service environment, agent state, and raw journal logs are excluded.
The verifier requires the named real journey and every sibling protocol test
to actually pass. This lane qualifies installation and service lifecycle; it
does not claim certificate issuance, browser coverage, release-package testing,
or ARM64 host execution. Those require separate qualified environments.

The workflow and fixture are implemented but have not been executed on an
opted-in Linux host. Local syntax/lint checks are preparation, not execution
evidence.
