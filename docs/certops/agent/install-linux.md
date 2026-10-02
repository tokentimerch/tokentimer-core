# Install an agent on Linux

Install on the host that holds the certificate keys. Use Node.js 22 or 24 and a systemd Linux host with outbound HTTPS to the TokenTimer API. Enable CertOps and provide its signing/registration encryption keys on the control plane first.

1. In the workspace's Agent fleet panel, create a bootstrap token and copy the generated deployment command. Tokens are single-use and shown once.
2. Download the matching released agent package and verify its checksum against the release before extracting it. Use the package installer, not an unreviewed copy of a script.
3. Run the generated command as root. Prefer the hidden bootstrap-token prompt. Keep initial execution disabled while you configure [local policy](configuration.md).
4. Check `systemctl status tokentimer-agent` and `journalctl -u tokentimer-agent -n 50 --no-pager`. Confirm registration and a fresh heartbeat in the fleet panel.
5. Prepare the command, path, CA, and DNS allowlists before requesting work. Set `execution.enabled: true` with `execution.dryRun: true`, restart, and verify a signed job with `mode: "dry_run"`. After checking its plan, set `execution.dryRun: false` and restart to allow real work. The complete [public Linux walkthrough](https://tokentimer.ch/docs/self-hosted/runbooks/certops-agent-install) includes package and policy examples.

The flags below explain what the installer changes. State/enrollment details live in [Configuration](configuration.md); upgrades and removal live in [Operations](operations.md).

<a id="2-install-and-run"></a>

## Install and run

Requirements: Node.js 22 or 24 (`packages/agent/package.json` `engines`; the
protocol client uses the built-in global `fetch`). The package has zero
runtime dependencies.

Entry point: `packages/agent/bin/tokentimer-agent.js` (also exposed as the
`tokentimer-agent` bin). Start it with:

```
node packages/agent/bin/tokentimer-agent.js
```

or `pnpm start` from `packages/agent`. There are no CLI flags; configuration
is via `config.json` and `TOKENTIMER_AGENT_*` environment variables.

<a id="installer-script-linux-systemd"></a>

### Installer script (Linux, systemd)

`packages/agent/scripts/install-agent.sh` automates the production install
that the dashboard's Deploy-an-agent panel generates a command for. It:

- verifies OS/arch and a Node.js 22 or 24 runtime;
- creates a dedicated system user and install directory;
- writes a `config.json` skeleton and stores the bootstrap token in a
  0600-mode file consumed once at first start;
- installs, enables, and (re)starts the hardened systemd unit
  (`packages/agent/scripts/tokentimer-agent.service`, `ProtectSystem=strict`
  among other directives). Re-running the installer to upgrade restarts the
  unit, so the atomically swapped app dir is what actually runs.

`--dry-run` prints every action without touching the system.

<a id="installer-flags"></a>

#### Installer flags

Run `install-agent.sh --help` for the authoritative list; the table below is
the same surface with the operator-relevant caveats.

| Flag | Required | Notes |
|------|----------|-------|
| `--api-url URL` | yes (install) | Control plane base URL, written to `config.json` `serverUrl`. Must be `https://` unless `--allow-insecure-local-http` is set **and** the host is loopback. |
| `--workspace-id ID` | yes (install) | Recorded in `config.json`. The bootstrap token is already workspace-scoped server-side. |
| bootstrap token | yes (install) | Preferably **not** a flag. With neither `TOKENTIMER_AGENT_BOOTSTRAP_TOKEN` nor `--bootstrap-token` set, the installer reads it from a hidden prompt, so nothing lands in shell history or process listings. |
| `--bootstrap-token TOKEN` | no | Works, but discouraged: argv is visible in process listings while the installer runs. Prefer the prompt or the env var. |
| `--ca-bundle PATH` | no | PEM CA bundle for a private-CA control plane; copied into the state dir and referenced as `caBundlePath`. Note it *replaces* the default trust store for control-plane requests rather than extending it. |
| `--write-path PATH` | no | Absolute directory the agent may write certificates into. Repeatable. Installed into a systemd drop-in `ReadWritePaths` list. Never grants all of `/etc`. Do not use this for the OS trust store (the installer takes ownership of `--write-path` dirs). |
| `--write-paths-file F` | no | One absolute path per line (`#` comments and blank lines allowed), merged with `--write-path`. |
| `--trust-store` | no | Linux: require the OS trust-store grant (the default is to apply it automatically on Debian/Ubuntu and RHEL/AlmaLinux when `update-ca-certificates` or `update-ca-trust` is present). Windows: accepted for flag parity; LocalSystem already has `LocalMachine\Root` and `LocalMachine\CA`. |
| `--no-trust-store` | no | Linux: skip the OS trust-store sandbox/ACL grant. Windows: accepted, no effect (the service still runs as LocalSystem). |
| `--reload-service NAME` | no | Allows `systemctl reload NAME` through a generated polkit rule. Repeatable. Allowlist: `nginx`, `apache`/`apache2`, `httpd`, `haproxy`. Polkit rather than sudoers because the unit keeps `NoNewPrivileges=true`, under which sudo cannot escalate at all. On Windows this flag is accepted for parity and does not install a polkit rule. |
| `--allow-insecure-local-http` | no | Development only. Permits plain `http://` for loopback hosts only, and writes `allowInsecureLocalHttp=true` into `config.json`. |
| `--dry-run` | no | Print every action, execute nothing. Also valid with `--uninstall`. |
| `--uninstall` | no | See [Operations](operations.md#upgrade-and-uninstall). |

`--write-path` is a sandbox grant, not a filesystem permission. It only lets
the systemd sandbox *reach* the directory; the `tokentimer-agent` user must
still be able to write there, for example
`setfacl -m u:tokentimer-agent:rwx /etc/nginx/certs`. Without that, deploy
jobs fail with a permission error even though the path is allowlisted.

`--trust-store` is applied automatically on every tested Linux family when
the OS trust-store tools are present: Ubuntu 22.04/24.04/26.04
(`update-ca-certificates`, `/usr/local/share/ca-certificates` and
`/etc/ssl/certs`) and AlmaLinux 9 (`update-ca-trust extract`, pki anchors,
extracted bundles, and `/etc/pki/tls/certs`). The hardened unit uses
`ProtectSystem=strict`, so those directories are read-only unless they are
listed in `ReadWritePaths`. Passing them as `--write-path` is wrong: the
installer `chown`s those directories, which would take the host CA bundle
away from every other process. The grant only opens the sandbox and applies
a write ACL (`setfacl`), or group-write with owner left `root` when the
`acl` package is missing. On an already-installed agent, re-run the
installer (trust-store paths are re-detected) or add the family paths to
the unit drop-in, grant write as above, then
`systemctl daemon-reload && systemctl restart tokentimer-agent`.

Windows Server 2019/2022/2025 (and 2016+) needs no extra grant:
`install-agent.ps1` runs the service as LocalSystem, which can already
write `LocalMachine\Root` and `LocalMachine\CA`. `--trust-store` is
accepted so a Linux install command pasted into PowerShell does not fail.

The installer is POSIX shell and needs root (or sudo) for a real install. Create a bootstrap token, run the generated command, then verify registration and a fresh heartbeat in the dashboard. For removal, see [Upgrade and uninstall](operations.md#upgrade-and-uninstall).

## Related

[Agent overview](../agent.md) · [Configuration](configuration.md) · [Operations](operations.md)
