# Install an agent on Windows

Use a supported Windows Server host, Node.js 22 or 24, and an elevated PowerShell session. The host needs outbound HTTPS to the TokenTimer API. For IIS work, create the site and listener first. The agent updates bindings; it does not create sites.

The agent also needs Windows PowerShell 5.1 (`powershell.exe`, present by default on Windows Server) at runtime to read the machine certificate store and the `http.sys` bindings. Without it, discovery and IIS deploys fail closed. It works on any display language and under Constrained Language Mode. It is verified on Windows Server 2019 and 2022 (en-US) and Windows Server 2025 (de-DE and fr-FR).

For discovery of non-SNI IIS sites with host headers, install IIS Management Scripts and Tools (`Web-Scripting-Tools`). Without its `WebAdministration` module, the agent retains the HTTP.sys binding but cannot safely associate those sites with it.

## Prepare the control plane

Enable CertOps and provision the signing and registration encryption keys. In the workspace's Agent fleet panel, create a single-use bootstrap token. A bootstrap token is shown once and expires 24 hours after creation by default (maximum 30 days); create a new one if it expires. Prepare [local policy](configuration.md) before enrolling the host for real work.

## Install

Download the matching agent release and verify its checksum before running the installer. Recent Windows versions include `tar.exe`; check with `Get-Command tar.exe` and use another trusted extractor if it is missing. Extract the `.tgz` with `tar -xzf <archive>` into a new protected directory, such as one under Program Files. Set the owner of the extracted tree to the Administrators group and allow only Administrators and SYSTEM to modify it. Use the protected directory for installation and elevated dry runs. From that directory:

```powershell
$workspaceId = Read-Host 'Workspace ID'
.\scripts\install-agent.ps1 --api-url https://tokentimer.example.com --workspace-id $workspaceId --dry-run
.\scripts\install-agent.ps1 --api-url https://tokentimer.example.com --workspace-id $workspaceId
Get-Service TokenTimerAgent
```

The installer prompts privately for the bootstrap token. The service runs as LocalSystem through the bundled native service host. The app lives at `C:\ProgramData\TokenTimerAgent\app`; configuration and custody state live at `C:\ProgramData\TokenTimerAgent\state`.

For a private API CA, install its public chain in the Windows machine stores. The installer enables system CA trust for the service with Node 22.15–22.x, 23.8–23.x, or 24.x unless explicitly overridden. On Node 22.0–22.14 or 23.0–23.7, upgrade Node or use `--ca-bundle` for a new configuration. An existing `config.json` needs `caBundlePath` set explicitly; a reinstall does not add it. A configured bundle replaces the API's default CA trust. `--trust-store` does not configure API TLS trust. Restart the service after changing trust.

Use a machine-wide Node.js installation on PATH in a protected directory such as `C:\Program Files\nodejs`. The installer rejects a Node path that uses a junction or allows unprivileged changes. If an older application has no verified installation record or uses an unsafe directory, the upgrade stops before changing the service or its state. Preserve the configuration, credentials, signing pins, custody keys and journals. Plan a controlled reinstall from a verified package in a clean protected directory and validate the preserved state before resuming jobs.

Write your policy first, then run the installer: it keeps an existing `config.json` and only creates one when absent. Command profile names and target selectors are read when the agent starts, so prepare them before the first registration. With a loopback `http` API address, pass `--allow-insecure-local-http` and also add `"allowInsecureLocalHttp": true` to a hand-written `config.json`. For an already enrolled agent, follow [unattended Windows upgrades](operations.md#unattended-windows-upgrades).

Save `config.json` and any DNS credentials file as UTF-8 without a byte order mark. Windows PowerShell 5.1 `Set-Content -Encoding utf8` adds one and the agent refuses the file. Use Notepad, or `[IO.File]::WriteAllText($path, $text, (New-Object Text.UTF8Encoding($false)))`.

Windows state is protected with `icacls` ACLs. Local Administrators can access and edit `config.json`; credential files remain restricted to the agent identity and SYSTEM. A failed permission check stops the operation.

For a protected config that even an elevated editor cannot change, follow [Windows configuration maintenance](../windows-maintenance.md). Never delete enrolled identity or keys to get past an access error.

For a controlled reinstall of an enrolled agent, use `--prepare-only` from the verified package extracted into a protected directory. This mode requires a verified state restore, matching API URL and workspace, and an empty application and service slot. It preserves the restored state and leaves the new LocalSystem service disabled for inspection. The prepared service uses the verified API origin at startup. After an interruption, preserve the staged files and inspect the disabled registration before recovery. Enable the service only after verifying the installed candidate and its state.

### Unattended classic installation

Verify the classic archive against its published checksum before extracting it. From the extracted directory, run an elevated RMM job or a Group Policy startup script scoped to the target computers. Supply the API URL and workspace ID from the deployment job. Inject a distinct, unexpired, single-use token per host as `TOKENTIMER_AGENT_BOOTSTRAP_TOKEN` and stop if the token is missing or expired. Restrict any local token file to SYSTEM and Administrators before writing it. Keep tokens out of SYSVOL, command arguments and logs.

```powershell
powershell.exe -NoProfile -NonInteractive -File .\scripts\install-agent.ps1 --api-url $ApiUrl --workspace-id $WorkspaceId
```

Clear the environment variable and remove any staged token file after the installer exits. Pause on any nonzero exit. Advance after exit `0`, a running service and a fresh, compatible heartbeat in the intended workspace.

## Verify

Confirm the service is Running and the fleet panel shows registration and a fresh heartbeat. Keep execution disabled while configuring [local policy](configuration.md). Set `execution.enabled: true` with `execution.dryRun: true`, restart, and verify a signed job with `mode: "dry_run"`. Its signed payload must retain `dry_run` and its terminal status must be `dry_run_complete`, never `succeeded`. The local `dryRun` switch refuses real mutating jobs; it does not convert them into previews. A signed no-op checks dispatch/reporting, not later DNS, deployment or reload permissions. For AD CS, keep local dry-run enabled through the [read-only check, trusted pin and fresh post-pin check](adcs.md#operator-sequence); switch it off and restart before enrollment. For other mutating work, review the intended operation's local policy and destinations before switching it off. The [complete public Windows guide](https://tokentimer.ch/docs/self-hosted/runbooks/certops-agent-install-windows) includes troubleshooting and the permission model.

The bundled ACME path uses DNS-01, including Windows/IIS targets. See [DNS and ACME](dns-and-acme.md) for providers and the external HTTP-01 alternative. A domain-joined member can enroll from an enterprise CA. See [Microsoft AD CS](adcs.md). The agent contacts a CA only when a local enrollment rule names it.

In **Jobs → Create manual job**, choose **No-op**, select **Simulation (dry run)** and the agent, then create the job. Confirm **Dry-run complete**. Alternatively, list `GET /api/v1/workspaces/{workspaceId}/certops/agents`, match `items[].agentId` to the local configuration's `agentId`, and use that row's `items[].id` as `assignedAgentId`. Send `POST /api/v1/workspaces/{workspaceId}/certops/jobs` with `{"operation":"noop","mode":"dry_run","assignedAgentId":"REPLACE_WITH_FLEET_AGENT_ROW_UUID"}`; approve it if required, then poll for `dry_run_complete`.

If registration or heartbeat fails, check `Get-Service TokenTimerAgent`, the Windows Application log, and the configured URL and workspace. For a private CA or an approved TLS-inspecting proxy, update `caBundlePath` in the existing configuration using [Windows maintenance](../windows-maintenance.md#edit-configuration-without-losing-identity). Restart and check the original fleet row for an enrolled agent. For a rejected or expired token on a new host, obtain a new one-use token. Redact bootstrap tokens, credentials and keys from support logs.

## Worked rollout for 500 Windows agents

This example uses the classic installer, an RMM job or computer-scoped GPO, and existing IIS HTTPS bindings. Start with 5 hosts, then 25, then batches of up to 50. Keep rollout batches within the workspace and issuer limits.

1. Record the device ID, workspace and intended endpoint for each host. Before each wave, a workspace manager creates a short-lived, single-use bootstrap token for each new host in **Agent fleet** or via `POST /api/v1/workspaces/{workspaceId}/certops/agent-bootstrap-tokens` using an authorized user session. Keep the manager session at the rollout coordinator. Deliver only the host’s token through its protected secret channel.
2. Run the [unattended installer](#unattended-classic-installation). Record the exit code, then match the local `agentId` to its fleet row. Require exit `0`, the intended version, compatibility and a fresh heartbeat. If enrollment consumed the token without a heartbeat, inspect the original protected state and fleet record before issuing another token.
3. On the first pilot host, [verify signed dispatch](#verify), review local DNS and IIS policy, then enable real execution. Create a manual **Issue** job with a `windows-iis` target for that binding and the configured [DNS-01 provider](dns-and-acme.md). Select the intended host in the **Agent** picker. For API requests, use that host’s fleet row UUID as `assignedAgentId`. Obtain any required approval. From a separate client, [connect to that endpoint](../verify-live-service.md#windows-and-iis) and match the served serial or fingerprint to the issued certificate.
4. Repeat the checks for each target and record its fleet row, job ID and verified fingerprint. Advance only after the wave passes. Pause on exceptions and [recover the original job](operations.md#recover-a-failed-job). Resume only the affected hosts.

## Continue

[Windows runtime details](windows-runtime.md) · [Upgrades and retirement](operations.md) · [Agent overview](../agent.md)

Follow the [bundled runtime](https://github.com/tokentimerch/tokentimer-core/issues/542) and [release signatures and SBOM](https://github.com/tokentimerch/tokentimer-core/issues/537) issues for packaging updates.
