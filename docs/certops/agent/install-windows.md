# Install an agent on Windows

Use a supported Windows Server host, Node.js 22 or 24, and an elevated PowerShell session. The host needs outbound HTTPS to the TokenTimer API. For IIS work, create the site and listener first. The agent updates bindings; it does not create sites.

The agent also needs Windows PowerShell 5.1 (`powershell.exe`, present by default on Windows Server) at runtime to read the machine certificate store and the `http.sys` bindings. Without it, discovery and IIS deploys fail closed. It works on any display language and under Constrained Language Mode. It is verified on Windows Server 2019 and 2022 (en-US) and Windows Server 2025 (de-DE and fr-FR).

## Prepare the control plane

Enable CertOps and provision the signing and registration encryption keys. In the workspace's Agent fleet panel, create a single-use bootstrap token. Prepare [local policy](configuration.md) before enrolling the host for real work.

## Install

Download the matching agent release, compare its checksum with the published checksum, and extract the package. From that directory:

```powershell
$workspaceId = Read-Host 'Workspace ID'
.\scripts\install-agent.ps1 --api-url https://tokentimer.example.com --workspace-id $workspaceId --dry-run
.\scripts\install-agent.ps1 --api-url https://tokentimer.example.com --workspace-id $workspaceId
Get-Service TokenTimerAgent
```

The installer prompts privately for the bootstrap token. The service runs as LocalSystem through the bundled native service host. The app lives at `C:\ProgramData\TokenTimerAgent\app`; configuration and custody state live at `C:\ProgramData\TokenTimerAgent\state`.

Windows state is protected and checked with `icacls` ACLs. Only the agent identity and SYSTEM are granted access; Administrators are accepted if already present. A failed permission check stops the operation.

## Verify

Confirm the service is Running and the fleet panel shows registration and a fresh heartbeat. Keep execution disabled while configuring [local policy](configuration.md). Set `execution.enabled: true` with `execution.dryRun: true`, restart, and verify a signed job with `mode: "dry_run"`. Its signed payload must retain `dry_run` and its terminal status must be `dry_run_complete`, never `succeeded`. The local `dryRun` switch refuses real jobs; it does not convert them into previews. After checking its plan, set `execution.dryRun: false` and restart to allow real work. The [complete public Windows guide](https://tokentimer.ch/docs/self-hosted/runbooks/certops-agent-install-windows) includes troubleshooting and the permission model.

The bundled ACME path uses DNS-01, including Windows/IIS targets. See [DNS and ACME](dns-and-acme.md) for providers and the external HTTP-01 alternative. A domain-joined member can enroll from an enterprise CA. See [Microsoft AD CS](adcs.md). The agent contacts a CA only when a local enrollment rule names it.

For an API-created preview, list `GET /api/v1/workspaces/{workspaceId}/certops/agents`, match `items[].agentId` to the local configuration's `agentId`, and use that row's `items[].id` as `assignedAgentId`. Send `POST /api/v1/workspaces/{workspaceId}/certops/jobs` with `{"operation":"noop","mode":"dry_run","assignedAgentId":"REPLACE_WITH_FLEET_AGENT_ROW_UUID"}`; approve it if required by workspace policy, then poll its job endpoint for `dry_run_complete`.

## Continue

[Windows runtime details](windows-runtime.md) · [Upgrades and retirement](operations.md) · [Agent overview](../agent.md)
