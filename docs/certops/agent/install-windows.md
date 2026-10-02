# Install an agent on Windows

Use a supported Windows Server host, Node.js 22 or 24, and an elevated PowerShell session. The host needs outbound HTTPS to the TokenTimer API. For IIS work, create the site and listener first. The agent updates bindings; it does not create sites.

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

Confirm the service is Running and the fleet panel shows registration and a fresh heartbeat. Keep execution disabled while configuring [local policy](configuration.md). Verify a signed dry-run, then enable real execution deliberately and restart the service. The [complete public Windows guide](https://tokentimer.ch/docs/self-hosted/runbooks/certops-agent-install-windows) includes troubleshooting and the permission model.

The bundled ACME path uses DNS-01, including Windows/IIS targets. See [DNS and ACME](dns-and-acme.md) for providers and the external HTTP-01 alternative.

## Continue

[Windows runtime details](windows-runtime.md) · [Upgrades and retirement](operations.md) · [Agent overview](../agent.md)
