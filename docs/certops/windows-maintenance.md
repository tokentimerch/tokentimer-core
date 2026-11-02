# Maintain an enrolled Windows agent

Use this page for configuration access or private-CA client failures. Ordinary public-CA operation does not need private-CA adjustments.

## Edit configuration without losing identity

Edit `C:\ProgramData\TokenTimerAgent\state\config.json` in an elevated authorized administrator session. Merge the intended fields; preserve `agentId`, API/workspace settings, signing pins, existing policy and custody state. Restart only the agent:

```powershell
Restart-Service TokenTimerAgent
Get-Service TokenTimerAgent
```

Confirm **Running** and a fresh fleet heartbeat. If startup fails, inspect its log before submitting jobs.

If an elevated editor gets Access denied, agent-created config may be SYSTEM-only. Use an authorized LocalSystem provisioning tool or the [one-shot scheduled-task procedure](https://tokentimer.ch/docs/self-hosted/runbooks/certops-windows-maintenance#edit-config). Keep the maintenance script restricted to administrators/SYSTEM, merge only intended fields, check its result and remove the temporary task/script. Preserve the original owner/DACL; do not widen access to credentials, keys or journals. Never delete identity or custody state to clear an error. See the [Windows permission model](agent/install-windows.md).

## Keep private-CA trust paths separate

- `caBundlePath` configures agent-to-TokenTimer API HTTPS trust.
- The ACME client's TLS settings must trust its directory's HTTPS endpoint.
- Before IIS activation, install the approved root in `LocalMachine\Root` and intermediate issuers in `LocalMachine\CA`; they may differ from the directory's transport CA. A probe's `trustCaFile` does not configure these Windows stores. Shared import does not grant root trust. After a trust correction, verify the served chain; HTTP.sys may need the exact affected HTTPS binding refreshed before [read-only reconciliation](distribution-extensions.md#failure-recovery-and-rollback).
- Independent probes validate the served hostname and chain.

Retrieve CA certificates through a trusted administrative/export channel and compare their identity independently. Do not disable TLS validation to bootstrap trust.

With acme.sh, inspect the allowlisted Bash executable and the curl it launches in the **service** environment. Git's `bin/bash.exe` launcher may change PATH; an interactive shell is not proof of the service's selection. The installed `usr/bin/bash.exe` can avoid that launcher behavior when you have qualified it. Keep the command allowlist consistent. Scope any required HOME/CA/client configuration to the agent service; do not change global PATH or install another curl merely because a tutorial used a private test CA.
