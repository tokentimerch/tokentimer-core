# Maintain an enrolled Windows agent

Use this page for configuration access or private-CA client failures. Ordinary public-CA operation does not need private-CA adjustments.

## Edit configuration without losing identity

Edit `C:\ProgramData\TokenTimerAgent\state\config.json` in an elevated authorized administrator session. Merge the intended fields; preserve `agentId`, API/workspace settings, signing pins, existing policy and custody state. Restart only the agent:

```powershell
Restart-Service TokenTimerAgent
Get-Service TokenTimerAgent
```

Confirm **Running** and a fresh fleet heartbeat. If startup fails, inspect its log before submitting jobs.

If an elevated editor gets Access denied, inspect the file's owner and DACL. Agent-created config may be SYSTEM-only. Have an authorized administrator save the original config/owner/DACL, obtain approved maintenance access to **this config file only**, then restore temporary permissions after the edit/restart. Do not grant broad access to the state directory, credentials, keys or journals. Never delete identity or custody state to clear an error. See the [Windows permission model](agent/install-windows.md).

## Keep private-CA trust paths separate

- `caBundlePath` configures agent-to-TokenTimer API HTTPS trust.
- The ACME client's TLS settings must trust its directory's HTTPS endpoint.
- Windows must trust the CA chain signing the issued leaf; it may differ from the directory's transport CA.
- Independent probes validate the served hostname and chain.

Retrieve CA certificates through a trusted administrative/export channel and compare their identity independently. Do not disable TLS validation to bootstrap trust.

With acme.sh, inspect the allowlisted Bash executable and the curl it launches in the **service** environment. Git's `bin/bash.exe` launcher may change PATH; an interactive shell is not proof of the service's selection. The installed `usr/bin/bash.exe` can avoid that launcher behavior when you have qualified it. Keep the command allowlist consistent. Scope any required HOME/CA/client configuration to the agent service; do not change global PATH or install another curl merely because a tutorial used a private test CA.
