# TokenTimer assistant adapter

This development adapter runs over stdio and calls the operator REST namespace.
It supports eight read tools and optional renewal preview/request/status/cancel
tools. A renewal request waits for approval by a different manager or admin.
The manual-renew tool does not orchestrate AD CS enrollment or consumer rollouts.

The supported development setup is a source checkout with Node 24 and the
repository's pinned pnpm version:

```sh
pnpm install --frozen-lockfile
node packages/mcp/bin/tokentimer-mcp.js enroll --api-url https://your-server.example
```

A signed-in workspace member creates a short-lived enrollment grant using
`POST /api/v1/workspaces/:id/operator/enrollments` with the desired `name`,
`scopes`, `roleCeiling` and optional lifetime. This management request uses the
normal session/CSRF flow. Enter the returned grant at the local enrollment
prompt; never put it in a command argument or assistant message. The command
stores a restricted, server-bound credential and prints client configuration.
Use that configuration with a local MCP client that supports stdio. Use an
absolute path to this checkout's `packages/mcp/bin/tokentimer-mcp.js` when
configuring the Node command. No published npm package is available yet.

The server requires `MCP_OPERATOR_INTERFACE_ENABLED=true` and CertOps enabled
for operational reads. Keep assistant writes disabled until the human approval
surface identifies assistant origin, resolved effects and expiries. Write
requests additionally require `MCP_OPERATOR_WRITES_ENABLED=true`, the admin's
workspace operator setting, `mcp:renew:request`, and local adapter opt-in
`TOKENTIMER_MCP_ENABLE_WRITES=true`. Turning ordinary Vault approval off does
not remove independent approval for assistant renewals.

After enrollment, run the adapter through the printed client configuration.
Confirm `tt_whoami`, list certificates, inspect one, then exercise a renewal
preview in a disposable workspace. Check both a refusal and independent
approval before any write rollout. A lost enrollment response requires revoking
the connection and creating a fresh grant. Never retry by exposing a credential.

An `unknown_effect` request requires human reconciliation. Do not submit a new
request merely because a previous response was lost; retry the original
`requestId` for that same deliberate submission. Publication does not prove
consumer installation or live TLS verification.

See [configuration](../../docs/CONFIGURATION.md) and
[ADR-0015](../../docs/adr/0015-mcp-operator-interface.md).
