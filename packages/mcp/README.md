# TokenTimer local MCP adapter

The optional stdio adapter is for clients that cannot use remote HTTP. Prefer
**Preferences → MCP assistants → Connect an MCP assistant → Remote HTTP** for
browser sign-in without Node. Follow the [setup guide](https://tokentimer.ch/docs/api/mcp-setup).

## Install and connect

Use Node 24 and the repository's pinned pnpm from a reviewed Core checkout:

```sh
pnpm install --frozen-lockfile
node packages/mcp/bin/tokentimer-mcp.js enroll --api-url https://your-server.example
```

Choose **Local adapter (stdio)** in the setup dialog, select access and create a
code. Enter it only at the hidden terminal prompt. Add the printed command,
arguments and environment to your client. Keep the checkout and credential file
in place; no published npm package is required.

Enrollment requires a private directory controlled by your operating-system
user, including for `--credential-file`. If shared-directory or Windows ACL
checks refuse it, choose a private location. A lost enrollment response requires
revoking the connection and creating a fresh code.

## Use

Available tools (subject to connection scopes, workspace role and feature settings):

| Purpose | Tools |
| --- | --- |
| Connection and inventory | `tt_whoami`, `tt_list_tokens`, `tt_get_token`, `tt_list_sections`, `tt_list_similar_tokens` |
| Inventory import | `tt_preview_inventory_import`, `tt_import_inventory` |
| Reviewed inventory update | `tt_preview_inventory_update`, `tt_update_inventory` |
| Workspace contacts | `tt_preview_contact_create`, `tt_create_contact` |
| Workspace webhooks | `tt_preview_webhook_create`, `tt_create_webhook` |
| Contact groups | `tt_list_group_sources`, `tt_preview_contact_group`, `tt_create_contact_group` |
| Certificate issuance | `tt_preview_issuance`, `tt_request_issuance` |
| Workspace members | `tt_preview_member_invite`, `tt_invite_member` |
| Certificates and agents | `tt_list_certificates`, `tt_get_certificate`, `tt_get_certificate_observations`, `tt_explain_certificate_state`, `tt_get_agent_health` |
| Jobs and certificate requests | `tt_list_jobs`, `tt_get_job`, `tt_preview_renew`, `tt_request_renew`, `tt_list_my_requests`, `tt_get_action_request`, `tt_cancel_request` |

Certificate issuance requires a separate connection permission and workspace switch. Review the certificate, issuer, agent and installation destination before submitting; Job approval follows workspace settings. Successful issuance can establish a renewal profile.

Similar inventory means records with the same type and category; it does not establish duplicates. Contact, webhook and group creation require separate permissions and previews; they do not verify delivery channels or use Job approval. Webhook previews hide destination paths and routing keys, but the assistant receives them as input; use a trusted client. Alert delivery can begin when the webhook is used. Member invitations grant viewer access only and follow the workspace's manual-invitation policy.

Member invitations require separate permission and grant viewer access by email only. Existing users gain access immediately; new users receive an invitation. Check the reported email status if delivery is failed or unknown.

Choose **Read-only** (default) or **Read-write**, then select each required action separately. Selecting **Read-only** clears write permissions. A manager role does not automatically grant writes. Run `tt_whoami` to check the workspace and permissions. Write
tools need `TOKENTIMER_MCP_ENABLE_WRITES=true` plus their explicit
connection scopes and server controls. Imports keep existing records; updates exclude provider-managed records and certificates. Renewals also need workspace permission and follow CertOps
**Job approval**. Inspect job evidence to confirm completion; retry a lost
submission with the same `requestId` and reconcile `unknown_effect` before retrying.

For Codex stdio clients requiring the legacy handshake, set
`TOKENTIMER_MCP_LEGACY=serve`. Register the printed command, arguments and
environment with `codex mcp add`; Codex uses TOML rather than the generic JSON.

See the [configuration reference](https://github.com/tokentimerch/tokentimer-core/blob/main/docs/CONFIGURATION.md#mcp-operator-interface)
and [ADR-0017](https://github.com/tokentimerch/tokentimer-core/blob/main/docs/adr/0017-mcp-operator-interface.md).
