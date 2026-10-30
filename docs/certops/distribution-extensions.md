# Distribution providers and Windows IIS consumers

This extends [the distribution operations runbook](wildcard-vault-operations.md).
One ordinary, wildcard or SAN certificate can be published once, then rolled
out independently to authorized consumers. Sharing a key increases the impact
of a consumer compromise. Use an explicit distribution group and customer
opt-in; use local CNG enrollment when sharing is unnecessary.

## Availability and qualification

Vault KV v2 and Linux nginx/Apache/HAProxy retain their released behavior.
OpenBao uses the same KV v2 implementation, with explicit `openbao-kv2` identity.
Azure and Windows shared import are implemented behind independent production
qualification gates. A configuration example or a passing mock is not a
qualification claim. See [qualification](distribution-extensions-qualification.md)
for exact evidence and remaining gates.

The canonical schema sequence is migration 78 for installed-file assurance,
released auto-sync migrations 79–82, then migration 83 for immutable provider references. Upgrade API/worker and
consumer agents together. Previously applied migration rows are retained;
recognized early provider-first preview databases append the missing assurance
change without renumbering their ledger. Provider-at-81 previews retain that row
and receive metric labels at 82 and system metrics at 83. Provider-at-82 previews
retain that row and append system metrics at 83. See the [cross-PR integration plan](../migrations/open-pr-numbering.md)
before combining #461, #496 or #498; unknown or mixed ledgers fail closed.

Cleanup operation identity is separate from provider identity in the shared
`material-provider.cjs` contract: new cleanup intents use
`operation: "vault-kv2-soft-delete", provider: "vault-kv2"`. The exact legacy
#498 `type: "vault-kv2-soft-delete"` is also recognized as an operation and maps
only to Vault. Contradictory identities and unsupported providers are rejected.
The shared adapter primitive uses the separate local cleanup credential,
retention floor, lease checks, pre-mutation journal callback and metadata-first
retry. This does not enable cleanup jobs or its production capability; #498
still owns independent approval, permanent reference fences and receipt admission.

Linux endpoint consumers support `installed`, `served` and `trust`. Installed
assurance reads back the certificate, key and full chain without probes or a
reload hook. IIS consumers require the typed Windows connector and `served` or
`trust`; installed-only assurance is rejected by the API and agent.

Public provider identifiers are `vault-kv2`, `openbao-kv2`, and
`azure-key-vault`. Existing store configuration can omit `provider`, which
means Vault. New publication requests use `publicationDestination.type`:

```json
{
  "publicationDestination": {
    "type": "openbao-kv2",
    "materialStoreRef": "customer",
    "issuanceProfileRef": "shared-web",
    "profileRevision": 1
  }
}
```

The group ID/workspace ID, issuer agent, CA, DNS zone/provider, SANs, algorithm
and revisions must match the customer-local policy, just as in the existing
Vault issuer example. Customer endpoints and credential paths belong only in
the agent's protected configuration. They are never API request fields.

## OpenBao

Set `materialStores.customer.provider` to `openbao-kv2` in the existing Vault
example, point `address` at the customer's HTTPS OpenBao listener, and retain
the KV v2 `mount`, `caFile`, `tokenFile` and group `prefix`. Use OpenBao Agent
AppRole auto-auth to maintain the protected token sink; follow the existing
[agent authentication walkthrough](vault-agent-authentication.md) with `bao`
and OpenBao Agent equivalents. Credentials are read again for every request.

Compatibility tests exercise OpenBao 2.3.2 and 2.4.1. This establishes KV v2
compatibility for these versions, not a provider-vendor security support claim.
KV v1, PKI issuance, namespaces and custom KV response formats are unsupported
by this compatibility boundary. Do not configure `namespace` for OpenBao.

The issuer needs `create` and `read` on
`<mount>/data/<prefix>/bundles/*`; consumers need `read` only. No list,
update, delete, destroy or metadata access is needed by the adapter. Keep
retention administration separate. Each logical UUID is published with CAS=0
and read at version 1. Deleted/destroyed versions fail rather than using latest.

## Azure Key Vault

The [dedicated Azure CI runbook](azure-keyvault-ci-qualification.md) describes
trusted-main OIDC activation, exact issuer/consumer roles, disposable vault
ownership and cleanup, and the mandatory provider/signed-service campaign.
The [real development campaign](azure-keyvault-ci-qualification.md) passed all eighteen
mandatory scenarios at its recorded source/package hashes. Final merged HEAD and
the exact production release artifact require their own validation; the Azure
production capability remains disabled.

Use a dedicated customer-controlled **public Azure Key Vault Secrets**
namespace. Private endpoints are supported through customer DNS resolving the
normal `<name>.vault.azure.net` hostname and a trusted TLS chain. Managed HSM,
sovereign clouds, non-exportable private keys, Certificates-only objects and
bundles whose serialized UTF-8 JSON exceeds 25 KiB are rejected. Certificate
metadata alone is never treated as deployable private material.

Customer-local store configuration, abbreviated to show provider fields:

```json
{
  "materialStores": {
    "customer": {
      "provider": "azure-key-vault",
      "address": "https://customer-certops.vault.azure.net",
      "timeoutMs": 10000,
      "auth": {
        "type": "workload-identity",
        "tenantId": "11111111-1111-4111-8111-111111111111",
        "clientId": "22222222-2222-4222-8222-222222222222",
        "assertionFile": "/run/customer-identity/token"
      },
      "groups": {
        "33333333-3333-4333-8333-333333333333": {
          "workspaceId": "44444444-4444-4444-8444-444444444444",
          "prefix": "production/shared-web",
          "keyAlgorithm": "rsa",
          "sans": ["*.example.com"]
        }
      }
    }
  }
}
```

Copy the issuer-specific group fields from the Vault issuer example as well.
Never add Vault `mount`, `namespace` or `tokenFile` fields to an Azure store.
Azure auth alternatives are:

- `{"type":"managed-identity"}` on an Azure VM with IMDS. Optional `clientId`
  chooses a user-assigned identity. App Service-specific MSI endpoints are not
  implemented. Workload federation uses the public Azure authority and scope
  `https://vault.azure.net/.default`.
- `{"type":"token-file","tokenFile":"C:\\ProgramData\\TokenTimer\\azure-token.json"}`
  for a customer-managed renewable token sink. File contents are
  `{"accessToken":"<customer-local bearer token>","expiresOn":"<ISO timestamp>"}`;
  numeric `expiresOn` is epoch **milliseconds**. Keep the sink and its parent
  owner/SYSTEM-only (0600/0700 on Linux). Never paste its contents into TokenTimer.

Federated assertions and sinks must be regular protected absolute-path files,
without symlinks. Assertion tokens renew before expiry; sinks are reread on
every request. A 401 triggers bounded renewal, and transient GET failures have
bounded retries. Token or provider response contents never become error text.

Prefer a custom Azure RBAC data role: consumers need only
`Microsoft.KeyVault/vaults/secrets/getSecret/action`; issuers additionally need
secret version-list metadata access (`readMetadata/action`) and `setSecret/action`.
Legacy access policies use **get** for consumers and **get/list/set** for issuers.
No certificate/key APIs or delete/purge/recover permissions are needed. Scope
the identity to the test/production vault or namespace as customer policy
permits; broad built-in administrator roles are unnecessary. Ensure no other
writer can publish into the agent's deterministic secret names.

Each logical UUID gets a `tt-<sha256>` secret name scoped by the group's local
prefix. Consumers use the exact immutable 32-hex secret version in the approved
job. The API records that identifier, never a secret URL or bundle. Do not
interpret it as a certificate version, monotonic number or timestamp.

Azure has no Set Secret CAS. The agent refuses multiple existing versions of a
logical publication object and never blindly repeats a PUT. If publication is
uncertain, retain the staged bundle/checkpoint, restore read/list access, and
retry the original signed job. One matching retained version can reconcile the
write. An absent or conflicting object stays uncertain; investigate Azure audit
history and use a reviewed recovery/new publication instead of deleting the
checkpoint to force a new CA order. Never overwrite/delete a pinned object to
repair an uncertain rollout.

## Windows Server / IIS

Install the native Windows agent using the existing installer and signed-job
configuration. The service runs as LocalSystem. Install IIS and the Management
Scripts/Tools feature (Microsoft.Web.Administration), Windows PowerShell 5.1,
and .NET Framework 4.8. The fixed installed helper must be permitted by the
host's application-control policy; no remotely supplied PowerShell is accepted.
The shared-import candidate targets Server 2019 or later. Local non-exportable
CNG enrollment remains a separate supported workflow.

Create the exact HTTPS site/binding in IIS first. Centralized Certificate Store
bindings and selectors shared by another IIS site are rejected. Local consumer
configuration uses the existing binding/profile authorization fields plus:

```json
{
  "connector": "windows-material-iis-v1",
  "serviceAccountSids": ["S-1-5-20"],
  "target": {
    "type": "windows-iis",
    "reference": "iis-web-01",
    "store": "My",
    "binding": {
      "site": "Customer web",
      "address": "*",
      "port": 443,
      "sniHost": "web.example.com",
      "store": "My"
    }
  },
  "probes": [
    { "dialAddress": "127.0.0.1", "port": 443, "sni": "web.example.com" }
  ]
}
```

Place this inside the binding UUID under `materialBindings`, together with
`workspaceId`, `groupId`, `agentId`, `materialStoreRef`, `deploymentProfileRef`,
`profileRevision`, `authorizationRevision` and `verificationPolicy` from the
existing consumer example. `target.reference` must be allowed by local target
policy. `store` is the machine personal store (`My` or `WebHosting`, for example),
not a trusted-root store. Repeat this binding configuration on each authorized
consumer; no additional CA order is needed.

Resolve application-pool/service identities to explicit SIDs locally. Do not
grant Everyone, Users or Authenticated Users. HTTP.sys uses SYSTEM; the example
also grants NetworkService read access. Imported CNG private keys are persisted
as non-exportable; SYSTEM/Administrators retain full control, and the configured
service SIDs receive read access. Shared import uses the Microsoft Software
Key Storage Provider; TPM/HSM and custom KSP imports are unsupported. Windows
may expand generic ACL masks, so verification compares their effective rights
while still rejecting additional permissions and inheritance.
The shared IIS connector accepts RSA and EC P-256/P-384 material. P-521
passed native CNG parsing and signing but failed IIS activation in the Server
2022 and 2025 lab, so `material_windows_algorithm_unsupported` rejects it
before import, binding changes or an uncertainty record. General provider
storage and Linux validation retain their existing algorithm support.
An existing identical certificate is reused
only when key association and the exact protected key ACL already match.

Activation reuses the existing IIS rebind/compensation helper, preserves binding
flags and updates exact IIS certificate metadata. Every configured probe must
have the binding's port and SNI and an IP dial address; its hostname must match
the published SANs. Use `verificationPolicy: "trust"` and a local `trustCaFile`
on each probe for chain/hostname validation in addition to fingerprint pinning.
Successful store import alone never means the listener deployment succeeded.

Each consumer has its own desired/observed version and freshness proof in
certificate details → **Deployments**. Provider, Windows/Linux platform and safe
failure codes appear there. Offline consumers remain pending/failed according
to existing rollout policy; they cannot advance a canary without evidence.

## Failure recovery and rollback

Keep the existing state directory, protected credentials, journals and retained
material across service restarts. After uncertain activation, stop competing
work, inspect the exact store/IIS/HTTP.sys/listener state, and follow the existing
binding-lock recovery procedure. Run `certops-reconcile-binding <binding UUID>`
locally. It never imports, rebinds, restarts a service or promotes server state.
It clears uncertainty only after installed identity/key permissions, exact
binding and every listener match the original intent. Then retry that original
signed job and resume the authorized rollout.

If the listener does not match, restore the intended state under customer change
control before reconciliation. Do not clear an uncertain marker just to run a
different generation. To roll back, request a new rollout generation selecting
an authorized retained material version whose identity remains permitted and
unexpired. Existing retirement/revocation and separation-of-duties rules apply.
No automatic certificate/key deletion or retention-policy change is introduced.
