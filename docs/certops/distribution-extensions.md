# Distribution providers and Windows IIS consumers

Use the [distribution guide](distribution-lifecycle.md) for rollouts, verification and recovery, and the [onboarding lab](distribution-onboarding-lab.md) for a disposable setup. Sharing a private key increases the impact of a compromised consumer; use separate certificates where sharing is unnecessary.

## Availability and qualification

Vault and OpenBao KV v2 support Linux distribution. Azure Key Vault material storage and shared Windows/IIS material deployment are available only after their separate capabilities are qualified and enabled. Staging and exact-version cleanup also have separate closed gates. Upgrade matching API, worker and agents together; use the normal migration runner and preserve applied migration identities.

Linux consumers support installed, served and trust assurance. IIS consumers require a typed Windows connector and served or trust verification. Store endpoints, credentials and executable target configuration remain customer-local; the API uses public aliases and references.

## OpenBao

Set the public publicationDestination.type to openbao-kv2; omitting the store provider defaults to Vault.

Set `materialStores.primary.provider` to `openbao-kv2` in the existing Vault
example, point `address` at your HTTPS OpenBao listener, and retain
the KV v2 `mount`, `caFile`, `tokenFile` and group `prefix`. Use OpenBao Agent
AppRole auto-auth to maintain the protected token sink; follow the existing
[agent authentication walkthrough](vault-agent-authentication.md) with `bao`
and OpenBao Agent equivalents. Credentials are read again for every request.

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
The Azure material-store capability remains disabled until its exact native artifact and complete operator journey are qualified.

Use your own dedicated **public Azure Key Vault Secrets**
namespace. Private endpoints are supported through your DNS resolving the
normal `<name>.vault.azure.net` hostname and a trusted TLS chain. Managed HSM,
sovereign clouds, non-exportable private keys, Certificates-only objects and
bundles whose serialized UTF-8 JSON exceeds 25 KiB are rejected. Certificate
metadata alone is never treated as deployable private material.

Host-local store configuration, abbreviated to show provider fields:

```json
{
  "materialStores": {
    "primary": {
      "provider": "azure-key-vault",
      "address": "https://certops-example.vault.azure.net",
      "timeoutMs": 10000,
      "auth": {
        "type": "workload-identity",
        "tenantId": "11111111-1111-4111-8111-111111111111",
        "clientId": "22222222-2222-4222-8222-222222222222",
        "assertionFile": "/run/workload-identity/token"
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
  for an operator-managed renewable token sink. File contents are
  `{"accessToken":"<host-local bearer token>","expiresOn":"<ISO timestamp>"}`;
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
the identity to the test/production vault or namespace as your policy
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
      "site": "Example web",
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
existing consumer example. Append both the binding UUID and `target.reference`
to the top-level `declaredTargetSelectors`; a `policy.allowedTargetSelectors`
entry alone does not authorize either target. Preserve other selectors. `store` is the machine personal store (`My` or `WebHosting`, for example),
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
The shared IIS connector accepts RSA and EC P-256/P-384 material. P-521 is rejected before import or binding changes with `material_windows_algorithm_unsupported`. General provider
storage and Linux validation retain their existing algorithm support.
An existing identical certificate is reused
only when key association and the exact protected key ACL already match.

Activation reuses the existing IIS rebind/compensation helper, preserves binding
flags and updates exact IIS certificate metadata. Every configured probe must
have the binding's port and SNI and an IP dial address; its hostname must match
the published SANs. Use `verificationPolicy: "trust"` and a local `trustCaFile`
on each probe for chain/hostname validation in addition to fingerprint pinning.
Successful store import alone never means the listener deployment succeeded.
Provision the [Windows machine chain](windows-maintenance.md#keep-private-ca-trust-paths-separate)
before activation: approved roots in `LocalMachine\Root`, intermediates in
`LocalMachine\CA`. A probe's CA file does not populate these stores.

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

If the listener does not match, restore the intended state under your change
control before reconciliation. Do not clear an uncertain marker just to run a
different generation. To roll back, request a new rollout generation selecting
an authorized retained material version whose identity remains permitted and
unexpired. Existing retirement/revocation and separation-of-duties rules apply.
No automatic certificate/key deletion or retention-policy change is introduced.
