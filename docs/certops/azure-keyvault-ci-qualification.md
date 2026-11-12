# Azure Key Vault qualification

Use this runbook for the protected real-Azure qualification campaign. The Azure material-store capability remains disabled until its exact native artifact and complete operator journey are independently accepted. A provider test or source-mounted fixture is supporting evidence only.
## Existing infrastructure and prerequisites

The qualification lab provisions Key Vaults using control-plane API `2026-02-01`. Inventory and material operations use Key Vault data-plane API `7.4`.

The AD CS workflow already selects a subscription with `AZURE_SUBSCRIPTION_ID`
and uses `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` with GitHub OIDC. The Key Vault
login wrapper reuses `infra/certops-adcs/login-oidc.ps1`, with an isolated CLI
cache. It does not provision an AD CS domain or use the AD CS cleanup helpers.

Use dedicated Key Vault environments and OIDC
identities, separate from `certops-adcs-lab` and `certops-adcs-cleanup`.
Do not dispatch the paid AD CS domain lab to probe Key Vault permissions.
The trusted-main campaign checks actual ARM permissions and exact role
definitions before creating a resource group, then proves data access against
Azure. It reports a sanitized missing-action/scope code and fails on denial.

A repository/Azure administrator must configure the following after reviewing
these workflows. This implementation does not change environment protections,
repository rules or Azure grants automatically.

| Setting                                                  | Required configuration                                                                                                                                 |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Repository variable `CERTOPS_AZURE_KEYVAULT_LAB_ENABLED` | Exact string `true`; independent of the AD CS opt-in                                                                                                   |
| Environment `certops-azure-keyvault-lab`                 | Custom deployment policy with **one branch rule `main`**, no tag rules; required reviewers and **prevent self-review** enabled                         |
| Environment `certops-azure-keyvault-cleanup`             | Separate unattended environment, same exact main-only branch policy; no required reviewers                                                             |
| Lab environment variables                                | `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AZURE_KV_ISSUER_ROLE_ID`, `AZURE_KV_ATTRIBUTES_ROLE_ID` (UUIDs, not credentials)       |
| Cleanup environment variables                            | Its own `AZURE_CLIENT_ID`, plus the same tenant and isolated lab subscription IDs                                                                      |
| Subscription                                             | Existing AD CS **lab** subscription may be reused after authorization; `Microsoft.KeyVault` and `Microsoft.ManagedIdentity` must already be registered |
| Default branch                                           | Qualification and cleanup workflows plus reviewed helper/test code present on `main`; janitor active                                                                |

Configure the provisioning identity's federated trust for issuer
`https://token.actions.githubusercontent.com`, audience
`api://AzureADTokenExchange`, subject
`repo:tokentimerch/tokentimer-core:environment:certops-azure-keyvault-lab`.
The separate cleanup identity needs the analogous
`:environment:certops-azure-keyvault-cleanup` subject. Existing AD CS environment
subjects do not authorize the Key Vault subjects. No app password, PAT, client
secret or manually copied access token is required.

Environment/branch-policy introspection uses read-only `actions: read` GitHub
permissions; only the protected Azure jobs receive `id-token: write`.
See [GitHub environment API permissions](https://docs.github.com/en/rest/deployments/environments)
and [branch-policy API permissions](https://docs.github.com/en/rest/deployments/branch-policies).

## Azure permissions and identities

Use an isolated lab subscription and a reviewed custom **management-plane**
role for provisioning. It needs resource-group read/create/delete, resource
inventory/provider-registration reads, vault read/create, user-assigned identity
read/create and federated-credential write. It also needs permission/role-definition
reads and delegated role-assignment create/delete for the three approved data
roles. Do not grant Owner or broad secret-administrator roles to test identities.
Prefer a role-assignment delegation condition restricted to the three role IDs
and service principals; the workflow never creates role definitions or grants a
role to its provisioning identity. Subscription delegation is necessary for
new disposable groups; actual assignments are made only at the run-owned vault
or approved secret objects. Existing Contributor alone cannot assign these roles.
See [Key Vault RBAC guidance](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide).

Create two custom data roles in advance with `Actions`, `NotActions` and
`NotDataActions` all empty, one permissions entry, and exactly these `DataActions`:

| Role / identity                                                                    | DataActions                                                                                                                                                         | Assignment scope                                              |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| Issuer (`AZURE_KV_ISSUER_ROLE_ID`)                                                 | `Microsoft.KeyVault/vaults/secrets/getSecret/action`, `Microsoft.KeyVault/vaults/secrets/readMetadata/action`, `Microsoft.KeyVault/vaults/secrets/setSecret/action` | Run-owned vault                                               |
| Attributes tester (`AZURE_KV_ATTRIBUTES_ROLE_ID`)                                  | `Microsoft.KeyVault/vaults/secrets/update/action`                                                                                                                   | Run-owned vault; only used to disable/re-enable test versions |
| Consumer (built-in Key Vault Secrets User, `4633458b-17de-408a-b874-0445c86b69e6`) | `getSecret/action`, `readMetadata/action` under the same secret action prefix                                                                                       | **Individual approved secrets**, never the whole vault        |
| Unauthorized tester                                                                | None                                                                                                                                                                | No role assignments                                           |

The implementation verifies the built-in consumer definition too. Custom issuer
and attributes roles must be assignable in the lab subscription. There are no
delete, recover or purge data permissions and no directory/Graph administration
requirement. All four test identities are disposable user-assigned managed
identities **authenticated through workload federation**, not IMDS. The
workflow creates their ARM federated credentials for the protected lab subject.
See [secret action definitions](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-abac)
and [Key Vault Secrets User](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/security#key-vault-secrets-user).
The campaign uses ordinary object-scoped RBAC, not preview data-plane ABAC.

The cleanup identity needs group/inventory/ownership reads and group deletion
within the authorized lab subscription. It needs no secret-value access,
identity creation, role assignment or purge. Both workflows check exact names,
tags, inventory and the owning GitHub run before group deletion; subscription
visibility does not authorize deleting unrelated groups.

## Resource lifetime and spending

One manual campaign creates one Standard public Azure Key Vault and four small
identity resources in `tt-kvqual-<run-id>-<attempt>`. No VMs, domain, HSM, storage
account, log workspace or AD CS resources are created. Region is restricted to
`swedencentral`, `westeurope` or `northeurope`; only one paid campaign runs at a
time. The job has a 90-minute limit; resource ownership tags expire in two hours.
Read-only RBAC propagation polls have ten-minute bounds. The genuine assertion
expiry case can take several minutes and fails if Azure does not reject the
expired assertion within its additional five-minute tolerance budget.

Public network access is explicit and Azure TLS verification stays enabled.
RBAC protects all values. Standard-vault operations and retained objects may
incur Azure charges; check current regional pricing and subscription budgets
before enabling the opt-in. No fixed cost estimate is asserted here.

Vault names include random entropy. Soft delete uses seven days' retention and
purge protection; cleanup deletes the group, **never purges**. A retry gets a new
vault name. Deleted names/retained data need no privileged purge to run again.

`always()` reauthenticates and verifies ownership before cleanup, then scrubs
the protected runner directory. Hard cancellation or runner loss can prevent
those steps: the independent hourly janitor deletes only expired groups with
the exact Key Vault purpose, repository, run/attempt, SHA, vault name and bounded
TTL. It verifies the original manual-main GitHub run and rejects foreign
resources, incomplete inventory or AD CS names. Janitor scanning and deletion
are bounded; failed/incomplete cleanup leaves the workflow red and requires
operator inspection. Do not bypass ownership checks to remove an unexpected
resource. Disabling the spending opt-in does not disable orphan cleanup.

## Safe activation and dispatch

1. Review and merge the workflow through normal protected-main policy. Do not
   dispatch a privileged job from a PR ref or copy PR scripts into the AD CS lab.
2. Configure the two protected environments, Azure trust/grants/custom roles
   and non-secret UUID variables above; activate the reviewed janitor on main.
3. Set the explicit repository opt-in only when spending is authorized.
4. Dispatch the qualification workflow on main and obtain the independent environment
   approval. Preflight rejects missing configuration before provisioning.

```sh
gh workflow run certops-azure-keyvault-qualification.yml \
  --repo tokentimerch/tokentimer-core --ref main -f location=swedencentral
gh run list --repo tokentimerch/tokentimer-core \
  --workflow certops-azure-keyvault-qualification.yml --branch main
gh run view RUN_ID --repo tokentimerch/tokentimer-core
gh run download RUN_ID --repo tokentimerch/tokentimer-core \
  --name azure-keyvault-sanitized-evidence --dir azure-evidence
node scripts/certops-azure-keyvault-report.js azure-evidence/azure-keyvault-evidence.json
```

## Evidence and scope

The protected campaign uses a qualification package, a real owned Azure vault, scoped independent identities and PostgreSQL. It validates provider operations, authorization failures, version pinning, token renewal, interruption and recovery. Its signed-agent service integration is not a complete HTTP/operator and native release qualification. Genuine managed identity, natural access-token expiry and the full installed release journey need their own applicable evidence.

Upload only sanitized, schema-validated evidence and cleanup reports. Never upload tokens, keys, bundles or raw provider responses. Passing tests do not replace verified teardown or independent release acceptance.
