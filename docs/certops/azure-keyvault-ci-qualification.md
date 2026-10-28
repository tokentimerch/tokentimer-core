# Real Azure Key Vault CI qualification

Status on 2026-10-27: **AWAITING AZURE ACCESS / TRUSTED WORKFLOW DISPATCH**.
No live Azure campaign has run for this change. No Azure scenarios have passed
or failed, and no live evidence artifact exists yet. Offline protocol tests and
the PostgreSQL bridge regression are supporting tests, never live qualification.

## Existing infrastructure and prerequisites

The AD CS workflow already selects a subscription with `AZURE_SUBSCRIPTION_ID`
and uses `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` with GitHub OIDC. The Key Vault
login wrapper reuses `infra/certops-adcs/login-oidc.ps1`, with an isolated CLI
cache. It does not provision an AD CS domain or use the AD CS cleanup helpers.

Read-only GitHub inspection found `certops-adcs-lab`, `certops-adcs-cleanup`
and the repository opt-in `CERTOPS_ADCS_LAB_ENABLED`. The dedicated Key Vault
environments, opt-in, role variables and registered workflows did not exist.
The existing identity's Key Vault and role-assignment permissions remain
**unknown**: dispatching the paid domain lab merely to probe them is unnecessary.
The new trusted-main campaign checks actual ARM permissions and exact role
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
| Default branch                                           | Both new workflow files and reviewed helper/test code present on `main`; janitor active                                                                |

Configure the provisioning identity's federated trust for issuer
`https://token.actions.githubusercontent.com`, audience
`api://AzureADTokenExchange`, subject
`repo:tokentimerch/tokentimer-core:environment:certops-azure-keyvault-lab`.
The separate cleanup identity needs the analogous
`:environment:certops-azure-keyvault-cleanup` subject. Existing AD CS environment
subjects do not authorize these new subjects. No app password, PAT, client
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
4. Dispatch the new workflow on main and obtain the independent environment
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

GitHub normally requires a newly dispatched workflow to exist on the default
branch ([workflow dispatch](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)).
Until then the result is **AWAITING AZURE ACCESS / TRUSTED WORKFLOW DISPATCH**,
not a failed Azure campaign and not a passing qualification.

## Evidence and scope

The existing real-provider baseline remains available. The dedicated runner is
mandatory (`TT_REAL_AZURE=1`, `TT_AZURE_QUALIFICATION_REQUIRED=1`) and has no skip
path. It builds with the canonical packager, verifies the archive hash and uses
that extracted package's adapter, signature verifier and deployment lifecycle.
Its eighteen required scenarios cover real opaque versions, complete chain/key
association, separate consumer denial, foreign scopes, actual Azure 401/403,
disabled/missing versions, object-scoped role revocation/restoration, token-sink
rotation and actual GitHub assertion expiration/renewal through Entra.

A test-only HTTPS boundary forwards to the actual owned Azure vault with normal
TLS validation. It drops a successful committed PUT response, temporarily
disconnects recovery reads, verifies the protected write-attempt checkpoint,
then restarts the publication session. It requires exactly one PUT and one
Azure version after recovery. GET reset/deadline cases also discard actual
successful responses; they do not manufacture provider status codes. The 401
case sends an invalid bearer to Azure and observes Azure rejecting it before
the real workload identity renews. This is **not natural Azure access-token
expiration**. No production transport or auth fallback is added.

Real PostgreSQL receives only public setup/receipts and encrypted test job-signing
keys; certificate private keys remain in the protected customer-side runner and
Azure. Actual Core services sign jobs, allocate/accept exact receipts, enforce
fixture-user approvals, freeze rollout pins and accept installed-only receipts.
The packaged Linux agent installs the full chain and matching key, proves readback,
reconciles an interrupted install, retries the same intent and rolls back to a
retained version after a new approval. This is **signed-agent/PostgreSQL service
integration with a fixture CA**, not full HTTP/operator/RBAC/real-CA E2E.

Only `azure-keyvault-evidence.json` and `azure-keyvault-cleanup.json` can be
uploaded, after a closed-schema validator passes. Reports contain scenario IDs,
counts, status and source/package hashes, with fixed qualification limitations.
Failures use fixed codes; raw Azure/Entra bodies, assertion/JWT values, bundles,
credential files and packages are excluded. Cleanup status is independent of
scenario success. A green campaign requires all eighteen cases and successful
cleanup; missing prerequisites or unexecuted scenarios cannot turn green.

Still unqualified: genuine Azure IMDS managed identity (requires a real Azure
host), natural access-token expiration, full HTTP/operator/real-CA E2E, and any
production release artifact. Azure and Windows production manifest entries stay
disabled. A development package pass cannot promote a release: build the
proposed release candidate, run the required campaign on that **exact** packaged
artifact, record its hash/evidence, and promote those same bytes unchanged only
after all release gates pass. This task publishes no release or image and
changes no Cloud/Enterprise pins.
