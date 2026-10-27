"use strict";
// Pure ownership/permission policy. No cloud, credential or filesystem actions.
const crypto = require("node:crypto");
const REPOSITORY = "tokentimerch/tokentimer-core";
const PURPOSE = "certops-azure-keyvault-qualification";
const LAB_ENV = "certops-azure-keyvault-lab";
const CLEANUP_ENV = "certops-azure-keyvault-cleanup";
const WORKFLOW = ".github/workflows/certops-azure-keyvault-qualification.yml";
// WARNING: TEMPORARY PRE-MERGE EXCEPTION. Revert before merging.
const TEMPORARY_BRANCH = "feat/certops-distribution-extensions";
function trustedRef(env) {
  return (
    env.GITHUB_REF === "refs/heads/main" ||
    (env.GITHUB_REF === `refs/heads/${TEMPORARY_BRANCH}` &&
      env.GITHUB_EVENT_NAME === "workflow_dispatch")
  );
}
const GUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const GROUP = /^tt-kvqual-([1-9][0-9]{0,19})-([1-9][0-9]{0,4})$/;
const READ = [
  "Microsoft.KeyVault/vaults/secrets/getSecret/action",
  "Microsoft.KeyVault/vaults/secrets/readMetadata/action",
];
const ROLE_ACTIONS = Object.freeze({
  issuer: [...READ, "Microsoft.KeyVault/vaults/secrets/setSecret/action"],
  consumer: READ,
  attributes: ["Microsoft.KeyVault/vaults/secrets/update/action"],
});
const CONSUMER_ROLE = "4633458b-17de-408a-b874-0445c86b69e6";
function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}
function requireTrusted(env, manual = true) {
  if (
    env.GITHUB_ACTIONS !== "true" ||
    env.GITHUB_REPOSITORY !== REPOSITORY ||
    !trustedRef(env) ||
    !/^[a-f0-9]{40}$/.test(env.GITHUB_SHA || "") ||
    (manual && env.GITHUB_EVENT_NAME !== "workflow_dispatch")
  )
    fail("AZURE_KV_TRUSTED_MAIN_REQUIRED");
  if (manual && env.CERTOPS_AZURE_KEYVAULT_LAB_ENABLED !== "true")
    fail("AZURE_KV_EXPLICIT_OPT_IN_REQUIRED");
}
function requireEnvironment(metadata, branches, name) {
  if (
    metadata?.name !== name ||
    metadata.deployment_branch_policy?.custom_branch_policies !== true ||
    metadata.deployment_branch_policy?.protected_branches !== false ||
    !Array.isArray(branches?.branch_policies) ||
    branches.branch_policies.length < 1 ||
    branches.branch_policies.length > 2 ||
    !branches.branch_policies.some((rule) => rule.name === "main") ||
    new Set(branches.branch_policies.map((rule) => rule.name)).size !==
      branches.branch_policies.length ||
    branches.branch_policies.some(
      (rule) =>
        rule.type !== "branch" ||
        !["main", TEMPORARY_BRANCH].includes(rule.name),
    )
  )
    fail("AZURE_KV_ENVIRONMENT_MAIN_ONLY_REQUIRED");
  const reviewers = metadata.protection_rules?.find(
    (rule) => rule.type === "required_reviewers",
  );
  if (
    name === LAB_ENV &&
    (!reviewers?.reviewers?.length || reviewers.prevent_self_review !== true)
  )
    fail("AZURE_KV_INDEPENDENT_ENVIRONMENT_APPROVAL_REQUIRED");
  if (name === CLEANUP_ENV && reviewers?.reviewers?.length)
    fail("AZURE_KV_UNATTENDED_CLEANUP_ENVIRONMENT_REQUIRED");
}
function plan(
  env,
  now = Date.now(),
  nonce = crypto.randomBytes(16).toString("hex"),
) {
  requireTrusted(env);
  if (
    !/^[1-9][0-9]{0,19}$/.test(env.GITHUB_RUN_ID || "") ||
    !/^[1-9][0-9]{0,4}$/.test(env.GITHUB_RUN_ATTEMPT || "")
  )
    fail("AZURE_KV_RUN_CONTEXT_INVALID");
  for (const key of [
    "AZURE_SUBSCRIPTION_ID",
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_ID",
    "AZURE_KV_ISSUER_ROLE_ID",
    "AZURE_KV_ATTRIBUTES_ROLE_ID",
  ])
    if (!GUID.test(env[key] || ""))
      fail(`AZURE_KV_CONFIGURATION_REQUIRED_${key}`);
  if (
    !["swedencentral", "westeurope", "northeurope"].includes(env.LAB_LOCATION)
  )
    fail("AZURE_KV_REGION_DENIED");
  const runId = env.GITHUB_RUN_ID,
    attempt = env.GITHUB_RUN_ATTEMPT;
  const suffix = crypto
    .createHash("sha256")
    .update(`${runId}/${attempt}/${nonce}`)
    .digest("hex")
    .slice(0, 20);
  const group = `tt-kvqual-${runId}-${attempt}`,
    vault = `ttkv${suffix}`;
  const tags = {
    purpose: PURPOSE,
    repository: REPOSITORY,
    schema: "kvqual-v1",
    runId,
    attempt,
    sourceSha: env.GITHUB_SHA,
    vaultName: vault,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 2 * 3600000).toISOString(),
  };
  return {
    schemaVersion: 1,
    group,
    vault,
    location: env.LAB_LOCATION,
    tags,
    subscriptionId: env.AZURE_SUBSCRIPTION_ID.toLowerCase(),
    tenantId: env.AZURE_TENANT_ID.toLowerCase(),
    roles: {
      issuer: env.AZURE_KV_ISSUER_ROLE_ID,
      consumer: CONSUMER_ROLE,
      attributes: env.AZURE_KV_ATTRIBUTES_ROLE_ID,
    },
    identities: Object.fromEntries(
      ["issuer", "consumer", "attributes", "unauthorized"].map((kind) => [
        kind,
        { name: `ttkv-${suffix}-${kind}` },
      ]),
    ),
  };
}
function ownedGroup(
  group,
  { subscriptionId, now = Date.now(), expired = false, runId, attempt } = {},
) {
  const match = GROUP.exec(group?.name || ""),
    t = group?.tags;
  if (
    !GUID.test(subscriptionId || "") ||
    !match ||
    !t ||
    t.purpose !== PURPOSE ||
    t.repository !== REPOSITORY ||
    t.schema !== "kvqual-v1" ||
    t.runId !== match[1] ||
    t.attempt !== match[2] ||
    !/^ttkv[a-f0-9]{20}$/.test(t.vaultName || "") ||
    !/^[a-f0-9]{40}$/.test(t.sourceSha || "") ||
    group.id?.toLowerCase() !==
      `/subscriptions/${subscriptionId}/resourcegroups/${group.name}`.toLowerCase()
  )
    fail("AZURE_KV_FOREIGN_GROUP_DENIED");
  const created = Date.parse(t.createdAt),
    expiry = Date.parse(t.expiresAt);
  if (
    !Number.isFinite(created) ||
    !Number.isFinite(expiry) ||
    expiry - created !== 2 * 3600000 ||
    created > now + 60000 ||
    (expired && expiry > now) ||
    (runId && (t.runId !== runId || t.attempt !== attempt))
  )
    fail("AZURE_KV_OWNERSHIP_EXPIRY_DENIED");
  return t;
}
function ownedResources(resources, p) {
  if (!Array.isArray(resources)) fail("AZURE_KV_RESOURCE_INVENTORY_INVALID");
  if (
    p.vault !== p.tags?.vaultName ||
    !/^ttkv[a-f0-9]{20}$/.test(p.vault || "") ||
    Object.keys(p.identities || {})
      .sort()
      .join() !== "attributes,consumer,issuer,unauthorized" ||
    Object.entries(p.identities).some(
      ([kind, row]) => row.name !== `ttkv-${p.vault.slice(4)}-${kind}`,
    )
  )
    fail("AZURE_KV_FOREIGN_RESOURCE_DENIED");
  for (const resource of resources) {
    const type = resource.type?.toLowerCase();
    const identity = Object.values(p.identities).find(
      (row) => row.name === resource.name,
    );
    // ARM can enumerate untaggable FIC children. Accept only our exact child
    // beneath a separately inventoried, tagged parent, never a type-wide bypass.
    if (
      type ===
      "microsoft.managedidentity/userassignedidentities/federatedidentitycredentials"
    ) {
      const parent = Object.values(p.identities).find(
        (row) => resource.name === `${row.name}/github`,
      );
      const id = `/subscriptions/${p.subscriptionId}/resourceGroups/${p.group}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/${parent?.name}/federatedIdentityCredentials/github`;
      if (
        !parent ||
        resource.id?.toLowerCase() !== id.toLowerCase() ||
        !resources.some(
          (row) =>
            row.type?.toLowerCase() ===
              "microsoft.managedidentity/userassignedidentities" &&
            row.name === parent.name,
        )
      )
        fail("AZURE_KV_FOREIGN_RESOURCE_DENIED");
      continue;
    }
    if (
      !(type === "microsoft.keyvault/vaults" && resource.name === p.vault) &&
      !(type === "microsoft.managedidentity/userassignedidentities" && identity)
    )
      fail("AZURE_KV_FOREIGN_RESOURCE_DENIED");
    const id = `/subscriptions/${p.subscriptionId}/resourceGroups/${p.group}/providers/${type === "microsoft.keyvault/vaults" ? "Microsoft.KeyVault/vaults/" + p.vault : "Microsoft.ManagedIdentity/userAssignedIdentities/" + identity.name}`;
    if (
      resource.id?.toLowerCase() !== id.toLowerCase() ||
      Object.entries(p.tags).some(
        ([key, value]) => resource.tags?.[key] !== value,
      )
    )
      fail("AZURE_KV_FOREIGN_RESOURCE_DENIED");
  }
}
function roleDefinition(definition, kind) {
  const entries = definition?.properties?.permissions;
  const wanted = ROLE_ACTIONS[kind];
  if (!wanted || !Array.isArray(entries) || entries.length !== 1)
    fail("AZURE_KV_ROLE_DEFINITION_DENIED");
  const entry = entries[0],
    actual = entry.dataActions?.map((value) => value.toLowerCase()).sort();
  if (
    (entry.actions || []).length ||
    (entry.notActions || []).length ||
    (entry.notDataActions || []).length ||
    JSON.stringify(actual) !==
      JSON.stringify(wanted.map((value) => value.toLowerCase()).sort())
  )
    fail("AZURE_KV_ROLE_DEFINITION_DENIED");
}
function allowedPermission(permissions, action) {
  const match = (pattern) =>
    new RegExp(
      "^" +
        pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") +
        "$",
      "i",
    ).test(action);
  return permissions.some(
    (row) => row.actions?.some(match) && !(row.notActions || []).some(match),
  );
}
function verifyRun(run, tags) {
  if (
    String(run?.id) !== tags.runId ||
    run.head_sha !== tags.sourceSha ||
    run.event !== "workflow_dispatch" ||
    !["main", TEMPORARY_BRANCH].includes(run.head_branch) ||
    run.path !== WORKFLOW ||
    Number(run.run_attempt) < Number(tags.attempt) ||
    !Number.isFinite(Date.parse(run.created_at)) ||
    Date.parse(run.created_at) > Date.parse(tags.createdAt) + 60000
  )
    fail("AZURE_KV_UNVERIFIED_OWNER_RUN");
}
module.exports = {
  TEMPORARY_BRANCH,
  trustedRef,
  REPOSITORY,
  PURPOSE,
  LAB_ENV,
  CLEANUP_ENV,
  WORKFLOW,
  GUID,
  GROUP,
  ROLE_ACTIONS,
  CONSUMER_ROLE,
  fail,
  requireTrusted,
  requireEnvironment,
  plan,
  ownedGroup,
  ownedResources,
  roleDefinition,
  allowedPermission,
  verifyRun,
};
