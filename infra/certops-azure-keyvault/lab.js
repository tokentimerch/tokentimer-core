"use strict";
// ARM only: this module never requests Key Vault values or Azure access tokens.
const fs = require("node:fs"),
  path = require("node:path"),
  cp = require("node:child_process"),
  crypto = require("node:crypto");
const policy = require("./policy");
const ARM = "https://management.azure.com";
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function privateRoot(env = process.env) {
  if (
    !path.isAbsolute(env.RUNNER_TEMP || "") ||
    !/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ID || "") ||
    !/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ATTEMPT || "")
  )
    policy.fail("AZURE_KV_PRIVATE_DIRECTORY_REQUIRED");
  const parent = fs.realpathSync(env.RUNNER_TEMP),
    root = path.resolve(
      parent,
      `tt-kvqual-${env.GITHUB_RUN_ID}-${env.GITHUB_RUN_ATTEMPT}`,
    );
  if (!root.startsWith(parent + path.sep))
    policy.fail("AZURE_KV_PRIVATE_DIRECTORY_DENIED");
  if (
    fs.existsSync(root) &&
    (!fs.lstatSync(root).isDirectory() || fs.lstatSync(root).isSymbolicLink())
  )
    policy.fail("AZURE_KV_PRIVATE_DIRECTORY_DENIED");
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  fs.chmodSync(root, 0o700);
  return root;
}
function save(file, value) {
  const temporary = file + ".new";
  // Refuse a planted link or an unfinished writer instead of following it.
  fs.writeFileSync(temporary, JSON.stringify(value), {
    mode: 0o600,
    flag: "wx",
  });
  fs.renameSync(temporary, file);
}
function load(file) {
  const stat = fs.lstatSync(file);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.size > 262144 ||
    (process.platform !== "win32" && stat.mode & 0o077)
  )
    policy.fail("AZURE_KV_PRIVATE_STATE_DENIED");
  return JSON.parse(fs.readFileSync(file, "utf8"));
}
function arm(
  method,
  resource,
  body,
  permission = "Microsoft.Resources/subscriptions/resourceGroups/read",
  allowMissing = false,
) {
  if (!resource.startsWith("/subscriptions/") || /[\r\n#]/.test(resource))
    policy.fail("AZURE_KV_ARM_SCOPE_DENIED");
  const args = [
    "rest",
    "--method",
    method,
    "--uri",
    ARM + resource,
    "--only-show-errors",
    "--output",
    "json",
  ];
  if (body !== undefined) args.push("--body", JSON.stringify(body));
  const result = cp.spawnSync("az", args, {
    encoding: "utf8",
    timeout: 120000,
    windowsHide: true,
    maxBuffer: 4 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    // Azure CLI error bodies/diagnostics are deliberately not forwarded.
    if (
      allowMissing &&
      /\b(?:ResourceGroupNotFound|ResourceNotFound|RoleAssignmentNotFound|RoleAssignmentDoesNotExist)\b/.test(
        result.stderr || "",
      )
    )
      return null;
    policy.fail(
      `AZURE_KV_ARM_REQUIRED_${permission.replace(/[^a-z0-9]/gi, "_")}_AT_OWNED_LAB_SCOPE`,
    );
  }
  try {
    return result.stdout.trim() ? JSON.parse(result.stdout) : {};
  } catch {
    policy.fail("AZURE_KV_ARM_RESPONSE_INVALID");
  }
}
async function github(route, env = process.env) {
  if (!route.startsWith(`/repos/${policy.REPOSITORY}/`))
    policy.fail("AZURE_KV_GITHUB_SCOPE_DENIED");
  const response = await fetch("https://api.github.com" + route, {
    redirect: "error",
    signal: AbortSignal.timeout(30000),
    headers: {
      Authorization: `Bearer ${env.GH_TOKEN || env.GITHUB_TOKEN || ""}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });
  if (!response.ok) policy.fail("AZURE_KV_GITHUB_CONFIGURATION_READ_REQUIRED");
  return response.json();
}
async function githubPreflight(env = process.env) {
  policy.requireTrusted(env);
  for (const name of [policy.LAB_ENV, policy.CLEANUP_ENV]) {
    const root = `/repos/${policy.REPOSITORY}/environments/${name}`;
    policy.requireEnvironment(
      await github(root, env),
      await github(root + "/deployment-branch-policies", env),
      name,
    );
  }
  const janitor = await github(
    `/repos/${policy.REPOSITORY}/actions/workflows/certops-azure-keyvault-janitor.yml`,
    env,
  );
  if (
    janitor.state !== "active" ||
    janitor.path !== ".github/workflows/certops-azure-keyvault-janitor.yml"
  )
    policy.fail("AZURE_KV_TRUSTED_JANITOR_REQUIRED");
}
const groupId = (p) =>
  `/subscriptions/${p.subscriptionId}/resourceGroups/${p.group}`;
const vaultId = (p) =>
  `${groupId(p)}/providers/Microsoft.KeyVault/vaults/${p.vault}`;
function assertPlan(p) {
  policy.ownedGroup(
    { id: groupId(p), name: p.group, tags: p.tags },
    { subscriptionId: p.subscriptionId },
  );
  if (p.vault !== p.tags.vaultName || !policy.GUID.test(p.tenantId || ""))
    policy.fail("AZURE_KV_PLAN_INVALID");
  const stem = `ttkv-${p.vault.slice(4)}`;
  if (
    Object.keys(p.identities || {})
      .sort()
      .join() !== "attributes,consumer,issuer,unauthorized"
  )
    policy.fail("AZURE_KV_PLAN_INVALID");
  for (const kind of ["issuer", "consumer", "attributes", "unauthorized"])
    if (p.identities?.[kind]?.name !== `${stem}-${kind}`)
      policy.fail("AZURE_KV_PLAN_INVALID");
  for (const kind of ["issuer", "consumer", "attributes"])
    if (!policy.GUID.test(p.roles?.[kind] || ""))
      policy.fail("AZURE_KV_PLAN_INVALID");
  if (p.roles.consumer !== policy.CONSUMER_ROLE)
    policy.fail("AZURE_KV_PLAN_INVALID");
}
async function verifyOwned(p, env = process.env) {
  assertPlan(p);
  if (
    p.subscriptionId !== env.AZURE_SUBSCRIPTION_ID?.toLowerCase() ||
    p.tenantId !== env.AZURE_TENANT_ID?.toLowerCase()
  )
    policy.fail("AZURE_KV_SUBSCRIPTION_MISMATCH");
  const group = arm(
    "GET",
    groupId(p) + "?api-version=2022-09-01",
    undefined,
    undefined,
    true,
  );
  if (!group) return null;
  policy.ownedGroup(group, { subscriptionId: p.subscriptionId });
  if (
    Object.entries(p.tags).some(([key, value]) => group.tags?.[key] !== value)
  )
    policy.fail("AZURE_KV_FOREIGN_GROUP_DENIED");
  policy.verifyRun(
    await github(
      `/repos/${policy.REPOSITORY}/actions/runs/${p.tags.runId}`,
      env,
    ),
    p.tags,
  );
  return group;
}
function roleAssignment(p, kind, scope = vaultId(p)) {
  const identity = p.identities[kind];
  if (!policy.GUID.test(identity?.principalId || ""))
    policy.fail("AZURE_KV_IDENTITY_INVALID");
  return {
    id: `${scope}/providers/Microsoft.Authorization/roleAssignments/${crypto
      .createHash("sha256")
      .update(`${scope}/${identity.principalId}/${p.roles[kind]}`)
      .digest("hex")
      .slice(0, 32)
      .replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, "$1-$2-$3-$4-$5")}`,
    body: {
      properties: {
        roleDefinitionId: `/subscriptions/${p.subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/${p.roles[kind]}`,
        principalId: identity.principalId,
        principalType: "ServicePrincipal",
      },
    },
  };
}
async function provision(env = process.env) {
  policy.requireTrusted(env);
  const root = privateRoot(env),
    file = path.join(root, "state.json"),
    p = policy.plan(env);
  if (fs.existsSync(file)) policy.fail("AZURE_KV_STATE_REUSE_DENIED");
  save(file, p); // Ownership survives interruption before any ARM mutation.
  const account = cp.spawnSync(
    "az",
    ["account", "show", "--query", "id", "-o", "tsv"],
    { encoding: "utf8", windowsHide: true, timeout: 30000 },
  );
  if (
    account.status !== 0 ||
    account.stdout.trim().toLowerCase() !== p.subscriptionId
  )
    policy.fail("AZURE_KV_SUBSCRIPTION_MISMATCH");
  const permissions = arm(
    "GET",
    `/subscriptions/${p.subscriptionId}/providers/Microsoft.Authorization/permissions?api-version=2015-07-01`,
  ).value;
  for (const action of [
    "Microsoft.Resources/subscriptions/resourceGroups/write",
    "Microsoft.Resources/subscriptions/resourceGroups/delete",
    "Microsoft.KeyVault/vaults/write",
    "Microsoft.ManagedIdentity/userAssignedIdentities/write",
    "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write",
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleAssignments/delete",
  ])
    if (!policy.allowedPermission(permissions || [], action))
      policy.fail(
        `AZURE_KV_PERMISSION_REQUIRED_${action.replace(/[^a-z0-9]/gi, "_")}_AT_LAB_SUBSCRIPTION`,
      );
  for (const provider of ["Microsoft.KeyVault", "Microsoft.ManagedIdentity"])
    if (
      arm(
        "GET",
        `/subscriptions/${p.subscriptionId}/providers/${provider}?api-version=2021-04-01`,
      ).registrationState !== "Registered"
    )
      policy.fail(
        `AZURE_KV_PROVIDER_REGISTRATION_REQUIRED_${provider.replaceAll(".", "_")}`,
      );
  for (const kind of ["issuer", "consumer", "attributes"])
    policy.roleDefinition(
      arm(
        "GET",
        `/subscriptions/${p.subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/${p.roles[kind]}?api-version=2022-04-01`,
      ),
      kind,
    );
  if (
    arm(
      "GET",
      groupId(p) + "?api-version=2022-09-01",
      undefined,
      undefined,
      true,
    )
  )
    policy.fail("AZURE_KV_EXISTING_GROUP_DENIED");
  arm(
    "PUT",
    groupId(p) + "?api-version=2022-09-01",
    { location: p.location, tags: p.tags },
    "Microsoft.Resources/subscriptions/resourceGroups/write",
  );
  await verifyOwned(p, env);
  arm(
    "PUT",
    vaultId(p) + "?api-version=2023-07-01",
    {
      location: p.location,
      tags: p.tags,
      properties: {
        tenantId: p.tenantId,
        sku: { family: "A", name: "standard" },
        enableRbacAuthorization: true,
        enableSoftDelete: true,
        softDeleteRetentionInDays: 7,
        enablePurgeProtection: true,
        publicNetworkAccess: "Enabled",
        networkAcls: {
          defaultAction: "Allow",
          bypass: "None",
          ipRules: [],
          virtualNetworkRules: [],
        },
        accessPolicies: [],
      },
    },
    "Microsoft.KeyVault/vaults/write",
  );
  const deadline = Date.now() + 600000;
  let vault;
  do {
    vault = arm("GET", vaultId(p) + "?api-version=2023-07-01");
    if (vault.properties?.provisioningState === "Succeeded") break;
    await sleep(5000);
  } while (Date.now() < deadline);
  if (
    vault.properties?.provisioningState !== "Succeeded" ||
    vault.properties.enableRbacAuthorization !== true ||
    vault.properties.vaultUri !== `https://${p.vault}.vault.azure.net/`
  )
    policy.fail("AZURE_KV_VAULT_CONFIGURATION_UNVERIFIED");
  for (const [kind, identity] of Object.entries(p.identities)) {
    const id = `${groupId(p)}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/${identity.name}`;
    const created = arm(
      "PUT",
      id + "?api-version=2023-01-31",
      { location: p.location, tags: p.tags },
      "Microsoft.ManagedIdentity/userAssignedIdentities/write",
    );
    if (
      !policy.GUID.test(created.properties?.clientId || "") ||
      !policy.GUID.test(created.properties?.principalId || "")
    )
      policy.fail("AZURE_KV_IDENTITY_UNVERIFIED");
    Object.assign(identity, {
      clientId: created.properties.clientId,
      principalId: created.properties.principalId,
    });
    save(file, p);
    arm(
      "PUT",
      id + "/federatedIdentityCredentials/github?api-version=2023-01-31",
      {
        properties: {
          issuer: "https://token.actions.githubusercontent.com",
          subject: `repo:${policy.REPOSITORY}:environment:${policy.LAB_ENV}`,
          audiences: ["api://AzureADTokenExchange"],
        },
      },
      "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write",
    );
    if (kind === "issuer" || kind === "attributes") {
      const assignment = roleAssignment(p, kind);
      arm(
        "PUT",
        assignment.id + "?api-version=2022-04-01",
        assignment.body,
        "Microsoft.Authorization/roleAssignments/write",
      );
    }
  }
  save(file, p);
  return p;
}
async function consumerAccess(p, names, grant, env = process.env) {
  await verifyOwned(p, env);
  if (
    !Array.isArray(names) ||
    !names.length ||
    names.length > 8 ||
    names.some((name) => !/^tt-[a-f0-9]{64}$/.test(name))
  )
    policy.fail("AZURE_KV_SECRET_SCOPE_DENIED");
  // The campaign supplies only its previously journaled material names.
  if (
    !p.approvedSecrets ||
    names.some((name) => !p.approvedSecrets.includes(name))
  )
    policy.fail("AZURE_KV_SECRET_SCOPE_DENIED");
  for (const name of names) {
    const assignment = roleAssignment(
      p,
      "consumer",
      vaultId(p) + "/secrets/" + name,
    );
    arm(
      grant ? "PUT" : "DELETE",
      assignment.id + "?api-version=2022-04-01",
      grant ? assignment.body : undefined,
      `Microsoft.Authorization/roleAssignments/${grant ? "write" : "delete"}`,
      !grant,
    );
  }
}
function fromOwnedGroup(group, subscriptionId) {
  policy.ownedGroup(group, { subscriptionId, expired: true });
  const vault = group.tags.vaultName,
    stem = `ttkv-${vault.slice(4)}`;
  return {
    group: group.name,
    subscriptionId,
    vault,
    tags: group.tags,
    identities: Object.fromEntries(
      ["issuer", "consumer", "attributes", "unauthorized"].map((k) => [
        k,
        { name: `${stem}-${k}` },
      ]),
    ),
  };
}
async function remove(p, env = process.env, expired = false) {
  if (p.subscriptionId !== env.AZURE_SUBSCRIPTION_ID?.toLowerCase())
    policy.fail("AZURE_KV_SUBSCRIPTION_MISMATCH");
  const group = arm(
    "GET",
    groupId(p) + "?api-version=2022-09-01",
    undefined,
    undefined,
    true,
  );
  if (!group) return;
  policy.ownedGroup(group, {
    subscriptionId: p.subscriptionId,
    expired,
    ...(!expired
      ? { runId: env.GITHUB_RUN_ID, attempt: env.GITHUB_RUN_ATTEMPT }
      : {}),
  });
  if (
    Object.entries(p.tags).some(([key, value]) => group.tags?.[key] !== value)
  )
    policy.fail("AZURE_KV_FOREIGN_GROUP_DENIED");
  policy.verifyRun(
    await github(
      `/repos/${policy.REPOSITORY}/actions/runs/${group.tags.runId}`,
      env,
    ),
    group.tags,
  );
  const inventory = arm(
    "GET",
    groupId(p) + "/resources?api-version=2021-04-01",
  );
  // A partial inventory cannot authorize deletion of a resource group.
  if (inventory.nextLink)
    policy.fail("AZURE_KV_PARTIAL_RESOURCE_INVENTORY_DENIED");
  policy.ownedResources(inventory.value, p);
  arm(
    "DELETE",
    groupId(p) + "?api-version=2022-09-01",
    undefined,
    "Microsoft.Resources/subscriptions/resourceGroups/delete",
    true,
  );
  const deadline = Date.now() + 600000;
  while (Date.now() < deadline) {
    if (
      !arm(
        "GET",
        groupId(p) + "?api-version=2022-09-01",
        undefined,
        undefined,
        true,
      )
    )
      return;
    await sleep(10000);
  }
  policy.fail("AZURE_KV_CLEANUP_INCOMPLETE_JANITOR_REQUIRED");
}
async function cleanup(env = process.env) {
  policy.requireTrusted(env);
  const root = privateRoot(env),
    file = path.join(root, "state.json");
  const receipt = {
    schemaVersion: 1,
    sourceSha: env.GITHUB_SHA,
    cleanup: "failed",
    purgeRequested: false,
  };
  fs.mkdirSync("qualification-results", { recursive: true });
  try {
    if (fs.existsSync(file)) await remove(load(file), env);
    receipt.cleanup = "completed";
  } finally {
    save("qualification-results/azure-keyvault-cleanup.json", receipt);
  }
}
async function janitor(env = process.env) {
  policy.requireTrusted(env, false);
  if (
    !["schedule", "workflow_dispatch"].includes(env.GITHUB_EVENT_NAME) ||
    !policy.GUID.test(env.AZURE_SUBSCRIPTION_ID || "")
  )
    policy.fail("AZURE_KV_JANITOR_CONTEXT_DENIED");
  const subscriptionId = env.AZURE_SUBSCRIPTION_ID.toLowerCase();
  let next = `/subscriptions/${subscriptionId}/resourceGroups?api-version=2022-09-01`,
    count = 0,
    pages = 0;
  const deadline = Date.now() + 15 * 60000;
  do {
    if (++pages > 100 || Date.now() > deadline)
      policy.fail("AZURE_KV_JANITOR_BUDGET_EXCEEDED");
    const page = arm("GET", next);
    for (const group of page.value || []) {
      if (
        !policy.GROUP.test(group.name || "") ||
        group.tags?.purpose !== policy.PURPOSE ||
        group.tags?.repository !== policy.REPOSITORY
      )
        continue;
      policy.ownedGroup(group, { subscriptionId });
      if (Date.parse(group.tags.expiresAt) > Date.now()) continue;
      if (count >= 8 || Date.now() > deadline)
        policy.fail("AZURE_KV_JANITOR_BUDGET_EXCEEDED");
      await remove(fromOwnedGroup(group, subscriptionId), env, true);
      count++;
    }
    next = null;
    if (page.nextLink) {
      const u = new URL(page.nextLink);
      if (
        u.origin !== ARM ||
        u.pathname.toLowerCase() !==
          `/subscriptions/${subscriptionId}/resourcegroups`
      )
        policy.fail("AZURE_KV_ARM_PAGE_DENIED");
      next = u.pathname + u.search;
    }
  } while (next);
  console.log(`Expired owned Key Vault qualification groups removed: ${count}`);
}
module.exports = {
  privateRoot,
  save,
  load,
  arm,
  github,
  githubPreflight,
  groupId,
  vaultId,
  assertPlan,
  verifyOwned,
  roleAssignment,
  provision,
  consumerAccess,
  remove,
  janitor,
  cleanup,
  sleep,
};
if (require.main === module) {
  const actions = {
    "github-preflight": githubPreflight,
    provision,
    cleanup,
    janitor,
  };
  const action = actions[process.argv[2]];
  Promise.resolve()
    .then(() => (action ? action() : policy.fail("AZURE_KV_ACTION_DENIED")))
    .catch((error) => {
      console.error(
        /^AZURE_KV_[A-Za-z0-9_]+$/.test(error.code || "")
          ? error.code
          : "AZURE_KV_OPERATION_FAILED_NO_SENSITIVE_DIAGNOSTICS",
      );
      process.exitCode = 1;
    });
}
