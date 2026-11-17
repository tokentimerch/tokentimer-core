"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { sha256 } = require("./probe.cjs");

const COMPUTE_API = "2024-07-01";
const RG_API = "2022-09-01";
const VAULT_API = "2024-11-01";
const ROLE_API = "2022-04-01";
const WORKFLOW = ".github/workflows/certops-azure-imds-qualification.yml";
const ENVIRONMENT = "certops-azure-imds-lab";
const ROLES = ["issuer", "consumer"];
const GUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const HASH = /^[a-f0-9]{64}$/;
const SHA = /^[a-f0-9]{40}$/;
const ARM_SCOPE = /^[a-zA-Z0-9_./-]{1,500}$/;
const REGION = "swedencentral";
const COMMAND_TIMEOUT_SECONDS = 120;
const VAULT_ROLE = "4633458b-17de-408a-b874-0445c86b69e6";
const RUNNER_ACTIONS = ["Microsoft.Compute/virtualMachines/read",
  "Microsoft.Compute/virtualMachines/runCommands/read", "Microsoft.Compute/virtualMachines/runCommands/write"];
const ARM_TIMEOUT_MS = 120000;
const COLLECTION_REQUEST_MS = 10000;

function resource(groupId, provider, name) {
  return groupId + "/providers/" + provider + "/" + name;
}
function uri(resourceId, version) {
  assert.match(resourceId, ARM_SCOPE);
  return resourceId + "?api-version=" + version;
}
function equalId(actual, expected) {
  assert.equal(actual?.toLowerCase(), expected.toLowerCase());
}
function exactIds(actual, expected) {
  assert.deepEqual(actual.map(id => id.toLowerCase()).sort(), expected.map(id => id.toLowerCase()).sort());
  assert.equal(new Set(expected.map(id => id.toLowerCase())).size, expected.length);
}
function ownedInventory(plan) {
  assert.match(plan.runId, /^[1-9][0-9]{0,15}$/);
  assert.equal(plan.attempt, "1");
  assert.match(plan.sourceSha, SHA);
  assert.match(plan.subscriptionId, GUID);
  assert.match(plan.tenantId, GUID);
  assert.equal(plan.group, "tt-imds-" + plan.runId + "-1");
  assert.match(plan.vault, /^ttimds[a-f0-9]{18}$/);
  assert.match(plan.secret, /^tt-imds-[a-f0-9]{32}$/);
  assert.match(plan.pinnedVersion, /^[a-f0-9]{32}$/);
  assert.match(plan.newerVersion, /^[a-f0-9]{32}$/);
  assert.notEqual(plan.pinnedVersion, plan.newerVersion);
  assert.match(plan.valueSha256, HASH);
  assert.match(plan.probeSha256, HASH);
  for (const field of ["runnerClientId", "runnerPrincipalId", "runnerRoleDefinition"]) assert.match(plan[field], GUID);
  assert.equal(plan.location, REGION);
  assert.ok(Number.isSafeInteger(plan.createdAt) && Number.isSafeInteger(plan.expiresAt));
  assert.ok(plan.expiresAt > plan.createdAt && plan.expiresAt - plan.createdAt <= 7200000);
  const groupId = "/subscriptions/" + plan.subscriptionId + "/resourceGroups/" + plan.group;
  const vaultId = resource(groupId, "Microsoft.KeyVault/vaults", plan.vault);
  const names = ROLES.map(role => "tt-imds-" + role);
  const vmIds = names.map(name => resource(groupId, "Microsoft.Compute/virtualMachines", name));
  const commandIds = vmIds.map(id => id + "/runCommands/imds-proof");
  const identityIds = names.map(name => resource(groupId, "Microsoft.ManagedIdentity/userAssignedIdentities", name));
  const nicIds = names.map(name => resource(groupId, "Microsoft.Network/networkInterfaces", name));
  const diskIds = names.map(name => resource(groupId, "Microsoft.Compute/disks", name));
  const subnetIds = names.map(name => resource(groupId, "Microsoft.Network/virtualNetworks", "tt-imds/subnets/" + name));
  const nsgIds = names.map(name => resource(groupId, "Microsoft.Network/networkSecurityGroups", name));
  const natId = resource(groupId, "Microsoft.Network/natGateways", "tt-imds");
  const publicIpId = resource(groupId, "Microsoft.Network/publicIPAddresses", "tt-imds-nat");
  const networkId = resource(groupId, "Microsoft.Network/virtualNetworks", "tt-imds");
  const resourceIds = [vaultId, networkId, natId, publicIpId, ...vmIds, ...identityIds, ...nicIds, ...diskIds, ...nsgIds];
  for (const field of ["vmId", "principalId", "clientId"]) {
    for (const role of ROLES) assert.match(plan.hosts[role][field], GUID);
    assert.notEqual(plan.hosts.issuer[field], plan.hosts.consumer[field]);
  }
  assert.deepEqual(Object.keys(plan.hosts).sort(), [...ROLES].sort());
  const secretScope = vaultId + "/secrets/" + plan.secret;
  for (const role of ROLES) assert.match(plan.hosts[role].vaultRoleAssignment, GUID);
  const dataRoles = ROLES.map(role => secretScope + "/providers/Microsoft.Authorization/roleAssignments/" +
    plan.hosts[role].vaultRoleAssignment);
  const guestRoles = ROLES.map((role, index) => {
    assert.match(plan.hosts[role].runnerRoleAssignment, GUID);
    assert.notEqual(plan.hosts[role].principalId, plan.runnerPrincipalId);
    assert.notEqual(plan.hosts[role].clientId, plan.runnerClientId);
    return vmIds[index] + "/providers/Microsoft.Authorization/roleAssignments/" + plan.hosts[role].runnerRoleAssignment;
  });
  const roleAssignmentIds = [...dataRoles, ...guestRoles];
  assert.equal(new Set(roleAssignmentIds).size, roleAssignmentIds.length);
  const runnerRoleId = "/subscriptions/" + plan.subscriptionId + "/providers/Microsoft.Authorization/roleDefinitions/" +
    plan.runnerRoleDefinition;
  return { groupId, vaultId, vmIds, commandIds, identityIds, nicIds, diskIds, subnetIds,
    nsgIds, natId, publicIpId, networkId, resourceIds, roleAssignmentIds, secretScope, dataRoles, guestRoles, runnerRoleId };
}

function validateGitHub(plan, env, run, approvalHistory, jobs) {
  assert.equal(env.GITHUB_RUN_ID, plan.runId);
  assert.equal(env.GITHUB_RUN_ATTEMPT, plan.attempt);
  assert.equal(env.GITHUB_SHA, plan.sourceSha);
  assert.equal(env.GITHUB_EVENT_NAME, "workflow_dispatch");
  assert.equal(env.RUNNER_ENVIRONMENT, "github-hosted");
  assert.equal(env.CERTOPS_AZURE_IMDS_LAB_ENABLED, "true");
  assert.equal(String(run.id), plan.runId);
  assert.equal(run.run_attempt, 1);
  assert.equal(run.path, WORKFLOW);
  assert.equal(run.head_sha, plan.sourceSha);
  assert.equal(run.head_branch, "main");
  assert.equal(run.event, "workflow_dispatch");
  assert.equal(run.status, "in_progress");
  assert.equal(String(run.actor.id), env.GITHUB_ACTOR_ID);
  assert.equal(String(run.triggering_actor.id), env.GITHUB_ACTOR_ID);
  const approvals = approvalHistory.filter(record => record.environments?.some(item => item.name === ENVIRONMENT));
  assert.equal(approvals.length, 1);
  assert.equal(approvals[0].state, "approved");
  assert.ok(Number.isSafeInteger(approvals[0].user.id) && approvals[0].user.id > 0);
  assert.notEqual(String(approvals[0].user.id), env.GITHUB_ACTOR_ID);
  assert.ok(jobs.total_count === jobs.jobs.length && jobs.jobs.length < 100);
  const selected = jobs.jobs.filter(job => job.name === "IMDS qualification");
  assert.equal(selected.length, 1);
  const job = selected[0];
  // The authenticated endpoint is the list for attempt 1.
  if (job.run_attempt !== undefined) assert.equal(job.run_attempt, 1);
  assert.equal(String(job.run_id), plan.runId);
  assert.equal(job.head_sha, plan.sourceSha);
  assert.equal(job.status, "in_progress");
  assert.equal(job.runner_name, env.RUNNER_NAME);
  const startedAt = Date.parse(job.started_at);
  assert.ok(startedAt >= Date.parse(run.run_started_at) && startedAt <= Date.now());
  assert.ok(Date.parse(run.created_at) <= plan.createdAt + 60000);
  return startedAt;
}

function checkRule(rule, { direction, address }) {
  const props = rule.properties;
  assert.equal(props.direction, direction);
  assert.equal(props.access, "Deny");
  assert.equal(props.priority, 100);
  assert.equal(props.protocol, "*");
  assert.equal(props.sourcePortRange, "*");
  assert.equal(props.destinationPortRange, "*");
  assert.equal(props.sourceAddressPrefix, "*");
  assert.equal(props.destinationAddressPrefix, address);
}
function validateGroup(plan, owned, group) {
  equalId(group.id, owned.groupId);
  assert.equal(group.location, REGION);
  assert.deepEqual(group.tags, {
    purpose: "certops-azure-keyvault-imds",
    repository: "tokentimerch/tokentimer-core",
    runId: plan.runId,
    attempt: plan.attempt,
    sourceSha: plan.sourceSha,
    vaultName: plan.vault,
    createdAt: new Date(plan.createdAt).toISOString(),
    expiresAt: new Date(plan.expiresAt).toISOString(),
  });
}

function validateCloud(plan, owned, arm) {
  const get = (id, version, permission) => arm("GET", uri(id, version), undefined, permission);
  const group = get(owned.groupId, RG_API);
  validateGroup(plan, owned, group);
  const inventory = get(owned.groupId + "/resources", "2021-04-01");
  assert.ok(!inventory.nextLink);
  exactIds(inventory.value.map(item => item.id), owned.resourceIds);
  for (const item of inventory.value)
    for (const [key, value] of Object.entries(group.tags)) assert.equal(item.tags?.[key], value);
  const networkApi = "2024-05-01";
  const net = get(owned.networkId, networkApi, "Microsoft.Network/virtualNetworks/read");
  assert.equal(net.location, REGION);
  assert.deepEqual(net.properties.virtualNetworkPeerings ?? [], []);
  exactIds(net.properties.subnets.map(subnet => subnet.id), owned.subnetIds);
  const nat = get(owned.natId, networkApi, "Microsoft.Network/natGateways/read");
  assert.equal(nat.location, REGION);
  assert.equal(nat.sku.name, "Standard");
  exactIds(nat.properties.publicIpAddresses.map(item => item.id), [owned.publicIpId]);
  const ip = get(owned.publicIpId, networkApi, "Microsoft.Network/publicIPAddresses/read");
  const vault = get(owned.vaultId, VAULT_API, "Microsoft.KeyVault/vaults/read");
  assert.equal(vault.location, REGION);
  assert.equal(vault.properties.enableRbacAuthorization, true);
  assert.equal(vault.properties.enableSoftDelete, true);
  assert.equal(vault.properties.sku.name, "standard");
  assert.equal(vault.properties.tenantId, plan.tenantId);
  const acls = vault.properties.networkAcls;
  assert.equal(acls.defaultAction, "Deny");
  assert.equal(acls.bypass, "None");
  assert.ok(acls.ipRules.length === 1 && [ip.properties.ipAddress, ip.properties.ipAddress + "/32"].includes(acls.ipRules[0].value));
  assert.deepEqual(acls.virtualNetworkRules, []);
  const runner = get(owned.runnerRoleId, ROLE_API, "Microsoft.Authorization/roleDefinitions/read");
  const descriptors = runner.properties.permissions;
  assert.equal(descriptors.length, 1);
  const permission = descriptors[0];
  exactIds(permission.actions, RUNNER_ACTIONS);
  for (const field of ["notActions", "dataActions", "notDataActions"]) assert.deepEqual(permission[field], []);

  for (const [index, role] of ROLES.entries()) {
    const vm = get(owned.vmIds[index], COMPUTE_API, "Microsoft.Compute/virtualMachines/read");
    equalId(vm.id, owned.vmIds[index]);
    assert.equal(vm.location, REGION);
    assert.equal(vm.properties.vmId, plan.hosts[role].vmId);
    assert.equal(vm.properties.hardwareProfile.vmSize, "Standard_D2s_v5");
    const image = vm.properties.storageProfile.imageReference;
    assert.equal(image.publisher.toLowerCase(), "canonical");
    assert.equal(image.offer, "ubuntu-24_04-lts");
    assert.equal(image.sku, "server");
    assert.equal(image.version, "24.04.202610250");
    assert.equal(image.exactVersion, image.version);
    assert.equal(vm.properties.osProfile.linuxConfiguration.disablePasswordAuthentication, true);
    assert.equal(vm.properties.storageProfile.osDisk.osType, "Linux");
    assert.deepEqual(vm.properties.storageProfile.dataDisks, []);
    equalId(vm.properties.storageProfile.osDisk.managedDisk.id, owned.diskIds[index]);
    exactIds(vm.properties.networkProfile.networkInterfaces.map(item => item.id), [owned.nicIds[index]]);
    assert.equal(vm.identity.type, "UserAssigned");
    exactIds(Object.keys(vm.identity.userAssignedIdentities), [owned.identityIds[index]]);
    const binding = Object.values(vm.identity.userAssignedIdentities)[0];
    assert.equal(binding.clientId, plan.hosts[role].clientId);
    assert.equal(binding.principalId, plan.hosts[role].principalId);

    const nic = get(owned.nicIds[index], networkApi, "Microsoft.Network/networkInterfaces/read");
    assert.equal(nic.properties.ipConfigurations.length, 1);
    const config = nic.properties.ipConfigurations[0].properties;
    assert.ok(!config.publicIPAddress && (!config.loadBalancerBackendAddressPools?.length) &&
      (!config.loadBalancerInboundNatRules?.length));
    equalId(config.subnet.id, owned.subnetIds[index]);
    equalId(nic.properties.networkSecurityGroup.id, owned.nsgIds[index]);
    const subnet = net.properties.subnets.find(item => item.id.toLowerCase() === owned.subnetIds[index].toLowerCase());
    equalId(subnet.properties.natGateway.id, owned.natId);
    assert.ok(!subnet.properties.routeTable && !subnet.properties.networkSecurityGroup);
    const nsg = get(owned.nsgIds[index], networkApi, "Microsoft.Network/networkSecurityGroups/read");
    assert.equal(nsg.properties.securityRules.length, 2);
    checkRule(nsg.properties.securityRules.find(rule => rule.properties.direction === "Inbound"),
      { direction: "Inbound", address: "*" });
    checkRule(nsg.properties.securityRules.find(rule => rule.properties.direction === "Outbound"),
      { direction: "Outbound", address: "VirtualNetwork" });

    const assignment = get(owned.dataRoles[index], ROLE_API, "Microsoft.Authorization/roleAssignments/read");
    equalId(assignment.properties.scope, owned.secretScope);
    assert.equal(assignment.properties.principalId, plan.hosts[role].principalId);
    equalId(assignment.properties.roleDefinitionId, "/subscriptions/" + plan.subscriptionId +
      "/providers/Microsoft.Authorization/roleDefinitions/" + VAULT_ROLE);
    const runnerAssignment = get(owned.guestRoles[index], ROLE_API, "Microsoft.Authorization/roleAssignments/read");
    equalId(runnerAssignment.properties.scope, owned.vmIds[index]);
    assert.equal(runnerAssignment.properties.principalId, plan.runnerPrincipalId);
    equalId(runnerAssignment.properties.roleDefinitionId, owned.runnerRoleId);
  }
}

function guestPlan(plan, role) {
  assert.ok(ROLES.includes(role));
  const { packageArtifact, runId, attempt, sourceSha, tenantId, subscriptionId, group, vault,
    secret, pinnedVersion, newerVersion, valueSha256, expiresAt, hosts } = plan;
  return { runId, attempt, sourceSha, tenantId, subscriptionId, group, vault, secret,
    pinnedVersion, newerVersion, valueSha256, expiresAt, role, hosts, packageArtifact };
}

function guestSource(plan, role, deadlineAt) {
  const root = "/opt/" + plan.group;
  const user = "tt-imds-" + role;
  const { sourceSha } = plan;
  assert.match(sourceSha, SHA);
  assert.equal(plan.group, "tt-imds-" + plan.runId + "-1");
  assert.match(plan.runId, /^[1-9][0-9]{0,15}$/);
  const digest = sha256(JSON.stringify(guestPlan(plan, role)));
  const script = root + "/checkout/infra/certops-azure-keyvault/imds/probe.cjs";
  assert.match(plan.probeSha256, HASH);
  assert.ok(Number.isSafeInteger(deadlineAt) && deadlineAt > Date.now());
  return {
    location: REGION,
    properties: {
      source: { script: [
        "#!/bin/sh",
        "set -eu",
        "ulimit -c 0",
        "test \"$(id -un)\" = '" + user + "'",
        "test \"$(/opt/tt-imds-node/bin/node --version)\" = 'v24.22.3'",
        "printf '%s  %s\\n' '" + plan.probeSha256 + "' '" + script + "' | sha256sum --check --status",
        "test \"$(git -c safe.directory='" + root + "/checkout' -C '" + root + "/checkout' rev-parse HEAD)\" = '" + sourceSha + "'",
        "test -z \"$(git -c safe.directory='" + root + "/checkout' -C '" + root + "/checkout' status --porcelain --untracked-files=all)\"",
        "exec env -i PATH=/usr/bin:/bin timeout --signal=TERM --kill-after=5 90 /opt/tt-imds-node/bin/node '" +
          script + "' '" + root + "/" + role + ".json' '" + digest + "' '" + deadlineAt + "'",
      ].join("\n") },
      runAsUser: user,
      asyncExecution: true,
      timeoutInSeconds: COMMAND_TIMEOUT_SECONDS,
      treatFailureAsDeploymentFailure: true,
    },
  };
}
function commandView(id, arm) {
  return arm("GET", uri(id, COMPUTE_API) + "&$expand=instanceView", undefined,
    "Microsoft.Compute/virtualMachines/runCommands/read", true);
}
function resultFromView(body, id, submitted, deadlineAt) {
  equalId(body.id, id);
  assert.equal(body.properties.source?.script, submitted.job.properties.source.script);
  assert.equal(body.properties.runAsUser, submitted.job.properties.runAsUser);
  const view = body.properties.instanceView;
  assert.ok(!["Failed", "Canceled", "Cancelled"].includes(body.properties.provisioningState));
  if (!view || ["Pending", "Running", "Unknown"].includes(view.executionState)) return null;
  assert.equal(view.executionState, "Succeeded");
  assert.equal(view.exitCode, 0);
  const started = Date.parse(view.startTime);
  const ended = Date.parse(view.endTime);
  assert.ok(started >= submitted.at - 30000 && ended >= started && ended <= Date.now() + 30000 && ended < deadlineAt);
  assert.equal(String(view.error ?? "").trim(), "");
  assert.equal(typeof view.output, "string");
  assert.ok(Buffer.byteLength(view.output) < 3500);
  return {
    command: { id, state: view.executionState, exitCode: view.exitCode },
    observation: JSON.parse(view.output.trim()),
  };
}

async function launchCommands(plan, owned, deadlineAt, { arm, sleep }) {
  const jobs = ROLES.map(role => ({ job: guestSource(plan, role, deadlineAt), at: null }));
  for (const id of owned.commandIds) assert.equal(commandView(id, arm), null);
  for (const [index, id] of owned.commandIds.entries()) {
    assert.ok(Date.now() + COMMAND_TIMEOUT_SECONDS * 1000 < deadlineAt);
    jobs[index].at = Date.now();
    arm("PUT", uri(id, COMPUTE_API), jobs[index].job,
      "Microsoft.Compute/virtualMachines/runCommands/write");
  }
  const results = [];
  while (Date.now() + ARM_TIMEOUT_MS < deadlineAt) {
    for (const [index, id] of owned.commandIds.entries()) {
      if (results[index]) continue;
      const response = commandView(id, arm);
      if (response) results[index] = resultFromView(response, id, jobs[index], deadlineAt);
    }
    if (owned.commandIds.every((_, index) => results[index])) return results;
    await sleep(5000);
  }
  throw new Error("IMDS_COMMAND_DEADLINE_REACHED");
}

function readGroupAfterLaunch(owned, arm) {
  return arm("GET", uri(owned.groupId, RG_API), undefined, "Microsoft.Resources/subscriptions/resourceGroups/read", true,
    { missingCodes: ["ResourceGroupNotFound"] });
}

function observeTeardown(plan, owned, commands, arm) {
  assert.equal(readGroupAfterLaunch(owned, arm), null);
  const targets = [
    ...owned.commandIds.map(id => [id, COMPUTE_API, "Microsoft.Compute/virtualMachines/runCommands/read"]),
    ...owned.roleAssignmentIds.map(id => [id, ROLE_API, "Microsoft.Authorization/roleAssignments/read"]),
    ...owned.resourceIds.map(id => {
      const kind = id.split("/providers/")[1].split("/").slice(0, 2).join("/");
      const version = {
        "Microsoft.KeyVault": VAULT_API, "Microsoft.Network": "2024-05-01",
        "Microsoft.Compute": COMPUTE_API, "Microsoft.ManagedIdentity": "2023-01-31",
      }[kind.split("/")[0]];
      return [id, version, kind + "/read"];
    }),
  ];
  const missingCodes = ["ResourceNotFound", "ResourceGroupNotFound", "ParentResourceNotFound",
    "RoleAssignmentNotFound", "RoleAssignmentDoesNotExist"];
  const absence = [{ id: owned.groupId, state: "absent" }, ...targets.map(([id, version, permission]) => {
    assert.ok(id.startsWith(owned.groupId + "/providers/"));
    assert.equal(arm("GET", uri(id, version), undefined, permission, true, { missingCodes }), null);
    return { id, state: "absent" };
  })];
  const deletedId = "/subscriptions/" + plan.subscriptionId +
    "/providers/Microsoft.KeyVault/locations/" + REGION + "/deletedVaults/" + plan.vault;
  const deleted = arm("GET", uri(deletedId, VAULT_API), undefined, "Microsoft.KeyVault/locations/deletedVaults/read");
  equalId(deleted.properties.vaultId, owned.vaultId);
  return { runId: plan.runId, attempt: plan.attempt, sourceSha: plan.sourceSha, packageArtifact: plan.packageArtifact,
    groupId: owned.groupId, vault: plan.vault, vaultState: "soft-deleted", purged: false, commands, absence };
}

async function waitForRemoval(plan, owned, { deadlineAt, arm, sleep }) {
  while (Date.now() + COLLECTION_REQUEST_MS < deadlineAt) {
    const group = readGroupAfterLaunch(owned, arm);
    if (group === null) return;
    validateGroup(plan, owned, group);
    await sleep(5000);
  }
  throw new Error("IMDS_INDEPENDENT_TEARDOWN_DEADLINE_REACHED");
}

function approvedPlanBytes(encoded, digest) {
  assert.match(encoded, /^[A-Za-z0-9+/]+={0,2}$/);
  assert.ok(encoded.length <= 48000);
  const bytes = Buffer.from(encoded, "base64");
  assert.equal(bytes.toString("base64"), encoded);
  assert.equal(sha256(bytes), digest);
  return bytes;
}

async function run(action, planDigest, artifactDirectory, env = process.env) {
  const policy = require("../policy.js");
  const { arm, github, load, save, privateRoot, sleep } = require("../lab.js");
  const { inspect, verifyIdentity } = require("../../../scripts/certops-azure-keyvault-package.cjs");
  policy.requireTrusted(env, false);
  assert.match(planDigest, HASH);
  assert.ok(path.isAbsolute(artifactDirectory));
  assert.ok(["launch", "collect"].includes(action));
  const work = privateRoot(env);
  const planPath = path.join(work, "approved-imds-plan.json");
  if (action === "launch") {
    const bytes = approvedPlanBytes(env.TT_IMDS_APPROVED_PLAN_B64, planDigest);
    fs.writeFileSync(planPath, bytes, { mode: 0o600, flag: "wx" });
  }
  const plan = load(planPath);
  assert.equal(sha256(fs.readFileSync(planPath)), planDigest);
  const owned = ownedInventory(plan);
  assert.equal(plan.subscriptionId, env.AZURE_SUBSCRIPTION_ID?.toLowerCase());
  assert.equal(plan.tenantId, env.AZURE_TENANT_ID?.toLowerCase());
  assert.equal(plan.runnerClientId, env.AZURE_CLIENT_ID?.toLowerCase());
  const identity = verifyIdentity(plan.packageArtifact);
  inspect(artifactDirectory, identity.candidateSha, identity.packageSha256);
  assert.equal(identity.artifactId, env.TT_IMDS_PACKAGE_ARTIFACT_ID);
  assert.equal(identity.runId, env.TT_IMDS_PACKAGE_RUN_ID);
  assert.equal(identity.packageSha256, env.TT_IMDS_PACKAGE_SHA256);
  const prefix = "/repos/" + policy.REPOSITORY;
  const endpoint = prefix + "/actions/runs/" + plan.runId;
  const run = await github(endpoint, env);
  const jobStart = validateGitHub(plan, env, run, await github(endpoint + "/approvals", env),
    await github(endpoint + "/attempts/1/jobs?per_page=100", env));
  const state = path.join(work, "imds-launch-observations.json");
  const leaseDeadline = Math.min(jobStart + 5400000, plan.expiresAt);
  if (action === "launch") {
    assert.ok(!fs.existsSync(state));
    const environment = await github(prefix + "/environments/" + ENVIRONMENT, env);
    const branches = await github(prefix + "/environments/" + ENVIRONMENT + "/deployment-branch-policies", env);
    policy.requireEnvironment(environment, branches, ENVIRONMENT);
    assert.ok(environment.protection_rules?.find(rule => rule.type === "required_reviewers")?.reviewers?.length);
    assert.equal(env.TT_IMDS_INDEPENDENT_TEARDOWN_READY, "true");
    const deadline = leaseDeadline - 600000;
    assert.ok(plan.createdAt <= Date.now() && Date.now() + 300000 < deadline);
    const boundedArm = (...args) => {
      assert.ok(Date.now() + ARM_TIMEOUT_MS < deadline);
      return arm(...args);
    };
    validateCloud(plan, owned, boundedArm);
    fs.writeFileSync(path.join(work, "imds-command-intent.json"), JSON.stringify({
      runId: plan.runId, attempt: plan.attempt, commandIds: owned.commandIds,
      consumerWriteIntent: true, planDigest,
    }), { flag: "wx", mode: 0o600 });
    const results = await launchCommands(plan, owned, deadline, { arm: boundedArm, sleep });
    const { verifyObservation } = require("./report.cjs");
    results.forEach(({ observation }, index) => verifyObservation(observation, plan, ROLES[index], index === 0 ? null : 403));
    save(state, results);
  } else {
    assert.equal(env.TT_IMDS_INDEPENDENT_TEARDOWN_READY, "true");
    const results = load(state);
    const { assemble } = require("./report.cjs");
    const boundedArm = (method, endpoint, body, permission, allowMissing, options) => {
      assert.equal(method, "GET");
      const remaining = leaseDeadline - Date.now();
      assert.ok(remaining > 0);
      return arm(method, endpoint, body, permission, allowMissing,
        { ...options, timeoutMs: Math.min(COLLECTION_REQUEST_MS, remaining) });
    };
    await waitForRemoval(plan, owned, { deadlineAt: leaseDeadline, arm: boundedArm, sleep });
    const teardown = observeTeardown(plan, owned, results.map(result => result.command), boundedArm);
    const report = assemble({ plan, owned, teardown, run, observations: results.map(result => result.observation) });
    process.stdout.write(JSON.stringify(report) + "\n");
  }
}

module.exports = { ownedInventory, validateCloud, validateGitHub, guestPlan, guestSource, launchCommands, observeTeardown,
  waitForRemoval, approvedPlanBytes, run };
if (require.main === module) run(...process.argv.slice(2)).catch(() => {
  process.stderr.write("CERTOPS_IMDS_ARM_OPERATION_FAILED\n");
  process.exitCode = 1;
});
