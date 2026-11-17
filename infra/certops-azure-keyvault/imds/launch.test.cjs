"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const cp = require("node:child_process");
const { ownedInventory, validateCloud, validateGitHub, guestSource,
  launchCommands, observeTeardown, waitForRemoval, approvedPlanBytes } = require("./launch.cjs");
const { sha256 } = require("./probe.cjs");

const digitGuid = digit => digit.repeat(8) + "-" + Array(3).fill(digit.repeat(4)).join("-") + "-" + digit.repeat(12);
function fixture() {
  const now = Date.now();
  return {
    location: "swedencentral", group: "tt-imds-1234-1", vault: "ttimds" + "c".repeat(18),
    secret: "tt-imds-" + "d".repeat(32), pinnedVersion: "1".repeat(32), newerVersion: "2".repeat(32),
    createdAt: now - 60000, expiresAt: now + 7000000, runId: "1234", sourceSha: "a".repeat(40), attempt: "1",
    valueSha256: "b".repeat(64), probeSha256: "c".repeat(64), packageArtifact: { runId: "5678", artifactId: "11", packageSha256: "a".repeat(64) },
    subscriptionId: digitGuid("1"), tenantId: digitGuid("2"), runnerClientId: digitGuid("a"),
    runnerPrincipalId: digitGuid("b"), runnerRoleDefinition: digitGuid("c"),
    hosts: {
      issuer: { vmId: digitGuid("3"), clientId: digitGuid("4"), principalId: digitGuid("5"),
        vaultRoleAssignment: digitGuid("d"), runnerRoleAssignment: digitGuid("f") },
      consumer: { vmId: digitGuid("6"), clientId: digitGuid("7"), principalId: digitGuid("8"),
        vaultRoleAssignment: digitGuid("e"), runnerRoleAssignment: digitGuid("9") },
    },
  };
}

function cloud(plan) {
  const owned = ownedInventory(plan);
  const map = new Map();
  const put = (id, data) => map.set(id, { id, location: plan.location, ...data });
  put(owned.groupId, { tags: {
    purpose: "certops-azure-keyvault-imds", repository: "tokentimerch/tokentimer-core",
    runId: plan.runId, attempt: plan.attempt, sourceSha: plan.sourceSha, vaultName: plan.vault,
    createdAt: new Date(plan.createdAt).toISOString(), expiresAt: new Date(plan.expiresAt).toISOString(),
  } });
  put(owned.groupId + "/resources", { value: owned.resourceIds.map(id => ({ id, tags: map.get(owned.groupId).tags })) });
  put(owned.networkId, { properties: { subnets: owned.subnetIds.map(id => ({ id,
    properties: { natGateway: { id: owned.natId } },
  })), virtualNetworkPeerings: [] } });
  put(owned.natId, { sku: { name: "Standard" }, properties: { publicIpAddresses: [{ id: owned.publicIpId }] } });
  put(owned.publicIpId, { properties: { ipAddress: "192.0.2.1" } });
  put(owned.vaultId, { properties: { enableRbacAuthorization: true, enableSoftDelete: true,
    sku: { name: "standard" }, tenantId: plan.tenantId, networkAcls: {
      defaultAction: "Deny", bypass: "None", ipRules: [{ value: "192.0.2.1/32" }], virtualNetworkRules: [],
    } } });
  put(owned.runnerRoleId, { properties: { permissions: [{
    actions: ["Microsoft.Compute/virtualMachines/read", "Microsoft.Compute/virtualMachines/runCommands/read",
      "Microsoft.Compute/virtualMachines/runCommands/write"],
    notActions: [], dataActions: [], notDataActions: [],
  }] } });
  const rule = (direction, destinationAddressPrefix) => ({ properties: {
    direction, destinationAddressPrefix, access: "Deny", priority: 100, protocol: "*", sourcePortRange: "*",
    destinationPortRange: "*", sourceAddressPrefix: "*",
  } });
  for (const [index, role] of ["issuer", "consumer"].entries()) {
    const { vmId, clientId, principalId } = plan.hosts[role];
    put(owned.vmIds[index], { properties: { vmId, hardwareProfile: { vmSize: "Standard_D2s_v5" },
      storageProfile: {
        imageReference: { publisher: "Canonical", offer: "ubuntu-24_04-lts", sku: "server",
          version: "24.04.202610250", exactVersion: "24.04.202610250" },
        osDisk: { osType: "Linux", managedDisk: { id: owned.diskIds[index] } }, dataDisks: [],
      },
      networkProfile: { networkInterfaces: [{ id: owned.nicIds[index] }] },
      osProfile: { linuxConfiguration: { disablePasswordAuthentication: true } },
    }, identity: { type: "UserAssigned", userAssignedIdentities: { [owned.identityIds[index]]: { clientId, principalId } } } });
    put(owned.nicIds[index], { properties: { ipConfigurations: [{ properties: { subnet: { id: owned.subnetIds[index] } } }],
      networkSecurityGroup: { id: owned.nsgIds[index] },
    } });
    put(owned.nsgIds[index], { properties: { securityRules: [rule("Inbound", "*"), rule("Outbound", "VirtualNetwork")] } });
    put(owned.dataRoles[index], { properties: {
      scope: owned.secretScope, principalId,
      roleDefinitionId: "/subscriptions/" + plan.subscriptionId +
        "/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6",
    } });
    put(owned.guestRoles[index], { properties: {
      scope: owned.vmIds[index], principalId: plan.runnerPrincipalId, roleDefinitionId: owned.runnerRoleId,
    } });
  }
  return { owned, map, read(method, endpoint) {
    assert.equal(method, "GET");
    const result = map.get(endpoint.split("?")[0]);
    assert.ok(result);
    return result;
  } };
}

test("recognizes only the exact resource inventory, VM roles and private network", () => {
  const plan = fixture();
  const { owned, map, read } = cloud(plan);
  assert.doesNotThrow(() => validateCloud(plan, owned, read));
  const nic = map.get(owned.nicIds[0]).properties.ipConfigurations[0].properties;
  nic.publicIPAddress = { id: "unexpected" };
  assert.throws(() => validateCloud(plan, owned, read));
  delete nic.publicIPAddress;
  map.get(owned.groupId + "/resources").nextLink = "https://unexpected.invalid";
  assert.throws(() => validateCloud(plan, owned, read));
  delete map.get(owned.groupId + "/resources").nextLink;
  map.get(owned.runnerRoleId).properties.permissions[0].actions.push("*");
  assert.throws(() => validateCloud(plan, owned, read));
});

test("derives the deadline anchor from the authenticated in-progress job and independent review", () => {
  const plan = fixture();
  const startedAt = plan.createdAt;
  const env = { GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: "tokentimerch/tokentimer-core", GITHUB_REF: "refs/heads/main",
    GITHUB_RUN_ID: plan.runId, GITHUB_RUN_ATTEMPT: "1", GITHUB_SHA: plan.sourceSha,
    GITHUB_ACTOR_ID: "18", GITHUB_EVENT_NAME: "workflow_dispatch", RUNNER_ENVIRONMENT: "github-hosted",
    RUNNER_NAME: "runner", CERTOPS_AZURE_IMDS_LAB_ENABLED: "true" };
  const run = { id: Number(plan.runId), actor: { id: 18 }, triggering_actor: { id: 18 },
    run_attempt: 1, path: ".github/workflows/certops-azure-imds-qualification.yml",
    head_sha: plan.sourceSha, head_branch: "main", event: "workflow_dispatch", status: "in_progress",
    run_started_at: new Date(startedAt - 1000).toISOString(), created_at: new Date(startedAt - 1500).toISOString(),
  };
  const approvals = [{ state: "approved", user: { id: 19 }, environments: [{ name: "certops-azure-imds-lab" }] }];
  const jobs = { total_count: 1, jobs: [{ name: "IMDS qualification", run_attempt: 1, run_id: Number(plan.runId),
    head_sha: plan.sourceSha, status: "in_progress", runner_name: env.RUNNER_NAME, started_at: new Date(startedAt).toISOString() }] };
  assert.equal(validateGitHub(plan, env, run, approvals, jobs), startedAt);
  approvals[0].user.id = 18;
  assert.throws(() => validateGitHub(plan, env, run, approvals, jobs));
  const { runId, artifactId, packageSha256 } = plan.packageArtifact;
  const scope = {
    environment: "certops-azure-imds-lab", runId: plan.runId, actorId: env.GITHUB_ACTOR_ID, headSha: plan.sourceSha,
    producerRunId: runId, artifactId, packageSha256, expiresAt: Date.now() + 60000,
  };
  const temporary = {
    ...env, TT_IMDS_PACKAGE_RUN_ID: runId, TT_IMDS_PACKAGE_ARTIFACT_ID: artifactId,
    TT_IMDS_PACKAGE_SHA256: packageSha256, TT_AZURE_LAB_SELF_APPROVAL: JSON.stringify(scope),
  };
  assert.equal(validateGitHub(plan, temporary, run, approvals, jobs), startedAt);
  assert.throws(() => validateGitHub(plan, { ...temporary, TT_IMDS_PACKAGE_ARTIFACT_ID: "12345" }, run, approvals, jobs));
  approvals[0].user.id = 19;
  jobs.jobs[0].runner_name = "stale";
  assert.throws(() => validateGitHub(plan, env, run, approvals, jobs));
});

test("uses two bounded, non-root commands and waits for terminal success", async () => {
  const plan = fixture(), owned = ownedInventory(plan);
  const active = new Map();
  const observed = await launchCommands(plan, owned, Date.now() + 300000, {
    sleep: async () => assert.fail("unexpected poll"),
    arm(method, endpoint, body) {
      const id = endpoint.split("?")[0];
      assert.ok(owned.commandIds.includes(id));
      if (method === "GET") return active.get(id) ?? null;
      assert.equal(method, "PUT");
      assert.ok(!active.has(id));
      const role = id.includes("/tt-imds-issuer/") ? "issuer" : "consumer";
      assert.equal(body.properties.runAsUser, "tt-imds-" + role);
      assert.equal(body.properties.timeoutInSeconds, 120);
      assert.ok(!body.properties.source.scriptUri);
      assert.match(body.properties.source.script, /sha256sum --check --status/);
      assert.ok(!body.properties.source.script.includes("://"));
      const observedAt = new Date().toISOString();
      active.set(id, { id, properties: { provisioningState: "Succeeded", source: body.properties.source,
        runAsUser: body.properties.runAsUser,
        instanceView: { executionState: "Succeeded", exitCode: 0, startTime: observedAt, endTime: observedAt,
          output: JSON.stringify({ role }) } } });
      return {};
    },
  });
  assert.equal(active.size, 2);
  assert.deepEqual(observed.map(result => result.observation.role), ["issuer", "consumer"]);
  assert.equal(guestSource(plan, "consumer", Date.now() + 360000).properties.asyncExecution, true);
});

test("refuses a substituted ARM script or execution outside its own submission window", async () => {
  const plan = fixture(), owned = ownedInventory(plan);
  const zero = new Date(0).toISOString();
  for (const swapScript of [false, true]) {
    const active = new Map();
    await assert.rejects(() => launchCommands(plan, owned, Date.now() + 300000, {
      sleep: async () => assert.fail("unexpected poll"),
      arm(method, endpoint, body) {
        const id = endpoint.split("?")[0];
        if (method === "GET") return active.get(id) ?? null;
        assert.equal(method, "PUT");
        const observedAt = new Date().toISOString();
        active.set(id, { id, properties: {
          provisioningState: "Succeeded", runAsUser: body.properties.runAsUser,
          source: swapScript ? { script: "other" } : body.properties.source,
          instanceView: { executionState: "Succeeded", exitCode: 0, startTime: swapScript ? observedAt : zero,
            endTime: observedAt, output: "{}" },
        } });
        return {};
      },
    }));
  }
});

test("refuses an existing command instead of overwriting or retrying it", async () => {
  const plan = fixture(), owned = ownedInventory(plan);
  let touched = 0;
  await assert.rejects(() => launchCommands(plan, owned, Date.now() + 300000, {
    sleep: async () => assert.fail("unexpected poll"),
    arm(method) {
      if (method === "PUT") touched++;
      assert.equal(method, "GET");
      return { id: owned.commandIds[0] };
    },
  }));
  assert.equal(touched, 0);
});

test("independent teardown reader requires all resources and grants absent and the owned tombstone present", () => {
  const plan = fixture(), owned = ownedInventory(plan);
  const commands = owned.commandIds.map(id => ({ id, state: "Succeeded", exitCode: 0 }));
  let leftover;
  const arm = (method, endpoint, body, permission, allowMissing, options) => {
    assert.equal(method, "GET");
    if (permission === "Microsoft.KeyVault/locations/deletedVaults/read")
      return { properties: { vaultId: owned.vaultId } };
    assert.equal(allowMissing, true);
    const id = endpoint.split("?")[0];
    if (id === owned.groupId) assert.deepEqual(options.missingCodes, ["ResourceGroupNotFound"]);
    else assert.ok(options.missingCodes.includes("ParentResourceNotFound"));
    return id === leftover ? { id: leftover } : null;
  };
  const teardown = observeTeardown(plan, owned, commands, arm);
  assert.equal(teardown.absence.length, 1 + owned.commandIds.length + owned.resourceIds.length + owned.roleAssignmentIds.length);
  assert.equal(teardown.vaultState, "soft-deleted");
  leftover = owned.guestRoles[0];
  assert.throws(() => observeTeardown(plan, owned, commands, arm));
});

test("waits for the owned group only and stops at the lease budget", async () => {
  const plan = fixture();
  const { owned, map } = cloud(plan);
  const group = map.get(owned.groupId);
  const reads = [];
  let sleeps = 0;
  await waitForRemoval(plan, owned, {
    deadlineAt: Date.now() + 300000,
    sleep: async () => { sleeps++; },
    arm(method, endpoint) {
      reads.push(endpoint.split("?")[0]);
      assert.equal(method, "GET");
      return sleeps === 0 ? group : null;
    },
  });
  assert.deepEqual(reads, [owned.groupId, owned.groupId]);
  await assert.rejects(() => waitForRemoval(plan, owned, {
    deadlineAt: Date.now(), arm: () => assert.fail("must not poll beyond deadline"), sleep: () => assert.fail("unexpected sleep"),
  }), /IMDS_INDEPENDENT_TEARDOWN_DEADLINE_REACHED/);
});

test("strict ARM absence uses the structured 404 code and per-request bound", t => {
  const { arm } = require("../lab.js");
  let result = { status: 1, stderr: 'ERROR: Not Found({"error":{"code":"ParentResourceNotFound"}})' };
  const proc = t.mock.method(cp, "spawnSync", () => result);
  const uri = "/subscriptions/id/resourceGroups/group/providers/Microsoft.Compute/virtualMachines/vm?api-version=2024-07-01";
  const read = (missingCodes) => arm("GET", uri, undefined, "Microsoft.Compute/virtualMachines/read", true,
    { timeoutMs: 8750, missingCodes });
  assert.equal(read(["ParentResourceNotFound"]), null);
  assert.equal(proc.mock.calls[0].arguments[2].timeout, 8750);
  assert.throws(() => read(["ResourceGroupNotFound"]), /AZURE_KV_ARM_REQUIRED/);
  result = { status: 1, stderr: 'ERROR: Forbidden({"error":{"code":"AuthorizationFailed","message":"ParentResourceNotFound"}})' };
  assert.throws(() => read(["ParentResourceNotFound"]), /AZURE_KV_ARM_REQUIRED/);
  result = { status: 1, stderr: 'ERROR: Not Found({"error":{"code":"Unauthorized","message":"ParentResourceNotFound"}})' };
  assert.throws(() => read(["ParentResourceNotFound"]), /AZURE_KV_ARM_REQUIRED/);
});

test("accepts only an exact base64 manifest with the separately pinned digest", () => {
  const bytes = Buffer.from(JSON.stringify(fixture()));
  const base64 = bytes.toString("base64");
  assert.deepEqual(approvedPlanBytes(base64, sha256(bytes)), bytes);
  assert.throws(() => approvedPlanBytes(base64, "0".repeat(64)));
  assert.throws(() => approvedPlanBytes(base64 + "\n", sha256(bytes)));
});
