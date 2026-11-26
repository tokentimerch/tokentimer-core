"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const { createRequire } = require("node:module");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { validateWorkflow } = require("./certops-workflow-security");

const infra = path.resolve(__dirname, "../infra/certops-adcs");
const script = "provision-store-media-receiver.ps1";
const sha = value => createHash("sha256").update(value).digest("hex");
const subscription = "2c4aa1c2-42b3-4a1f-a4ac-555555555555";
const clientId = "22999ba7-55f3-4e46-ba73-666666666666";
const memberId = "70eafbb5-5041-4ab7-815f-777777777777";
const group = "tt-certops-12345-1";
const groupId = "/subscriptions/" + subscription + "/resourceGroups/" + group;
const hostname = "ttstore123456789abcd.blob.core.windows.net";
const provider = groupId + "/providers/";
const storageId = provider + "Microsoft.Storage/storageAccounts/" + hostname.split(".")[0];
const networkId = provider + "Microsoft.Network/virtualNetworks/qualification-private";
const endpointId = provider + "Microsoft.Network/privateEndpoints/store-media-ingress";
const memberResourceId = provider + "Microsoft.Compute/virtualMachines/windows-agent";
const memberNicId = provider + "Microsoft.Network/networkInterfaces/windows-agent-nic";
const receiverWorkflow = "certops-adcs-store-private-receiver.yml";

test("receiver controls are bound to its exact manual protected job", () => {
  const yaml = createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
  const value = yaml.load(fs.readFileSync(path.join(__dirname, "../.github/workflows", receiverWorkflow), "utf8"));
  assert.deepEqual(validateWorkflow(value, receiverWorkflow), []);
  for (const mutation of [
    job => { job.if = "always()"; },
    job => { job.environment = "certops-adcs-cleanup"; },
    job => { job.env.STORE_PREPARE_RUN_ID = "12345"; },
    job => { job.steps[2].run = "az group create"; },
    job => { job.steps[3].with.path = "qualification-results/"; },
  ]) {
    const rejected = structuredClone(value);
    mutation(rejected.jobs.receiver);
    assert.notDeepEqual(validateWorkflow(rejected, receiverWorkflow), []);
  }
});

function runFixture(t, mode = "exact") {
  const temp = fs.realpathSync(os.tmpdir());
  const root = fs.mkdtempSync(path.join(temp, "store-private-receiver-"));
  t.after(() => {
    assert.equal(path.dirname(root), temp);
    fs.rmSync(root, { force: true, recursive: true });
  });
  for (const file of [script, "store-noiis-prepare-guard.ps1"])
    fs.copyFileSync(path.join(infra, file), path.join(root, file));
  fs.writeFileSync(path.join(root, "login-oidc.ps1"), "Add-Content -LiteralPath $env:STORE_TRACE -Value 'login'");
  const remaining = { expired: -5000, short: 60000 }[mode] ?? 30 * 60000;
  const expiresAt = new Date(Date.now() + remaining).toISOString();
  const registration = {
    resourceGroup: group, runId: "12345", runAttempt: "1", workflowCommit: "a".repeat(40),
    subscriptionSha256: sha(subscription), provisionClientSha256: sha(mode === "wrong-principal" ? "foreign" : clientId),
    cleanupClientSha256: "b".repeat(64), registrationNonce: "c".repeat(64), mediaReceiptSha256: "d".repeat(64),
    createdAt: new Date(Date.now() - 600000).toISOString(), expiresAt, location: "swedencentral",
  };
  const proof = { registration, prepared: {
    scope: "store-preparation-inputs-only", memberVmId: memberId,
    registrationDigest: "e".repeat(64), preparationDigest: "f".repeat(64),
  } };
  const tags = {
    purpose: "certops-adcs-qualification", candidateSha: registration.workflowCommit, expiresAt,
    createdAt: registration.createdAt, storePrepareRun: registration.runId, storePrepareAttempt: registration.runAttempt,
    storePrepareNonce: registration.registrationNonce,
  };
  const data = {
    group: { id: groupId, name: group, location: registration.location, properties: { provisioningState: "Succeeded" }, tags },
    vm: { id: memberResourceId,
      vmId: mode === "replaced" ? "d4873706-e97d-4efe-b609-999999999999" : memberId, provisioningState: "Succeeded", tags },
    attached: [mode === "changed-nic" ? "unexpected" : memberNicId],
    memberNic: {
      id: memberNicId, virtualMachine: { id: memberResourceId }, ipConfigurations: [{
        subnet: { id: networkId + "/subnets/qualification" },
        privateIPAddress: "10.64.0.5", privateIPAllocationMethod: "Static",
        publicIPAddress: mode === "public-member" ? { id: "foreign" } : null,
      }],
    },
    network: { id: networkId, peerings: mode === "peered" ? [{ id: "foreign" }] : [] },
    outputs: {
      blobHostname: { value: hostname }, endpointResourceId: { value: endpointId },
      containerResourceId: { value: storageId + "/blobServices/default/containers/store-media" },
    },
    storage: { network: mode === "public" ? "Enabled" : "Disabled", anonymous: false, sharedKey: false, tls: "TLS1_2" },
    endpoint: { provisioningState: "Succeeded", subnet: { id: networkId + "/subnets/qualification" },
      networkInterfaces: [{ id: provider + "Microsoft.Network/networkInterfaces/receiver-fixture" }],
      privateLinkServiceConnections: [{
        privateLinkServiceId: storageId, groupIds: ["blob"], privateLinkServiceConnectionState: { status: "Approved" },
      }] },
    identity: { type: "SystemAssigned", principalId: "91e6b449-be1d-409f-8366-888888888888" },
  };
  const harness = path.join(root, "fixture.ps1");
  const trace = path.join(root, "trace");
  fs.writeFileSync(harness, String.raw`
$ErrorActionPreference = 'Stop'
$fixture = $env:STORE_FIXTURE | ConvertFrom-Json -DateKind String
$script:identity = $null
function node {
  if ($args.Count -ne 2 -or $args[1] -cne '--receiver') { throw 'Wrong proof entrypoint' }
  $global:LASTEXITCODE = 0
  $env:STORE_PROOF
}
function az {
  $global:LASTEXITCODE = 0
  if ('--subscription' -cnotin $args -or $env:AZURE_SUBSCRIPTION_ID -cnotin $args) { throw 'Unexpected subscription' }
  $operation = "$($args[0]) $($args[1])"
  if ($args[0] -in @('deployment','network','storage','vm') -and $args[1] -ne 'show') { $operation += " $($args[2])" }
  Add-Content -LiteralPath $env:STORE_TRACE -Value $operation
  $result = switch ($operation) {
    'group show' { $fixture.group }
    'vm show' {
      if ($args -contains '{vmId:vmId,identity:identity}') {
        @{vmId=$fixture.vm.vmId;identity=$script:identity}
      } elseif ($args -contains 'networkProfile.networkInterfaces[].id') {
        return (ConvertTo-Json -InputObject @($fixture.attached) -Compress)
      } else { $fixture.vm }
    }
    'network vnet show' { $fixture.network }
    'deployment group create' {
      if ('Incremental' -cnotin $args -or $fixture.group.name -cnotin $args) { throw 'Unexpected deployment scope' }
      $fixture.outputs
    }
    'storage account show' { $fixture.storage }
    'network private-endpoint show' { $fixture.endpoint }
    'network nic show' {
      if ($fixture.memberNic.id -in $args) { $fixture.memberNic } else { return '10.64.0.7' }
    }
    'vm identity assign' {
      if ('windows-agent' -cnotin $args -or $fixture.group.name -cnotin $args) { throw 'Unexpected identity scope' }
      $script:identity=$fixture.identity
      return
    }
    default { throw 'Unexpected fixture operation' }
  }
  $result | ConvertTo-Json -Compress -Depth 20
}
& (Join-Path $PSScriptRoot 'provision-store-media-receiver.ps1')
`);
  const execution = spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-File", harness], {
    cwd: root, encoding: "utf8", windowsHide: true, timeout: 15000, env: {
      ...process.env, AZURE_SUBSCRIPTION_ID: subscription, AZURE_CLIENT_ID: clientId, GITHUB_SHA: "1".repeat(40),
      STORE_PROOF: JSON.stringify(proof), STORE_FIXTURE: JSON.stringify(data), STORE_TRACE: trace,
    },
  });
  const output = path.join(root, "qualification-results/store-private-media-receiver.json");
  return {
    execution, operations: fs.existsSync(trace) ? fs.readFileSync(trace, "utf8").trim().split(/\r?\n/) : [],
    receipt: fs.existsSync(output) ? JSON.parse(fs.readFileSync(output, "utf8")) : null,
  };
}

test("receiver prepares the original private endpoint without a grant or transfer", t => {
  const { execution, operations, receipt } = runFixture(t);
  assert.equal(execution.status, 0, execution.stderr);
  assert.ok(operations.includes("deployment group create") && operations.includes("vm identity assign"));
  assert.ok(operations.indexOf("network nic show") < operations.indexOf("vm identity assign"));
  assert.equal(receipt.resourceGroup, group);
  assert.equal(receipt.memberVmId, memberId);
  assert.equal(receipt.endpointPrivateAddress, "10.64.0.7");
  assert.equal(receipt.receiverReaderGranted, false);
  assert.equal(receipt.mediaTransferred, false);
  assert.equal(receipt.qualificationPassed, false);
});

test("unsafe leases, identities and networks refuse before deployment", t => {
  const refusals = {
    "wrong-principal": /original Store provisioning identity/,
    expired: /lease expired/,
    short: /lease is too short/,
    replaced: /Original prepared Store member changed/,
    peered: /original unpeered Store network/,
    "public-member": /outside its private network scope/,
    "changed-nic": /single original private member interface/,
  };
  for (const [mode, reason] of Object.entries(refusals)) {
    const { execution, operations, receipt } = runFixture(t, mode);
    assert.notEqual(execution.status, 0, mode);
    assert.match(execution.stderr, reason, mode);
    assert.ok(!operations.includes("deployment group create"), mode);
    assert.equal(receipt, null, mode);
  }
});

test("unexpected public storage withholds identity setup and the receiver receipt", t => {
  const { execution, operations, receipt } = runFixture(t, "public");
  assert.notEqual(execution.status, 0);
  assert.match(execution.stderr, /private, Entra-only storage policy/);
  assert.ok(!operations.includes("vm identity assign"));
  assert.equal(receipt, null);
});
