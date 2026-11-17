"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");
const { observe, sha256 } = require("./probe.cjs");
const { assembleReport } = require("./report.cjs");

const core = process.env.TT_IMDS_TEST_CORE ?? path.resolve(__dirname, "../../..");
const { credential } = require(path.join(core, "packages/agent/src/material-store/azure.js"));
const { CAPABILITIES } = require(path.join(core, "scripts/certops-azure-keyvault-package.cjs"));
const profiles = require(path.join(core, "scripts/certops-final-package-evidence.cjs"));

const guid = digit => digit.repeat(8) + "-" + Array(3).fill(digit.repeat(4)).join("-") + "-" + digit.repeat(12);

function fixture(role, overrides = {}) {
  const plan = {
    runId: "51", attempt: "1", sourceSha: "f".repeat(40), tenantId: guid("a"), subscriptionId: guid("b"),
    group: "tt-imds-51-1", vault: "ttimds" + "c".repeat(18), secret: "tt-imds-" + "d".repeat(32),
    pinnedVersion: "aa".repeat(16), newerVersion: "bb".repeat(16), valueSha256: sha256("old-fixture-marker"),
    deadlineAt: Date.now() + 300000, expiresAt: Date.now() + 1800000, role,
    hosts: {
      issuer: { vmId: guid("1"), clientId: guid("2"), principalId: guid("3") },
      consumer: { vmId: guid("4"), clientId: guid("5"), principalId: guid("6") },
    },
    packageArtifact: {
      artifactId: "11", candidateSha: "7".repeat(40), runId: "12", packageSha256: "8".repeat(64),
      packageVersion: "0.20.0", capabilities: CAPABILITIES,
    },
  };
  const own = plan.hosts[role];
  const opposite = plan.hosts[role === "issuer" ? "consumer" : "issuer"];
  const claims = { appid: own.clientId, oid: own.principalId, aud: "https://vault.azure.net", tid: plan.tenantId };
  const token = "header." + Buffer.from(JSON.stringify(claims)).toString("base64url") + ".signature";
  const groupId = "/subscriptions/" + plan.subscriptionId + "/resourceGroups/" + plan.group;
  const resourceId = groupId + "/providers/Microsoft.Compute/virtualMachines/tt-imds-" + role;
  const events = [];
  const requestJson = async (url, options) => {
    events.push(url.pathname);
    if (url.pathname === "/metadata/instance/compute") {
      assert.equal(options.headers.Metadata, "true");
      return { status: 200, json: { resourceId, vmId: own.vmId, osType: "Linux" } };
    }
    if (url.pathname === "/metadata/identity/oauth2/token") {
      assert.equal(url.searchParams.get("client_id"), own.clientId);
      return { status: 200, json: { access_token: token, expires_in: 3600 } };
    }
    assert.equal(url.href, "https://" + plan.vault + ".vault.azure.net/secrets/" + plan.secret +
      "/" + plan.pinnedVersion + "?api-version=7.4");
    assert.equal(options.headers.Authorization, "Bearer " + token);
    return { status: 200, json: {
      id: url.origin + (overrides.latest ? "/secrets/" + plan.secret + "/" + plan.newerVersion : url.pathname),
      value: "old-fixture-marker",
    } };
  };
  const deny = async (url, options, status, predicate) => {
    events.push(url.pathname);
    if (url.origin === "http://169.254.169.254") {
      assert.equal(url.searchParams.get("client_id"), opposite.clientId);
      assert.equal(status, 400);
      assert.ok(predicate({ error: overrides.malformedRequest ? "bad_request_102" : "invalid_request",
        error_description: "provider-specific diagnostic" }));
    } else {
      assert.equal(role, "consumer");
      assert.equal(status, 403);
      assert.equal(url.pathname, "/secrets/" + plan.secret);
      assert.equal(options.method, "PUT");
      assert.equal(options.headers.Authorization, "Bearer " + token);
      assert.ok(predicate({ error: { code: "Forbidden",
        innererror: { code: overrides.firewall ? "ForbiddenByFirewall" : "ForbiddenByRbac" } } }));
    }
    return { status, json: null };
  };
  return { plan, events, token, groupId, resourceId, dependencies: { credential, requestJson, deny } };
}

test("uses the product's IMDS credential for both clients and reads only the pinned older version", async () => {
  for (const role of ["issuer", "consumer"]) {
    const { plan, events, token, dependencies } = fixture(role);
    const result = await observe(plan, dependencies);
    assert.equal(result.identity.imdsRequests, 2);
    assert.equal(result.azureConsumerWriteStatus, role === "consumer" ? 403 : null);
    assert.equal(events.length, role === "consumer" ? 5 : 4);
    const output = JSON.stringify(result);
    for (const privateValue of [token, plan.hosts.issuer.principalId, plan.hosts.consumer.principalId,
      "old-fixture-marker", plan.secret, plan.vault]) assert.ok(!output.includes(privateValue));
  }
});

test("refuses a shared VM before making contact", async () => {
  const { plan, events, dependencies } = fixture("issuer");
  plan.hosts.consumer.vmId = plan.hosts.issuer.vmId;
  await assert.rejects(() => observe(plan, dependencies), /IMDS_ROLE_BOUNDARY_INVALID/);
  assert.deepEqual(events, []);
});

test("rejects a 400 caused by an invalid IMDS request instead of identity denial", async () => {
  const { plan, dependencies } = fixture("issuer", { malformedRequest: true });
  await assert.rejects(() => observe(plan, dependencies), /IMDS_OPPOSITE_IDENTITY_DENIAL_MISSING/);
});

test("rejects a response for the newer Key Vault version", async () => {
  const { plan, dependencies } = fixture("consumer", { latest: true });
  await assert.rejects(() => observe(plan, dependencies), /IMDS_EXACT_VERSION_READ_FAILED/);
});

test("rejects a firewall 403 as evidence of the consumer's RBAC denial", async () => {
  const { plan, dependencies } = fixture("consumer", { firewall: true });
  await assert.rejects(() => observe(plan, dependencies));
});

test("assembles a canonical report after exact-lease teardown and rejects changed evidence", async () => {
  const issuer = fixture("issuer"), consumer = fixture("consumer");
  const { plan, groupId } = issuer;
  const run = { id: Number(plan.runId), run_attempt: 1, head_sha: plan.sourceSha,
    event: "workflow_dispatch", head_branch: "main" };
  const binding = { runId: plan.runId, attempt: plan.attempt, sourceSha: plan.sourceSha,
    packageArtifact: plan.packageArtifact };
  const observations = await Promise.all([issuer, consumer].map(async role =>
    ({ ...binding, ...await observe(role.plan, role.dependencies) })));
  const resourceIds = [issuer.resourceId, consumer.resourceId,
    groupId + "/providers/Microsoft.KeyVault/vaults/" + plan.vault];
  const commandIds = [issuer.resourceId, consumer.resourceId].map(id => id + "/runCommands/imds-proof");
  const owned = { groupId, resourceIds, commandIds, roleAssignmentIds: [groupId + "/roleAssignments/proof-1"] };
  const teardown = { ...binding, groupId, vault: plan.vault, vaultState: "soft-deleted", purged: false,
    commands: commandIds.map(id => ({ id, state: "Succeeded", exitCode: 0 })),
    absence: [groupId, ...resourceIds, ...commandIds, ...owned.roleAssignmentIds]
      .map(id => ({ id, state: "absent" })),
  };
  const input = { plan, run, observations, owned, teardown };
  const report = assembleReport(input, profiles);
  assert.equal(report.facts.azureConsumerWriteStatus, 403);
  assert.equal(report.fullOperatorE2e, false);
  assert.throws(() => assembleReport({ ...input, teardown: { ...teardown, absence: teardown.absence.slice(1) } }, profiles));
  assert.throws(() => assembleReport({ ...input, teardown: { ...teardown,
    commands: [{ ...teardown.commands[0], state: "Running" }, teardown.commands[1]] } }, profiles));
  const wrongPackage = { ...observations[1], packageArtifact: { ...plan.packageArtifact, artifactId: "99" } };
  assert.throws(() => assembleReport({ ...input, observations: [observations[0], wrongPackage] }, profiles));
});
