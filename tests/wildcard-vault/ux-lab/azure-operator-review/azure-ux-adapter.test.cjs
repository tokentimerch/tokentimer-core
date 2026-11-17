"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { azureLabConfig, configForLabAgent, capabilityForProvider, readRetainedAzureBundles, privacyInventory, credentialNeedles, suppliedArchive, rejectSharedAssertionBytes } = require("./azure-ux-adapter.cjs");
const base = () => ({ vaultHost: "tt-own-vault.vault.azure.net", workspaceId: "workspace", groupId: "group",
  scope: { prefix: "workspace/group", sans: ["nginx.wildcard.test"], keyAlgorithm: "ec" },
  issuer: { identityId: "issuer", auth: { type: "token-file", tokenFile: "/lab/issuer/token.json" } },
  consumers: [{ identityId: "consumer", auth: { type: "token-file", tokenFile: "/lab/nginx/token.json" } }] });
test("constructs distinct provider configs and capability for the disposable lab", () => {
  const result = azureLabConfig(base());
  assert.equal(result.capability, "material-store-azure-key-vault-v1");
  assert.equal(result.issuer.customer.address, "https://tt-own-vault.vault.azure.net");
  assert.equal(result.issuer.customer.groups.group.workspaceId, "workspace");
  assert.equal(result.consumers[0].customer.auth.tokenFile, "/lab/nginx/token.json");
  assert.equal("mount" in result.issuer.customer, false);
});
test("rejects an issuer identity reused as consumer", () => {
  const input = base(); input.consumers[0].identityId = input.issuer.identityId;
  assert.throws(() => azureLabConfig(input), /identity identifiers must be distinct/);
});
test("rejects different labels that point at the issuer's same token file", () => {
  const input = base(); input.consumers[0].auth.tokenFile = input.issuer.auth.tokenFile;
  assert.throws(() => azureLabConfig(input), /credential files must be distinct/);
});
test("rejects separate assertion paths sharing the same federation subject", () => {
  const input = base(), trust = { issuer: "https://issuer.test", subject: "shared", audience: "api://AzureADTokenExchange" };
  input.issuer.auth = { type: "workload-identity", tenantId: "tenant", clientId: "issuer-client", assertionFile: "/lab/issuer/assertion" };
  input.issuer.federation = trust;
  input.consumers[0].auth = { type: "workload-identity", tenantId: "tenant", clientId: "consumer-client", assertionFile: "/lab/consumer/assertion" };
  input.consumers[0].federation = { ...trust };
  assert.throws(() => azureLabConfig(input), /federation trusts must differ/);
  input.consumers[0].federation.subject = "consumer";
  assert.doesNotThrow(() => azureLabConfig(input));
  input.consumers[0].auth.assertionFile = input.issuer.auth.assertionFile;
  assert.throws(() => azureLabConfig(input), /assertion files must differ/);
});
test("different assertion files containing the same assertion are refused", () => {
  const issuer = { auth: { type: "workload-identity", assertionFile: "/issuer" } };
  const consumer = { auth: { type: "workload-identity", assertionFile: "/consumer" } };
  assert.throws(() => rejectSharedAssertionBytes(issuer, consumer, () => Buffer.from("same")), /shared issuer\/consumer assertion refused/);
  assert.doesNotThrow(() => rejectSharedAssertionBytes(issuer, consumer, file => Buffer.from(file)));
});
test("managed identities on a common host are refused", () => {
  const input = base();
  input.issuer.auth = { type: "managed-identity" }; input.consumers[0].auth = { type: "managed-identity" };
  input.issuer.hostIdentitySha256 = input.consumers[0].hostIdentitySha256 = "a".repeat(64);
  assert.throws(() => azureLabConfig(input), /separate hosts/);
  input.consumers[0].hostIdentitySha256 = "b".repeat(64);
  assert.doesNotThrow(() => azureLabConfig(input));
});
test("supplied archive must match the expected digest and candidate", t => {
  const fs = require("node:fs"), os = require("node:os"), path = require("node:path"), crypto = require("node:crypto");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tt-azure-archive-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const archivePath = path.join(root, "agent.tgz"); fs.writeFileSync(archivePath, "archive bytes");
  const archiveSha256 = crypto.createHash("sha256").update("archive bytes").digest("hex"), candidateSha = "a".repeat(40);
  assert.equal(suppliedArchive({archivePath, archiveSha256, candidateSha, expectedCandidateSha:candidateSha}).archiveSha256, archiveSha256);
  assert.throws(() => suppliedArchive({archivePath, archiveSha256:"b".repeat(64), candidateSha, expectedCandidateSha:candidateSha}), /digest mismatch/);
  assert.throws(() => suppliedArchive({archivePath, archiveSha256, candidateSha, expectedCandidateSha:"c".repeat(40)}), /candidate mismatch/);
});
test("rejects a non-Azure endpoint and relative credential paths", () => {
  const input = base(); input.vaultHost = "localhost";
  assert.throws(() => azureLabConfig(input));
  input.vaultHost = "tt-own-vault.vault.azure.net"; input.consumers[0].auth.tokenFile = "relative";
  assert.throws(() => azureLabConfig(input), /credential path must be absolute/);
});
test("customer-host agent names map to one explicitly configured identity", () => {
  const input = base(); input.consumers[0].name = "nginx";
  const args = { identities: input, workspaceId: input.workspaceId, groupId: input.groupId, scope: input.scope };
  assert.equal(configForLabAgent({ ...args, issuer: true, name: "issuer" }).customer.auth.tokenFile, "/lab/issuer/token.json");
  assert.equal(configForLabAgent({ ...args, issuer: false, name: "nginx" }).customer.auth.tokenFile, "/lab/nginx/token.json");
  assert.throws(() => configForLabAgent({ ...args, issuer: false, name: "haproxy" }), /exactly one mapped identity/);
  input.consumers.push({ ...input.consumers[0] });
  assert.throws(() => configForLabAgent({ ...args, issuer: false, name: "nginx" }), /identity identifiers must be distinct/);
});
test("lab-only capability selection handles all supported provider types and fails closed", () => {
  assert.equal(capabilityForProvider("azure-key-vault"), "material-store-azure-key-vault-v1");
  assert.equal(capabilityForProvider("vault-kv2"), "material-store-vault-kv2-v1");
  assert.equal(capabilityForProvider("openbao-kv2"), "material-store-openbao-kv2-v1");
  assert.throws(() => capabilityForProvider("unknown"), /unknown lab material provider/);
});
test("privacy read uses the exact opaque Azure version for every material version", async () => {
  const calls = [];
  const versions = [{ materialVersionId: "material-1", providerVersion: "a".repeat(32) }, { materialVersionId: "material-2", providerVersion: "b".repeat(32) }];
  const bundles = await readRetainedAzureBundles({ materialStores: {}, workspaceId: "w", groupId: "g", versions,
    createMaterialStore: (_stores, intent) => ({ fetch: async version => { calls.push({ intent, version }); return { materialVersionId: intent.materialVersionId }; } }) });
  assert.deepEqual(calls.map(call => call.version), versions.map(item => item.providerVersion));
  assert.deepEqual(bundles.map(item => item.materialVersionId), versions.map(item => item.materialVersionId));
  assert.ok(calls.every(call => call.intent.provider === "azure-key-vault"));
  await assert.rejects(() => readRetainedAzureBundles({ createMaterialStore: () => ({}), materialStores: {}, workspaceId: "w", groupId: "g", versions: [{ materialVersionId: "x", providerVersion: "1" }] }), /exact Azure version required/);
});
test("operator journey preserves the Azure version ref for each published row", () => {
  const rows = [{ id: "m1", state: "published", provider_version: "a".repeat(32) }, { id: "m2", state: "pending", provider_version: null }, { id: "m3", state: "published", provider_version: "b".repeat(32) }];
  assert.deepEqual(privacyInventory("azure-key-vault", rows), [{ materialVersionId: "m1", providerVersion: "a".repeat(32) }, { materialVersionId: "m3", providerVersion: "b".repeat(32) }]);
  assert.deepEqual(privacyInventory("vault-kv2", rows), ["m1", "m3"]);
  assert.throws(() => privacyInventory("azure-key-vault", [{ id: "m1", state: "published", provider_version: null }]), /exact provider version/);
});
test("privacy audit scans both serialized Azure token sink and actual token", () => {
  const raw = JSON.stringify({ accessToken: "synthetic-token-value-only-for-test", expiresOn: 123 });
  assert.deepEqual(credentialNeedles(raw), [raw, "synthetic-token-value-only-for-test"]);
  assert.deepEqual(credentialNeedles("vault-raw-token"), ["vault-raw-token"]);
});
test("scratch runner refuses live Azure startup before credential handling is implemented", () => {
  const fs = require("node:fs"), os = require("node:os"), path = require("node:path"), { spawnSync } = require("node:child_process");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tt-azure-harness-test-"));
  try {
    const repo = path.join(root, "candidate"), input = path.join(root, "input");
    fs.mkdirSync(repo); fs.mkdirSync(input); fs.writeFileSync(path.join(input, "azure-identities.json"), "{}\n");
    const result = spawnSync("pwsh", ["-NoProfile", "-File", path.join(__dirname, "run.ps1"), "-Action", "Up", "-Project", "tt-wildcard-ux-scratch-test", "-MaterialProvider", "azure-key-vault", "-AzureInputDirectory", input], { env: { ...process.env, TT_UX_CANDIDATE_REPO: repo }, encoding: "utf8", timeout: 30000 });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Azure scratch journey is not runnable/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
