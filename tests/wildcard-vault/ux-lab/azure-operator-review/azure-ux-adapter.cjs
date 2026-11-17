"use strict";

// Supporting UX lab adapter: caller supplies already-provisioned, independent
// identities and protected local credential paths. This does not provision or
// promote any Azure capability and must not be used as production authority.
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");

// The producer owns artifact authentication. This checks only that the file
// handed to the journey is byte-identical to the producer's selected digest.
function suppliedArchive({ archivePath, archiveSha256, candidateSha, expectedCandidateSha }) {
  assert.ok(path.isAbsolute(archivePath || ""), "absolute supplied archive path required");
  assert.match(archiveSha256 || "", /^[a-f0-9]{64}$/, "supplied archive digest required");
  assert.match(candidateSha || "", /^[a-f0-9]{40}$/, "candidate SHA required");
  assert.equal(candidateSha, expectedCandidateSha, "candidate mismatch");
  const digest = crypto.createHash("sha256").update(fs.readFileSync(archivePath)).digest("hex");
  assert.equal(digest, archiveSha256, "supplied archive digest mismatch");
  return { archivePath, archiveSha256: digest, candidateSha };
}

// Local comparison is only an additional rejection guard, not proof that
// either Azure trust excludes the other role's independently minted tokens.
function rejectSharedAssertionBytes(issuer, consumer, read = file => fs.readFileSync(file)) {
  assert.equal(issuer.auth.type, "workload-identity");
  assert.equal(consumer.auth.type, "workload-identity");
  const left = read(issuer.auth.assertionFile), right = read(consumer.auth.assertionFile);
  assert.ok(Buffer.isBuffer(left) && left.length && Buffer.isBuffer(right) && right.length, "assertions unavailable");
  const a = crypto.createHash("sha256").update(left).digest(), b = crypto.createHash("sha256").update(right).digest();
  assert.equal(crypto.timingSafeEqual(a, b), false, "shared issuer/consumer assertion refused");
}

function azureLabConfig({ vaultHost, issuer, consumers, groupId, workspaceId, scope }) {
  assert.match(vaultHost, /^[a-z0-9-]{3,24}\.vault\.azure\.net$/i);
  assert.ok(issuer && Array.isArray(consumers) && consumers.length >= 1);
  assert.ok(typeof issuer.identityId === "string" && issuer.identityId.length > 0);
  const identities = [issuer, ...consumers];
  const normalized = value => typeof value === "string" ? value.trim().toLowerCase() : "";
  assert.equal(new Set(identities.map(identity => normalized(identity.identityId))).size, identities.length, "identity identifiers must be distinct");
  for (const identity of identities) {
    assert.ok(identity.auth && ["token-file", "workload-identity", "managed-identity"].includes(identity.auth.type));
    if (identity.auth.type === "workload-identity") {
      assert.ok(normalized(identity.auth.tenantId) && normalized(identity.auth.clientId), "workload tenant and client required");
      const trust = identity.federation;
      assert.ok(trust && [trust.issuer, trust.subject, trust.audience].every(value => typeof value === "string" && value.length > 0), "distinct federation issuer, subject and audience required");
    }
    if (identity.auth.type === "managed-identity")
      assert.match(identity.hostIdentitySha256 || "", /^[a-f0-9]{64}$/, "managed identity requires an isolated host identity");
  }
  for (const consumer of consumers) {
    assert.ok(typeof consumer.identityId === "string" && consumer.identityId.length > 0);
    assert.notEqual(consumer.identityId, issuer.identityId, "issuer and consumer identities must be distinct");
    if (issuer.auth?.type === "token-file" && consumer.auth?.type === "token-file")
      assert.notEqual(consumer.auth.tokenFile, issuer.auth.tokenFile, "issuer and consumer credential files must be distinct");
    if (issuer.auth.type === "workload-identity" && consumer.auth.type === "workload-identity") {
      assert.notEqual(normalized(consumer.auth.clientId), normalized(issuer.auth.clientId), "issuer and consumer clients must differ");
      assert.notEqual(consumer.auth.assertionFile, issuer.auth.assertionFile, "issuer and consumer assertion files must differ");
      const key = identity => JSON.stringify([identity.federation.issuer, identity.federation.subject, identity.federation.audience]);
      assert.notEqual(key(consumer), key(issuer), "issuer and consumer federation trusts must differ");
    }
    if (issuer.auth.type === "managed-identity" && consumer.auth.type === "managed-identity")
      assert.notEqual(consumer.hostIdentitySha256, issuer.hostIdentitySha256, "managed identities require separate hosts");
  }
  assert.ok(groupId && workspaceId && scope && typeof scope === "object");
  function configFor(identity) {
    assert.ok(identity.auth && ["token-file", "workload-identity", "managed-identity"].includes(identity.auth.type));
    const file = identity.auth.type === "token-file" ? identity.auth.tokenFile : identity.auth.assertionFile;
    if (identity.auth.type !== "managed-identity") assert.ok(path.posix.isAbsolute(file || ""), "credential path must be absolute in customer container");
    return { customer: { provider: "azure-key-vault", address: `https://${vaultHost}`, auth: { ...identity.auth }, timeoutMs: 10000,
      groups: { [groupId]: { ...scope, workspaceId } } } };
  }
  return { issuer: configFor(issuer), consumers: consumers.map(configFor), capability: "material-store-azure-key-vault-v1" };
}

function configForLabAgent({ identities, name, issuer, groupId, workspaceId, scope }) {
  const configs = azureLabConfig({ ...identities, groupId, workspaceId, scope });
  if (issuer) {
    assert.equal(name, "issuer", "issuer role must use the issuer agent");
    return configs.issuer;
  }
  const matches = identities.consumers.map((consumer, i) => ({ consumer, i })).filter(item => item.consumer.name === name);
  assert.equal(matches.length, 1, "consumer agent needs exactly one mapped identity");
  return configs.consumers[matches[0].i];
}

function capabilityForProvider(provider) {
  const capabilities = { "azure-key-vault": "material-store-azure-key-vault-v1", "vault-kv2": "material-store-vault-kv2-v1", "openbao-kv2": "material-store-openbao-kv2-v1" };
  assert.ok(Object.hasOwn(capabilities, provider), "unknown lab material provider");
  return capabilities[provider];
}

// Return material only to the caller's customer-side privacy scanner. The
// exact Azure provider version is mandatory; never substitute Vault version 1.
async function readRetainedAzureBundles({ createMaterialStore, materialStores, workspaceId, groupId, versions }) {
  assert.equal(typeof createMaterialStore, "function");
  assert.ok(Array.isArray(versions) && versions.length > 0);
  const out = [];
  for (const entry of versions) {
    assert.ok(entry.materialVersionId && /^[a-f0-9]{32}$/.test(entry.providerVersion || ""), "exact Azure version required");
    const reader = createMaterialStore(materialStores, { materialStoreRef: "customer", provider: "azure-key-vault", workspaceId, groupId, materialVersionId: entry.materialVersionId });
    out.push(await reader.fetch(entry.providerVersion));
  }
  return out;
}

function privacyInventory(provider, rows) {
  assert.ok(Array.isArray(rows));
  const published = rows.filter(row => row.state === "published");
  if (provider !== "azure-key-vault") return published.map(row => row.id);
  return published.map(row => {
    assert.ok(typeof row.id === "string" && /^[a-f0-9]{32}$/.test(row.provider_version || ""), "published Azure row needs exact provider version");
    return { materialVersionId: row.id, providerVersion: row.provider_version };
  });
}

function credentialNeedles(raw) {
  const input = String(raw).trim();
  const values = [input];
  try {
    const parsed = JSON.parse(input);
    if (typeof parsed.accessToken === "string" && parsed.accessToken) values.push(parsed.accessToken);
  } catch { /* Vault-style raw token. */ }
  return [...new Set(values.filter(Boolean))];
}

module.exports = { azureLabConfig, configForLabAgent, capabilityForProvider, readRetainedAzureBundles, privacyInventory, credentialNeedles, suppliedArchive, rejectSharedAssertionBytes };
if (require.main === module) {
  if (process.argv[2] === "--capability") console.log(capabilityForProvider(process.argv[3]));
  else if (process.argv[2] === "--check-archive") {
    const [, , , archivePath, archiveSha256, candidateSha, expectedCandidateSha] = process.argv;
    const checked = suppliedArchive({ archivePath, archiveSha256, candidateSha, expectedCandidateSha });
    console.log(JSON.stringify({ archiveSha256: checked.archiveSha256, candidateSha: checked.candidateSha, qualification: "not-established" }));
  } else throw new Error("unsupported scratch adapter command");
}
