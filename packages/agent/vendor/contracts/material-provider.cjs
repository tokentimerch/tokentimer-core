"use strict";
// Public identifiers only; shared by orchestration and capability negotiation.
const PROVIDERS = Object.freeze([
  "vault-kv2",
  "openbao-kv2",
  "azure-key-vault",
]);
function providerOf(intent) {
  // Old publication intents use type for the provider. Cleanup intents from
  // #498 use it for an operation. Recognize only the pinned legacy operation;
  // unknown types and contradictory explicit identities still fail closed.
  const legacyCleanup = intent?.type === VAULT_SOFT_DELETE;
  const operationProvider = cleanupOperationOf(intent) === VAULT_SOFT_DELETE ? "vault-kv2" : null;
  const provider = intent?.provider ?? (legacyCleanup ? "vault-kv2" : intent?.type) ?? "vault-kv2";
  if ((operationProvider && provider !== operationProvider) ||
      (intent?.type && !legacyCleanup && intent.type !== provider) ||
      (legacyCleanup && !operationProvider)) return null;
  return provider;
}
const VAULT_SOFT_DELETE = "vault-kv2-soft-delete";
function cleanupOperationOf(intent) {
  const operation = intent?.operation;
  // Canonical operation identity is provider-independent. Preserve the earlier
  // explicit method spelling and legacy signed type without rewriting either.
  if (operation !== undefined && operation !== "soft-delete" && operation !== VAULT_SOFT_DELETE) return null;
  if (intent?.type === VAULT_SOFT_DELETE || operation === "soft-delete" || operation === VAULT_SOFT_DELETE) return VAULT_SOFT_DELETE;
  return null;
}
function providerCapability(provider) {
  return (
    {
      "vault-kv2": "material-store-vault-kv2-v1",
      "openbao-kv2": "material-store-openbao-kv2-v1",
      "azure-key-vault": "material-store-azure-key-vault-v1",
    }[provider] || "material-store-unsupported"
  );
}
function validProviderVersion(provider, version) {
  return provider === "azure-key-vault"
    ? typeof version === "string" && /^[a-f0-9]{32}$/.test(version)
    : ["vault-kv2", "openbao-kv2"].includes(provider) &&
        Number.isInteger(version) &&
        version > 0 &&
        version <= 2147483647;
}
// Retain the existing integer column and its wire number for KV v2; Azure's
// opaque ID lives in a separate additive column. Never coerce an ID to a number.
function versionOf(row) {
  return row?.provider_version_ref ?? row?.provider_version;
}
module.exports = {
  PROVIDERS,
  providerOf,
  VAULT_SOFT_DELETE,
  cleanupOperationOf,
  providerCapability,
  validProviderVersion,
  versionOf,
};
