"use strict";
// Public identifiers only; shared by orchestration and capability negotiation.
const PROVIDERS = Object.freeze([
  "vault-kv2",
  "openbao-kv2",
  "azure-key-vault",
]);
function providerOf(intent) {
  return intent?.type || intent?.provider || "vault-kv2";
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
  providerCapability,
  validProviderVersion,
  versionOf,
};
