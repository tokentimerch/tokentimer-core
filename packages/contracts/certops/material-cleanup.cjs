"use strict";

// Operation identity is independent of the provider discriminator used by the
// publication/deployment adapters. Keep approved legacy payloads byte-for-byte:
// normalize only the copy passed to the local adapter, never the signed intent.
function cleanupIdentity(intent) {
  const legacy = intent?.type === "vault-kv2-soft-delete" && intent.operation == null;
  if ((!legacy && (intent?.type != null || intent?.operation !== "soft-delete")) ||
    !["vault-kv2", "openbao-kv2"].includes(intent?.provider ?? (legacy ? "vault-kv2" : null)) ||
    legacy && intent.provider != null && intent.provider !== "vault-kv2") {
    const error = new Error("material_cleanup_intent_invalid");
    error.code = "material_cleanup_intent_invalid";
    throw error;
  }
  const provider = legacy ? "vault-kv2" : intent.provider;
  return { operation: "soft-delete", provider, method: `${provider}-soft-delete` };
}

function cleanupCapability(provider) {
  return {"vault-kv2":"material-cleanup-vault-kv2-v1","openbao-kv2":"material-cleanup-openbao-kv2-v1"}[provider] || null;
}

function cleanupStoreIntent(intent, workspaceId) {
  const copy = { ...intent };
  delete copy.type;
  const { operation, provider } = cleanupIdentity(intent);
  return { ...copy, operation, provider, workspaceId };
}

module.exports = { cleanupIdentity, cleanupStoreIntent, cleanupCapability };
