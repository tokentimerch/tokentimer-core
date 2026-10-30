"use strict";

// Operation identity is independent of the provider discriminator used by the
// publication/deployment adapters. Keep approved legacy payloads byte-for-byte:
// normalize only the copy passed to the local adapter, never the signed intent.
function cleanupIdentity(intent) {
  const legacy = intent?.type === "vault-kv2-soft-delete" && intent.operation == null;
  if ((!legacy && (intent?.type != null || intent?.operation !== "soft-delete")) ||
    (intent?.provider ?? (legacy ? "vault-kv2" : null)) !== "vault-kv2") {
    const error = new Error("material_cleanup_intent_invalid");
    error.code = "material_cleanup_intent_invalid";
    throw error;
  }
  return { operation: "soft-delete", provider: "vault-kv2", method: "vault-kv2-soft-delete" };
}

function cleanupStoreIntent(intent, workspaceId) {
  const copy = { ...intent };
  delete copy.type;
  const { operation, provider } = cleanupIdentity(intent);
  return { ...copy, operation, provider, workspaceId };
}

module.exports = { cleanupIdentity, cleanupStoreIntent };
