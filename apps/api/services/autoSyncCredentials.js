"use strict";

const ALLOWED_AUTH_METHODS = new Set(["token", "client_credentials"]);

function requiredFieldsFor(provider, credentials) {
  const authMethod = credentials?.authMethod;
  if (authMethod === undefined) {
    // omitted authMethod stays legacy token mode
  } else if (
    typeof authMethod !== "string" ||
    !ALLOWED_AUTH_METHODS.has(authMethod)
  ) {
    return {
      error:
        typeof authMethod === "string" && authMethod !== ""
          ? `Unknown authMethod "${authMethod}"`
          : 'authMethod must be "token" or "client_credentials"',
    };
  }
  const method = authMethod || "token";
  if (provider === "azure") {
    return method === "client_credentials"
      ? ["vaultUrl", "tenantId", "clientId", "clientSecret"]
      : ["vaultUrl", "token"];
  }
  if (provider === "azure-ad") {
    return method === "client_credentials"
      ? ["tenantId", "clientId", "clientSecret"]
      : ["token"];
  }
  return null;
}

const STATIC_REQUIRED_CRED_FIELDS = {
  github: ["token"],
  gitlab: ["token"],
  aws: ["accessKeyId", "secretAccessKey"],
  gcp: ["projectId", "accessToken"],
  vault: ["address", "token"],
};

function requiredAutoSyncCredFields(provider, credentials) {
  const azureFields = requiredFieldsFor(provider, credentials);
  if (azureFields && azureFields.error) return azureFields;
  if (azureFields) return { fields: azureFields };
  return { fields: STATIC_REQUIRED_CRED_FIELDS[provider] || [] };
}

function validateAutoSyncCredentials(provider, credentials) {
  if (!credentials || typeof credentials !== "object") return null;
  const resolved = requiredAutoSyncCredFields(provider, credentials);
  if (resolved.error) return resolved.error;
  const empty = resolved.fields.filter((f) => !credentials[f]);
  if (empty.length === 0) return null;
  const detail = empty.map((f) =>
    f in credentials ? `${f} (empty)` : `${f} (absent)`,
  );
  return `Missing required credential fields for ${provider}: ${detail.join(", ")}`;
}

function azureAuthFieldsFromCreds(creds) {
  if (creds.authMethod === "client_credentials") {
    return {
      authMethod: "client_credentials",
      tenantId: creds.tenantId,
      clientId: creds.clientId,
      clientSecret: creds.clientSecret,
    };
  }
  return { token: creds.token };
}

function buildAzureAutoSyncScanBody(provider, creds, scanParams) {
  const filterRules = Array.isArray(scanParams?.filterRules)
    ? scanParams.filterRules
    : undefined;
  const auth = azureAuthFieldsFromCreds(creds);
  if (provider === "azure") {
    return {
      vaultUrl: creds.vaultUrl,
      ...auth,
      include: scanParams?.include || {
        secrets: true,
        certificates: true,
        keys: true,
      },
      maxItems: scanParams?.maxItems || 500,
      filterRules,
    };
  }
  if (provider === "azure-ad") {
    return {
      ...auth,
      include: scanParams?.include || {
        applications: true,
        servicePrincipals: true,
      },
      maxItems: scanParams?.maxItems || 500,
      filterRules,
    };
  }
  return null;
}

module.exports = {
  requiredAutoSyncCredFields,
  validateAutoSyncCredentials,
  buildAzureAutoSyncScanBody,
};
