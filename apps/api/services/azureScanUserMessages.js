"use strict";

function azureKeyVaultUserMessage(e, errorRef, formatIntegrationError) {
  if (e?.azureTenantDiscovery) return e.message;
  if (e?.status === 400) {
    return `Invalid request: ${e?.message || "Bad Request"}. Check your Key Vault URL format (should be https://[name].vault.azure.net).`;
  }
  if (e?.status === 401) {
    if (
      e?.azureErrorCode ||
      e?.correlationId ||
      /tenantId|clientId|Client secret|Azure authentication failed/i.test(
        e?.message || "",
      )
    ) {
      return e.message;
    }
    return "Authentication failed. Token may be expired (Azure CLI tokens expire quickly) or invalid. Clear cache: az account clear && az login, then regenerate: az account get-access-token --resource https://vault.azure.net";
  }
  if (e?.status === 403) {
    return 'Permission denied. Grant the "Key Vault Reader" role on the vault (Azure RBAC). That role is enough to list secret, certificate, and key metadata used for expiration inventory. Key Vault still supports legacy access policies; Azure RBAC is the recommended model.';
  }
  if (e?.status === 404) {
    return "Key Vault not found. Check the vault name and ensure it exists in your subscription.";
  }
  if (e?.status === 429) {
    return "Azure rate limit exceeded. Wait a moment and try again.";
  }
  if (
    e?.message?.includes("VaultNotFound") ||
    e?.message?.includes("ResourceNotFound")
  ) {
    return "Key Vault not found. Verify the vault URL and ensure you have access.";
  }
  if (e?.code === "ENOTFOUND" || e?.code === "ECONNREFUSED") {
    return "Cannot connect to Azure. Check your vault URL and network connectivity.";
  }
  if (e?.message) return e.message;
  return formatIntegrationError("Azure Key Vault", e, errorRef);
}

function azureAdUserMessage(e, errorRef, formatIntegrationError) {
  if (e?.azureTenantDiscovery) return e.message;
  if (e?.status === 400 || e?.graphError === "BadRequest") {
    if (e?.message?.includes("Invalid version")) {
      return `Microsoft Graph API version error. This should not happen - please report this. Reference: ${errorRef}`;
    }
    return `Invalid request: ${e?.message || "Bad Request"}. Ensure token is for Microsoft Graph API (resource: https://graph.microsoft.com).`;
  }
  if (e?.status === 401 || e?.graphError === "InvalidAuthenticationToken") {
    if (
      e?.azureErrorCode ||
      e?.correlationId ||
      /tenantId|clientId|Client secret|Azure authentication failed/i.test(
        e?.message || "",
      )
    ) {
      return e.message;
    }
    return "Authentication failed. Token may be expired (Azure CLI tokens expire quickly) or invalid. Clear cache: az account clear && az login, then regenerate.";
  }
  if (e?.status === 403 || e?.graphError === "Forbidden") {
    return "Permission denied. Grant the application permission Application.Read.All (recommended least privilege for listing applications) with admin consent. Directory.Read.All also works but is broader.";
  }
  if (e?.status === 404) {
    return "Microsoft Graph endpoint not found. Verify the token audience is correct.";
  }
  if (e?.status === 429 || e?.graphError === "TooManyRequests") {
    return "Microsoft Graph rate limit exceeded. Wait a moment and try again.";
  }
  if (e?.message?.includes("CompactToken") || e?.message?.includes("audience")) {
    return `Token audience mismatch: ${e?.message}. Token must be for https://graph.microsoft.com (not ARM or other resource).`;
  }
  if (e?.code === "ENOTFOUND" || e?.code === "ECONNREFUSED") {
    return "Cannot connect to Microsoft Graph API. Check your network connectivity.";
  }
  if (e?.message) return e.message;
  return formatIntegrationError("Azure AD", e, errorRef);
}

module.exports = {
  azureKeyVaultUserMessage,
  azureAdUserMessage,
};
