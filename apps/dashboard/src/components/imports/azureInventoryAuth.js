export function buildAzureInventoryCredentials({
  vaultUrl,
  authMethod,
  token,
  tenantId,
  clientId,
  clientSecret,
}) {
  if (authMethod === 'client_credentials') {
    const creds = {
      authMethod: 'client_credentials',
      tenantId: String(tenantId || '').trim(),
      clientId: String(clientId || '').trim(),
      clientSecret: String(clientSecret || '').trim(),
    };
    if (vaultUrl !== undefined) creds.vaultUrl = String(vaultUrl || '').trim();
    return creds;
  }
  const creds = { token: String(token || '').trim() };
  if (vaultUrl !== undefined) creds.vaultUrl = String(vaultUrl || '').trim();
  return creds;
}

export function azureInventoryCredentialsHaveSecrets(credentials) {
  if (!credentials || typeof credentials !== 'object') return false;
  if (credentials.authMethod === 'client_credentials') {
    return Boolean(String(credentials.clientSecret || '').trim());
  }
  return Boolean(String(credentials.token || '').trim());
}

export function azureInventoryScanAuthPayload(credentials) {
  if (!credentials || typeof credentials !== 'object') return {};
  if (credentials.authMethod === 'client_credentials') {
    return {
      authMethod: 'client_credentials',
      tenantId: credentials.tenantId,
      clientId: credentials.clientId,
      clientSecret: credentials.clientSecret,
    };
  }
  return { token: credentials.token };
}

export function validateAzureInventoryAuth({
  authMethod,
  token,
  tenantId,
  clientId,
  clientSecret,
  requireVaultUrl,
  vaultUrl,
}) {
  if (requireVaultUrl && !String(vaultUrl || '').trim()) {
    return 'Azure Key Vault URL is required';
  }
  if (authMethod === 'client_credentials') {
    if (!String(tenantId || '').trim()) return 'Tenant ID is required';
    if (!String(clientId || '').trim())
      return 'Application (client) ID is required';
    if (!String(clientSecret || '').trim()) return 'Client secret is required';
    return null;
  }
  if (!String(token || '').trim()) return 'Access token is required';
  return null;
}
