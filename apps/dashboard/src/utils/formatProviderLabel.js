const PROVIDER_LABELS = {
  github: 'GitHub',
  gitlab: 'GitLab',
  aws: 'AWS',
  azure: 'Azure KV',
  'azure-ad': 'Azure AD',
  gcp: 'GCP',
  vault: 'HashiCorp Vault',
};

export function formatProviderLabel(provider) {
  if (!provider) return 'Unknown';
  const key = String(provider);
  if (PROVIDER_LABELS[key]) return PROVIDER_LABELS[key];
  return key
    .split(/[-_]/g)
    .filter(Boolean)
    .map(part => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}
