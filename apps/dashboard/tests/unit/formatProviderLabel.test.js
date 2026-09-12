import { describe, it, expect } from 'vitest';
import { formatProviderLabel } from '../../src/utils/formatProviderLabel.js';

describe('formatProviderLabel', () => {
  it('returns the import-modal name for each auto-sync provider', () => {
    expect(formatProviderLabel('github')).toBe('GitHub');
    expect(formatProviderLabel('gitlab')).toBe('GitLab');
    expect(formatProviderLabel('aws')).toBe('AWS');
    expect(formatProviderLabel('azure')).toBe('Azure KV');
    expect(formatProviderLabel('azure-ad')).toBe('Azure AD');
    expect(formatProviderLabel('gcp')).toBe('GCP');
    expect(formatProviderLabel('vault')).toBe('HashiCorp Vault');
  });

  it('does not drop the title when the provider slug has no hyphen', () => {
    expect(formatProviderLabel('github')).not.toBe('');
  });

  it('falls back to Unknown or title-case for empty and unknown slugs', () => {
    expect(formatProviderLabel('')).toBe('Unknown');
    expect(formatProviderLabel(null)).toBe('Unknown');
    expect(formatProviderLabel('custom-provider')).toBe('Custom Provider');
  });
});
