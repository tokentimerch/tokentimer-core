import { describe, it, expect } from 'vitest';
import {
  azureReplacementAuthError,
  azureVaultUrlLocked,
} from '../../src/components/imports/azureInventoryAuth.js';

describe('azure inventory manage-mode helpers', () => {
  it('locks the vault URL except while replacing credentials', () => {
    expect(azureVaultUrlLocked(true, false)).toBe(true);
    expect(azureVaultUrlLocked(true, true)).toBe(false);
    expect(azureVaultUrlLocked(false, false)).toBe(false);
  });

  it('requires a complete replacement payload before Save', () => {
    expect(
      azureReplacementAuthError({
        replacing: false,
        requireVaultUrl: true,
        vaultUrl: '',
        authMethod: 'token',
        token: '',
      })
    ).toBeNull();
    expect(
      azureReplacementAuthError({
        replacing: true,
        requireVaultUrl: true,
        vaultUrl: 'https://v.vault.azure.net',
        authMethod: 'token',
        token: '',
      })
    ).toBe('Access token is required');
    expect(
      azureReplacementAuthError({
        replacing: true,
        requireVaultUrl: true,
        vaultUrl: 'https://v.vault.azure.net',
        authMethod: 'client_credentials',
        tenantId: 'tid',
        clientId: 'cid',
        clientSecret: '',
      })
    ).toBe('Client secret is required');
  });
});
