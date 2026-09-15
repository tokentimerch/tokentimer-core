import { describe, expect, it } from 'vitest';
import { redactLogValue } from '../../src/utils/logger.js';

describe('redactLogValue', () => {
  it('redacts nested AppRole credentials without dropping sibling fields', () => {
    expect(
      redactLogValue({
        address: 'https://vault.example',
        credentials: {
          roleId: 'role-uuid',
          secretId: 'secret-uuid',
          token: 's.abc',
        },
        mounts: ['secret/'],
      })
    ).toEqual({
      address: 'https://vault.example',
      credentials: '[REDACTED]',
      mounts: ['secret/'],
    });
  });

  it('redacts roleId and secretId keys at any depth', () => {
    expect(
      redactLogValue({
        data: { roleId: 'r', secretId: 's', namespace: 'ops' },
      })
    ).toEqual({
      data: { roleId: '[REDACTED]', secretId: '[REDACTED]', namespace: 'ops' },
    });
  });
});
