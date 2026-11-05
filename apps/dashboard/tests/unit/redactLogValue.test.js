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

  it.each(['object', 'array'])(
    'redacts %s content beyond the depth limit',
    kind => {
      const secret = {
        password: 'synthetic-deep-secret',
        detail: 'private payload',
      };
      let value = secret;
      for (let index = 0; index < 10; index += 1) {
        value = kind === 'array' ? [value] : { child: value };
      }

      const result = redactLogValue({ requestId: 'request-123', data: value });
      const serialized = JSON.stringify(result);
      expect(serialized).not.toContain('synthetic-deep-secret');
      expect(serialized).not.toContain('private payload');
      expect(serialized).toContain('[REDACTED]');
      expect(result.requestId).toBe('request-123');
      expect(secret.password).toBe('synthetic-deep-secret');
    }
  );

  it('bounds circular metadata without returning the original object', () => {
    const value = {
      requestId: 'request-123',
      password: 'synthetic-cycle-secret',
    };
    value.child = value;

    const result = redactLogValue(value);
    expect(() => JSON.stringify(result)).not.toThrow();
    expect(JSON.stringify(result)).not.toContain('synthetic-cycle-secret');
    expect(result.requestId).toBe('request-123');
  });
});
