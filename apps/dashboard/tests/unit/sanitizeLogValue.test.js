import { describe, it, expect } from 'vitest';
import { sanitizeLogValue } from '../../src/utils/sanitizeLogValue.js';

describe('sanitizeLogValue', () => {
  it('redacts nested clientSecret and token keys', () => {
    const out = sanitizeLogValue({
      vaultUrl: 'https://v.vault.azure.net',
      tenantId: 'tid',
      clientSecret: 'leaked-secret',
      nested: { token: 'leaked-token', count: 2 },
    });
    expect(out.clientSecret).toBe('[REDACTED]');
    expect(out.nested.token).toBe('[REDACTED]');
    expect(out.nested.count).toBe(2);
    expect(out.vaultUrl).toBe('https://v.vault.azure.net');
    expect(out.tenantId).toBe('tid');
  });

  it('redacts nested objects past depth 6 instead of returning them raw', () => {
    const nested = { secret: 'leaked' };
    let value = nested;
    for (let i = 0; i < 7; i += 1) {
      value = { child: value };
    }
    const out = sanitizeLogValue(value);
    let cursor = out;
    while (cursor && typeof cursor === 'object') {
      cursor = cursor.child;
    }
    expect(cursor).toBe('[REDACTED]');
  });
});
