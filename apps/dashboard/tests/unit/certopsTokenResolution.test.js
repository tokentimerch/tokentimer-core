import { describe, it, expect, vi, beforeEach } from 'vitest';

const { get } = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock('../../src/utils/apiClient', () => ({ default: { get } }));
import {
  getManagedCertificateForToken,
  getManagedCertificatesForToken,
  invalidateCertOpsInventoryCache,
} from '../../src/components/certops/certopsApi';

describe('token-linked inventory API resolution', () => {
  beforeEach(() => {
    invalidateCertOpsInventoryCache();
    get.mockReset();
  });

  it('retains all linked sources but refuses an automatic cross-fingerprint target', async () => {
    const items = [
      {
        id: 'a',
        tokenId: 1,
        fingerprintSha256: 'a'.repeat(64),
        status: 'revoked',
      },
      {
        id: 'b',
        tokenId: 1,
        fingerprintSha256: 'b'.repeat(64),
        status: 'active',
      },
    ];
    get.mockResolvedValue({ data: { items } });
    expect(await getManagedCertificateForToken('ws', 1)).toBeNull();
    expect(await getManagedCertificatesForToken('ws', 1)).toEqual(items);
    expect(get).toHaveBeenCalledOnce();
  });

  it('resolves equivalent fingerprints across source records and leaves unlinked tokens empty', async () => {
    const a = {
      id: 'import',
      tokenId: 1,
      fingerprintSha256: 'a'.repeat(64),
      updatedAt: '2026-01-01',
    };
    const b = {
      id: 'agent',
      tokenId: 1,
      fingerprintSha256: 'AA:'.repeat(31) + 'AA',
      updatedAt: '2026-02-01',
    };
    get.mockResolvedValue({ data: { items: [a, b] } });
    expect(await getManagedCertificateForToken('ws', 1)).toEqual(b);
    expect(await getManagedCertificateForToken('ws', 2)).toBeNull();
  });
});
