import { renderHook } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { useLoadedAssetMetrics } from '../../src/hooks/useLoadedAssetMetrics.js';

describe('retired inventory metrics', () => {
  it('keeps retired records in inventory totals while excluding them from health and expiry counts', () => {
    const { result } = renderHook(() =>
      useLoadedAssetMetrics([
        { id: 1, cert_lifecycle_status: 'revoked', expiresAt: '2000-01-01' },
        {
          id: 2,
          cert_lifecycle_status: 'decommissioned',
          expiresAt: '2099-01-01',
        },
        { id: 3, __managedCertificatesRetired: true, expiresAt: '2099-01-01' },
        {
          id: 4,
          __managedCert: { lifecycleStatus: 'revoked' },
          expiresAt: '2000-01-01',
        },
        { id: 5, cert_lifecycle_status: 'active', expiresAt: '2099-01-01' },
      ])
    );
    expect(result.current).toMatchObject({
      total: 5,
      loaded: 5,
      healthy: 1,
      expired: 0,
      critical: 0,
      dueSoon: 0,
    });
  });
});
