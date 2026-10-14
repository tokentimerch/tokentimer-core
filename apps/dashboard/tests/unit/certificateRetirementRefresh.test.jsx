import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { useLoadedAssetMetrics } from '../../src/hooks/useLoadedAssetMetrics.js';
import { retireCertificateAndRefreshAssets } from '../../src/components/certops/certificateRetirement.js';

const certificate = {
  id: 'source-a',
  identityId: 'identity-a',
  fingerprintSha256: 'a'.repeat(64),
  tokenId: 7,
};

describe('dashboard token refresh after certificate retirement', () => {
  it('immediately renders the live sibling expiry and health without reloading the page or first-page pagination', async () => {
    const retire = vi.fn().mockResolvedValue({});
    const getToken = vi.fn().mockResolvedValue({
      id: 7,
      expiresAt: '2099-01-01',
      cert_lifecycle_status: 'active',
    });
    function Inventory() {
      const [tokens, setTokens] = useState([
        { id: 7, name: 'Shared asset', expiresAt: '2000-01-01' },
      ]);
      const metrics = useLoadedAssetMetrics(tokens);
      return (
        <>
          <output aria-label='expiry'>{tokens[0].expiresAt}</output>
          <output aria-label='healthy'>{metrics.healthy}</output>
          <button
            onClick={() =>
              retireCertificateAndRefreshAssets({
                workspaceId: 'ws-1',
                certificate,
                status: 'revoked',
                reason: 'Retired A',
                tokenId: 7,
                updateTokens: setTokens,
                retire,
                getToken,
              })
            }
          >
            Retire A
          </button>
        </>
      );
    }
    render(<Inventory />);
    expect(screen.getByLabelText('healthy')).toHaveTextContent('0');
    fireEvent.click(screen.getByRole('button', { name: 'Retire A' }));
    await waitFor(() =>
      expect(screen.getByLabelText('expiry')).toHaveTextContent('2099-01-01')
    );
    expect(screen.getByLabelText('healthy')).toHaveTextContent('1');
    expect(getToken).toHaveBeenCalledExactlyOnceWith(7);
    expect(retire).toHaveBeenCalledWith(
      'ws-1',
      'source-a',
      expect.objectContaining({
        identityId: 'identity-a',
        fingerprintSha256: certificate.fingerprintSha256,
      })
    );
  });

  it('refreshes each affected token once across same-fingerprint sources and leaves unrelated tokens alone', async () => {
    const getToken = vi.fn(async id => ({ id, expiresAt: '2099-01-01' })),
      refreshCertOps = vi.fn(),
      updateTokens = vi.fn();
    await retireCertificateAndRefreshAssets({
      workspaceId: 'ws-1',
      certificate,
      tokenId: 7,
      managedByTokenId: new Map([
        [7, [certificate, certificate]],
        [8, [{ ...certificate, id: 'source-copy' }]],
        [
          9,
          [
            {
              ...certificate,
              identityId: 'identity-b',
              fingerprintSha256: 'b'.repeat(64),
            },
          ],
        ],
      ]),
      retire: vi.fn().mockResolvedValue({}),
      getToken,
      refreshCertOps,
      updateTokens,
    });
    expect(getToken.mock.calls).toEqual([[7], [8]]);
    expect(refreshCertOps).toHaveBeenCalledOnce();
    expect(
      updateTokens.mock.calls[0][0]([{ id: 7 }, { id: 8 }, { id: 9 }])
    ).toEqual([
      { id: 7, expiresAt: '2099-01-01' },
      { id: 8, expiresAt: '2099-01-01' },
      { id: 9 },
    ]);
  });

  it('does not apply an old workspace response after switching workspaces', async () => {
    const updateTokens = vi.fn();
    await retireCertificateAndRefreshAssets({
      workspaceId: 'old',
      certificate,
      tokenId: 7,
      retire: vi.fn().mockResolvedValue({}),
      getToken: vi.fn().mockResolvedValue({ id: 7 }),
      updateTokens,
      isCurrentWorkspace: () => false,
    });
    expect(updateTokens).not.toHaveBeenCalled();
  });

  it('keeps retirement successful when token refresh fails and reports that details need reloading', async () => {
    const outcome = await retireCertificateAndRefreshAssets({
      workspaceId: 'ws-1',
      certificate,
      retire: vi.fn().mockResolvedValue({}),
      getToken: vi.fn().mockRejectedValue(new Error('offline')),
    });
    expect(outcome.refreshFailed).toBe(true);
  });

  it.each([
    { id: 8, workspaceId: 'ws-1' },
    { id: 7, workspaceId: 'other' },
  ])(
    'rejects token refresh data from a different identity or workspace',
    async row => {
      const updateTokens = vi.fn();
      const outcome = await retireCertificateAndRefreshAssets({
        workspaceId: 'ws-1',
        certificate,
        retire: vi.fn().mockResolvedValue({}),
        getToken: vi.fn().mockResolvedValue(row),
        updateTokens,
      });
      expect(outcome.refreshFailed).toBe(true);
      expect(updateTokens).not.toHaveBeenCalled();
    }
  );

  it('does not refresh or update token state after a stale fingerprint rejection', async () => {
    const getToken = vi.fn(),
      updateTokens = vi.fn(),
      refreshCertOps = vi.fn();
    await expect(
      retireCertificateAndRefreshAssets({
        workspaceId: 'ws-1',
        certificate,
        retire: vi.fn().mockRejectedValue(new Error('precondition failed')),
        getToken,
        updateTokens,
        refreshCertOps,
      })
    ).rejects.toThrow('precondition failed');
    expect(getToken).not.toHaveBeenCalled();
    expect(updateTokens).not.toHaveBeenCalled();
    expect(refreshCertOps).not.toHaveBeenCalled();
  });
});
