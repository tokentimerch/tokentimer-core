import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';

const {
  useWorkspaceMock,
  useCertOpsEnabledMock,
  useCertOpsIsWorkspaceAdminMock,
  listTrustAnchorsMock,
  listTrustAnchorInstallationsMock,
} = vi.hoisted(() => ({
  useWorkspaceMock: vi.fn(),
  useCertOpsEnabledMock: vi.fn(),
  useCertOpsIsWorkspaceAdminMock: vi.fn(),
  listTrustAnchorsMock: vi.fn(),
  listTrustAnchorInstallationsMock: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: useWorkspaceMock,
}));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsEnabled: useCertOpsEnabledMock,
  useCertOpsIsWorkspaceAdmin: useCertOpsIsWorkspaceAdminMock,
}));

vi.mock('../../src/components/certops/certopsTrustAnchorsApi.js', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsTrustAnchorsApi.js'
  );
  return {
    ...actual,
    listTrustAnchors: listTrustAnchorsMock,
    listTrustAnchorInstallations: listTrustAnchorInstallationsMock,
  };
});

import {
  useCertOpsTrustAnchorInstallations,
  useCertOpsTrustAnchors,
} from '../../src/components/certops/useCertOpsTrustAnchors.js';

describe('useCertOpsTrustAnchors', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
    useCertOpsEnabledMock.mockReturnValue(true);
    useCertOpsIsWorkspaceAdminMock.mockReturnValue(true);
  });

  it('loads anchors for an admin viewer', async () => {
    listTrustAnchorsMock.mockResolvedValue({
      items: [{ id: 'anchor-1', name: 'Root CA' }],
    });

    const { result } = renderHook(() => useCertOpsTrustAnchors());

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.anchors).toEqual([
      { id: 'anchor-1', name: 'Root CA' },
    ]);
    expect(listTrustAnchorsMock).toHaveBeenCalledWith(
      'ws-1',
      expect.objectContaining({ signal: expect.anything() })
    );
  });

  it('does not fetch and returns an empty list for a non-admin viewer', () => {
    useCertOpsIsWorkspaceAdminMock.mockReturnValue(false);

    const { result } = renderHook(() => useCertOpsTrustAnchors());

    expect(listTrustAnchorsMock).not.toHaveBeenCalled();
    expect(result.current.anchors).toEqual([]);
    expect(result.current.isAdmin).toBe(false);
  });

  it('does not fetch while CertOps is disabled', () => {
    useCertOpsEnabledMock.mockReturnValue(false);

    renderHook(() => useCertOpsTrustAnchors());

    expect(listTrustAnchorsMock).not.toHaveBeenCalled();
  });

  it('surfaces a load failure as an error, with an empty anchor list', async () => {
    listTrustAnchorsMock.mockRejectedValue({
      response: { data: { error: 'Internal error' } },
    });

    const { result } = renderHook(() => useCertOpsTrustAnchors());

    await waitFor(() => expect(result.current.error).toBe('Internal error'));
    expect(result.current.anchors).toEqual([]);
  });

  it('refetches when refresh() is called', async () => {
    listTrustAnchorsMock.mockResolvedValue({ items: [] });
    const { result } = renderHook(() => useCertOpsTrustAnchors());
    await waitFor(() => expect(result.current.loading).toBe(false));

    result.current.refresh();

    await waitFor(() =>
      expect(listTrustAnchorsMock).toHaveBeenCalledTimes(2)
    );
  });
});

describe('useCertOpsTrustAnchorInstallations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
  });

  it('loads installations for a given anchor id', async () => {
    listTrustAnchorInstallationsMock.mockResolvedValue({
      items: [{ id: 'install-1', owner: 'team-a' }],
    });

    const { result } = renderHook(() =>
      useCertOpsTrustAnchorInstallations('anchor-1')
    );

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.installations).toEqual([
      { id: 'install-1', owner: 'team-a' },
    ]);
    expect(listTrustAnchorInstallationsMock).toHaveBeenCalledWith(
      'ws-1',
      'anchor-1',
      expect.objectContaining({ signal: expect.anything() })
    );
  });

  it('skips the fetch and clears state when anchorId is null (row collapsed)', () => {
    const { result } = renderHook(() =>
      useCertOpsTrustAnchorInstallations(null)
    );

    expect(listTrustAnchorInstallationsMock).not.toHaveBeenCalled();
    expect(result.current.installations).toEqual([]);
  });

  it('surfaces a load failure as an error', async () => {
    listTrustAnchorInstallationsMock.mockRejectedValue({
      response: { data: { error: 'Anchor not found' } },
    });

    const { result } = renderHook(() =>
      useCertOpsTrustAnchorInstallations('anchor-1')
    );

    await waitFor(() =>
      expect(result.current.error).toBe('Anchor not found')
    );
    expect(result.current.installations).toEqual([]);
  });
});
