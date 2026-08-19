import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';

const {
  useWorkspaceMock,
  probeCertOpsEnabledMock,
  getCachedCertOpsEnabledMock,
  getJobMock,
  listJobLogMock,
  listJobEvidenceMock,
} = vi.hoisted(() => ({
  useWorkspaceMock: vi.fn(),
  probeCertOpsEnabledMock: vi.fn(),
  getCachedCertOpsEnabledMock: vi.fn().mockReturnValue(null),
  getJobMock: vi.fn(),
  listJobLogMock: vi.fn(),
  listJobEvidenceMock: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: useWorkspaceMock,
}));

vi.mock('../../src/utils/apiClient', () => ({
  workspaceAPI: { get: vi.fn().mockResolvedValue({ role: 'admin' }) },
}));

vi.mock('../../src/components/certops/certopsApi', () => ({
  probeCertOpsEnabled: probeCertOpsEnabledMock,
  getCachedCertOpsEnabled: getCachedCertOpsEnabledMock,
  getCertificateInstances: vi.fn(),
  getManagedCertificatesForToken: vi.fn(),
  getWorkspaceCertOpsPauseState: vi.fn(),
  invalidateCertOpsInventoryCache: vi.fn(),
  loadCertOpsInventoryIndex: vi.fn(),
  updateWorkspaceCertOpsPauseState: vi.fn(),
}));

vi.mock('../../src/components/certops/certopsJobsApi', () => ({
  getJob: getJobMock,
  listJobLog: listJobLogMock,
  listJobEvidence: listJobEvidenceMock,
  listJobs: vi.fn(),
}));

vi.mock('../../src/components/certops/certopsTokensApi', () => ({
  listApiTokens: vi.fn(),
}));

import { useCertOpsJobTimeline } from '../../src/components/certops/useCertOpsJobs.js';

function mockTimelineData() {
  getJobMock.mockResolvedValue({ job: { id: 'job-1', status: 'succeeded' } });
  listJobLogMock.mockResolvedValue({ items: [], pagination: null });
  listJobEvidenceMock.mockResolvedValue({ items: [], pagination: null });
}

describe('useCertOpsJobTimeline availability resolution', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
    getCachedCertOpsEnabledMock.mockReturnValue(null);
  });

  it('loads the timeline once availability resolves enabled', async () => {
    probeCertOpsEnabledMock.mockResolvedValue({ enabled: true });
    mockTimelineData();

    const { result } = renderHook(() => useCertOpsJobTimeline('job-1'));

    expect(result.current.loading).toBe(true);
    await waitFor(() => expect(result.current.job?.id).toBe('job-1'));
    expect(result.current.loading).toBe(false);
    expect(result.current.error).toBe('');
  });

  it('stays loading (not "not found") while the availability probe is unresolved', async () => {
    let resolveProbe;
    probeCertOpsEnabledMock.mockImplementation(
      () =>
        new Promise(resolve => {
          resolveProbe = resolve;
        })
    );
    mockTimelineData();

    const { result } = renderHook(() => useCertOpsJobTimeline('job-1'));

    expect(result.current.loading).toBe(true);
    expect(result.current.error).toBe('');
    expect(getJobMock).not.toHaveBeenCalled();

    await act(async () => {
      resolveProbe({ enabled: true });
    });
    await waitFor(() => expect(result.current.job?.id).toBe('job-1'));
  });

  it('surfaces a failed availability probe as an error instead of an indefinite spinner', async () => {
    probeCertOpsEnabledMock.mockRejectedValue(
      Object.assign(new Error('network down'), {
        response: { status: 500, data: { error: 'Internal error' } },
      })
    );

    const { result } = renderHook(() => useCertOpsJobTimeline('job-1'));

    await waitFor(() => expect(result.current.error).toBe('Internal error'));
    expect(result.current.loading).toBe(false);
    expect(result.current.job).toBe(null);
    expect(getJobMock).not.toHaveBeenCalled();
  });

  it('refresh() re-probes availability and recovers from a failed probe', async () => {
    probeCertOpsEnabledMock.mockRejectedValueOnce(
      Object.assign(new Error('network down'), {
        response: { status: 503, data: { error: 'Service unavailable' } },
      })
    );
    mockTimelineData();

    const { result } = renderHook(() => useCertOpsJobTimeline('job-1'));

    await waitFor(() =>
      expect(result.current.error).toBe('Service unavailable')
    );

    probeCertOpsEnabledMock.mockResolvedValue({ enabled: true });
    act(() => {
      result.current.refresh();
    });

    await waitFor(() => expect(result.current.job?.id).toBe('job-1'));
    expect(result.current.error).toBe('');
    expect(result.current.loading).toBe(false);
  });

  it('an externalRefreshToken change re-probes availability like refresh()', async () => {
    probeCertOpsEnabledMock.mockRejectedValueOnce(
      Object.assign(new Error('network down'), {
        response: { status: 503, data: { error: 'Service unavailable' } },
      })
    );
    mockTimelineData();

    const { result, rerender } = renderHook(
      ({ token }) => useCertOpsJobTimeline('job-1', token),
      { initialProps: { token: 0 } }
    );

    await waitFor(() =>
      expect(result.current.error).toBe('Service unavailable')
    );

    probeCertOpsEnabledMock.mockResolvedValue({ enabled: true });
    rerender({ token: 1 });

    await waitFor(() => expect(result.current.job?.id).toBe('job-1'));
    expect(result.current.error).toBe('');
  });

  it('clears the timeline without an error when CertOps is disabled', async () => {
    probeCertOpsEnabledMock.mockResolvedValue({ enabled: false });

    const { result } = renderHook(() => useCertOpsJobTimeline('job-1'));

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.job).toBe(null);
    expect(result.current.error).toBe('');
    expect(getJobMock).not.toHaveBeenCalled();
  });
});
