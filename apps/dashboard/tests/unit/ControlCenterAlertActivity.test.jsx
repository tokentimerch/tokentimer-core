import { render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it, vi } from 'vitest';
import ControlCenter from '../../src/pages/ControlCenter.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const { loadMoreMock } = vi.hoisted(() => ({
  loadMoreMock: vi.fn(),
}));

vi.mock('../../src/components/DashboardShell', () => ({
  default: ({ children }) => <div>{children}</div>,
}));

vi.mock('../../src/components/SEO.jsx', () => ({ default: () => null }));

vi.mock('../../src/hooks/useControlCenterStats', () => ({
  useControlCenterStats: () => ({
    data: {
      totalAssets: 1,
      buckets: { healthy: 1 },
      sources: [],
      needsAttention: [],
      neverExpires: [],
      neverExpiresHasMore: false,
      privilegeHighlights: [],
      privilegeHighlightsTotal: 0,
      privilegeHighlightsHasMore: false,
      autoSync: [],
    },
    isLoading: false,
    isRefreshing: false,
    isError: false,
    isPartial: false,
    error: '',
    refetch: vi.fn(),
  }),
  useControlCenterListPage: () => ({
    items: [],
    hasMore: false,
    isLoadingMore: false,
    loadMore: vi.fn(),
  }),
}));

vi.mock('../../src/hooks/useControlCenterData', () => ({
  useControlCenterData: () => ({
    loading: false,
    refreshing: false,
    error: '',
    unauthorized: false,
    partial: false,
    noEligibleAccess: false,
    queue: [],
    eligibilityAssets: [],
    eligibilitySummary: {
      outside_threshold: 1,
      due: 0,
      suppressed: 0,
    },
    stats: { byChannel: [], monthUsage: 0, allMonthSuccesses: 0 },
    orgStats: { monthUsage: 0 },
    orgWorkspaceCount: 1,
    orgTokenCount: 1,
    workspaceMemberCount: 1,
    workspaces: [{ id: 'workspace-1', name: 'Workspace', role: 'admin' }],
    selectedWorkspaceId: 'workspace-1',
    setSelectedWorkspaceId: vi.fn(),
    isAdminAny: true,
    hasManagerOrViewerRole: true,
    planInfo: { plan: 'oss', alertLimitMonth: 0, memberCount: 1 },
    workspaceTokenCount: 1,
    retryHintDate: null,
    eligibleWorkspaces: [
      { id: 'workspace-1', name: 'Workspace', role: 'admin' },
    ],
    queueSummary: {},
    canRequeue: true,
    requeueDisabledReason: '',
    requeueAlerts: vi.fn(),
    refresh: vi.fn(),
    alertActivity: [
      {
        id: 'delivery:1',
        type: 'delivery_failed',
        occurred_at: new Date().toISOString(),
        token_id: 17,
        token_name: 'Production key',
        workspace_id: 'workspace-1',
        alert_id: 9,
        threshold_days: 7,
        channel: 'email',
        status: 'failed',
        reason: 'delivery_error',
        error_message: 'SMTP timeout',
        metadata: {},
        source: 'alert_delivery_log',
      },
    ],
    alertActivityLoading: false,
    alertActivityLoadingMore: false,
    alertActivityError: '',
    alertActivityHasMore: true,
    loadMoreAlertActivity: loadMoreMock,
  }),
}));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsAvailability: () => ({ ready: true, enabled: false }),
  useWorkspaceCertOps: () => ({ items: [], loading: false }),
}));

describe('Control Center recent alert activity', () => {
  it('renders dedicated workspace events with an asset deep link', () => {
    render(
      <ChakraProvider>
        <DashboardThemeProvider>
          <MemoryRouter>
            <ControlCenter
              session={{ displayName: 'Admin', email: 'admin@example.test' }}
              onLogout={vi.fn()}
              onAccountClick={vi.fn()}
            />
          </MemoryRouter>
        </DashboardThemeProvider>
      </ChakraProvider>
    );

    expect(screen.getByText('Recent alert activity')).toBeInTheDocument();
    expect(screen.getByText('Delivery failed')).toBeInTheDocument();
    expect(screen.getByText('SMTP timeout')).toBeInTheDocument();
    expect(
      screen.getByRole('link', { name: 'Production key' })
    ).toHaveAttribute('href', '/dashboard?workspace=workspace-1&token-id=17');
  });
});
