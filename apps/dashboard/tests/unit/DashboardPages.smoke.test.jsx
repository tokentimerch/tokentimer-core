import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { ChakraProvider } from '@chakra-ui/react';

import Workspaces from '../../src/pages/Workspaces.jsx';
import Usage from '../../src/pages/Usage.jsx';
import Audit from '../../src/pages/Audit.jsx';
import Account from '../../src/pages/Account.jsx';

const {
  apiGetMock,
  apiPostMock,
  apiDeleteMock,
  workspaceListMock,
  workspaceListMembersMock,
  workspaceCreateMock,
  alertGetAuditEventsMock,
  tokenGetTokensMock,
} = vi.hoisted(() => ({
  apiGetMock: vi.fn(),
  apiPostMock: vi.fn(),
  apiDeleteMock: vi.fn(),
  workspaceListMock: vi.fn(),
  workspaceListMembersMock: vi.fn(),
  workspaceCreateMock: vi.fn(),
  alertGetAuditEventsMock: vi.fn(),
  tokenGetTokensMock: vi.fn(),
}));

vi.mock('../../src/components/Navigation', () => ({
  default: () => <div>navigation</div>,
}));

vi.mock('../../src/components/SEO.jsx', () => ({
  default: () => null,
}));

vi.mock('../../src/components/TruncatedText', () => ({
  default: ({ text }) => <span>{text}</span>,
}));

vi.mock('../../src/utils/toast.js', () => ({
  showWarning: vi.fn(),
  showError: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({
    workspaceId: 'ws-1',
    selectWorkspace: vi.fn(),
  }),
}));

vi.mock('../../src/utils/analytics.js', () => ({
  trackEvent: vi.fn(),
}));

vi.mock('../../src/utils/logger.js', () => ({
  logger: {
    error: vi.fn(),
    warn: vi.fn(),
    info: vi.fn(),
    log: vi.fn(),
  },
}));

vi.mock('../../src/utils/apiClient', () => ({
  default: {
    get: apiGetMock,
    post: apiPostMock,
    delete: apiDeleteMock,
  },
  API_ENDPOINTS: {
    ACCOUNT_PLAN: '/api/account/plan',
    ALERT_QUEUE: '/api/alert-queue',
    ALERT_STATS: '/api/alert-stats',
  },
  workspaceAPI: {
    list: workspaceListMock,
    listMembers: workspaceListMembersMock,
    create: workspaceCreateMock,
    inviteMember: vi.fn(),
    changeRole: vi.fn(),
    removeMember: vi.fn(),
    remove: vi.fn(),
    transferTokens: vi.fn(),
    getAlertSettings: vi.fn(),
  },
  alertAPI: {
    getAuditEvents: alertGetAuditEventsMock,
    exportAudit: vi.fn(),
    requeueAlerts: vi.fn(),
  },
  tokenAPI: {
    getTokens: tokenGetTokensMock,
  },
  formatDate: d => String(d || ''),
}));

function renderWithProviders(ui) {
  return render(
    <ChakraProvider>
      <MemoryRouter>{ui}</MemoryRouter>
    </ChakraProvider>
  );
}

const baseProps = {
  session: {
    displayName: 'Test User',
    email: 'test@example.com',
    plan: 'oss',
    authMethod: 'local',
  },
  onLogout: vi.fn(),
  onAccountClick: vi.fn(),
  onNavigateToDashboard: vi.fn(),
  onNavigateToLanding: vi.fn(),
};

describe('Dashboard page smoke tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    workspaceListMock.mockResolvedValue({ items: [] });
    workspaceListMembersMock.mockResolvedValue({ items: [] });
    workspaceCreateMock.mockResolvedValue({ id: 'ws-2' });
    tokenGetTokensMock.mockResolvedValue({ items: [] });
    alertGetAuditEventsMock.mockResolvedValue([]);
    apiGetMock.mockResolvedValue({ data: { plan: 'oss', monthUsage: 0 } });
    apiPostMock.mockResolvedValue({ data: {} });
    apiDeleteMock.mockResolvedValue({ data: {} });
  });

  it('renders Workspaces route with mocked empty state', async () => {
    renderWithProviders(<Workspaces {...baseProps} />);
    await waitFor(() =>
      expect(screen.getByText('Workspaces')).toBeInTheDocument()
    );
    expect(workspaceListMock).toHaveBeenCalled();
  });

  it('renders Usage route and handles error state', async () => {
    apiGetMock.mockRejectedValueOnce(new Error('usage failed'));
    renderWithProviders(<Usage {...baseProps} />);

    await waitFor(() => expect(screen.getByText('Usage')).toBeInTheDocument());
    await waitFor(() =>
      expect(screen.getByText('Failed to load usage data')).toBeInTheDocument()
    );
  });

  it('renders Audit route with mocked data state', async () => {
    workspaceListMock.mockResolvedValue({
      items: [{ id: 'ws-1', name: 'Workspace', role: 'admin' }],
    });
    alertGetAuditEventsMock.mockResolvedValue([
      {
        id: 'ev-1',
        occurred_at: new Date().toISOString(),
        action: 'LOGIN_SUCCESS',
        actor_display_name: 'Test User',
        workspace_name: 'Workspace',
        metadata: {},
      },
    ]);
    renderWithProviders(<Audit {...baseProps} />);

    await waitFor(() =>
      expect(screen.getByText('Audit Log')).toBeInTheDocument()
    );
    await waitFor(() =>
      expect(screen.getByText('LOGIN_SUCCESS')).toBeInTheDocument()
    );
  });

  it('renders Account route fallback when session is missing', async () => {
    renderWithProviders(<Account session={null} onAccountDeleted={vi.fn()} />);
    expect(screen.getByText('Account Settings')).toBeInTheDocument();
    expect(
      screen.getByText('Session not found. Please log in again.')
    ).toBeInTheDocument();
  });
});
