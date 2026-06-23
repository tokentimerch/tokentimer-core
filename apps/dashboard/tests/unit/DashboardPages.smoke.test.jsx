import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { ChakraProvider } from '@chakra-ui/react';

import Workspaces from '../../src/pages/Workspaces.jsx';
import Audit from '../../src/pages/Audit.jsx';
import Account from '../../src/pages/Account.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

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

vi.mock('../../src/hooks/useDashboardShellProps.js', () => ({
  useDashboardShellProps: ({ pageTitle = '' } = {}) => ({
    dashboardColors: {},
    currentPath: '/',
    sessionName: 'Test User',
    sessionEmail: 'test@example.com',
    sessionInitials: 'TU',
    dashboardWorkspaces: [],
    dashboardWorkspace: null,
    workspaceLabel: 'Workspace',
    onWorkspaceSelect: vi.fn(),
    dashboardNotifications: [],
    onLogout: vi.fn(),
    onAccountClick: vi.fn(),
    isViewer: false,
    dashboardCanSeeManagerNav: true,
    isSystemAdmin: false,
    pageTitle,
  }),
}));

vi.mock('../../src/components/DashboardShell', () => ({
  default: ({ children, pageTitle }) => (
    <div>
      {pageTitle ? <h1>{pageTitle}</h1> : null}
      {children}
    </div>
  ),
}));

vi.mock('../../src/components/DashboardPageLayout', () => ({
  default: ({ children, pageTitle }) => (
    <div>
      {pageTitle ? <h1>{pageTitle}</h1> : null}
      {children}
    </div>
  ),
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
      <DashboardThemeProvider>
        <MemoryRouter>{ui}</MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

function expectTextPresent(text) {
  expect(screen.getAllByText(text).length).toBeGreaterThan(0);
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
    await waitFor(() => expectTextPresent('Workspaces'));
    expect(workspaceListMock).toHaveBeenCalled();
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

    await waitFor(() => expectTextPresent('Audit events'));
    await waitFor(() => expectTextPresent('LOGIN_SUCCESS'));
  });

  it('renders SSO audit metadata in Audit route', async () => {
    workspaceListMock.mockResolvedValue({
      items: [{ id: 'ws-1', name: 'Workspace', role: 'admin' }],
    });
    alertGetAuditEventsMock.mockResolvedValue([
      {
        id: 'ev-sso-1',
        occurred_at: new Date().toISOString(),
        action: 'LOGIN_SUCCESS',
        actor_display_name: 'Test User',
        workspace_name: 'Workspace',
        metadata: {
          method: 'saml',
          provider_slug: 'entra',
          protocol: 'saml',
          idp_groups_seen: 2,
          idp_groups_sample: ['TokenTimer-Admins', 'TokenTimer-Users'],
          matched_groups: ['TokenTimer-Admins'],
          is_admin_resolved: true,
          is_admin_after_login: true,
          admin_granted: true,
          workspace_grants_count: 3,
          workspace_revocations_count: 0,
        },
      },
    ]);

    renderWithProviders(<Audit {...baseProps} />);

    await waitFor(() => expectTextPresent(/Provider: entra/));
    expectTextPresent(/Observed groups:/);
    expectTextPresent(/System admin after login: yes/);
  });

  it('shows organization scope for system admins on Audit route', async () => {
    workspaceListMock.mockResolvedValue({
      items: [{ id: 'ws-1', name: 'Workspace', role: 'viewer' }],
    });
    alertGetAuditEventsMock.mockResolvedValue([]);

    renderWithProviders(
      <Audit
        {...baseProps}
        session={{
          ...baseProps.session,
          isAdmin: true,
        }}
      />
    );

    await waitFor(() => expectTextPresent('Audit events'));
    expect(
      screen.getByRole('option', { name: 'Organization (admin)' })
    ).toBeInTheDocument();
  });

  it('renders Account route fallback when session is missing', () => {
    renderWithProviders(<Account session={null} onAccountDeleted={vi.fn()} />);
    expectTextPresent('Account Settings');
    expect(
      screen.getByText('Session not found. Please log in again.')
    ).toBeInTheDocument();
  });
});
