import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { ChakraProvider } from '@chakra-ui/react';

import CertOpsOperations from '../../src/pages/certops/CertOpsOperations.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const {
  useCertOpsAvailabilityMock,
  useCertOpsJobsMock,
  useCertOpsCanManageMock,
  useCertOpsApiTokensMock,
} = vi.hoisted(() => ({
  useCertOpsAvailabilityMock: vi.fn(),
  useCertOpsJobsMock: vi.fn(),
  useCertOpsCanManageMock: vi.fn(),
  useCertOpsApiTokensMock: vi.fn(),
}));

vi.mock('../../src/hooks/useDashboardShellProps.js', () => ({
  useDashboardShellProps: ({ pageTitle = '' } = {}) => ({
    dashboardColors: {},
    currentPath: '/certops/operations',
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

vi.mock('../../src/components/SEO.jsx', () => ({
  default: () => null,
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({
    workspaceId: 'ws-1',
    selectWorkspace: vi.fn(),
  }),
}));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsAvailability: useCertOpsAvailabilityMock,
  useCertOpsCanManage: useCertOpsCanManageMock,
}));

vi.mock('../../src/components/certops/useCertOpsJobs.js', () => ({
  useCertOpsJobs: useCertOpsJobsMock,
  useCertOpsApiTokens: useCertOpsApiTokensMock,
  useCertOpsJobTimeline: () => ({
    job: null,
    logEntries: [],
    evidence: [],
    loading: false,
    error: '',
  }),
}));

function renderWithProviders(ui) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter initialEntries={['/certops/operations']}>
          {ui}
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

function jobsState(overrides = {}) {
  return {
    enabled: true,
    jobs: [],
    pagination: null,
    loading: false,
    error: '',
    refresh: vi.fn(),
    ...overrides,
  };
}

describe('CertOpsOperations', () => {
  beforeEach(() => {
    useCertOpsAvailabilityMock.mockReset();
    useCertOpsJobsMock.mockReset();
    useCertOpsCanManageMock.mockReset();
    useCertOpsApiTokensMock.mockReset();
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsApiTokensMock.mockReturnValue({
      enabled: true,
      tokens: [],
      loading: false,
      error: '',
      refresh: vi.fn(),
    });
  });

  it('shows a checking-availability state while resolving', () => {
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: false,
      enabled: null,
      error: null,
    });
    useCertOpsJobsMock.mockReturnValue(jobsState());

    renderWithProviders(<CertOpsOperations session={{ isAdmin: true }} />);

    expect(
      screen.getByText('Checking certificate operations availability...')
    ).toBeInTheDocument();
  });

  it('shows a disabled state distinct from the ready/enabled state', () => {
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: true,
      enabled: false,
      error: null,
    });
    useCertOpsJobsMock.mockReturnValue(jobsState());

    renderWithProviders(<CertOpsOperations session={{ isAdmin: true }} />);

    expect(
      screen.getByText('Certificate operations is not enabled')
    ).toBeInTheDocument();
    expect(
      screen.queryByText('Machine executor jobs')
    ).not.toBeInTheDocument();
  });

  it('renders the executor jobs panel and token panel when enabled', () => {
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: true,
      enabled: true,
      error: null,
    });
    useCertOpsJobsMock.mockReturnValue(jobsState());

    renderWithProviders(<CertOpsOperations session={{ isAdmin: true }} />);

    expect(screen.getByText('Machine executor jobs')).toBeInTheDocument();
    expect(screen.getByText('Machine API tokens')).toBeInTheDocument();
  });

  it('shows a loading state for the jobs panel distinct from the empty state', () => {
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: true,
      enabled: true,
      error: null,
    });
    useCertOpsJobsMock.mockReturnValue(jobsState({ loading: true }));

    renderWithProviders(<CertOpsOperations session={{ isAdmin: true }} />);

    expect(screen.getByText('Loading executor jobs...')).toBeInTheDocument();
    expect(
      screen.queryByText('No executor-reported certificate jobs yet')
    ).not.toBeInTheDocument();
  });

  it('shows an empty jobs state when there are no jobs', () => {
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: true,
      enabled: true,
      error: null,
    });
    useCertOpsJobsMock.mockReturnValue(jobsState());

    renderWithProviders(<CertOpsOperations session={{ isAdmin: true }} />);

    expect(
      screen.getByText('No executor-reported certificate jobs yet')
    ).toBeInTheDocument();
  });

  it('shows a jobs error message distinct from the loading/empty states', () => {
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: true,
      enabled: true,
      error: null,
    });
    useCertOpsJobsMock.mockReturnValue(
      jobsState({ error: 'Could not load certificate operations jobs.' })
    );

    renderWithProviders(<CertOpsOperations session={{ isAdmin: true }} />);

    expect(
      screen.getByText('Could not load certificate operations jobs.')
    ).toBeInTheDocument();
  });

  it('lists jobs and expands a row to reveal its evidence timeline on click', () => {
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: true,
      enabled: true,
      error: null,
    });
    useCertOpsJobsMock.mockReturnValue(
      jobsState({
        jobs: [
          {
            id: 'job-1',
            operation: 'renew',
            status: 'succeeded',
            source: 'scheduler',
            createdAt: '2026-01-01T00:00:00.000Z',
          },
        ],
      })
    );

    renderWithProviders(<CertOpsOperations session={{ isAdmin: true }} />);

    const row = screen.getByRole('button', { name: /Renew/i });
    expect(row).toHaveAttribute('aria-expanded', 'false');

    fireEvent.click(row);
    expect(row).toHaveAttribute('aria-expanded', 'true');
  });
});
