import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import CertOpsRoutes from '../../src/pages/certops/CertOpsRoutes.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const { useCertOpsAvailabilityMock, useCertOpsWorkspaceKillSwitchMock } =
  vi.hoisted(() => ({
    useCertOpsAvailabilityMock: vi.fn(),
    useCertOpsWorkspaceKillSwitchMock: vi.fn(),
  }));

vi.mock('../../src/hooks/useDashboardShellProps.js', () => ({
  useDashboardShellProps: ({ pageTitle = '' } = {}) => ({ pageTitle }),
}));

vi.mock('../../src/components/DashboardShell', () => ({
  default: ({ children }) => <div>{children}</div>,
}));

vi.mock('../../src/components/SEO.jsx', () => ({ default: () => null }));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: 'ws-1', selectWorkspace: vi.fn() }),
}));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsAvailability: useCertOpsAvailabilityMock,
  useCertOpsEnabled: () => true,
  useCertOpsIsWorkspaceAdmin: () => true,
  useCertOpsCanManage: () => false,
  useCertOpsWorkspaceKillSwitch: useCertOpsWorkspaceKillSwitchMock,
}));

// The panels have their own unit tests. Here they are stand-ins so a tab can
// be identified by what it mounts, which is the whole point of the split.
vi.mock('../../src/pages/certops/CertOpsCertificates.jsx', () => ({
  default: () => <div>Certificates tab</div>,
}));
vi.mock('../../src/components/certops/ExecutorJobsPanel.jsx', () => ({
  default: ({ certOpsPaused }) => (
    <div data-paused={String(Boolean(certOpsPaused))}>
      Machine executor jobs
    </div>
  ),
}));
vi.mock('../../src/components/certops/AgentFleetPanel.jsx', () => ({
  default: () => <div>Agent fleet</div>,
}));
vi.mock('../../src/components/certops/BootstrapTokenList.jsx', () => ({
  default: () => <div>Bootstrap tokens</div>,
}));
vi.mock('../../src/components/certops/DeployAgentModal.jsx', () => ({
  default: ({ isOpen, certOpsPaused }) =>
    isOpen ? (
      <div data-paused={String(Boolean(certOpsPaused))}>
        Deploy agent modal
      </div>
    ) : null,
}));
vi.mock('../../src/components/certops/ApiTokenList.jsx', () => ({
  default: () => <div>API token list</div>,
}));
vi.mock('../../src/components/certops/ApiTokenModal.jsx', () => ({
  default: ({ isOpen, certOpsPaused }) =>
    isOpen ? (
      <div data-paused={String(Boolean(certOpsPaused))}>
        Create token modal
      </div>
    ) : null,
}));
vi.mock('../../src/components/certops/RenewalProfilesPanel.jsx', () => ({
  default: () => <div>Renewal profiles</div>,
}));
vi.mock('../../src/components/certops/UpcomingRenewalsPanel.jsx', () => ({
  default: () => <div>Upcoming renewals</div>,
}));

function renderAt(path) {
  // Mounted the way App.jsx mounts it, under the /certops/* splat, so the
  // child paths and the redirects resolve exactly as they do in the app.
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter initialEntries={[path]}>
          <Routes>
            <Route
              path='/certops/*'
              element={<CertOpsRoutes session={{ isAdmin: true }} />}
            />
          </Routes>
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

function killSwitchState(overrides = {}) {
  return {
    certOpsPaused: false,
    certOpsEnabled: true,
    certOpsActive: true,
    loading: false,
    error: '',
    saving: false,
    setPaused: vi.fn(),
    ...overrides,
  };
}

const TAB_PANELS = {
  '/certops/jobs': 'Machine executor jobs',
  '/certops/certificates': 'Certificates tab',
  '/certops/renewals': 'Renewal profiles',
  '/certops/agents': 'Agent fleet',
  '/certops/settings': 'Machine API tokens',
};

beforeEach(() => {
  useCertOpsAvailabilityMock.mockReset();
  useCertOpsWorkspaceKillSwitchMock.mockReset();
  useCertOpsAvailabilityMock.mockReturnValue({
    ready: true,
    enabled: true,
    error: null,
    retry: vi.fn(),
  });
  useCertOpsWorkspaceKillSwitchMock.mockReturnValue(killSwitchState());
});

describe('CertOpsRoutes redirects', () => {
  // Both legacy paths are linked from published docs, the control center and
  // agent runbooks, so neither may 404 or land on an empty shell.
  it('sends /certops to the jobs tab', () => {
    renderAt('/certops');

    expect(screen.getByText('Machine executor jobs')).toBeInTheDocument();
  });

  it('sends the legacy /certops/operations path to the jobs tab', () => {
    renderAt('/certops/operations');

    expect(screen.getByText('Machine executor jobs')).toBeInTheDocument();
  });

  it('sends an unknown CertOps path to the jobs tab', () => {
    renderAt('/certops/does-not-exist');

    expect(screen.getByText('Machine executor jobs')).toBeInTheDocument();
  });
});

describe('CertOpsRoutes tabs', () => {
  it.each(Object.keys(TAB_PANELS))(
    '%s renders its own panels and not those of another tab',
    path => {
      renderAt(path);

      expect(screen.getByText(TAB_PANELS[path])).toBeInTheDocument();
      Object.entries(TAB_PANELS)
        .filter(([otherPath]) => otherPath !== path)
        .forEach(([, otherPanel]) => {
          expect(screen.queryByText(otherPanel)).not.toBeInTheDocument();
        });
    }
  );

  it('marks only the current tab as the current page', () => {
    renderAt('/certops/agents');

    const current = screen.getAllByRole('link', { current: 'page' });
    expect(current).toHaveLength(1);
    expect(current[0]).toHaveTextContent('Agents');
  });

  it('keeps the five sections on one scrollable row instead of wrapping', () => {
    renderAt('/certops/renewals');

    const nav = screen.getByRole('navigation', {
      name: 'Certificate operations sections',
    });
    const links = screen.getAllByRole('link');
    expect(links.map(link => link.textContent)).toEqual([
      'Jobs',
      'Certificates',
      'Renewals',
      'Agents',
      'Settings',
    ]);
    expect(nav).toHaveStyle({ flexWrap: 'nowrap' });
  });

  it('does not claim tablist semantics for what are real navigations', () => {
    renderAt('/certops/jobs');

    expect(screen.queryAllByRole('tablist')).toHaveLength(0);
    expect(screen.queryAllByRole('tab')).toHaveLength(0);
  });
});

describe('CertOpsRoutes kill-switch banner', () => {
  it.each(Object.keys(TAB_PANELS))('stays quiet on %s while active', path => {
    renderAt(path);

    expect(screen.getByText('Active')).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Pause certificate operations' })
    ).toBeInTheDocument();
  });

  it.each(Object.keys(TAB_PANELS))('warns on %s while paused', path => {
    useCertOpsWorkspaceKillSwitchMock.mockReturnValue(
      killSwitchState({ certOpsPaused: true, certOpsActive: false })
    );

    renderAt(path);

    expect(
      screen.getByText('Certificate operations are paused for this workspace')
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Resume certificate operations' })
    ).toBeInTheDocument();
  });

  it('hands the paused state to the tabs so they can disable refused controls', () => {
    useCertOpsWorkspaceKillSwitchMock.mockReturnValue(
      killSwitchState({ certOpsPaused: true, certOpsActive: false })
    );

    renderAt('/certops/jobs');

    expect(screen.getByText('Machine executor jobs')).toHaveAttribute(
      'data-paused',
      'true'
    );
  });
});

describe('CertOpsRoutes availability gate', () => {
  it('shows a checking state while availability is unresolved, on every tab', () => {
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: false,
      enabled: null,
      error: null,
    });

    renderAt('/certops/agents');

    expect(
      screen.getByText('Checking certificate operations availability...')
    ).toBeInTheDocument();
    expect(screen.queryByText('Agent fleet')).not.toBeInTheDocument();
  });

  it('keeps a failed availability check distinct from a disabled workspace', () => {
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: true,
      enabled: null,
      error: 'Network Error',
      retry: vi.fn(),
    });

    renderAt('/certops/jobs');

    expect(
      screen.getByText('Could not load certificate operations status')
    ).toBeInTheDocument();
    expect(
      screen.queryByText('Certificate operations is not enabled')
    ).not.toBeInTheDocument();
    expect(screen.queryByText('Machine executor jobs')).not.toBeInTheDocument();
  });

  it('renders neither the tabs nor the banner when CertOps is disabled', () => {
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: true,
      enabled: false,
      error: null,
    });

    renderAt('/certops/settings');

    expect(
      screen.getByText('Certificate operations is not enabled')
    ).toBeInTheDocument();
    expect(screen.queryByText('Machine API tokens')).not.toBeInTheDocument();
    expect(screen.queryByText('Active')).not.toBeInTheDocument();
  });
});
