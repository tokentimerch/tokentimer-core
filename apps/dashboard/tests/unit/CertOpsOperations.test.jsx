import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { ChakraProvider } from '@chakra-ui/react';

import CertOpsOperations from '../../src/pages/certops/CertOpsOperations.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const {
  useCertOpsAvailabilityMock,
  useCertOpsJobsMock,
  useCertOpsCanManageMock,
  useCertOpsApiTokensMock,
  createJobMock,
  listCertificatesMock,
  listCertificateTargetsMock,
  listWorkspaceCertificateInstancesMock,
} = vi.hoisted(() => ({
  useCertOpsAvailabilityMock: vi.fn(),
  useCertOpsJobsMock: vi.fn(),
  useCertOpsCanManageMock: vi.fn(),
  useCertOpsApiTokensMock: vi.fn(),
  createJobMock: vi.fn(),
  listCertificatesMock: vi.fn(),
  listCertificateTargetsMock: vi.fn(),
  listWorkspaceCertificateInstancesMock: vi.fn(),
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

vi.mock('../../src/components/certops/certopsJobsApi.js', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsJobsApi.js'
  );
  return {
    ...actual,
    createJob: createJobMock,
  };
});

vi.mock('../../src/components/certops/certopsApi.js', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsApi.js'
  );
  return {
    ...actual,
    listCertificates: listCertificatesMock,
    listCertificateTargets: listCertificateTargetsMock,
    listWorkspaceCertificateInstances: listWorkspaceCertificateInstancesMock,
  };
});

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

// The agent panels have their own dedicated unit tests; here they only need
// stable hook returns so the page renders. `enabled: false` makes them
// render null, keeping these page-level assertions focused on jobs/tokens.
vi.mock('../../src/components/certops/useCertOpsAgents.js', () => ({
  useCertOpsAgents: () => ({
    enabled: false,
    agents: [],
    loading: false,
    error: '',
    refresh: vi.fn(),
  }),
  useCertOpsBootstrapTokens: () => ({
    enabled: false,
    tokens: [],
    loading: false,
    error: '',
    refresh: vi.fn(),
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
    createJobMock.mockReset();
    listCertificatesMock.mockReset();
    listCertificatesMock.mockResolvedValue({ items: [] });
    listCertificateTargetsMock.mockReset();
    listCertificateTargetsMock.mockResolvedValue({ items: [] });
    listWorkspaceCertificateInstancesMock.mockReset();
    listWorkspaceCertificateInstancesMock.mockResolvedValue({ items: [] });
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

  it('shows an availability error distinct from the disabled empty state', () => {
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: true,
      enabled: null,
      error: 'Network Error',
      retry: vi.fn(),
    });
    useCertOpsJobsMock.mockReturnValue(jobsState());

    renderWithProviders(<CertOpsOperations session={{ isAdmin: true }} />);

    expect(
      screen.getByText('Could not load certificate operations status')
    ).toBeInTheDocument();
    expect(
      screen.queryByText('Certificate operations is not enabled')
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText('Machine executor jobs')
    ).not.toBeInTheDocument();
  });

  it('offers a Retry action on the availability error that re-triggers the check', () => {
    const retry = vi.fn();
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: true,
      enabled: null,
      error: 'Network Error',
      retry,
    });
    useCertOpsJobsMock.mockReturnValue(jobsState());

    renderWithProviders(<CertOpsOperations session={{ isAdmin: true }} />);

    const retryButton = screen.getByRole('button', { name: 'Retry' });
    fireEvent.click(retryButton);
    expect(retry).toHaveBeenCalledTimes(1);
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

  it('shows a truncation indicator when pagination reports more jobs than shown', () => {
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
        pagination: { limit: 20, offset: 0, total: 57 },
      })
    );

    renderWithProviders(<CertOpsOperations session={{ isAdmin: true }} />);

    expect(screen.getByText('Showing 1 of 57 jobs')).toBeInTheDocument();
  });

  it('hides the truncation indicator when all jobs fit in one page', () => {
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
        pagination: { limit: 20, offset: 0, total: 1 },
      })
    );

    renderWithProviders(<CertOpsOperations session={{ isAdmin: true }} />);

    expect(screen.queryByText(/Showing .* jobs/)).not.toBeInTheDocument();
  });

  it('does not show the "Create manual job" button for a non-manager viewer', () => {
    useCertOpsCanManageMock.mockReturnValue(false);
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: true,
      enabled: true,
      error: null,
    });
    useCertOpsJobsMock.mockReturnValue(jobsState());

    renderWithProviders(<CertOpsOperations session={{ isAdmin: false }} />);

    expect(
      screen.queryByRole('button', { name: 'Create manual job' })
    ).not.toBeInTheDocument();
  });

  it('opens the manual job modal, submits it, and refreshes the job list', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: true,
      enabled: true,
      error: null,
    });
    const refresh = vi.fn();
    useCertOpsJobsMock.mockReturnValue(jobsState({ refresh }));
    createJobMock.mockResolvedValue({
      job: { id: 'job-new', operation: 'deploy', status: 'pending' },
    });

    renderWithProviders(<CertOpsOperations session={{ isAdmin: true }} />);

    fireEvent.click(
      screen.getByRole('button', { name: 'Create manual job' })
    );
    expect(screen.getByRole('dialog', { name: 'Create manual job' })).toBeInTheDocument();

    const createButton = screen.getByRole('button', { name: 'Create job' });
    expect(createButton).toBeDisabled();

    fireEvent.change(screen.getByLabelText(/^Operation/), {
      target: { value: 'deploy' },
    });
    expect(createButton).not.toBeDisabled();

    fireEvent.click(createButton);

    await waitFor(() => expect(createJobMock).toHaveBeenCalledTimes(1));
    expect(createJobMock).toHaveBeenCalledWith('ws-1', {
      operation: 'deploy',
    });
    await waitFor(() => expect(refresh).toHaveBeenCalledTimes(1));
  });

  it('requires a subject ID once a subject type is chosen', () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: true,
      enabled: true,
      error: null,
    });
    useCertOpsJobsMock.mockReturnValue(jobsState());

    renderWithProviders(<CertOpsOperations session={{ isAdmin: true }} />);

    fireEvent.click(
      screen.getByRole('button', { name: 'Create manual job' })
    );
    fireEvent.change(screen.getByLabelText(/^Operation/), {
      target: { value: 'deploy' },
    });
    const createButton = screen.getByRole('button', { name: 'Create job' });
    expect(createButton).not.toBeDisabled();

    fireEvent.change(screen.getByLabelText(/^Subject type/), {
      target: { value: 'managed_certificate' },
    });
    expect(createButton).toBeDisabled();

    fireEvent.change(screen.getByLabelText(/^Subject ID/), {
      target: { value: 'cert-1' },
    });
    expect(createButton).not.toBeDisabled();
  });

  it('offers managed-certificate suggestions as a datalist once that subject type is chosen', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: true,
      enabled: true,
      error: null,
    });
    useCertOpsJobsMock.mockReturnValue(jobsState());
    listCertificatesMock.mockResolvedValue({
      items: [
        { id: 'cert-uuid-1', commonName: 'example.com' },
        { id: 'cert-uuid-2', commonName: null },
      ],
    });

    renderWithProviders(<CertOpsOperations session={{ isAdmin: true }} />);

    fireEvent.click(
      screen.getByRole('button', { name: 'Create manual job' })
    );
    // No fetch, and no datalist wiring, before a subject type is picked.
    expect(listCertificatesMock).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText(/^Subject type/), {
      target: { value: 'managed_certificate' },
    });

    await waitFor(() =>
      expect(listCertificatesMock).toHaveBeenCalledWith(
        'ws-1',
        expect.objectContaining({ limit: 100 })
      )
    );

    const subjectIdInput = await screen.findByLabelText(/^Subject ID/);
    await waitFor(() => expect(subjectIdInput).toHaveAttribute('list'));
    const listId = subjectIdInput.getAttribute('list');
    const datalist = document.getElementById(listId);
    expect(datalist).toBeTruthy();
    expect(datalist.querySelectorAll('option')).toHaveLength(2);
  });

  it('offers certificate target suggestions once subject type is switched to certificate target', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: true,
      enabled: true,
      error: null,
    });
    useCertOpsJobsMock.mockReturnValue(jobsState());
    listCertificatesMock.mockResolvedValue({
      items: [{ id: 'cert-uuid-1', commonName: 'example.com' }],
    });
    listCertificateTargetsMock.mockResolvedValue({
      items: [
        { id: 'target-uuid-1', name: 'prod-lb-01' },
        { id: 'target-uuid-2', name: null },
      ],
    });

    renderWithProviders(<CertOpsOperations session={{ isAdmin: true }} />);

    fireEvent.click(
      screen.getByRole('button', { name: 'Create manual job' })
    );

    // Start on managed_certificate so a cert suggestion list is loaded...
    fireEvent.change(screen.getByLabelText(/^Subject type/), {
      target: { value: 'managed_certificate' },
    });
    await waitFor(() => expect(listCertificatesMock).toHaveBeenCalledTimes(1));

    // ...then switch to certificate target: suggestions should now come
    // from the targets list endpoint instead, not the certificate one.
    fireEvent.change(screen.getByLabelText(/^Subject type/), {
      target: { value: 'certificate_target' },
    });

    await waitFor(() =>
      expect(listCertificateTargetsMock).toHaveBeenCalledWith(
        'ws-1',
        expect.objectContaining({ limit: 100 })
      )
    );

    const subjectIdInput = await screen.findByLabelText(/^Subject ID/);
    await waitFor(() => expect(subjectIdInput).toHaveAttribute('list'));
    const listId = subjectIdInput.getAttribute('list');
    const datalist = document.getElementById(listId);
    expect(datalist).toBeTruthy();
    expect(datalist.querySelectorAll('option')).toHaveLength(2);
    // listCertificates should not be called again just for switching types.
    expect(listCertificatesMock).toHaveBeenCalledTimes(1);
  });

  it('offers certificate instance suggestions once subject type is switched to certificate instance', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: true,
      enabled: true,
      error: null,
    });
    useCertOpsJobsMock.mockReturnValue(jobsState());
    listWorkspaceCertificateInstancesMock.mockResolvedValue({
      items: [
        { id: 'instance-uuid-1', observedSubject: 'example.com' },
        { id: 'instance-uuid-2', observedSubject: null },
      ],
    });

    renderWithProviders(<CertOpsOperations session={{ isAdmin: true }} />);

    fireEvent.click(
      screen.getByRole('button', { name: 'Create manual job' })
    );
    fireEvent.change(screen.getByLabelText(/^Subject type/), {
      target: { value: 'certificate_instance' },
    });

    await waitFor(() =>
      expect(listWorkspaceCertificateInstancesMock).toHaveBeenCalledWith(
        'ws-1',
        expect.objectContaining({ limit: 100 })
      )
    );

    const subjectIdInput = await screen.findByLabelText(/^Subject ID/);
    await waitFor(() => expect(subjectIdInput).toHaveAttribute('list'));
    const listId = subjectIdInput.getAttribute('list');
    const datalist = document.getElementById(listId);
    expect(datalist).toBeTruthy();
    expect(datalist.querySelectorAll('option')).toHaveLength(2);
  });

  it('does not offer "token" as a subject type, since no job/executor logic acts on it', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: true,
      enabled: true,
      error: null,
    });
    useCertOpsJobsMock.mockReturnValue(jobsState());

    renderWithProviders(<CertOpsOperations session={{ isAdmin: true }} />);

    fireEvent.click(
      screen.getByRole('button', { name: 'Create manual job' })
    );

    const subjectTypeSelect = screen.getByLabelText(/^Subject type/);
    const optionValues = Array.from(subjectTypeSelect.options).map(
      option => option.value
    );
    expect(optionValues).not.toContain('token');
    expect(optionValues).toEqual(
      expect.arrayContaining([
        'managed_certificate',
        'certificate_instance',
        'certificate_target',
        'domain',
        'endpoint',
        'external',
      ])
    );
  });

  it('falls back to a plain text input with no datalist for subject types without a suggestion source', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: true,
      enabled: true,
      error: null,
    });
    useCertOpsJobsMock.mockReturnValue(jobsState());

    renderWithProviders(<CertOpsOperations session={{ isAdmin: true }} />);

    fireEvent.click(
      screen.getByRole('button', { name: 'Create manual job' })
    );
    fireEvent.change(screen.getByLabelText(/^Subject type/), {
      target: { value: 'domain' },
    });

    const subjectIdInput = await screen.findByLabelText(/^Subject ID/);
    expect(subjectIdInput).not.toHaveAttribute('list');
    expect(listCertificatesMock).not.toHaveBeenCalled();
    expect(listCertificateTargetsMock).not.toHaveBeenCalled();
    expect(listWorkspaceCertificateInstancesMock).not.toHaveBeenCalled();
  });

  it('shows an inline error and keeps the modal open when creation fails', async () => {
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsAvailabilityMock.mockReturnValue({
      ready: true,
      enabled: true,
      error: null,
    });
    const refresh = vi.fn();
    useCertOpsJobsMock.mockReturnValue(jobsState({ refresh }));
    createJobMock.mockRejectedValue({
      response: { status: 403, data: { code: 'INSUFFICIENT_ROLE' } },
    });

    renderWithProviders(<CertOpsOperations session={{ isAdmin: true }} />);

    fireEvent.click(
      screen.getByRole('button', { name: 'Create manual job' })
    );
    fireEvent.change(screen.getByLabelText(/^Operation/), {
      target: { value: 'deploy' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create job' }));

    await waitFor(() => expect(createJobMock).toHaveBeenCalledTimes(1));
    // The modal stays open on failure so the manager can retry.
    expect(screen.getByRole('dialog', { name: 'Create manual job' })).toBeInTheDocument();
    expect(refresh).not.toHaveBeenCalled();
  });
});
