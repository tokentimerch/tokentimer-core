import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  render,
  screen,
  fireEvent,
  waitFor,
  within,
} from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ChakraProvider } from '@chakra-ui/react';

import ExecutorJobsPanel from '../../src/components/certops/ExecutorJobsPanel.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const {
  useCertOpsJobsMock,
  useCertOpsCanManageMock,
  useCertOpsJobTimelineMock,
  useCertOpsAgentsMock,
  createJobMock,
  approveJobMock,
  rejectJobMock,
  listCertificatesMock,
  listCertificateTargetsMock,
  listWorkspaceCertificateInstancesMock,
} = vi.hoisted(() => ({
  useCertOpsJobsMock: vi.fn(),
  useCertOpsCanManageMock: vi.fn(),
  useCertOpsJobTimelineMock: vi.fn(() => ({
    job: null,
    logEntries: [],
    evidence: [],
    loading: false,
    error: '',
  })),
  useCertOpsAgentsMock: vi.fn(() => ({
    enabled: true,
    agents: [],
    pagination: null,
    loading: false,
    error: '',
    refresh: vi.fn(),
  })),
  createJobMock: vi.fn(),
  approveJobMock: vi.fn(),
  rejectJobMock: vi.fn(),
  listCertificatesMock: vi.fn(),
  listCertificateTargetsMock: vi.fn(),
  listWorkspaceCertificateInstancesMock: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: 'ws-1', selectWorkspace: vi.fn() }),
}));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsCanManage: useCertOpsCanManageMock,
  useCertOpsEnabled: () => true,
  useCertOpsIsWorkspaceAdmin: () => false,
}));

vi.mock('../../src/components/certops/certopsJobsApi.js', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsJobsApi.js'
  );
  return {
    ...actual,
    createJob: createJobMock,
    approveJob: approveJobMock,
    rejectJob: rejectJobMock,
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
  useCertOpsJobTimeline: useCertOpsJobTimelineMock,
}));

vi.mock('../../src/components/certops/useCertOpsAgents.js', () => ({
  useCertOpsAgents: useCertOpsAgentsMock,
}));

function renderPanel(props = {}, initialEntries = ['/']) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter initialEntries={initialEntries}>
          <ExecutorJobsPanel {...props} />
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

function job(overrides = {}) {
  return {
    id: 'job-1',
    operation: 'renew',
    status: 'succeeded',
    source: 'scheduler',
    createdAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

beforeEach(() => {
  useCertOpsJobsMock.mockReset();
  useCertOpsCanManageMock.mockReset();
  useCertOpsJobTimelineMock.mockClear();
  useCertOpsJobTimelineMock.mockReturnValue({
    job: null,
    logEntries: [],
    evidence: [],
    loading: false,
    error: '',
  });
  createJobMock.mockReset();
  approveJobMock.mockReset();
  rejectJobMock.mockReset();
  listCertificatesMock.mockReset();
  listCertificatesMock.mockResolvedValue({ items: [] });
  listCertificateTargetsMock.mockReset();
  listCertificateTargetsMock.mockResolvedValue({ items: [] });
  listWorkspaceCertificateInstancesMock.mockReset();
  listWorkspaceCertificateInstancesMock.mockResolvedValue({ items: [] });
  useCertOpsCanManageMock.mockReturnValue(true);
  useCertOpsAgentsMock.mockReset();
  useCertOpsAgentsMock.mockReturnValue({
    enabled: true,
    agents: [],
    pagination: null,
    loading: false,
    error: '',
    refresh: vi.fn(),
  });
  useCertOpsJobsMock.mockReturnValue(jobsState());
});

describe('ExecutorJobsPanel manual job creation', () => {
  it('does not show the create button for a non-manager viewer', () => {
    useCertOpsCanManageMock.mockReturnValue(false);

    renderPanel();

    expect(
      screen.queryByRole('button', { name: 'Create manual job' })
    ).not.toBeInTheDocument();
  });

  it('disables creation with the reason stated while the workspace is paused', () => {
    renderPanel({ certOpsPaused: true });

    expect(
      screen.getByRole('button', { name: 'Create manual job' })
    ).toBeDisabled();
    expect(
      screen.getByText(/Certificate operations are paused for this workspace/)
    ).toBeInTheDocument();
  });

  it('opens the modal, submits it, and refreshes the job list', async () => {
    const refresh = vi.fn();
    useCertOpsJobsMock.mockReturnValue(jobsState({ refresh }));
    createJobMock.mockResolvedValue({
      job: { id: 'job-new', operation: 'noop', status: 'pending' },
    });

    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Create manual job' }));
    expect(
      screen.getByRole('dialog', { name: /Create manual job/ })
    ).toBeInTheDocument();

    const createButton = screen.getByRole('button', { name: 'Create job' });
    expect(createButton).toBeDisabled();

    fireEvent.change(screen.getByLabelText(/^Operation/), {
      target: { value: 'noop' },
    });
    expect(createButton).not.toBeDisabled();

    fireEvent.click(createButton);

    await waitFor(() => expect(createJobMock).toHaveBeenCalledTimes(1));
    expect(createJobMock).toHaveBeenCalledWith('ws-1', { operation: 'noop' });
    await waitFor(() => expect(refresh).toHaveBeenCalledTimes(1));
  });

  it('requires a subject ID once a subject type is chosen', () => {
    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Create manual job' }));
    fireEvent.change(screen.getByLabelText(/^Operation/), {
      target: { value: 'noop' },
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

  it('requires a subject pair for an operation that acts on an existing entity', () => {
    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Create manual job' }));
    fireEvent.change(screen.getByLabelText(/^Operation/), {
      target: { value: 'renew' },
    });

    expect(screen.getByRole('button', { name: 'Create job' })).toBeDisabled();
  });

  it('offers managed-certificate suggestions once that subject type is chosen', async () => {
    listCertificatesMock.mockResolvedValue({
      items: [
        { id: 'cert-uuid-1', commonName: 'example.com' },
        { id: 'cert-uuid-2', commonName: null },
      ],
    });

    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Create manual job' }));
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
    const datalist = document.getElementById(
      subjectIdInput.getAttribute('list')
    );
    expect(datalist.querySelectorAll('option')).toHaveLength(2);
  });

  it('switches the suggestion source when the subject type changes', async () => {
    listCertificatesMock.mockResolvedValue({
      items: [{ id: 'cert-uuid-1', commonName: 'example.com' }],
    });
    listCertificateTargetsMock.mockResolvedValue({
      items: [
        { id: 'target-uuid-1', name: 'prod-lb-01' },
        { id: 'target-uuid-2', name: null },
      ],
    });

    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Create manual job' }));
    fireEvent.change(screen.getByLabelText(/^Subject type/), {
      target: { value: 'managed_certificate' },
    });
    await waitFor(() => expect(listCertificatesMock).toHaveBeenCalledTimes(1));

    fireEvent.change(screen.getByLabelText(/^Subject type/), {
      target: { value: 'certificate_target' },
    });

    await waitFor(() =>
      expect(listCertificateTargetsMock).toHaveBeenCalledWith(
        'ws-1',
        expect.objectContaining({ limit: 100 })
      )
    );
    expect(listCertificatesMock).toHaveBeenCalledTimes(1);
  });

  it('offers certificate instance suggestions for that subject type', async () => {
    listWorkspaceCertificateInstancesMock.mockResolvedValue({
      items: [
        { id: 'instance-uuid-1', observedSubject: 'example.com' },
        { id: 'instance-uuid-2', observedSubject: null },
      ],
    });

    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Create manual job' }));
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
  });

  it('does not offer "token" as a subject type, since no job logic acts on it', () => {
    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Create manual job' }));

    const optionValues = Array.from(
      screen.getByLabelText(/^Subject type/).options
    ).map(option => option.value);
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

  it('falls back to a plain input for subject types with no suggestion source', async () => {
    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Create manual job' }));
    fireEvent.change(screen.getByLabelText(/^Subject type/), {
      target: { value: 'domain' },
    });

    const subjectIdInput = await screen.findByLabelText(/^Subject ID/);
    expect(subjectIdInput).not.toHaveAttribute('list');
    expect(listCertificatesMock).not.toHaveBeenCalled();
    expect(listCertificateTargetsMock).not.toHaveBeenCalled();
    expect(listWorkspaceCertificateInstancesMock).not.toHaveBeenCalled();
  });

  it('keeps the modal open when creation fails so the manager can retry', async () => {
    const refresh = vi.fn();
    useCertOpsJobsMock.mockReturnValue(jobsState({ refresh }));
    createJobMock.mockRejectedValue({
      response: { status: 403, data: { code: 'INSUFFICIENT_ROLE' } },
    });

    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Create manual job' }));
    fireEvent.change(screen.getByLabelText(/^Operation/), {
      target: { value: 'noop' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create job' }));

    await waitFor(() => expect(createJobMock).toHaveBeenCalledTimes(1));
    expect(
      screen.getByRole('dialog', { name: /Create manual job/ })
    ).toBeInTheDocument();
    expect(refresh).not.toHaveBeenCalled();
  });

  it('sends requiresApproval when the checkbox is checked', async () => {
    createJobMock.mockResolvedValue({
      job: { id: 'job-new', operation: 'noop', status: 'pending_approval' },
    });

    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Create manual job' }));
    fireEvent.change(screen.getByLabelText(/^Operation/), {
      target: { value: 'noop' },
    });
    fireEvent.click(
      screen.getByText('Require approval before this job can run')
    );
    fireEvent.click(screen.getByRole('button', { name: 'Create job' }));

    await waitFor(() =>
      expect(createJobMock).toHaveBeenCalledWith('ws-1', {
        operation: 'noop',
        requiresApproval: true,
      })
    );
  });
});

describe('ExecutorJobsPanel approvals', () => {
  const pendingJob = job({ status: 'pending_approval' });

  it('shows Approve/Reject only for a manager on a job pending approval', () => {
    useCertOpsJobsMock.mockReturnValue(jobsState({ jobs: [pendingJob] }));

    const { unmount } = renderPanel();
    expect(screen.getByRole('button', { name: 'Approve' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reject' })).toBeInTheDocument();
    unmount();

    useCertOpsCanManageMock.mockReturnValue(false);
    renderPanel();
    expect(
      screen.queryByRole('button', { name: 'Approve' })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Reject' })
    ).not.toBeInTheDocument();
  });

  it('does not show Approve/Reject on a job not pending approval', () => {
    useCertOpsJobsMock.mockReturnValue(
      jobsState({ jobs: [job({ status: 'pending' })] })
    );

    renderPanel();

    expect(
      screen.queryByRole('button', { name: 'Approve' })
    ).not.toBeInTheDocument();
  });

  it('keeps approve and reject available while the workspace is paused', () => {
    // Deliberate: rejecting a queued job is what an operator needs during the
    // incident that caused the pause.
    useCertOpsJobsMock.mockReturnValue(jobsState({ jobs: [pendingJob] }));

    renderPanel({ certOpsPaused: true });

    expect(screen.getByRole('button', { name: 'Approve' })).not.toBeDisabled();
    expect(screen.getByRole('button', { name: 'Reject' })).not.toBeDisabled();
  });

  it('labels a queued job as not executable while the workspace is paused', () => {
    useCertOpsJobsMock.mockReturnValue(
      jobsState({ jobs: [job({ status: 'queued' })] })
    );

    renderPanel({ certOpsPaused: true });

    expect(screen.getByText('Not executable while paused')).toBeInTheDocument();
  });

  it('approves a job through the confirm modal with an optional reason', async () => {
    const refresh = vi.fn();
    useCertOpsJobsMock.mockReturnValue(
      jobsState({ jobs: [pendingJob], refresh })
    );
    approveJobMock.mockResolvedValue({ job: { id: 'job-1' } });

    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Approve' }));
    const dialog = await screen.findByRole('dialog', { name: /Approve job/ });

    fireEvent.change(
      screen.getByPlaceholderText('e.g. confirmed with the domain owner'),
      { target: { value: 'confirmed with the owner' } }
    );
    fireEvent.click(within(dialog).getByRole('button', { name: 'Approve' }));

    await waitFor(() => {
      expect(approveJobMock).toHaveBeenCalledWith('ws-1', 'job-1', {
        reason: 'confirmed with the owner',
      });
      expect(refresh).toHaveBeenCalledTimes(1);
    });
  });

  it('rejects a job through the confirm modal', async () => {
    const refresh = vi.fn();
    useCertOpsJobsMock.mockReturnValue(
      jobsState({ jobs: [pendingJob], refresh })
    );
    rejectJobMock.mockResolvedValue({ job: { id: 'job-1' } });

    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Reject' }));
    const dialog = await screen.findByRole('dialog', { name: /Reject job/ });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Reject' }));

    await waitFor(() => {
      expect(rejectJobMock).toHaveBeenCalledWith('ws-1', 'job-1', {
        reason: undefined,
      });
      expect(refresh).toHaveBeenCalledTimes(1);
    });
  });

  it('keeps the job listed and the modal open on a refused approval', async () => {
    const refresh = vi.fn();
    useCertOpsJobsMock.mockReturnValue(
      jobsState({ jobs: [pendingJob], refresh })
    );
    approveJobMock.mockRejectedValue({
      response: {
        status: 403,
        data: { code: 'CERTOPS_APPROVAL_SELF_APPROVAL_FORBIDDEN' },
      },
    });

    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Approve' }));
    const dialog = await screen.findByRole('dialog', { name: /Approve job/ });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Approve' }));

    await waitFor(() => expect(approveJobMock).toHaveBeenCalledTimes(1));
    expect(
      screen.getByRole('dialog', { name: /Approve job/ })
    ).toBeInTheDocument();
    expect(refresh).not.toHaveBeenCalled();
  });
});

describe('ExecutorJobsPanel list states', () => {
  it('shows a loading state distinct from the empty state', () => {
    useCertOpsJobsMock.mockReturnValue(jobsState({ loading: true }));

    renderPanel();

    expect(screen.getByText('Loading executor jobs...')).toBeInTheDocument();
    expect(
      screen.queryByText('No executor-reported certificate jobs yet')
    ).not.toBeInTheDocument();
  });

  it('shows an empty state when there are no jobs', () => {
    renderPanel();

    expect(
      screen.getByText('No executor-reported certificate jobs yet')
    ).toBeInTheDocument();
  });

  it('shows an error message distinct from the loading and empty states', () => {
    useCertOpsJobsMock.mockReturnValue(
      jobsState({ error: 'Could not load certificate operations jobs.' })
    );

    renderPanel();

    expect(
      screen.getByText('Could not load certificate operations jobs.')
    ).toBeInTheDocument();
    expect(
      screen.queryByText('No executor-reported certificate jobs yet')
    ).not.toBeInTheDocument();
  });

  it('expands a row to reveal its evidence timeline on click', () => {
    useCertOpsJobsMock.mockReturnValue(jobsState({ jobs: [job()] }));

    renderPanel();

    const row = screen.getByRole('button', { name: /Renew/i });
    expect(row).toHaveAttribute('aria-expanded', 'false');

    fireEvent.click(row);
    expect(row).toHaveAttribute('aria-expanded', 'true');
  });

  it('refetches an expanded row\'s evidence timeline when "Refresh" is clicked', () => {
    // Regression test: the top-level "Refresh" button used to only call the
    // job list's own refresh(), leaving an already-expanded row's
    // EvidenceTimeline (a separate hook instance/fetch) stale - a manager
    // watching a mid-renewal job never saw newer log/evidence entries land
    // without collapsing and re-expanding the row.
    const refresh = vi.fn();
    useCertOpsJobsMock.mockReturnValue(jobsState({ jobs: [job()], refresh }));

    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: /Renew/i }));
    const firstCallCount = useCertOpsJobTimelineMock.mock.calls.length;
    const firstRefreshToken =
      useCertOpsJobTimelineMock.mock.calls[firstCallCount - 1][1];

    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));

    expect(refresh).toHaveBeenCalledTimes(1);
    const lastCallCount = useCertOpsJobTimelineMock.mock.calls.length;
    const lastRefreshToken =
      useCertOpsJobTimelineMock.mock.calls[lastCallCount - 1][1];
    expect(lastRefreshToken).not.toBe(firstRefreshToken);
  });

  it('renders a page control, not a caption, when more jobs exist than are shown', () => {
    useCertOpsJobsMock.mockReturnValue(
      jobsState({
        jobs: [job()],
        pagination: { limit: 20, offset: 0, total: 57 },
      })
    );

    renderPanel();

    // The caption this replaced told the operator rows existed without giving
    // them any way to reach them.
    expect(screen.queryByText('Showing 1 of 57 jobs')).not.toBeInTheDocument();
    expect(
      screen.getByRole('navigation', { name: 'jobs pagination' })
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Next page of jobs' })
    ).toBeEnabled();
    expect(screen.getByText('Showing 1 to 20 of 57 jobs')).toBeInTheDocument();
  });

  it('keeps the page control but disables both arrows when one page holds everything', () => {
    useCertOpsJobsMock.mockReturnValue(
      jobsState({
        jobs: [job()],
        pagination: { limit: 20, offset: 0, total: 1 },
      })
    );

    renderPanel();

    expect(
      screen.getByRole('button', { name: 'Next page of jobs' })
    ).toBeDisabled();
    expect(
      screen.getByRole('button', { name: 'Previous page of jobs' })
    ).toBeDisabled();
  });

  it('pages forward and back through the URL', () => {
    useCertOpsJobsMock.mockReturnValue(
      jobsState({
        jobs: [job()],
        pagination: { limit: 20, offset: 0, total: 57 },
      })
    );

    renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Next page of jobs' }));
    expect(useCertOpsJobsMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ limit: 20, offset: 20 })
    );

    fireEvent.click(
      screen.getByRole('button', { name: 'Previous page of jobs' })
    );
    expect(useCertOpsJobsMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ limit: 20, offset: 0 })
    );
  });

  it('resets the offset to the first page when a filter changes', () => {
    useCertOpsJobsMock.mockReturnValue(
      jobsState({
        jobs: [job()],
        pagination: { limit: 20, offset: 40, total: 57 },
      })
    );

    renderPanel({}, ['/?status=failed&offset=40']);

    expect(useCertOpsJobsMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ offset: 40, status: 'failed' })
    );

    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));

    expect(useCertOpsJobsMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ offset: 0, status: undefined })
    );
  });

  it('restores a filtered, paged view from the URL on load', () => {
    useCertOpsJobsMock.mockReturnValue(
      jobsState({
        jobs: [job()],
        pagination: { limit: 50, offset: 50, total: 300 },
      })
    );

    renderPanel({}, ['/?status=failed&source=scheduler&limit=50&offset=50']);

    expect(useCertOpsJobsMock).toHaveBeenLastCalledWith(
      expect.objectContaining({
        limit: 50,
        offset: 50,
        status: 'failed',
        source: 'scheduler',
      })
    );
    expect(screen.getByText(/Filtered by/)).toBeInTheDocument();
    expect(
      screen.getByText('Showing 51 to 100 of 300 jobs')
    ).toBeInTheDocument();
  });

  it('offers a way back instead of claiming the list is empty when the URL page is past the end', () => {
    useCertOpsJobsMock.mockReturnValue(
      jobsState({
        jobs: [],
        pagination: { limit: 20, offset: 200, total: 3 },
      })
    );

    renderPanel({}, ['/?offset=200']);

    expect(
      screen.getByText('This page is past the end of the list')
    ).toBeInTheDocument();
    expect(
      screen.queryByText('No executor-reported certificate jobs yet')
    ).not.toBeInTheDocument();

    fireEvent.click(
      screen.getByRole('button', { name: 'Back to the first page' })
    );
    expect(useCertOpsJobsMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ offset: 0 })
    );
  });

  it('shows the assigned agent hostname on the job row, not only the id', () => {
    useCertOpsAgentsMock.mockReturnValue({
      enabled: true,
      agents: [
        {
          id: 'agent-row-1',
          agentId: 'candidate-tt-trustvfy-5100',
          hostname: 'tt-trustvfy',
        },
      ],
      pagination: null,
      loading: false,
      error: '',
      refresh: vi.fn(),
    });
    useCertOpsJobsMock.mockReturnValue(
      jobsState({
        jobs: [
          job({
            operation: 'distribute-trust',
            assignedAgentId: 'agent-row-1',
            subjectType: 'trust_anchor',
            subjectId: 'anchor-1',
          }),
        ],
      })
    );

    renderPanel();

    expect(screen.getByText(/tt-trustvfy \(agent-row-1\)/)).toBeInTheDocument();
  });
});

describe('ExecutorJobsPanel manual-reconciliation visibility', () => {
  it('shows the "Needs reconciliation" badge for an orphaned_unknown_effect job', () => {
    useCertOpsJobsMock.mockReturnValue(
      jobsState({ jobs: [job({ status: 'orphaned_unknown_effect' })] })
    );

    renderPanel();

    expect(screen.getByText('Needs reconciliation')).toBeInTheDocument();
  });

  it('shows the advisory line for a job needing reconciliation with no errorMessage', () => {
    useCertOpsJobsMock.mockReturnValue(
      jobsState({
        jobs: [
          job({
            status: 'orphaned_unknown_effect',
            needsOperatorReconciliation: true,
          }),
        ],
      })
    );

    renderPanel();

    expect(
      screen.getByText(/could not be confirmed and need manual review/)
    ).toBeInTheDocument();
  });

  it('prefers a real errorMessage over the reconciliation advisory line', () => {
    useCertOpsJobsMock.mockReturnValue(
      jobsState({
        jobs: [
          job({
            status: 'orphaned_unknown_effect',
            needsOperatorReconciliation: true,
            errorMessage: 'Lease expired after renew; side effects unknown',
          }),
        ],
      })
    );

    renderPanel();

    expect(
      screen.getByText('Lease expired after renew; side effects unknown')
    ).toBeInTheDocument();
    expect(
      screen.queryByText(/could not be confirmed and need manual review/)
    ).not.toBeInTheDocument();
  });

  it('shows no second line under the badge for a job that needs no reconciliation', () => {
    useCertOpsJobsMock.mockReturnValue(jobsState({ jobs: [job()] }));

    renderPanel();

    expect(
      screen.queryByText(/could not be confirmed and need manual review/)
    ).not.toBeInTheDocument();
  });

  it('does not show errorMessage for a failed job that does not need reconciliation', () => {
    // Regression guard: errorMessage is common on ordinary failed/rejected
    // jobs too. The advisory VStack must stay scoped to jobs actually
    // flagged needsOperatorReconciliation, not to "has an errorMessage".
    useCertOpsJobsMock.mockReturnValue(
      jobsState({
        jobs: [
          job({
            status: 'failed',
            needsOperatorReconciliation: false,
            errorMessage: 'Deploy target rejected the certificate',
          }),
        ],
      })
    );

    renderPanel();

    expect(
      screen.queryByText('Deploy target rejected the certificate')
    ).not.toBeInTheDocument();
  });
});
