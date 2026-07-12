import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { ChakraProvider } from '@chakra-ui/react';

import EvidenceTimeline from '../../src/components/certops/EvidenceTimeline.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const { useCertOpsJobTimelineMock } = vi.hoisted(() => ({
  useCertOpsJobTimelineMock: vi.fn(),
}));

vi.mock('../../src/components/certops/useCertOpsJobs.js', () => ({
  useCertOpsJobTimeline: useCertOpsJobTimelineMock,
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

function baseJob(overrides = {}) {
  return {
    id: 'job-1',
    operation: 'renew',
    status: 'succeeded',
    source: 'scheduler',
    subjectType: 'certificate',
    subjectId: 'cert-1',
    ...overrides,
  };
}

describe('EvidenceTimeline', () => {
  beforeEach(() => {
    useCertOpsJobTimelineMock.mockReset();
  });

  it('shows a loading spinner while the timeline is loading', () => {
    useCertOpsJobTimelineMock.mockReturnValue({
      job: null,
      logEntries: [],
      evidence: [],
      loading: true,
      error: '',
    });

    renderWithProviders(<EvidenceTimeline jobId='job-1' />);

    expect(screen.getByText('Loading...')).toBeInTheDocument();
  });

  it('shows an error message distinct from loading/empty states', () => {
    useCertOpsJobTimelineMock.mockReturnValue({
      job: null,
      logEntries: [],
      evidence: [],
      loading: false,
      error: 'Could not load certificate operations job timeline.',
    });

    renderWithProviders(<EvidenceTimeline jobId='job-1' />);

    expect(
      screen.getByText('Could not load certificate operations job timeline.')
    ).toBeInTheDocument();
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });

  it('shows a not-found message when the job is missing (404 case)', () => {
    useCertOpsJobTimelineMock.mockReturnValue({
      job: null,
      logEntries: [],
      evidence: [],
      loading: false,
      error: '',
    });

    renderWithProviders(<EvidenceTimeline jobId='job-1' />);

    expect(
      screen.getByText('Job not found or no longer available.')
    ).toBeInTheDocument();
  });

  it('shows an empty timeline message when the job has no events', () => {
    useCertOpsJobTimelineMock.mockReturnValue({
      job: baseJob(),
      logEntries: [],
      evidence: [],
      loading: false,
      error: '',
    });

    renderWithProviders(<EvidenceTimeline jobId='job-1' />);

    expect(
      screen.getByText('No timeline events recorded yet.')
    ).toBeInTheDocument();
  });

  it('renders merged log and evidence items in chronological order', () => {
    useCertOpsJobTimelineMock.mockReturnValue({
      job: baseJob(),
      logEntries: [
        {
          id: 'log-1',
          eventType: 'job.completed',
          createdAt: '2026-01-03T00:00:00.000Z',
          message: 'Job finished',
        },
        {
          id: 'log-2',
          eventType: 'job.started',
          createdAt: '2026-01-01T00:00:00.000Z',
          message: 'Job kicked off',
        },
      ],
      evidence: [
        {
          id: 'ev-1',
          evidenceType: 'validation.passed',
          observedAt: '2026-01-02T00:00:00.000Z',
          subjectType: 'certificate',
          subjectId: 'cert-1',
        },
      ],
      loading: false,
      error: '',
    });

    renderWithProviders(<EvidenceTimeline jobId='job-1' />);

    const matches = screen
      .getAllByText(/^(Job started|Validation passed|Job completed)$/)
      .map(node => node.textContent);
    const titles = matches.filter((text, index) => text !== matches[index - 1]);
    expect(titles).toEqual(['Job started', 'Validation passed', 'Job completed']);
  });

  it('renders distinguishable content for different event and evidence types', () => {
    useCertOpsJobTimelineMock.mockReturnValue({
      job: baseJob(),
      logEntries: [
        {
          id: 'log-1',
          eventType: 'job.started',
          createdAt: '2026-01-01T00:00:00.000Z',
        },
        {
          id: 'log-2',
          eventType: 'job.failed',
          createdAt: '2026-01-02T00:00:00.000Z',
        },
      ],
      evidence: [
        {
          id: 'ev-1',
          evidenceType: 'validation.passed',
          observedAt: '2026-01-03T00:00:00.000Z',
        },
        {
          id: 'ev-2',
          evidenceType: 'validation.failed',
          observedAt: '2026-01-04T00:00:00.000Z',
        },
      ],
      loading: false,
      error: '',
    });

    renderWithProviders(<EvidenceTimeline jobId='job-1' />);

    expect(screen.getByText('Job started')).toBeInTheDocument();
    expect(screen.getByText('Job failed')).toBeInTheDocument();
    expect(screen.getAllByText('Validation passed').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Validation failed').length).toBeGreaterThan(0);
  });

  it('shows a visible redaction marker only on evidence flagged as redacted', () => {
    useCertOpsJobTimelineMock.mockReturnValue({
      job: baseJob(),
      logEntries: [
        {
          id: 'log-1',
          eventType: 'evidence.attached',
          createdAt: '2026-01-01T00:00:00.000Z',
          metadata: { redactionApplied: true },
        },
        {
          id: 'log-2',
          eventType: 'job.started',
          createdAt: '2026-01-02T00:00:00.000Z',
          metadata: {},
        },
      ],
      evidence: [],
      loading: false,
      error: '',
    });

    renderWithProviders(<EvidenceTimeline jobId='job-1' />);

    expect(screen.getAllByText('Redacted')).toHaveLength(1);
  });

  it('renders the failure reason for a failed job', () => {
    useCertOpsJobTimelineMock.mockReturnValue({
      job: baseJob({
        status: 'failed',
        errorCode: 'CERTOPS_RENEW_TIMEOUT',
        errorMessage: 'Executor did not respond in time.',
      }),
      logEntries: [],
      evidence: [],
      loading: false,
      error: '',
    });

    renderWithProviders(<EvidenceTimeline jobId='job-1' />);

    expect(screen.getByText('Failure reason')).toBeInTheDocument();
    expect(screen.getByText('CERTOPS_RENEW_TIMEOUT')).toBeInTheDocument();
    expect(
      screen.getByText('Executor did not respond in time.')
    ).toBeInTheDocument();
  });

  it('does not render a failure reason block for a successful job', () => {
    useCertOpsJobTimelineMock.mockReturnValue({
      job: baseJob(),
      logEntries: [],
      evidence: [],
      loading: false,
      error: '',
    });

    renderWithProviders(<EvidenceTimeline jobId='job-1' />);

    expect(screen.queryByText('Failure reason')).not.toBeInTheDocument();
  });

  it('renders a "View audit log" link pointing at /audit?q=<jobId>', () => {
    useCertOpsJobTimelineMock.mockReturnValue({
      job: baseJob({ id: 'job-abc-123' }),
      logEntries: [],
      evidence: [],
      loading: false,
      error: '',
    });

    renderWithProviders(<EvidenceTimeline jobId='job-abc-123' />);

    const link = screen.getByRole('link', { name: 'View audit log' });
    expect(link).toHaveAttribute('href', '/audit?q=job-abc-123');
  });

  it('renders the close button with an accessible name when onClose is provided', () => {
    const onClose = vi.fn();
    useCertOpsJobTimelineMock.mockReturnValue({
      job: baseJob(),
      logEntries: [],
      evidence: [],
      loading: false,
      error: '',
    });

    renderWithProviders(<EvidenceTimeline jobId='job-1' onClose={onClose} />);

    expect(
      screen.getByRole('button', { name: 'Close timeline' })
    ).toBeInTheDocument();
  });
});
