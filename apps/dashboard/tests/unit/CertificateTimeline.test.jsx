import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';

import CertificateTimeline from '../../src/components/certops/CertificateTimeline.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const { useCertOpsJobsMock } = vi.hoisted(() => ({
  useCertOpsJobsMock: vi.fn(),
}));

vi.mock('../../src/components/certops/useCertOpsJobs.js', () => ({
  useCertOpsJobs: useCertOpsJobsMock,
}));

vi.mock('../../src/components/certops/EvidenceTimeline.jsx', () => ({
  default: ({ jobId, compact }) => (
    <div data-compact={String(Boolean(compact))}>Timeline for {jobId}</div>
  ),
}));

function renderTimeline(props = {}) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <CertificateTimeline subjectId='certificate-1' {...props} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

describe('CertificateTimeline', () => {
  beforeEach(() => {
    useCertOpsJobsMock.mockReset();
    useCertOpsJobsMock.mockReturnValue({
      enabled: true,
      jobs: [
        {
          id: 'job-latest',
          operation: 'reload',
          status: 'running',
          createdAt: '2026-08-29T10:33:00.000Z',
        },
        {
          id: 'job-previous',
          operation: 'renew',
          status: 'succeeded',
          createdAt: '2026-07-20T10:33:00.000Z',
        },
      ],
      pagination: null,
      loading: false,
      error: '',
    });
  });

  it('expands the latest job by default when requested', async () => {
    renderTimeline({ defaultLatestExpanded: true, compact: true });

    const latest = await screen.findByText('Timeline for job-latest');
    expect(latest).toHaveAttribute('data-compact', 'true');
    expect(
      screen.queryByText('Timeline for job-previous')
    ).not.toBeInTheDocument();
  });

  it('allows a previous job to replace the expanded latest job', async () => {
    renderTimeline({ defaultLatestExpanded: true, compact: true });
    await screen.findByText('Timeline for job-latest');

    fireEvent.click(screen.getByRole('button', { name: /Renew/ }));

    expect(
      await screen.findByText('Timeline for job-previous')
    ).toBeInTheDocument();
    expect(
      screen.queryByText('Timeline for job-latest')
    ).not.toBeInTheDocument();
  });

  it('omits its section wrapper when no jobs are available', () => {
    useCertOpsJobsMock.mockReturnValue({
      enabled: true,
      jobs: [],
      pagination: null,
      loading: false,
      error: '',
    });

    renderTimeline({
      hideWhenEmpty: true,
      renderContainer: content => (
        <section aria-label='Job history'>{content}</section>
      ),
    });

    expect(
      screen.queryByRole('region', { name: 'Job history' })
    ).not.toBeInTheDocument();
    expect(screen.queryByText('No jobs found.')).not.toBeInTheDocument();
  });

  it('renders its section wrapper when job data exists', async () => {
    renderTimeline({
      hideWhenEmpty: true,
      renderContainer: content => (
        <section aria-label='Job history'>{content}</section>
      ),
    });

    expect(
      await screen.findByRole('region', { name: 'Job history' })
    ).toBeInTheDocument();
  });
});
