import {
  render,
  screen,
  fireEvent,
  waitFor,
  cleanup,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, afterEach, describe, it, expect, vi } from 'vitest';
import ApprovalDecisionModal from '../../src/components/certops/ApprovalDecisionModal.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import { getApprovalReview } from '../../src/components/certops/certopsJobsApi.js';

vi.mock('../../src/components/certops/certopsJobsApi.js', () => ({
  getApprovalReview: vi.fn(),
}));
const review = () => ({
  current: true,
  canApprove: true,
  reviewHash: 'a'.repeat(64),
  requester: { id: '2', name: '<script>Requester</script>' },
  connection: {
    id: 'connection-123',
    label: 'Untrusted client',
    expiresAt: new Date(Date.now() + 60000).toISOString(),
  },
  approvalExpiresAt: new Date(Date.now() + 30000).toISOString(),
  previewExpiresAt: new Date(Date.now() - 10000).toISOString(),
  effect: {
    operation: 'renew',
    renewalProfile: {
      ca: { endpoint: 'https://ca.example.test' },
      sanPolicy: { sans: ['app.example.test'] },
      deploymentTargets: [{ certPath: '/srv/tls/cert.pem' }],
    },
    standingRenewal: 'Creates no new automatic-renewal authority.',
  },
});
function show(props = {}) {
  const onDecide = vi.fn();
  const view = render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <ApprovalDecisionModal
          isOpen
          onClose={vi.fn()}
          workspaceId='ws'
          job={{
            id: 'job-1',
            operation: 'renew',
            requestedByConnectionId: 'connection-123',
          }}
          decision='approve'
          onDecide={onDecide}
          {...props}
        />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
  onDecide.view = view;
  return onDecide;
}
beforeEach(() => {
  vi.mocked(getApprovalReview).mockResolvedValue({ review: review() });
});
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});
describe('independent assistant request review', () => {
  it('retries a failed review without reopening the dialog', async () => {
    getApprovalReview.mockRejectedValueOnce(new Error('offline'));
    show();
    fireEvent.click(
      await screen.findByRole('button', { name: 'Retry review' })
    );
    expect(await screen.findByRole('checkbox')).not.toBeChecked();
    expect(
      screen.getByRole('button', { name: 'Approve', exact: true })
    ).toBeDisabled();
  });
  it('clears the previous job review and reason when switching jobs in place', async () => {
    const decide = show();
    fireEvent.click(await screen.findByRole('checkbox'));
    fireEvent.change(screen.getByLabelText('Reason (optional)'), {
      target: { value: 'First job only' },
    });
    getApprovalReview.mockReturnValue(new Promise(() => {}));
    decide.view.rerender(
      <ChakraProvider>
        <DashboardThemeProvider>
          <ApprovalDecisionModal
            isOpen
            onClose={vi.fn()}
            workspaceId='ws'
            job={{
              id: 'job-2',
              operation: 'renew',
              requestedByConnectionId: 'connection-123',
            }}
            decision='approve'
            onDecide={decide}
          />
        </DashboardThemeProvider>
      </ChakraProvider>
    );
    expect(screen.getByRole('status')).toHaveTextContent('Loading');
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Reason (optional)')).toHaveValue('');
    expect(
      screen.getByRole('button', { name: 'Approve', exact: true })
    ).toBeDisabled();
    expect(decide).not.toHaveBeenCalled();
  });
  it('keeps distinct legacy destinations and all settings reviewable', async () => {
    const value = review();
    value.effect.renewalProfile.target = { certPath: '/srv/other/cert.pem' };
    value.effect.renewalProfile.keyRotationPolicy = { rotateOnRenew: false };
    value.effect.executionRouting = { assignedAgentId: 'agent-one' };
    value.effect.futureField = 'future-value';
    getApprovalReview.mockResolvedValue({ review: value });
    show();
    expect(await screen.findByText('/srv/tls/cert.pem')).toBeVisible();
    expect(screen.getByText('/srv/other/cert.pem')).toBeVisible();
    expect(screen.getByText('agent-one')).toBeVisible();
    const details = screen
      .getByText('Renewal settings and request details')
      .closest('details');
    details.open = true;
    expect(screen.getByText('No')).toBeVisible();
    expect(screen.getByText('future-value')).toBeVisible();
  });
  it('shows an identical legacy destination once', async () => {
    const value = review();
    value.effect.renewalProfile.target =
      value.effect.renewalProfile.deploymentTargets[0];
    getApprovalReview.mockResolvedValue({ review: value });
    show();
    await screen.findByText('/srv/tls/cert.pem');
    expect(screen.getAllByText('/srv/tls/cert.pem')).toHaveLength(1);
  });

  it('requires the complete review and acknowledgement, then submits its binding', async () => {
    const decide = show();
    expect(
      screen.getByRole('button', { name: 'Approve', exact: true })
    ).toBeDisabled();
    await screen.findByText('Requested by');
    expect(screen.getByText('<script>Requester</script>')).toBeInTheDocument();
    expect(document.querySelector('script')).toBeNull();
    expect(screen.getByText('/srv/tls/cert.pem')).toBeInTheDocument();
    expect(
      screen
        .getAllByText('https://ca.example.test')
        .some(node => !node.closest('details'))
    ).toBe(true);
    // The preview expired after submission, but the approval window is open.
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(
      screen.getByRole('button', { name: 'Approve', exact: true })
    );
    await waitFor(() =>
      expect(decide).toHaveBeenCalledWith(undefined, 'a'.repeat(64))
    );
  });
  it.each([
    'missing',
    'failed',
    'expired',
    'changed',
    'connection expired',
    'malformed',
    'missing permission',
  ])('fails closed on %s review', async kind => {
    const value = review();
    if (kind === 'expired')
      value.approvalExpiresAt = new Date(Date.now() - 1).toISOString();
    if (kind === 'changed') value.current = false;
    if (kind === 'malformed') delete value.connection;
    if (kind === 'missing permission') delete value.canApprove;
    if (kind === 'connection expired')
      value.connection.expiresAt = new Date(Date.now() - 1).toISOString();
    if (kind === 'failed')
      getApprovalReview.mockRejectedValue(new Error('offline'));
    else
      getApprovalReview.mockResolvedValue({
        review: kind === 'missing' ? null : value,
      });
    const decide = show();
    await screen.findByRole('alert');
    expect(
      screen.getByRole('button', { name: 'Approve', exact: true })
    ).toBeDisabled();
    expect(decide).not.toHaveBeenCalled();
  });
  it('still permits rejection when review cannot load', async () => {
    getApprovalReview.mockRejectedValue(new Error('offline'));
    const decide = show({ decision: 'reject' });
    await screen.findByRole('alert');
    fireEvent.click(
      screen.getByRole('button', { name: 'Reject', exact: true })
    );
    await waitFor(() =>
      expect(decide).toHaveBeenCalledWith(undefined, undefined)
    );
  });
  it('disables self-approval before any decision request', async () => {
    getApprovalReview.mockResolvedValue({
      review: { ...review(), canApprove: false },
    });
    const decide = show();
    await screen.findByText(/You requested this job/);
    expect(
      screen.getByRole('button', { name: 'Approve', exact: true })
    ).toBeDisabled();
    expect(decide).not.toHaveBeenCalled();
  });
  it('expires an acknowledged review while the dialog stays open', async () => {
    getApprovalReview.mockResolvedValue({
      review: {
        ...review(),
        approvalExpiresAt: new Date(Date.now() + 1200).toISOString(),
      },
    });
    show();
    fireEvent.click(await screen.findByRole('checkbox'));
    expect(
      screen.getByRole('button', { name: 'Approve', exact: true })
    ).toBeEnabled();
    await waitFor(
      () =>
        expect(
          screen.getByRole('button', { name: 'Approve', exact: true })
        ).toBeDisabled(),
      { timeout: 3000 }
    );
  });
  it('discards acknowledgement after the server refuses the displayed review', async () => {
    show({ onDecide: vi.fn().mockResolvedValue(false) });
    fireEvent.click(await screen.findByRole('checkbox'));
    fireEvent.click(
      screen.getByRole('button', { name: 'Approve', exact: true })
    );
    await screen.findByRole('alert');
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Approve', exact: true })
    ).toBeDisabled();
  });
  it('ignores a late result from a different job and resets acknowledgement', async () => {
    let finish;
    getApprovalReview.mockReturnValue(
      new Promise(resolve => {
        finish = resolve;
      })
    );
    show();
    cleanup();
    getApprovalReview.mockResolvedValue({
      review: { ...review(), current: false },
    });
    show({
      job: {
        id: 'job-2',
        operation: 'renew',
        requestedByConnectionId: 'other',
      },
    });
    finish({ review: review() });
    await screen.findByRole('alert');
    expect(
      screen.getByRole('button', { name: 'Approve', exact: true })
    ).toBeDisabled();
  });
});
