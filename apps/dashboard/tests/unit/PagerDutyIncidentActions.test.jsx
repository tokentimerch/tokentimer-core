import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import PagerDutyIncidentActions from '../../src/components/PagerDutyIncidentActions.jsx';

const { api } = vi.hoisted(() => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn() },
}));
vi.mock('../../src/utils/apiClient.js', () => ({ default: api }));
vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: 'workspace' }),
}));
const incident = {
  id: 'incident',
  state: 'open',
  original_expiration: '2026-11-03',
  remote_incident_url: 'https://example.pagerduty.com/incidents/P123',
};
const show = () =>
  render(
    <ChakraProvider>
      <PagerDutyIncidentActions tokenId={7} enabled />
    </ChakraProvider>
  );

describe('PagerDuty token actions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.get.mockResolvedValue({
      data: { incidents: [incident], canManage: true },
    });
    api.post.mockResolvedValue({ data: { success: true } });
  });
  it('offers incident actions without REST credentials or incident lookup and requires a confirmed reason to resolve', async () => {
    show();
    await screen.findByRole('button', { name: 'Resolve' });
    expect(
      screen.queryByRole('link', { name: 'Open in PagerDuty' })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Configure incident lookup' })
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Resolve' }));
    expect(api.post).not.toHaveBeenCalled();
    const confirm = await screen.findByRole('button', {
      name: 'Confirm resolve',
    });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByRole('textbox', { name: /Reason/ }), {
      target: { value: 'Handled by operations' },
    });
    fireEvent.click(confirm);
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/workspaces/workspace/pagerduty-incidents/incident/actions',
        { action: 'resolve', confirmed: true, reason: 'Handled by operations' }
      )
    );
  });
  it('shows viewers lifecycle state without management actions', async () => {
    api.get.mockResolvedValue({
      data: { incidents: [incident], canManage: false },
    });
    show();
    await screen.findByText('Expiration 2026-11-03 · open');
    expect(
      screen.queryByRole('button', { name: 'Acknowledge' })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Resolve' })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Configure incident lookup' })
    ).not.toBeInTheDocument();
  });
  it('allows another ACK request after the previous delivery budget was exhausted', async () => {
    api.get.mockResolvedValue({
      data: {
        incidents: [
          {
            ...incident,
            acknowledge_requested_at: '2026-11-02',
            acknowledge_exhausted: true,
          },
        ],
        canManage: true,
      },
    });
    show();
    const acknowledge = await screen.findByRole('button', {
      name: 'Acknowledge',
    });
    expect(acknowledge).toBeEnabled();
    fireEvent.click(acknowledge);
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/workspaces/workspace/pagerduty-incidents/incident/actions',
        { action: 'acknowledge' }
      )
    );
  });
  it('requests ACK and reports provider acceptance separately from remote status', async () => {
    show();
    fireEvent.click(await screen.findByRole('button', { name: 'Acknowledge' }));
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/workspaces/workspace/pagerduty-incidents/incident/actions',
        { action: 'acknowledge' }
      )
    );
  });
});
