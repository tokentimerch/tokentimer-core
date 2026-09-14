import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import AlertStateDisplay from '../../src/components/AlertStateDisplay.jsx';
import AlertLifecycleTimeline, {
  AlertLifecycleEventRow,
} from '../../src/components/AlertLifecycleTimeline.jsx';

const { getAlertTimelineMock } = vi.hoisted(() => ({
  getAlertTimelineMock: vi.fn(),
}));

vi.mock('../../src/utils/apiClient', async importOriginal => {
  const actual = await importOriginal();
  return {
    ...actual,
    tokenAPI: {
      ...actual.tokenAPI,
      getAlertTimeline: getAlertTimelineMock,
    },
  };
});

function event(overrides = {}) {
  return {
    id: 'delivery:1',
    type: 'delivery_failed',
    occurred_at: '2026-09-13T08:04:00.000Z',
    token_id: 17,
    token_name: 'Production key',
    workspace_id: 'workspace-1',
    alert_id: 9,
    threshold_days: 7,
    channel: 'email',
    status: 'failed',
    reason: 'delivery_error',
    error_message: 'SMTP timeout '.repeat(20),
    metadata: {},
    source: 'alert_delivery_log',
    ...overrides,
  };
}

function renderTimeline(children) {
  return render(
    <ChakraProvider>
      <MemoryRouter>{children}</MemoryRouter>
    </ChakraProvider>
  );
}

describe('AlertLifecycleTimeline', () => {
  beforeEach(() => {
    getAlertTimelineMock.mockReset();
  });

  it('renders current eligibility/delivery independently from historical events', async () => {
    getAlertTimelineMock.mockResolvedValue({
      items: [
        event(),
        event({
          id: 'queue:9',
          type: 'alert_queued',
          occurred_at: '2026-09-13T08:03:00.000Z',
          channel: null,
          error_message: null,
        }),
      ],
      pagination: { limit: 20, offset: 0, hasMore: false },
    });

    renderTimeline(
      <>
        <AlertStateDisplay
          alertState={{
            eligibility: {
              status: 'suppressed',
              reason: 'retired_certificate',
              days_until_expiry: -1,
            },
            delivery: { status: 'sent' },
          }}
          tokenName='Production key'
          tokenId={17}
          canViewAudit={false}
        />
        <AlertLifecycleTimeline
          tokenId={17}
          alertState={{
            eligibility: { next_evaluation_at: '2026-09-20' },
            delivery: { next_attempt_at: '2026-09-13T09:00:00.000Z' },
          }}
        />
      </>
    );

    expect(await screen.findByText('Delivery failed')).toBeInTheDocument();
    expect(screen.getByText('Suppressed')).toBeInTheDocument();
    expect(screen.getByText('Sent')).toBeInTheDocument();
    expect(screen.getByText('Alert queued')).toBeInTheDocument();
    expect(screen.getByText('Upcoming')).toBeInTheDocument();
    expect(
      screen.queryByRole('link', { name: /audit/i })
    ).not.toBeInTheDocument();

    const regionText = screen.getByRole('region', {
      name: 'Alert history',
    }).textContent;
    expect(regionText.indexOf('Alert queued')).toBeLessThan(
      regionText.indexOf('Delivery failed')
    );
  });

  it('supports paginated load-more without replacing the current page', async () => {
    getAlertTimelineMock
      .mockResolvedValueOnce({
        items: [event()],
        pagination: { limit: 1, offset: 0, hasMore: true },
      })
      .mockResolvedValueOnce({
        items: [
          event({
            id: 'queue:9',
            type: 'alert_queued',
            occurred_at: '2026-09-13T08:03:00.000Z',
            error_message: null,
          }),
        ],
        pagination: { limit: 1, offset: 1, hasMore: false },
      });

    renderTimeline(<AlertLifecycleTimeline tokenId={17} pageSize={1} />);
    await screen.findByText('Delivery failed');
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));
    expect(await screen.findByText('Alert queued')).toBeInTheDocument();
    await waitFor(() => expect(getAlertTimelineMock).toHaveBeenCalledTimes(2));
    expect(getAlertTimelineMock).toHaveBeenLastCalledWith(17, 1, 1);
  });

  it('renders workspace activity with an asset deep link and relative time', () => {
    renderTimeline(
      <AlertLifecycleEventRow
        event={event({
          type: 'delivery_succeeded',
          occurred_at: new Date().toISOString(),
          error_message: null,
        })}
        showAsset
        workspaceId='workspace-1'
        relativeTime
      />
    );

    expect(screen.getByText('Alert sent')).toBeInTheDocument();
    expect(screen.getByText('Just now')).toBeInTheDocument();
    expect(
      screen.getByRole('link', { name: 'Production key' })
    ).toHaveAttribute('href', '/dashboard?workspace=workspace-1&token-id=17');
  });
});
