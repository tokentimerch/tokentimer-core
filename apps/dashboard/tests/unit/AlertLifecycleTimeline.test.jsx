import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import AlertStateDisplay, {
  AlertEligibilityOverview,
  AlertUpcomingSection,
} from '../../src/components/AlertStateDisplay.jsx';
import AlertLifecycleTimeline, {
  AlertLifecycleEventRow,
  formatAlertLifecycleEventTime,
  groupAlertLifecycleEvents,
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

  it('renders current status independently from history groups', async () => {
    getAlertTimelineMock.mockResolvedValue({
      items: [
        event(),
        event({
          id: 'queue:9',
          type: 'alert_queued',
          occurred_at: '2026-09-13T08:03:00.000Z',
          channel: null,
          error_message: null,
          reason: null,
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
        <AlertUpcomingSection
          alertState={{
            eligibility: {
              days_until_expiry: 20,
              effective_thresholds: [30, 14, 7],
              metadata: { expiration_date: '2026-10-05' },
            },
            delivery: { next_attempt_at: '2026-09-13T09:00:00.000Z' },
          }}
        />
        <AlertLifecycleTimeline tokenId={17} compact />
      </>
    );

    expect(await screen.findByText(/Delivery failed · Email ·/)).toBeInTheDocument();
    expect(screen.getByText('Suppressed')).toBeInTheDocument();
    expect(screen.getByText('Sent')).toBeInTheDocument();
    expect(screen.getByText(/Alert queued ·/)).toBeInTheDocument();
    expect(screen.getByText('7-day threshold')).toBeInTheDocument();
    expect(screen.getByText('Upcoming')).toBeInTheDocument();
    expect(
      screen.queryByRole('link', { name: /audit/i })
    ).not.toBeInTheDocument();

    const history = screen.getByRole('region', { name: 'Alert history' });
    expect(history.textContent.indexOf('Alert queued')).toBeLessThan(
      history.textContent.indexOf('Delivery failed')
    );
  });

  it('groups history by threshold and keeps the threshold badge once', async () => {
    getAlertTimelineMock.mockResolvedValue({
      items: [
        event({
          id: 'delivery:2',
          type: 'delivery_succeeded',
          occurred_at: '2026-09-15T07:31:00.000Z',
          threshold_days: 30,
          error_message: null,
          reason: null,
        }),
        event({
          id: 'queue:2',
          type: 'alert_queued',
          occurred_at: '2026-09-15T06:31:00.000Z',
          threshold_days: 30,
          channel: null,
          error_message: null,
          reason: null,
        }),
        event({
          id: 'threshold:2',
          type: 'threshold_reached',
          occurred_at: '2026-09-07T00:00:00.000Z',
          threshold_days: 30,
          channel: null,
          error_message: null,
          reason: null,
        }),
        event({
          id: 'queue:1',
          type: 'alert_queued',
          occurred_at: '2026-09-13T08:03:00.000Z',
          threshold_days: 14,
          channel: null,
          error_message: null,
          reason: null,
        }),
      ],
      pagination: { limit: 20, offset: 0, hasMore: false },
    });

    renderTimeline(<AlertLifecycleTimeline tokenId={17} compact />);
    expect(await screen.findByText('30-day threshold')).toBeInTheDocument();
    expect(screen.getByText('14-day threshold')).toBeInTheDocument();
    expect(screen.getAllByText('30-day threshold')).toHaveLength(1);
    expect(screen.getByText(/^Reached /)).toBeInTheDocument();
    expect(screen.getAllByText(/^Reached /)).toHaveLength(1);
  });

  it('expands history rows with extra details only', async () => {
    getAlertTimelineMock.mockResolvedValue({
      items: [event({ threshold_days: 7 })],
      pagination: { limit: 20, offset: 0, hasMore: false },
    });
    renderTimeline(<AlertLifecycleTimeline tokenId={17} compact />);
    const row = await screen.findByRole('button', {
      name: /Delivery failed · Email ·/,
    });
    expect(row).toHaveAttribute('aria-expanded', 'false');
    fireEvent.click(row);
    expect(row).toHaveAttribute('aria-expanded', 'true');
    await waitFor(() => {
      expect(screen.getByText(/SMTP timeout/)).toBeVisible();
    });
    expect(screen.getAllByRole('button', { name: /Delivery failed/ })).toHaveLength(
      1
    );
  });

  it('uses a date-only label for threshold reached events', () => {
    expect(
      formatAlertLifecycleEventTime({
        type: 'threshold_reached',
        occurred_at: '2026-09-07T00:00:00.000Z',
      })
    ).toBe(new Date('2026-09-07T00:00:00.000Z').toLocaleDateString());
  });

  it('orders grouped thresholds from widest to nearest', () => {
    const groups = groupAlertLifecycleEvents([
      event({ id: 'a', threshold_days: 7 }),
      event({ id: 'b', threshold_days: 30 }),
      event({ id: 'c', threshold_days: null, type: 'alert_requeued' }),
    ]);
    expect(groups.map(group => group.threshold_days)).toEqual([30, 7, null]);
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
            reason: null,
            channel: null,
          }),
        ],
        pagination: { limit: 1, offset: 1, hasMore: false },
      });

    renderTimeline(<AlertLifecycleTimeline tokenId={17} pageSize={1} compact />);
    await screen.findByText(/Delivery failed · Email ·/);
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));
    expect(await screen.findByText(/Alert queued ·/)).toBeInTheDocument();
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

    expect(screen.getByText(/Alert sent · Email/)).toBeInTheDocument();
    expect(screen.getByText('Just now')).toBeInTheDocument();
    expect(
      screen.getByRole('link', { name: 'Production key' })
    ).toHaveAttribute('href', '/dashboard?workspace=workspace-1&token-id=17');
  });

  it('labels discarded alerts separately from successful delivery in both views', () => {
    renderTimeline(<>
      <AlertStateDisplay alertState={{ eligibility: { status: 'suppressed',
        reason: 'retired_certificate' }, delivery: { status: 'discarded',
        reason: 'retired_certificate' } }} tokenId={17} />
      <AlertLifecycleEventRow event={event({ type: 'alert_discarded',
        status: 'discarded', reason: 'retired_certificate',
        error_message: 'Discarded: certificate revoked or decommissioned' })} />
    </>);
    expect(screen.getByText('Discarded')).toBeInTheDocument();
    expect(screen.getByText(/Alert discarded/)).toBeInTheDocument();
    expect(screen.queryByText('Alert sent')).not.toBeInTheDocument();
  });

  it('does not label an unverified closed queue as a sent alert', () => {
    renderTimeline(<AlertStateDisplay alertState={{
      eligibility: { status: 'due', reason: 'threshold_reached' },
      delivery: { status: 'sent_unverified', reason: 'delivery_unverified' },
    }} tokenId={17} />);
    expect(screen.getByText('Delivery unverified')).toBeInTheDocument();
    expect(screen.queryByText('Sent')).not.toBeInTheDocument();
  });

  it('links View latest attempt only for a persisted delivery-log attempt', () => {
    const fallbackDelivery = {
      status: 'failed', last_attempt_at: '2026-09-13T08:00:00Z',
      latest_attempt: { id: null, attempted_at: '2026-09-13T08:00:00Z' },
    };
    const eligibility = { status: 'due', reason: 'threshold_reached' };
    renderTimeline(<>
      <AlertStateDisplay alertState={{ eligibility, delivery: fallbackDelivery }}
        tokenName='Production key' tokenId={17} canViewAudit />
      <AlertEligibilityOverview workspaceId='workspace-1' tokens={[{
        id: 17, name: 'Production key', alert_state: {
          eligibility, delivery: fallbackDelivery,
        },
      }]} />
    </>);
    expect(screen.getAllByText(/Last delivery/).length).toBeGreaterThan(0);
    expect(screen.queryByRole('link', { name: /View latest attempt/i }))
      .not.toBeInTheDocument();
  });

  it('keeps the attempt link when the latest attempt has a delivery-log ID', () => {
    renderTimeline(<AlertStateDisplay alertState={{
      eligibility: { status: 'due', reason: 'threshold_reached' },
      delivery: { status: 'failed', latest_attempt: {
        id: 104, attempted_at: '2026-09-13T08:00:00Z', status: 'failed',
      } },
    }} tokenName='Production key' tokenId={17} canViewAudit />);
    expect(screen.getByRole('link', { name: /View latest attempt/i }))
      .toHaveAttribute(
        'href',
        '/dashboard?token-id=17&alert-event=delivery%3A104'
      );
  });

  it('expands and focuses the deep-linked delivery lifecycle event', async () => {
    getAlertTimelineMock.mockResolvedValue({
      items: [
        {
          id: 'delivery:104',
          type: 'delivery_failed',
          occurred_at: '2026-09-13T08:00:00.000Z',
          channel: 'email',
          threshold_days: 7,
          error_message: 'SMTP timeout',
        },
        {
          id: 'delivery:99',
          type: 'delivery_succeeded',
          occurred_at: '2026-09-12T08:00:00.000Z',
          channel: 'email',
          threshold_days: 7,
        },
      ],
      pagination: { limit: 20, offset: 0, hasMore: false },
    });
    renderTimeline(
      <AlertLifecycleTimeline
        tokenId={17}
        compact
        focusEventId='delivery:104'
      />
    );
    expect(
      await screen.findByRole('button', { name: /Delivery failed · Email ·/ })
    ).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByText('SMTP timeout')).toBeInTheDocument();
    expect(
      document.querySelector('[data-alert-event-id="delivery:104"]')
    ).toBeTruthy();
  });
});
