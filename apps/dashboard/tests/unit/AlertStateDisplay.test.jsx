import { render, screen, within } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it } from 'vitest';
import AlertStateDisplay, {
  AlertEligibilityOverview,
  AlertUpcomingSection,
  getUpcomingThresholds,
} from '../../src/components/AlertStateDisplay.jsx';
import AssetInventoryTable from '../../src/components/AssetInventoryTable.jsx';

function renderDisplay(alertState, props = {}) {
  return render(
    <ChakraProvider>
      <MemoryRouter>
        <AlertStateDisplay
          alertState={alertState}
          tokenName='Production key'
          tokenId={17}
          {...props}
        />
      </MemoryRouter>
    </ChakraProvider>
  );
}

describe('AlertStateDisplay', () => {
  it('renders a compact current-status view without repeating badge prose', () => {
    renderDisplay(
      {
        eligibility: {
          status: 'due',
          reason: 'threshold_reached',
          effective_threshold: 7,
          days_until_expiry: 5,
          eligible_channels: ['email', 'webhooks'],
        },
        delivery: {
          status: 'failed',
          reason: 'retry_scheduled',
          created_at: '2026-09-13T07:45:00.000Z',
          latest_attempt: {
            id: 101,
            channel: 'email',
            attempted_at: '2026-09-13T08:00:00.000Z',
          },
          next_attempt_at: '2026-09-13T09:00:00.000Z',
        },
      },
      {}
    );

    const eligibility = within(screen.getByTestId('alert-eligibility'));
    const delivery = within(screen.getByTestId('alert-delivery'));
    expect(eligibility.getByText('Due')).toBeInTheDocument();
    expect(eligibility.getByText('Expires in: 5 days')).toBeInTheDocument();
    expect(
      eligibility.getByText('Current threshold: 7 days before expiry')
    ).toBeInTheDocument();
    expect(
      eligibility.getByText('Channels: Email, Webhooks')
    ).toBeInTheDocument();
    expect(delivery.getByText('Failed')).toBeInTheDocument();
    expect(delivery.getByText(/Last delivery: Email ·/)).toBeInTheDocument();
    expect(
      delivery.queryByText(/Previous alert:/)
    ).not.toBeInTheDocument();
    expect(
      delivery.getByRole('link', { name: /View latest attempt/ })
    ).toHaveAttribute(
      'href',
      '/dashboard?token-id=17&alert-event=delivery%3A101'
    );
    expect(
      screen.queryByText(/7 days before expiry has been reached/)
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/Latest alert:/)).not.toBeInTheDocument();
    expect(screen.queryByText(/attempt is scheduled/)).not.toBeInTheDocument();
  });

  it('labels delivery as a previous alert when thresholds differ', () => {
    renderDisplay({
      eligibility: {
        status: 'due',
        reason: 'threshold_reached',
        effective_threshold: 7,
        days_until_expiry: 5,
      },
      delivery: {
        status: 'sent',
        threshold_days: 14,
        latest_attempt: {
          id: 55,
          channel: 'email',
          attempted_at: '2026-09-01T08:00:00.000Z',
        },
      },
    });
    const delivery = within(screen.getByTestId('alert-delivery'));
    expect(
      delivery.getByText('Previous alert: 14 days before expiry')
    ).toBeInTheDocument();
    expect(delivery.getByText(/Last delivery: Email ·/)).toBeInTheDocument();
    expect(
      within(screen.getByTestId('alert-eligibility')).getByText(
        'Current threshold: 7 days before expiry'
      )
    ).toBeInTheDocument();
  });

  it('omits Previous alert when delivery and eligibility thresholds match', () => {
    renderDisplay({
      eligibility: {
        status: 'due',
        effective_threshold: 0,
        days_until_expiry: 0,
      },
      delivery: {
        status: 'sent',
        threshold_days: 0,
        latest_attempt: {
          id: 56,
          channel: 'email',
          attempted_at: '2026-09-15T08:00:00.000Z',
        },
      },
    });
    expect(screen.queryByText(/Previous alert:/)).not.toBeInTheDocument();
    expect(screen.getByText('Current threshold: Expiry day')).toBeInTheDocument();
  });

  it('calls queue timestamps Last queue attempt without a delivery-log id', () => {
    renderDisplay({
      eligibility: { status: 'due', effective_threshold: 7, days_until_expiry: 5 },
      delivery: {
        status: 'failed',
        last_attempt_at: '2026-09-13T08:00:00.000Z',
        latest_attempt: { id: null, attempted_at: '2026-09-13T08:00:00.000Z' },
      },
    });
    const delivery = within(screen.getByTestId('alert-delivery'));
    expect(delivery.getByText(/Last queue attempt ·/)).toBeInTheDocument();
    expect(delivery.queryByText(/Last delivery/)).not.toBeInTheDocument();
    expect(
      delivery.queryByRole('link', { name: /View latest attempt/ })
    ).not.toBeInTheDocument();
  });

  it('labels discarded queue dispositions without implying a send', () => {
    renderDisplay({
      eligibility: { status: 'due', effective_threshold: 7, days_until_expiry: 5 },
      delivery: {
        status: 'discarded',
        reason: 'endpoint_recovered',
        last_attempt_at: '2026-09-13T08:00:00.000Z',
        latest_attempt: { id: null, attempted_at: '2026-09-13T08:00:00.000Z' },
      },
    });
    const delivery = within(screen.getByTestId('alert-delivery'));
    expect(delivery.getByText(/Discarded ·/)).toBeInTheDocument();
    expect(delivery.queryByText(/Last delivery/)).not.toBeInTheDocument();
    expect(delivery.queryByText(/Last queue attempt/)).not.toBeInTheDocument();
  });

  it('shows View latest attempt for readers with a real delivery-log id', () => {
    renderDisplay({
      eligibility: { status: 'due', effective_threshold: 7, days_until_expiry: 5 },
      delivery: {
        status: 'failed',
        latest_attempt: {
          id: 101,
          channel: 'email',
          attempted_at: '2026-09-13T08:00:00.000Z',
        },
      },
    });
    expect(
      screen.getByRole('link', { name: /View latest attempt/ })
    ).toBeInTheDocument();
  });

  it('lists upcoming thresholds and delivery retries in Upcoming', () => {
    render(
      <ChakraProvider>
        <AlertUpcomingSection
          alertState={{
            eligibility: {
              status: 'outside_threshold',
              days_until_expiry: 20,
              effective_thresholds: [30, 14, 7, 1, 0],
              metadata: { expiration_date: '2026-10-05' },
            },
            delivery: { next_attempt_at: '2026-09-13T09:00:00.000Z' },
          }}
        />
      </ChakraProvider>
    );

    expect(screen.getByText(/Next threshold:/)).toBeInTheDocument();
    expect(screen.getByText(/14 days before expiry/)).toBeInTheDocument();
    expect(screen.getByText(/Then:/)).toBeInTheDocument();
    expect(screen.getByText(/Next delivery attempt:/)).toBeInTheDocument();
  });

  it('says when no further thresholds are configured', () => {
    render(
      <ChakraProvider>
        <AlertUpcomingSection
          alertState={{
            eligibility: {
              status: 'due',
              days_until_expiry: 0,
              effective_threshold: 0,
              effective_thresholds: [7, 0],
            },
            delivery: null,
          }}
        />
      </ChakraProvider>
    );
    expect(
      screen.getByText('No further thresholds configured')
    ).toBeInTheDocument();
  });

  it('computes upcoming thresholds after the active window', () => {
    expect(
      getUpcomingThresholds({
        days_until_expiry: 5,
        effective_thresholds: [30, 14, 7, 1, 0],
        metadata: { expiration_date: '2026-09-20' },
      }).map(item => item.threshold)
    ).toEqual([1, 0]);
  });

  it('renders suppressed eligibility without delivery prose', () => {
    renderDisplay({
      eligibility: {
        status: 'suppressed',
        reason: 'no_eligible_channels',
        effective_threshold: 0,
        days_until_expiry: 0,
        eligible_channels: [],
      },
      delivery: {
        status: 'sent',
        latest_attempt: {
          id: 9,
          channel: 'email',
          attempted_at: '2026-09-12T08:00:00.000Z',
        },
      },
    });

    expect(screen.getByText('Suppressed')).toBeInTheDocument();
    expect(screen.getByText('Expires today')).toBeInTheDocument();
    expect(screen.getByText('Sent')).toBeInTheDocument();
    expect(
      screen.queryByText(/no eligible recipients or channels/)
    ).not.toBeInTheDocument();
    expect(screen.queryByText('The alert was delivered.')).not.toBeInTheDocument();
  });

  it('shows outside-threshold current status without next-evaluation prose', () => {
    renderDisplay({
      eligibility: {
        status: 'outside_threshold',
        reason: 'threshold_not_reached',
        effective_threshold: null,
        next_threshold: 30,
        next_evaluation_at: '2026-10-01',
        days_until_expiry: 45,
        eligible_channels: ['email'],
      },
      delivery: null,
    });

    expect(screen.getByText('Outside threshold')).toBeInTheDocument();
    expect(screen.getByText('No alert')).toBeInTheDocument();
    expect(screen.getByText('No delivery yet')).toBeInTheDocument();
    expect(
      screen.queryByText(/Next eligibility evaluation/)
    ).not.toBeInTheDocument();
  });
});

describe('AlertEligibilityOverview', () => {
  it('keeps eligibility and latest delivery visible as separate columns', () => {
    render(
      <ChakraProvider>
        <MemoryRouter>
          <AlertEligibilityOverview
            tokens={[
              {
                id: 17,
                name: 'Production key',
                alert_state: {
                  eligibility: {
                    status: 'suppressed',
                    reason: 'retired_certificate',
                    effective_threshold: null,
                    days_until_expiry: -3,
                  },
                  delivery: {
                    status: 'sent',
                    latest_attempt: {
                      id: 102,
                      attempted_at: '2026-09-12T08:00:00.000Z',
                    },
                  },
                },
              },
            ]}
          />
        </MemoryRouter>
      </ChakraProvider>
    );

    expect(screen.getAllByText('Suppressed').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Sent').length).toBeGreaterThan(0);
    expect(
      screen.getAllByRole('link', { name: /View latest attempt/ }).length
    ).toBeGreaterThan(0);
  });
});

describe('AssetInventoryTable alert eligibility', () => {
  it('shows eligibility without presenting delivery as asset status', () => {
    render(
      <ChakraProvider>
        <MemoryRouter>
          <AssetInventoryTable
            tokens={[
              {
                id: 17,
                name: 'Production key',
                category: 'general',
                expiresAt: '2026-09-18',
                alert_state: {
                  eligibility: {
                    status: 'due',
                    reason: 'threshold_reached',
                    effective_threshold: 7,
                    days_until_expiry: 5,
                  },
                  delivery: { status: 'failed' },
                },
              },
            ]}
            selectedCategories={[]}
            visibleCount={1}
            allTokensCount={1}
            sortedVisibleCount={1}
            isViewer
            onOpenTokenModal={() => {}}
            onOpenRenew={() => {}}
            onDeleteToken={() => {}}
            getAssetTypeLabel={() => 'General'}
            getCategoryLabel={() => 'General'}
            getStatusMeta={() => ({ label: 'Healthy', color: 'green.400' })}
            getTokenLocation={() => '-'}
            getTokenOwner={() => '-'}
          />
        </MemoryRouter>
      </ChakraProvider>
    );

    expect(screen.getAllByText('Due').length).toBeGreaterThan(0);
    expect(screen.queryByText('Failed')).not.toBeInTheDocument();
  });
});
