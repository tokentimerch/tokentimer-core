import { render, screen, within } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it } from 'vitest';
import AlertStateDisplay, {
  AlertEligibilityOverview,
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
  it('renders due eligibility independently from failed retrying delivery', () => {
    renderDisplay(
      {
        eligibility: {
          status: 'due',
          reason: 'threshold_reached',
          effective_threshold: 7,
          days_until_expiry: 5,
          eligible_channels: ['email'],
        },
        delivery: {
          status: 'failed',
          reason: 'retry_scheduled',
          created_at: '2026-09-13T07:45:00.000Z',
          latest_attempt: {
            id: 101,
            attempted_at: '2026-09-13T08:00:00.000Z',
          },
          next_attempt_at: '2026-09-13T09:00:00.000Z',
        },
      },
      { canViewAudit: true }
    );

    const eligibility = within(screen.getByTestId('alert-eligibility'));
    const delivery = within(screen.getByTestId('alert-delivery'));
    expect(eligibility.getByText('Due')).toBeInTheDocument();
    expect(eligibility.getByText(/7 days before expiry/)).toBeInTheDocument();
    expect(delivery.getByText('Failed')).toBeInTheDocument();
    expect(delivery.getByText(/attempt is scheduled/)).toBeInTheDocument();
    expect(delivery.getByText(/Latest alert:/)).toBeInTheDocument();
    expect(
      delivery.getByRole('link', { name: /View latest attempt/ })
    ).toHaveAttribute('href', '/audit?q=Production%20key');
    expect(delivery.getByText(/Next delivery attempt:/)).toBeInTheDocument();
  });

  it('renders suppressed eligibility independently from sent delivery', () => {
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
        latest_attempt: { attempted_at: '2026-09-12T08:00:00.000Z' },
      },
    });

    expect(screen.getByText('Suppressed')).toBeInTheDocument();
    expect(
      screen.getByText(/no eligible recipients or channels/)
    ).toBeInTheDocument();
    expect(screen.getByText('Sent')).toBeInTheDocument();
    expect(screen.getByText('The alert was delivered.')).toBeInTheDocument();
  });

  it('shows outside-threshold scheduling separately from an absent delivery', () => {
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
    expect(
      screen.getByText(/Next eligibility evaluation: 2026-10-01/)
    ).toBeInTheDocument();
    expect(screen.getByText('No alert')).toBeInTheDocument();
    expect(screen.getByText(/No alert has been generated/)).toBeInTheDocument();
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
