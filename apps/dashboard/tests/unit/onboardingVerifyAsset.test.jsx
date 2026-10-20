import { render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { actions } = vi.hoisted(() => ({
  actions: { getToken: vi.fn(), soonestToken: vi.fn() },
}));

vi.mock('../../src/utils/onboardingActions.js', () => ({
  onboardingActions: actions,
}));

import { VerifyStep } from '../../src/components/onboarding/recipientAndVerifySteps.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const summaryOf = ({ tokens, assets }) => ({
  monitors: { total: 0, items: [] },
  references: {
    tokenIds: { existing: tokens, missing: [] },
    assetTokenIds: { existing: assets, missing: [] },
    monitorIds: { existing: [], missing: [] },
  },
  alerts: { smtpConfigured: true },
  assets: { total: 2 },
});

function mount({ refs, summary, skipped = [] }) {
  const ctx = {
    workspaceId: 'ws-1',
    docs: () => [],
    refresh: vi.fn().mockResolvedValue(undefined),
    fetchSummary: vi.fn().mockResolvedValue(summary),
    session: {
      intent: { goal: 'track_asset' },
      progress: { skipped },
      operationRefs: refs,
    },
    controller: { update: vi.fn() },
  };
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <VerifyStep ctx={ctx} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

beforeEach(() => {
  actions.getToken.mockReset().mockResolvedValue({
    alert_state: { eligibility: { eligible_channels: ['email'] } },
  });
  actions.soonestToken.mockReset().mockResolvedValue({
    alert_state: { eligibility: { eligible_channels: ['email'] } },
  });
});

describe('VerifyStep for the asset goal', () => {
  it('checks the asset made in the asset step, not a website certificate', async () => {
    mount({
      refs: { monitorIds: ['m1'], tokenIds: [7, 8], assetTokenIds: [8] },
      summary: summaryOf({ tokens: [7, 8], assets: [8] }),
    });
    await waitFor(() => expect(actions.getToken).toHaveBeenCalledWith(8));
    expect(actions.getToken).not.toHaveBeenCalledWith(7);
  });

  it('fails the asset check when only website certificates remain', async () => {
    mount({
      refs: { monitorIds: ['m1'], tokenIds: [7], assetTokenIds: [8] },
      summary: summaryOf({ tokens: [7], assets: [] }),
    });
    expect(await screen.findByText('Asset exists')).toBeTruthy();
    expect(screen.getByText('Needs attention')).toBeTruthy();
    expect(actions.getToken).not.toHaveBeenCalled();
    expect(actions.soonestToken).not.toHaveBeenCalled();
  });

  it('samples a workspace asset when the asset step was skipped', async () => {
    mount({
      refs: { monitorIds: ['m1'], tokenIds: [7] },
      summary: summaryOf({ tokens: [7], assets: [] }),
      skipped: ['asset'],
    });
    await waitFor(() => expect(actions.soonestToken).toHaveBeenCalled());
  });
});
