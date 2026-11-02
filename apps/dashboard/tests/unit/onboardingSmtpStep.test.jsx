import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { actions } = vi.hoisted(() => ({
  actions: {
    getSystemSettings: vi.fn(),
    putSmtpSettings: vi.fn(),
    testSmtp: vi.fn(),
    getAlertSettings: vi.fn(),
  },
}));

vi.mock('../../src/utils/onboardingActions.js', () => ({
  onboardingActions: actions,
}));

import {
  NotificationsStep,
  SmtpStep,
} from '../../src/components/onboarding/notificationSteps.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const wrap = ui =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>{ui}</DashboardThemeProvider>
    </ChakraProvider>
  );

const ctxOf = (extra = {}) => ({
  isSystemAdmin: true,
  userEmail: 'ana@example.com',
  docs: () => [],
  refresh: vi.fn().mockResolvedValue(undefined),
  skip: vi.fn(),
  summary: { alerts: { smtpConfigured: false } },
  ...extra,
});

beforeEach(() => {
  actions.getSystemSettings.mockReset().mockResolvedValue({ smtp: {} });
  actions.getAlertSettings.mockReset().mockResolvedValue({});
});

describe('SmtpStep wording', () => {
  it('uses the same title as the steps list in every state', async () => {
    const unconfigured = wrap(<SmtpStep ctx={ctxOf()} />);
    expect(
      await screen.findByRole('heading', { name: 'Email delivery' })
    ).toBeVisible();
    unconfigured.unmount();

    const handoff = wrap(<SmtpStep ctx={ctxOf({ isSystemAdmin: false })} />);
    expect(
      await screen.findByRole('heading', { name: 'Email delivery' })
    ).toBeVisible();
    handoff.unmount();

    wrap(
      <SmtpStep
        ctx={ctxOf({ summary: { alerts: { smtpConfigured: true } } })}
      />
    );
    expect(
      await screen.findByRole('heading', { name: 'Email delivery' })
    ).toBeVisible();
  });

  it('labels the nothing-to-do state as already set up', async () => {
    wrap(
      <SmtpStep
        ctx={ctxOf({ summary: { alerts: { smtpConfigured: true } } })}
      />
    );
    expect(await screen.findByText('Nothing to do here.')).toBeVisible();
    expect(screen.getByTestId('step-kind').textContent).toBe('Already set up');
  });

  it('warns that the settings are server-wide', async () => {
    wrap(<SmtpStep ctx={ctxOf()} />);
    expect(
      await screen.findByText(/These settings are server-wide/)
    ).toBeVisible();
    expect(
      screen.getByText(/for every workspace on this installation/)
    ).toBeVisible();
  });

  it('explains why Send test email is disabled until the settings are saved', async () => {
    wrap(<SmtpStep ctx={ctxOf()} />);
    const test = await screen.findByRole('button', { name: 'Send test email' });
    expect(test).toBeDisabled();
    expect(screen.getByTestId('test-needs-save').textContent).toMatch(
      /^To continue: save the email settings first/
    );
  });
});

describe('NotificationsStep footnote', () => {
  it('defines delivery windows and weekly digests instead of naming them bare', async () => {
    wrap(<NotificationsStep ctx={{ ...ctxOf(), workspaceId: 'ws' }} />);
    await waitFor(() =>
      expect(screen.getByText(/delivery window \(the hours/)).toBeVisible()
    );
    expect(screen.getByText(/weekly digest \(one summary/)).toBeVisible();
  });
});

describe('NotificationsStep custom thresholds', () => {
  it('names the problem and why Save is off', async () => {
    wrap(<NotificationsStep ctx={{ ...ctxOf(), workspaceId: 'ws' }} />);
    fireEvent.click(await screen.findByRole('radio', { name: /Custom/ }));
    fireEvent.change(screen.getByLabelText('Custom thresholds in days'), {
      target: { value: 'soon' },
    });
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
    expect(screen.getByTestId('continue-hint').textContent).toMatch(
      /^To continue: fix the custom thresholds/
    );
  });
});
