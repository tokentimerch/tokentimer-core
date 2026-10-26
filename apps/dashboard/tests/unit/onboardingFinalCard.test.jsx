import { render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it, vi } from 'vitest';
import {
  DoneCard,
  nextSteps,
} from '../../src/components/onboarding/OnboardingPage.jsx';
import { GOALS } from '../../src/components/onboarding/modules.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const ctxFor = (goal, certops = {}) => ({
  session: { intent: { goal }, progress: { certops } },
  summary: { alerts: { smtpConfigured: true } },
  docs: () => [],
  refresh: vi.fn(),
  controller: { update: vi.fn() },
});

const show = (goal, certops) =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>
          <DoneCard ctx={ctxFor(goal, certops)} />
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );

describe('final card title follows the verdict', () => {
  it('reports the selected Vault distribution as verified only with its own backend evidence', () => {
    const ctx = ctxFor('certops_vault', {
      objective: 'vault',
      groupId: 'selected-group',
    });
    ctx.summary.certops = {
      distribution: { items: [{ id: 'selected-group', verified: true }] },
    };
    const view = render(
      <ChakraProvider>
        <DashboardThemeProvider>
          <MemoryRouter>
            <DoneCard ctx={ctx} />
          </MemoryRouter>
        </DashboardThemeProvider>
      </ChakraProvider>
    );
    expect(screen.getByText('You are set up')).toBeVisible();
    expect(document.body.textContent).toMatch(/current verification evidence/);
    view.unmount();
    ctx.summary.certops.distribution.items = [
      { id: 'unrelated-group', verified: true },
    ];
    render(
      <ChakraProvider>
        <DashboardThemeProvider>
          <MemoryRouter>
            <DoneCard ctx={ctx} />
          </MemoryRouter>
        </DashboardThemeProvider>
      </ChakraProvider>
    );
    expect(screen.getByText('Setup finished, not verified yet')).toBeVisible();
  });
  it('says all is well when the body does not hedge', () => {
    show('monitor_https');
    expect(screen.getByText('You are set up')).toBeVisible();
  });

  it('says the setup is not verified yet for AD CS and Vault', () => {
    for (const goal of ['certops_adcs', 'certops_vault']) {
      const view = show(goal);
      expect(
        screen.getByText('Setup finished, not verified yet')
      ).toBeVisible();
      expect(screen.queryByText('You are set up')).toBeNull();
      view.unmount();
    }
  });

  it('does not hedge Windows ACME or Linux ACME', () => {
    for (const infrastructure of ['windows', 'linux']) {
      const view = show('certops_automate', {
        objective: 'automate',
        infrastructure,
      });
      expect(screen.getByText('You are set up')).toBeVisible();
      expect(document.body.textContent).not.toMatch(/not (been )?verified/);
      view.unmount();
    }
  });
  it('flags exactly the goals whose body hedges', () => {
    const hedgingBodies = Object.entries(GOALS)
      .filter(([, g]) => /not verified/i.test(g.doneText))
      .map(([id]) => id)
      .sort();
    const flagged = Object.entries(GOALS)
      .filter(([, g]) => g.doneUnverified)
      .map(([id]) => id)
      .sort();
    expect(flagged).toEqual(hedgingBodies);
  });
});

describe('Vault next step', () => {
  it('uses plain words for a check-only rollout', () => {
    const text = nextSteps('certops_vault', {
      distribution: { verified: true },
    }).join(' ');
    expect(text).toMatch(/check-only rollout \(no changes\)/);
    expect(text).not.toMatch(/verificationOnly/);
  });
});
