import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it, vi } from 'vitest';
import { GoalStep } from '../../src/components/onboarding/steps.jsx';
import { saveCertops } from '../../src/components/onboarding/certopsSetupSteps.jsx';
import { progressForGoalChange } from '../../src/components/onboarding/sessionTransitions.js';
import {
  mergeCertops,
  scopeCertops,
} from '../../src/components/onboarding/certopsScope.js';
import { planJourney } from '../../src/components/onboarding/journeyPlanner.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const adcsSaved = {
  objective: 'adcs',
  infrastructure: 'windows',
  names: 'web.corp.example.com',
  caHost: 'ca01.corp.example.com',
  caName: 'Corp Issuing CA',
  template: 'WebServer',
  dnsScopes: 'corp.example.com',
  configReviewed: true,
  tokenCreatedAt: '2026-10-20T10:00:00.000Z',
};

// A fake session store that applies the same mutate functions the page uses.
function harness(progress, goal) {
  let session = { intent: { goal }, progress, operationRefs: {} };
  const ctx = {
    get session() {
      return session;
    },
    controller: {
      update: mutate => {
        session = { ...session, ...mutate(session) };
        return Promise.resolve();
      },
    },
    refresh: () => Promise.resolve(),
  };
  const chooseGoal = id => {
    session = {
      ...session,
      intent: { goal: id },
      progress: progressForGoalChange(session.progress, id),
    };
  };
  return { ctx, chooseGoal, get: () => session };
}

describe('switching goals keeps each objective saved config', () => {
  it('restores the AD CS config after saving an ACME step', async () => {
    const h = harness({ certops: adcsSaved }, 'certops_adcs');

    h.chooseGoal('certops_automate');
    await saveCertops(h.ctx, {
      objective: 'automate',
      infrastructure: 'windows',
    });
    await saveCertops(h.ctx, { zone: 'example.com', configReviewed: true });
    const acme = h.get().progress.certops;
    expect(acme.objective).toBe('automate');
    expect(acme.zone).toBe('example.com');
    // Nothing from AD CS leaks into the ACME view.
    expect(acme.caHost).toBeUndefined();

    h.chooseGoal('certops_adcs');
    const back = h.get().progress.certops;
    expect(back).toMatchObject(adcsSaved);
    expect(back.byObjective.automate).toMatchObject({
      objective: 'automate',
      zone: 'example.com',
      configReviewed: true,
    });
  });

  it('shows the AD CS configuration step as done again after returning', async () => {
    const h = harness({ certops: adcsSaved }, 'certops_adcs');
    h.chooseGoal('certops_automate');
    await saveCertops(h.ctx, {
      objective: 'automate',
      infrastructure: 'windows',
    });
    h.chooseGoal('certops_adcs');
    const plan = planJourney({
      intent: { goal: 'certops_adcs' },
      progress: h.get().progress,
      capabilities: null,
      reality: {
        certops: { agents: { live: 0, items: [] } },
        alerts: {},
        monitors: { items: [] },
        references: { tokenIds: { existing: [] } },
      },
    });
    const status = Object.fromEntries(plan.steps.map(s => [s.id, s.status]));
    expect(status.certops_objective).toBe('done');
    expect(status.certops_config).toBe('done');
    expect(status.certops_agent).toBe('current');
  });

  it('works without a goal change in between: a save also parks the old goal', async () => {
    const h = harness({ certops: adcsSaved }, 'certops_automate');
    await saveCertops(h.ctx, {
      objective: 'automate',
      infrastructure: 'linux',
    });
    const flat = h.get().progress.certops;
    expect(flat.objective).toBe('automate');
    expect(flat.byObjective.adcs).toMatchObject(adcsSaved);
  });

  it('keeps the active objective job ids flat, where the API reads them', async () => {
    const h = harness({ certops: adcsSaved }, 'certops_adcs');
    h.chooseGoal('certops_automate');
    await saveCertops(h.ctx, {
      objective: 'automate',
      infrastructure: 'windows',
      dryRunJobId: 'job-1',
    });
    expect(h.get().progress.certops.dryRunJobId).toBe('job-1');
    h.chooseGoal('certops_adcs');
    expect(h.get().progress.certops.dryRunJobId).toBeUndefined();
    h.chooseGoal('certops_automate');
    expect(h.get().progress.certops.dryRunJobId).toBe('job-1');
  });

  it('leaves certificate progress alone when the new goal is not a certificate goal', () => {
    const progress = { imported: [], certops: adcsSaved };
    expect(progressForGoalChange(progress, 'monitor_https').certops).toBe(
      adcsSaved
    );
  });
});

describe('sessions saved in the old flat shape', () => {
  it('load unchanged for the objective they were saved for', () => {
    expect(scopeCertops(adcsSaved, 'adcs')).toBe(adcsSaved);
    const plan = planJourney({
      intent: { goal: 'certops_adcs' },
      progress: { certops: adcsSaved },
      capabilities: null,
      reality: { certops: { agents: { live: 0, items: [] } } },
    });
    expect(plan.steps.find(s => s.id === 'certops_config').status).toBe('done');
  });

  it('show only host facts for another objective, as before', () => {
    expect(scopeCertops(adcsSaved, 'automate')).toEqual({
      infrastructure: 'windows',
      tokenCreatedAt: adcsSaved.tokenCreatedAt,
    });
  });

  it('gain a parked copy the first time another objective is written', () => {
    const next = mergeCertops(adcsSaved, 'automate', { objective: 'automate' });
    expect(next.byObjective.adcs).toMatchObject(adcsSaved);
    expect(next.byObjective.adcs.byObjective).toBeUndefined();
    expect(scopeCertops(next, 'adcs')).toMatchObject(adcsSaved);
  });

  it('never nest parked copies inside parked copies', () => {
    let c = adcsSaved;
    for (const o of ['automate', 'adcs', 'vault', 'automate', 'adcs']) {
      c = mergeCertops(c, o, { objective: o });
    }
    for (const parked of Object.values(c.byObjective)) {
      expect(parked.byObjective).toBeUndefined();
    }
    expect(Object.keys(c.byObjective).sort()).toEqual(['automate', 'vault']);
  });
});

const wrap = ui =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>{ui}</MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );

describe('goal picker', () => {
  const makeCtx = (goal, certops) => {
    const session = {
      intent: goal ? { goal } : {},
      progress: certops ? { certops } : {},
    };
    const captured = {};
    return {
      captured,
      ctx: {
        session,
        capabilities: null,
        plannerVersion: 2,
        docs: () => [],
        refresh: vi.fn().mockResolvedValue(undefined),
        onDone: vi.fn(),
        controller: {
          update: vi.fn(mutate => {
            captured.patch = mutate(session);
            return Promise.resolve();
          }),
        },
      },
    };
  };

  it('parks the previous objective config when a new certificate goal is picked', async () => {
    const { ctx, captured } = makeCtx('certops_adcs', adcsSaved);
    wrap(<GoalStep ctx={ctx} />);
    fireEvent.click(
      screen.getByRole('radio', { name: /Issue and renew certificates/ })
    );
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(captured.patch).toBeTruthy());
    const certops = captured.patch.progress.certops;
    expect(certops.byObjective.adcs).toMatchObject(adcsSaved);
    expect(certops.caHost).toBeUndefined();
  });
});
