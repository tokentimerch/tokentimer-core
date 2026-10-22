import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it, vi } from 'vitest';
import { ObjectiveStep } from '../../src/components/onboarding/certopsSetupSteps.jsx';
import {
  chooseInfrastructure,
  mergeCertops,
} from '../../src/components/onboarding/certopsScope.js';
import { planJourney } from '../../src/components/onboarding/journeyPlanner.js';
import { resolveNavigation } from '../../src/components/onboarding/stepNavigation.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const freshReality = {
  alerts: { smtpConfigured: true },
  certops: {
    agents: { live: 0, items: [] },
    controllers: { clusters: [] },
    certificates: { observed: 0, total: 0 },
  },
};

const plan = (progress, reality = freshReality, extra = {}) =>
  planJourney({
    intent: { goal: 'certops_observe' },
    progress,
    reality,
    ...extra,
  });

const statuses = p => Object.fromEntries(p.steps.map(s => [s.id, s.status]));

describe('fresh workspace, observe goal', () => {
  it.each(['linux', 'windows', 'kubernetes'])(
    'shows only the platform choice as done after picking %s',
    infrastructure => {
      const certops = chooseInfrastructure({}, 'observe', infrastructure);
      const p = plan({ certops });
      const s = statuses(p);
      expect(s.certops_objective).toBe('done');
      expect(s.certops_config).toBe('current');
      for (const id of [
        'certops_agent',
        'certops_execution',
        'certops_first',
        'recipients',
      ]) {
        expect(s[id]).toBe('upcoming');
      }
      expect(p.currentStepId).toBe('certops_config');
    }
  );

  it('still shows the agent and certificate steps done when they really exist', () => {
    const certops = {
      ...chooseInfrastructure({}, 'observe', 'linux'),
      configReviewed: true,
      executionAcknowledged: true,
    };
    const s = statuses(
      plan(
        { certops },
        {
          alerts: { smtpConfigured: true },
          certops: {
            agents: { live: 1, items: [{ livenessState: 'live' }] },
            certificates: { observed: 2, total: 2 },
          },
        }
      )
    );
    expect(s.certops_agent).toBe('done');
    expect(s.certops_first).toBe('done');
  });
});

describe('changing the platform choice', () => {
  const walked = {
    objective: 'observe',
    infrastructure: 'linux',
    configReviewed: true,
    executionAcknowledged: true,
    tokenCreatedAt: '2026-10-20T10:00:00.000Z',
    installerKey: 'k',
  };

  it('drops the previous platform step marks and keeps the rest', () => {
    const next = chooseInfrastructure(
      { ...walked, names: 'a.example.com' },
      'observe',
      'windows'
    );
    expect(next).toMatchObject({
      objective: 'observe',
      infrastructure: 'windows',
      names: 'a.example.com',
    });
    for (const key of [
      'configReviewed',
      'executionAcknowledged',
      'tokenCreatedAt',
      'installerKey',
    ]) {
      expect(next[key]).toBeUndefined();
    }
  });

  it('keeps everything when the same platform is picked again', () => {
    expect(chooseInfrastructure(walked, 'observe', 'linux')).toEqual(walked);
  });

  it('does not leak done marks across Linux, Windows, Kubernetes and back', () => {
    let certops = chooseInfrastructure({}, 'observe', 'linux');
    certops = { ...certops, configReviewed: true, executionAcknowledged: true };
    expect(statuses(plan({ certops })).certops_config).toBe('done');

    for (const next of ['windows', 'kubernetes', 'linux']) {
      certops = chooseInfrastructure(certops, 'observe', next);
      const p = plan({ certops });
      const s = statuses(p);
      expect(s.certops_config).toBe('current');
      expect(s.certops_execution).toBe('upcoming');
      expect(p.currentStepId).toBe('certops_config');
      // Simulate the operator walking the first two steps of the new variant.
      certops = {
        ...certops,
        configReviewed: true,
        executionAcknowledged: true,
      };
      expect(plan({ certops }).currentStepId).toBe('certops_agent');
    }
  });

  it('keeps another objective parked copy untouched', () => {
    const parked = mergeCertops(
      { objective: 'automate', infrastructure: 'linux', configReviewed: true },
      'observe',
      { objective: 'observe', infrastructure: 'linux' }
    );
    const next = chooseInfrastructure(parked, 'observe', 'kubernetes');
    expect(next.byObjective.automate.configReviewed).toBe(true);
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

function harness(certops) {
  let session = {
    intent: { goal: 'certops_observe' },
    progress: { certops },
    operationRefs: {},
  };
  const ctx = {
    get session() {
      return session;
    },
    summary: freshReality,
    docs: () => [],
    release: vi.fn(),
    onDone: vi.fn(),
    refresh: vi.fn().mockResolvedValue(undefined),
    controller: {
      update: vi.fn(mutate => {
        session = { ...session, ...mutate(session) };
        return Promise.resolve();
      }),
    },
  };
  return { ctx, get: () => session };
}

describe('Where will the certificates live? step', () => {
  it('saves the new platform and returns to the live step on Continue', async () => {
    const h = harness({
      objective: 'observe',
      infrastructure: 'linux',
      configReviewed: true,
      executionAcknowledged: true,
    });
    const { unmount } = wrap(<ObjectiveStep ctx={h.ctx} />);
    fireEvent.click(screen.getByRole('radio', { name: /Windows Server/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(h.ctx.onDone).toHaveBeenCalled());
    expect(h.ctx.release).toHaveBeenCalled();
    const saved = h.get().progress.certops;
    expect(saved.infrastructure).toBe('windows');
    expect(saved.configReviewed).toBeUndefined();

    // The planner puts the operator on the first step not really done.
    const p = plan(h.get().progress);
    expect(p.currentStepId).toBe('certops_config');
    const nav = resolveNavigation(p, null);
    expect(nav.shownId).toBe('certops_config');
    unmount();
  });

  it('moves on when the same platform is picked again', async () => {
    const h = harness({
      objective: 'observe',
      infrastructure: 'linux',
      configReviewed: true,
    });
    wrap(<ObjectiveStep ctx={h.ctx} />);
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(h.ctx.onDone).toHaveBeenCalled());
    expect(h.get().progress.certops.configReviewed).toBe(true);
    expect(plan(h.get().progress).currentStepId).toBe('certops_agent');
  });
});
