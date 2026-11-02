import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import {
  planJourney,
  stepsForGoal,
} from '../../src/components/onboarding/journeyPlanner.js';
import {
  DoneCard,
  importStepComponents,
} from '../../src/components/onboarding/OnboardingPage.jsx';
import { GOALS } from '../../src/components/onboarding/modules.js';

const IMPORT_STEP = {
  import_file: 'file_import',
  import_integration: 'integration',
};

// Off (the default): the import dialog is the whole journey. On: the parked
// guided path keeps its alerts and verify steps.
describe.each([
  [false, id => [id]],
  [true, id => [id, 'recipients', 'verify']],
])('import journeys (guided steps: %s)', (guided, expectedAfterGoal) => {
  const components = importStepComponents(guided);

  for (const [goal, importStep] of Object.entries(IMPORT_STEP)) {
    const planOf = extra =>
      planJourney({
        intent: { goal },
        guidedImportSteps: guided,
        ...extra,
      });

    it(`${goal}: runs ${expectedAfterGoal(importStep).join(' -> ')}`, () => {
      const plan = planOf({ reality: null });
      expect(plan.steps.map(s => s.id)).toEqual([
        'goal',
        ...expectedAfterGoal(importStep),
      ]);
      expect(plan.currentStepId).toBe(importStep);
      expect(typeof components[importStep]).toBe('function');
      expect(stepsForGoal(goal, guided)).toEqual(expectedAfterGoal(importStep));
    });

    it(`${goal}: ${guided ? 'moves to alerts' : 'is complete'} once an import is recorded`, () => {
      const plan = planOf({
        progress: { imported: [{ step: importStep, count: 3 }] },
        reality: { assets: { total: 3 } },
      });
      expect(plan.steps.find(s => s.id === importStep).status).toBe('done');
      if (guided) {
        expect(plan.currentStepId).toBe('recipients');
        expect(plan.complete).toBe(false);
      } else {
        expect(plan.complete).toBe(true);
        expect(plan.steps.map(s => s.id)).not.toContain('recipients');
        expect(plan.steps.map(s => s.id)).not.toContain('verify');
      }
    });

    it(`${goal}: stays on the import step until Continue, then completes`, () => {
      const progress = { imported: [{ step: importStep, count: 3 }] };
      const held = planOf({
        progress,
        reality: { assets: { total: 3 } },
        heldStepId: importStep,
      });
      expect(held.currentStepId).toBe(importStep);
      expect(held.complete).toBe(false);
    });

    it(`${goal}: reopens when the imported assets are gone`, () => {
      const plan = planOf({
        progress: { imported: [{ step: importStep, count: 3 }] },
        reality: { assets: { total: 1 } },
      });
      expect(plan.currentStepId).toBe(importStep);
      expect(plan.complete).toBe(false);
    });

    it(`${goal}: counts only the steps it shows`, () => {
      const plan = planOf({
        progress: { imported: [{ step: importStep, count: 3 }] },
        reality: { assets: { total: 3 } },
      });
      const finished = plan.steps.filter(s => s.status === 'done').length;
      expect(finished).toBe(guided ? 2 : plan.steps.length);
    });
  }
});

describe('other goals keep their alerts and verify steps', () => {
  it.each(['monitor_https', 'track_asset', 'alerting', 'certops_observe'])(
    '%s is unchanged with the switch off',
    goal => {
      expect(stepsForGoal(goal, false)).toEqual(GOALS[goal].steps);
      expect(stepsForGoal(goal, false)).toContain('verify');
    }
  );
});

describe('import step components', () => {
  it('differ between the two paths', () => {
    const off = importStepComponents(false);
    const on = importStepComponents(true);
    expect(off.file_import).not.toBe(on.file_import);
    expect(off.integration).not.toBe(on.integration);
  });
});

describe('closing card after an import', () => {
  const ctx = goal => ({
    workspaceId: 'ws-1',
    session: { intent: { goal }, progress: {} },
    summary: { alerts: { smtpConfigured: true } },
    docs: () => [],
    controller: { update: () => Promise.resolve() },
    refresh: () => Promise.resolve(),
  });
  const show = (goal, guided) =>
    render(
      <ChakraProvider>
        <DashboardThemeProvider>
          <MemoryRouter>
            <DoneCard ctx={ctx(goal)} guidedImportSteps={guided} />
          </MemoryRouter>
        </DashboardThemeProvider>
      </ChakraProvider>
    );

  it.each(['import_file', 'import_integration'])(
    '%s points at the inventory and Alert Preferences',
    goal => {
      show(goal, false);
      expect(
        screen.getByText(/Review your assets in the asset inventory/)
      ).toBeInTheDocument();
      expect(
        screen.getByRole('link', { name: 'Alert Preferences' })
      ).toHaveAttribute('href', '/alert-preferences');
      expect(
        screen.getByRole('link', { name: 'Open the asset inventory' })
      ).toHaveAttribute('href', '/dashboard');
    }
  );

  it('keeps the original card on the parked path and for other goals', () => {
    show('import_file', true);
    expect(screen.getByText(/alerts have somewhere to go/)).toBeInTheDocument();
    expect(
      screen.queryByRole('link', { name: 'Alert Preferences' })
    ).toBeNull();
  });
});
