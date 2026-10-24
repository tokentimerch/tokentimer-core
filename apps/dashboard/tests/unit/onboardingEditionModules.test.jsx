import { render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  GOALS,
  GOAL_AREAS,
  STEP_DEFS,
} from '../../src/components/onboarding/modules.js';
import {
  allGoalAreas,
  allGoals,
  allStepDefs,
  editionNextSteps,
  editionStepComponents,
  editionStepSatisfied,
  getEditionModules,
  registerEditionModule,
  resetEditionModules,
  viewerHasScope,
} from '../../src/components/onboarding/editionModules.js';
import {
  availableGoals,
  goalBlocker,
  isStepSatisfied,
  planJourney,
} from '../../src/components/onboarding/journeyPlanner.js';
import { GoalStep } from '../../src/components/onboarding/steps.jsx';
import {
  STEP_COMPONENTS,
  nextSteps,
} from '../../src/components/onboarding/OnboardingPage.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const ExampleStep = () => <div>example step</div>;

function exampleModule(overrides = {}) {
  return {
    id: 'example',
    areas: [{ id: 'example_area', label: 'Example area' }],
    steps: { example_step: { title: 'Do the example', kind: 'ui' } },
    goals: {
      example_goal: {
        label: 'Run the example',
        description: 'An extra goal from an edition.',
        time: 'About 1 min',
        steps: ['example_step', 'verify'],
        area: 'example_area',
        requires: [{ capability: 'example.setup', scope: 'system_admin' }],
      },
    },
    components: { example_step: ExampleStep },
    ...overrides,
  };
}

const cap = (id, state = 'ready') => ({ id, state, blockers: [] });
const caps = (viewer = { isSystemAdmin: true }, items = []) => ({
  items: [cap('example.setup'), ...items],
  viewer,
});

afterEach(() => resetEditionModules());

describe('edition module registry: nothing registered', () => {
  it('returns the core tables themselves', () => {
    expect(allGoals()).toBe(GOALS);
    expect(allStepDefs()).toBe(STEP_DEFS);
    expect(allGoalAreas()).toBe(GOAL_AREAS);
    expect(editionStepComponents()).toEqual({});
    expect(getEditionModules()).toEqual([]);
  });

  it('lists the same goals, none hidden, and plans as before', () => {
    const goals = availableGoals({ items: [], viewer: {} });
    expect(goals.map(g => g.id)).toEqual(Object.keys(GOALS));
    expect(goals.some(g => g.blocker?.hidden)).toBe(false);
    expect(availableGoals(null).every(g => g.blocker === null)).toBe(true);
    const plan = planJourney({ intent: { goal: 'monitor_https' } });
    expect(plan.steps.map(s => s.id)).toEqual([
      'goal',
      'monitor',
      'recipients',
      'verify',
    ]);
  });

  it('keeps the default suggestion for a goal nobody extends', () => {
    expect(editionNextSteps('monitor_https', {})).toBeUndefined();
    expect(editionStepSatisfied('monitor', {})).toBeUndefined();
    expect(nextSteps('unknown_goal')).toHaveLength(1);
  });
});

describe('registerEditionModule', () => {
  it('merges goals, steps, areas and components', () => {
    registerEditionModule(exampleModule());
    expect(Object.keys(allGoals())).toEqual([
      ...Object.keys(GOALS),
      'example_goal',
    ]);
    expect(allStepDefs().example_step.title).toBe('Do the example');
    expect(allGoalAreas().map(a => a.id)).toEqual([
      ...GOAL_AREAS.map(a => a.id),
      'example_area',
    ]);
    expect(editionStepComponents().example_step).toBe(ExampleStep);
    // The core tables are never modified.
    expect(GOALS.example_goal).toBeUndefined();
    expect(STEP_COMPONENTS.example_step).toBeUndefined();
  });

  it('rejects a duplicate module id', () => {
    registerEditionModule(exampleModule());
    expect(() => registerEditionModule(exampleModule())).toThrow(
      /already registered/
    );
  });

  it('rejects ids that collide with core or another module', () => {
    expect(() =>
      registerEditionModule(
        exampleModule({
          goals: {
            monitor_https: exampleModule().goals.example_goal,
          },
        })
      )
    ).toThrow(/goal "monitor_https"/);
    expect(() =>
      registerEditionModule(
        exampleModule({
          steps: { recipients: { title: 'x', kind: 'ui' } },
          components: { recipients: ExampleStep },
          goals: {},
        })
      )
    ).toThrow(/step "recipients"/);
    registerEditionModule(exampleModule());
    expect(() => registerEditionModule(exampleModule({ id: 'other' }))).toThrow(
      /already registered/
    );
    expect(getEditionModules()).toHaveLength(1);
  });

  it('rejects malformed modules', () => {
    const bad = [
      exampleModule({ id: 'Bad Id' }),
      exampleModule({ components: {} }),
      exampleModule({
        goals: {
          example_goal: {
            ...exampleModule().goals.example_goal,
            steps: ['missing_step'],
          },
        },
      }),
      exampleModule({
        goals: {
          example_goal: {
            ...exampleModule().goals.example_goal,
            area: 'nowhere',
          },
        },
      }),
      exampleModule({
        goals: {
          example_goal: {
            ...exampleModule().goals.example_goal,
            requires: [{ capability: 'x.y', scope: 'galaxy_admin' }],
          },
        },
      }),
      exampleModule({ isStepSatisfied: 'nope' }),
    ];
    for (const mod of bad) {
      expect(() => registerEditionModule(mod)).toThrow(/Edition module/);
    }
    expect(getEditionModules()).toEqual([]);
  });
});

describe('edition goal visibility', () => {
  const visible = capabilities =>
    availableGoals(capabilities)
      .filter(g => !g.blocker?.hidden)
      .map(g => g.id);

  it('shows the goal when the capability and scope are met', () => {
    registerEditionModule(exampleModule());
    expect(goalBlocker('example_goal', caps())).toBeNull();
    expect(visible(caps())).toContain('example_goal');
  });

  it('hides only that goal when the capability is missing', () => {
    registerEditionModule(exampleModule());
    const without = { items: [], viewer: { isSystemAdmin: true } };
    expect(goalBlocker('example_goal', without)).toMatchObject({
      code: 'CAPABILITY_MISSING',
      hidden: true,
    });
    expect(visible(without)).toEqual(Object.keys(GOALS));
  });

  it('hides the goal when the capability reports hidden', () => {
    registerEditionModule(exampleModule());
    const hidden = {
      items: [cap('example.setup', 'hidden')],
      viewer: { isSystemAdmin: true },
    };
    expect(goalBlocker('example_goal', hidden).hidden).toBe(true);
  });

  it('hides the goal when the viewer lacks the scope', () => {
    registerEditionModule(exampleModule());
    const member = caps({ isSystemAdmin: false, workspaceRole: 'admin' });
    expect(goalBlocker('example_goal', member)).toMatchObject({
      code: 'SCOPE_REQUIRED',
      scope: 'system_admin',
      hidden: true,
    });
    expect(goalBlocker('example_goal', caps({}))?.hidden).toBe(true);
  });

  it('hides the goal while capabilities are unknown, not core goals', () => {
    registerEditionModule(exampleModule());
    expect(goalBlocker('example_goal', null)).toMatchObject({ hidden: true });
    expect(goalBlocker('monitor_https', null)).toBeNull();
  });

  it('keeps the usual disabled state for a capability that is not ready', () => {
    registerEditionModule(exampleModule());
    const upgrade = {
      items: [
        {
          id: 'example.setup',
          state: 'upgrade',
          blockers: [{ code: 'LICENSE', remediation: 'Add a license.' }],
        },
      ],
      viewer: { isSystemAdmin: true },
    };
    const blocker = goalBlocker('example_goal', upgrade);
    expect(blocker.code).toBe('LICENSE');
    expect(blocker.hidden).toBeUndefined();
  });

  it('checks every workspace scope', () => {
    expect(viewerHasScope(null, undefined)).toBe(true);
    expect(viewerHasScope('workspace_admin', { workspaceRole: 'admin' })).toBe(
      true
    );
    expect(
      viewerHasScope('workspace_admin', { workspaceRole: 'workspace_manager' })
    ).toBe(false);
    expect(
      viewerHasScope('workspace_manager', {
        workspaceRole: 'workspace_manager',
      })
    ).toBe(true);
    expect(
      viewerHasScope('workspace_manager', { workspaceRole: 'viewer' })
    ).toBe(false);
  });

  it('accepts plain capability ids too', () => {
    registerEditionModule(
      exampleModule({
        goals: {
          example_goal: {
            ...exampleModule().goals.example_goal,
            requires: ['example.setup'],
          },
        },
      })
    );
    expect(goalBlocker('example_goal', caps({}))).toBeNull();
  });
});

describe('edition journey', () => {
  it('plans the edition steps and uses isStepSatisfied for done', () => {
    const rule = vi.fn((stepId, ctx) =>
      stepId === 'example_step' ? ctx.reality?.edition?.example?.ok : undefined
    );
    registerEditionModule(exampleModule({ isStepSatisfied: rule }));
    const open = planJourney({
      intent: { goal: 'example_goal' },
      capabilities: caps(),
      reality: { edition: { example: { ok: false } } },
    });
    expect(open.steps.map(s => [s.id, s.status])).toEqual([
      ['goal', 'done'],
      ['example_step', 'current'],
      ['verify', 'upcoming'],
    ]);
    expect(open.steps[1].title).toBe('Do the example');

    const done = planJourney({
      intent: { goal: 'example_goal' },
      capabilities: caps(),
      reality: { edition: { example: { ok: true } } },
    });
    expect(done.steps[1].status).toBe('done');
    expect(rule).toHaveBeenCalledWith(
      'example_step',
      expect.objectContaining({ goal: 'example_goal' })
    );
  });

  it('treats a missing or throwing rule as not done', () => {
    registerEditionModule(exampleModule());
    expect(isStepSatisfied('example_step', { reality: {} })).toBe(false);
    resetEditionModules();
    registerEditionModule(
      exampleModule({
        isStepSatisfied: () => {
          throw new Error('boom');
        },
      })
    );
    expect(isStepSatisfied('example_step', { reality: {} })).toBe(false);
  });

  it('never lets a module judge a core step', () => {
    const rule = vi.fn(() => true);
    registerEditionModule(exampleModule({ isStepSatisfied: rule }));
    expect(isStepSatisfied('smtp', { reality: {} })).toBe(false);
    expect(rule).not.toHaveBeenCalled();
  });

  it('resolves the component and the next-step suggestions', () => {
    registerEditionModule(
      exampleModule({
        nextSteps: (goalId, summary) => [
          `Review ${summary?.edition?.example?.count ?? 0} items.`,
        ],
      })
    );
    expect(editionStepComponents().example_step).toBe(ExampleStep);
    expect(
      nextSteps('example_goal', null, { edition: { example: { count: 2 } } })
    ).toEqual(['Review 2 items.']);
    // Core goals keep their own lists.
    expect(nextSteps('monitor_https', null, {})).toHaveLength(2);
  });
});

describe('goal picker with an edition module', () => {
  const wrap = ui =>
    render(
      <ChakraProvider>
        <DashboardThemeProvider>
          <MemoryRouter>{ui}</MemoryRouter>
        </DashboardThemeProvider>
      </ChakraProvider>
    );
  const ctx = capabilities => ({
    session: { intent: {}, progress: {} },
    capabilities,
    plannerVersion: 2,
    docs: () => [],
    refresh: vi.fn(),
    onDone: vi.fn(),
    controller: { update: vi.fn() },
  });

  it('lists the edition goal without a "not fully tested" mark', () => {
    registerEditionModule(exampleModule());
    wrap(<GoalStep ctx={ctx(caps())} />);
    const radio = screen.getByRole('radio', { name: 'Run the example' });
    expect(radio).not.toBeDisabled();
    expect(screen.getByText('EXAMPLE AREA')).toBeInTheDocument();
    const described = (radio.getAttribute('aria-describedby') || '')
      .split(' ')
      .map(id => document.getElementById(id)?.textContent)
      .join(' ');
    expect(described).not.toMatch(/Not fully tested/);
  });

  it('leaves the edition goal out when it is hidden', () => {
    registerEditionModule(exampleModule());
    wrap(
      <GoalStep ctx={ctx({ items: [], viewer: { isSystemAdmin: true } })} />
    );
    expect(screen.queryByText('Run the example')).not.toBeInTheDocument();
    expect(screen.queryByText('EXAMPLE AREA')).not.toBeInTheDocument();
    expect(screen.getAllByRole('radio')).toHaveLength(
      Object.keys(GOALS).length
    );
  });
});
