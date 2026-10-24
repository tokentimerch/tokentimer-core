import {
  configure,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import { commandProfileFor } from '../../src/components/onboarding/certopsMatrix.js';
import { realAgent } from './helpers/realAgentPayload.js';
import { stubOf } from './helpers/heldStepStubs.js';
import {
  registerEditionModule,
  resetEditionModules,
} from '../../src/components/onboarding/editionModules.js';
import {
  finishesByItself,
  journeyKey,
  observedDoneStep,
} from '../../src/components/onboarding/heldSteps.js';

// The steps that wait for outside work are replaced by stubs with a Poll
// button, so the page, the planner and the hold run for real while the test
// plays the job or the agent turning done through the summary.
const server = vi.hoisted(() => ({ session: null, summary: null }));

vi.mock('../../src/components/DashboardShell', () => ({
  default: ({ children }) => <div>{children}</div>,
}));
vi.mock('../../src/hooks/useDashboardShellProps', () => ({
  useDashboardShellProps: () => ({}),
}));
vi.mock('../../src/components/SEO.jsx', () => ({ default: () => null }));
vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: 'ws-1' }),
}));

const stub = async id =>
  (await import('./helpers/heldStepStubs.js')).stubOf(id);

vi.mock('../../src/components/onboarding/certopsSetupSteps.jsx', async () => ({
  ObjectiveStep: (await import('./helpers/heldStepStubs.js')).stubOf(
    'certops_objective'
  ),
  ConfigStep: (await import('./helpers/heldStepStubs.js')).stubOf(
    'certops_config'
  ),
}));
vi.mock('../../src/components/onboarding/certopsAgentStep.jsx', async () => ({
  AgentStep: (await import('./helpers/heldStepStubs.js')).stubOf(
    'certops_agent'
  ),
}));
vi.mock(
  '../../src/components/onboarding/certopsExecutionStep.jsx',
  async () => ({
    ExecutionStep: (await import('./helpers/heldStepStubs.js')).stubOf(
      'certops_execution'
    ),
  })
);
vi.mock('../../src/components/onboarding/certopsFinalSteps.jsx', async () => ({
  FirstCertificateStep: (await import('./helpers/heldStepStubs.js')).stubOf(
    'certops_first'
  ),
  VaultStep: (await import('./helpers/heldStepStubs.js')).stubOf(
    'certops_vault'
  ),
}));
vi.mock('../../src/components/onboarding/certopsAdcsStep.jsx', async () => ({
  default: (await import('./helpers/heldStepStubs.js')).stubOf('certops_adcs'),
}));
vi.mock(
  '../../src/components/onboarding/recipientAndVerifySteps.jsx',
  async () => ({
    RecipientsStep: (await import('./helpers/heldStepStubs.js')).stubOf(
      'recipients'
    ),
    VerifyStep: (await import('./helpers/heldStepStubs.js')).stubOf('verify'),
  })
);
vi.mock('../../src/utils/onboardingApi.js', () => {
  const clone = v => JSON.parse(JSON.stringify(v));
  class RevisionConflictError extends Error {}
  return {
    RevisionConflictError,
    onboardingAPI: {
      getCapabilities: async () => ({
        docsBaseUrl: 'https://tokentimer.ch/docs/self-hosted',
        items: [
          'certops.core',
          'certops.adcs',
          'certops.vault_distribution',
          'alerts.contact_groups',
        ].map(id => ({ id, state: 'ready', blockers: [] })),
      }),
      getSession: async () => clone(server.session),
      putSession: async (_w, _f, body) => {
        const s = server.session;
        if (body.intent) s.intent = body.intent;
        if (body.progress) s.progress = body.progress;
        if (body.operation_refs) s.operationRefs = body.operation_refs;
        if (body.status) s.status = body.status;
        s.revision += 1;
        return clone(s);
      },
      getSummary: async () => clone(server.summary),
    },
  };
});

import OnboardingPage from '../../src/components/onboarding/OnboardingPage.jsx';

const RAIL_COUNT = /(\d+) of \d+ steps finished/;
const finished = () =>
  Number(
    screen.getAllByTestId('rail-progress')[0].textContent.match(RAIL_COUNT)[1]
  );
const poll = id => fireEvent.click(screen.getByText(`Poll ${id}`));
const continueBar = () => screen.queryByTestId('step-continue');
const clickContinue = () =>
  fireEvent.click(
    within(screen.getByTestId('step-continue')).getByRole('button', {
      name: 'Continue',
    })
  );

const liveAgent = (extra = {}) => ({
  livenessState: 'live',
  platform: 'linux',
  commandProfiles: [],
  declaredCapabilities: [],
  ...extra,
});

function seed(goal, certops, summaryCertops = {}) {
  server.session = {
    exists: true,
    revision: 2,
    intent: { goal },
    progress: { certops },
    operationRefs: {},
  };
  server.summary = {
    assets: { total: 0 },
    monitors: { items: [] },
    alerts: { smtpConfigured: true, contactGroups: {} },
    references: {},
    certops: { agents: { live: 0, items: [] }, ...summaryCertops },
  };
}

function mount() {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>
          <OnboardingPage
            session={{ email: 'ana@example.com', name: 'Ana' }}
            onLogout={() => {}}
            onAccountClick={() => {}}
          />
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

beforeEach(() => {
  window.matchMedia = vi.fn(query => ({
    matches: false,
    media: query,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }));
});

describe('a step that finishes by itself stays open until Continue', () => {
  vi.setConfig({ testTimeout: 15000 });
  configure({ asyncUtilTimeout: 5000 });

  const observe = {
    objective: 'observe',
    infrastructure: 'linux',
    configReviewed: true,
  };

  it('keeps the agent step open when the agent checks in', async () => {
    seed('certops_observe', observe);
    mount();
    await screen.findByTestId('stub-certops_agent');
    expect(continueBar()).toBeNull();
    const before = finished();

    server.summary.certops.agents = { live: 1, items: [liveAgent()] };
    poll('certops_agent');

    await waitFor(() => expect(continueBar()).not.toBeNull());
    expect(screen.getByTestId('stub-certops_agent')).toBeVisible();
    // The counter and rail update at once, only the move waits.
    expect(finished()).toBe(before + 1);
    expect(
      within(continueBar()).getByRole('button', { name: 'Continue' })
    ).toBeEnabled();

    clickContinue();
    expect(await screen.findByTestId('stub-certops_execution')).toBeVisible();
    expect(screen.queryByTestId('stub-certops_agent')).toBeNull();
    expect(continueBar()).toBeNull();
  });

  it('keeps the dry run step open when the signed dry run completes', async () => {
    seed('certops_observe', observe, {
      agents: { live: 1, executionEnabled: true, items: [liveAgent()] },
      dryRun: { status: 'queued' },
    });
    mount();
    await screen.findByTestId('stub-certops_execution');
    expect(continueBar()).toBeNull();

    server.summary.certops.dryRun = { status: 'dry_run_complete' };
    poll('certops_execution');

    await waitFor(() => expect(continueBar()).not.toBeNull());
    expect(screen.getByTestId('stub-certops_execution')).toBeVisible();
    clickContinue();
    expect(await screen.findByTestId('stub-certops_first')).toBeVisible();
  });

  it('keeps the first certificate step open when the report arrives', async () => {
    seed(
      'certops_observe',
      { ...observe, executionAcknowledged: true },
      {
        agents: { live: 1, executionEnabled: true, items: [liveAgent()] },
        certificates: { observed: 0 },
      }
    );
    mount();
    await screen.findByTestId('stub-certops_first');

    server.summary.certops.certificates = { observed: 3 };
    poll('certops_first');

    await waitFor(() => expect(continueBar()).not.toBeNull());
    expect(screen.getByTestId('stub-certops_first')).toBeVisible();
    clickContinue();
    expect(await screen.findByTestId('stub-recipients')).toBeVisible();
  });

  it('waits for the Kubernetes controller to report', async () => {
    seed(
      'certops_observe',
      { objective: 'observe', infrastructure: 'kubernetes', clusterId: 'c1' },
      { controllers: { clusters: [] } }
    );
    mount();
    await screen.findByTestId('stub-certops_agent');

    server.summary.certops.controllers = { clusters: [{ clusterId: 'c1' }] };
    poll('certops_agent');

    await waitFor(() => expect(continueBar()).not.toBeNull());
    expect(screen.getByTestId('stub-certops_agent')).toBeVisible();
    clickContinue();
    expect(await screen.findByTestId('stub-certops_first')).toBeVisible();
  });

  it('keeps the issuance step open when the real order succeeds', async () => {
    const profile = commandProfileFor('automate', 'linux');
    seed(
      'certops_automate',
      {
        objective: 'automate',
        infrastructure: 'linux',
        configReviewed: true,
        executionAcknowledged: true,
      },
      {
        agents: {
          live: 1,
          executionEnabled: true,
          items: [liveAgent({ commandProfiles: profile ? [profile] : [] })],
        },
        dryRun: { status: 'dry_run_complete' },
        issueJob: { status: 'running', mode: 'real' },
      }
    );
    mount();
    await screen.findByTestId('stub-certops_first');

    server.summary.certops.issueJob = { status: 'succeeded', mode: 'real' };
    poll('certops_first');

    await waitFor(() => expect(continueBar()).not.toBeNull());
    expect(screen.getByTestId('stub-certops_first')).toBeVisible();
    clickContinue();
    expect(await screen.findByTestId('stub-recipients')).toBeVisible();
  });

  it('keeps a failed order on the step with no Continue', async () => {
    const profile = commandProfileFor('automate', 'linux');
    seed(
      'certops_automate',
      {
        objective: 'automate',
        infrastructure: 'linux',
        configReviewed: true,
        executionAcknowledged: true,
      },
      {
        agents: {
          live: 1,
          executionEnabled: true,
          items: [liveAgent({ commandProfiles: profile ? [profile] : [] })],
        },
        dryRun: { status: 'dry_run_complete' },
        issueJob: { status: 'running', mode: 'real' },
      }
    );
    mount();
    await screen.findByTestId('stub-certops_first');

    server.summary.certops.issueJob = { status: 'failed', mode: 'real' };
    poll('certops_first');

    await waitFor(() => expect(finished()).toBeGreaterThan(0));
    expect(screen.getByTestId('stub-certops_first')).toBeVisible();
    expect(continueBar()).toBeNull();
  });

  it('keeps the AD CS step open when the issuer and profile appear', async () => {
    seed(
      'certops_adcs',
      {
        objective: 'adcs',
        infrastructure: 'windows',
        configReviewed: true,
      },
      {
        agents: {
          live: 1,
          items: [realAgent('win32')],
        },
        adcs: { issuers: [], profiles: 0 },
      }
    );
    mount();
    await screen.findByTestId('stub-certops_adcs');

    server.summary.certops.adcs = {
      issuers: [{ confirmed: true, safe: true }],
      profiles: 1,
    };
    poll('certops_adcs');

    await waitFor(() => expect(continueBar()).not.toBeNull());
    expect(screen.getByTestId('stub-certops_adcs')).toBeVisible();
    clickContinue();
    expect(await screen.findByTestId('stub-recipients')).toBeVisible();
  });

  it('keeps the Vault step open when a rollout is verified', async () => {
    const profile = commandProfileFor('vault', 'linux');
    seed(
      'certops_vault',
      { objective: 'vault', infrastructure: 'linux', configReviewed: true },
      {
        agents: {
          live: 1,
          executionEnabled: true,
          items: [
            realAgent('linux', { commandProfiles: profile ? [profile] : [] }),
          ],
        },
        distribution: { groups: 1, verified: false },
      }
    );
    mount();
    await screen.findByTestId('stub-certops_vault');

    server.summary.certops.distribution = { groups: 1, verified: true };
    poll('certops_vault');

    await waitFor(() => expect(continueBar()).not.toBeNull());
    expect(screen.getByTestId('stub-certops_vault')).toBeVisible();
    clickContinue();
    expect(await screen.findByTestId('stub-certops_execution')).toBeVisible();
  });

  it('does not hold or add Continue when the page loads on a done step', async () => {
    seed('certops_observe', observe, {
      agents: { live: 1, items: [liveAgent()] },
    });
    mount();
    // The agent step is already done, so the guide opens on the next one.
    await screen.findByTestId('stub-certops_execution');
    expect(continueBar()).toBeNull();
  });

  it('shows Continue on a done step reached from the steps list', async () => {
    seed('certops_observe', observe, {
      agents: { live: 1, items: [liveAgent()] },
    });
    mount();
    await screen.findByTestId('stub-certops_execution');

    fireEvent.click(await screen.findByLabelText('Install the agent, review'));
    expect(await screen.findByTestId('stub-certops_agent')).toBeVisible();
    // The result of a finished step is still readable and Continue moves on.
    expect(continueBar()).not.toBeNull();
    clickContinue();
    expect(await screen.findByTestId('stub-certops_execution')).toBeVisible();
    expect(continueBar()).toBeNull();
  });
});

describe('the hold resets with the journey', () => {
  vi.setConfig({ testTimeout: 15000 });
  configure({ asyncUtilTimeout: 5000 });

  it('drops the hold when the platform changes', async () => {
    seed(
      'certops_observe',
      { objective: 'observe', infrastructure: 'linux', configReviewed: true },
      { agents: { live: 0, items: [] } }
    );
    mount();
    await screen.findByTestId('stub-certops_agent');
    server.summary.certops.agents = { live: 1, items: [liveAgent()] };
    poll('certops_agent');
    await waitFor(() => expect(continueBar()).not.toBeNull());

    // Another platform: the agent step now waits for a controller.
    server.summary.certops.controllers = { clusters: [] };
    fireEvent.click(screen.getByText('Switch platform certops_agent'));
    await waitFor(() => expect(continueBar()).toBeNull());
    expect(screen.getByTestId('stub-certops_agent')).toBeVisible();
  });

  it('drops the hold when the goal is changed', async () => {
    seed(
      'certops_observe',
      { objective: 'observe', infrastructure: 'linux', configReviewed: true },
      { agents: { live: 0, items: [] } }
    );
    mount();
    await screen.findByTestId('stub-certops_agent');
    server.summary.certops.agents = { live: 1, items: [liveAgent()] };
    poll('certops_agent');
    await waitFor(() => expect(continueBar()).not.toBeNull());

    fireEvent.click(
      screen.getAllByRole('button', {
        name: 'Change what I am setting up',
        hidden: true,
      })[0]
    );
    expect(
      await screen.findByRole('heading', {
        name: 'What do you want to do first?',
      })
    ).toBeVisible();
    expect(continueBar()).toBeNull();
  });
});

describe('observedDoneStep', () => {
  const steps = status => [
    { id: 'certops_agent', status },
    { id: 'certops_execution', status: 'current' },
  ];
  const session = { intent: { goal: 'certops_observe' }, progress: {} };
  const key = journeyKey(session.intent, session.progress);

  it('matches a shown step that turned done', () => {
    expect(
      observedDoneStep(
        { id: 'certops_agent', key },
        {
          key,
          plan: { currentStepId: 'certops_execution', steps: steps('done') },
          session,
        }
      )
    ).toBe('certops_agent');
  });

  it('ignores a first look, a still-open step and another journey', () => {
    const plan = { currentStepId: 'certops_execution', steps: steps('done') };
    expect(observedDoneStep(null, { key, plan, session })).toBeNull();
    expect(
      observedDoneStep(
        { id: 'certops_agent', key: 'x:y' },
        { key, plan, session }
      )
    ).toBeNull();
    expect(
      observedDoneStep(
        { id: 'certops_agent', key },
        {
          key,
          plan: { currentStepId: 'certops_agent', steps: steps('current') },
          session,
        }
      )
    ).toBeNull();
  });

  it('leaves forms and acknowledgements to move on at once', () => {
    expect(finishesByItself('monitor', { goal: 'monitor_https' })).toBe(false);
    expect(finishesByItself('certops_config', {})).toBe(false);
    expect(finishesByItself('recipients', { goal: 'import_file' })).toBe(false);
    expect(finishesByItself('recipients', { goal: 'monitor_https' })).toBe(
      true
    );
    expect(
      finishesByItself('certops_execution', {
        goal: 'certops_observe',
        progress: {
          certops: { objective: 'observe', executionAcknowledged: true },
        },
      })
    ).toBe(false);
  });
});

describe('closing card rail label', () => {
  vi.setConfig({ testTimeout: 15000 });
  configure({ asyncUtilTimeout: 5000 });

  const summaryButton = () =>
    screen.getByRole('button', { name: /^Step \d+ of \d+:/, hidden: true });

  it.each([
    ['import_file', 'Import assets from a file', 'file_import'],
    ['import_integration', 'Connect a service', 'integration'],
  ])('%s: the closing card reads as the last step', async (goal, title, id) => {
    seed(goal, {});
    server.session.progress.imported = [{ step: id, count: 3 }];
    server.summary.assets = { total: 3 };
    mount();
    expect(
      await screen.findByRole('heading', { name: 'You are set up' })
    ).toBeVisible();
    expect(summaryButton().textContent).toBe(`Step 2 of 2: ${title}`);
  });
});

describe('an edition step that finishes by itself', () => {
  vi.setConfig({ testTimeout: 15000 });
  configure({ asyncUtilTimeout: 5000 });

  const register = steps =>
    registerEditionModule({
      id: 'example',
      areas: [{ id: 'example_area', label: 'Example area' }],
      steps,
      goals: {
        example_goal: {
          label: 'Run the example',
          description: 'An extra goal from an edition.',
          time: 'About 1 min',
          steps: ['example_step', 'verify'],
          area: 'example_area',
          requires: [],
        },
      },
      components: { example_step: stubOf('example_step') },
      isStepSatisfied: (id, ctx) =>
        id === 'example_step'
          ? ctx.reality?.edition?.ready === true
          : undefined,
    });
  const setReady = ready => {
    server.summary.edition = { ready };
  };
  const hold = {
    example_step: { title: 'Do it', kind: 'ui', holdWhenDone: true },
  };
  const plain = { example_step: { title: 'Do it', kind: 'ui' } };

  afterEach(() => resetEditionModules());

  it('is not held, and changes nothing, when nothing is registered', () => {
    expect(finishesByItself('example_step', {})).toBe(false);
  });

  it('rejects a flag that is not a boolean', () => {
    expect(() =>
      register({
        example_step: { title: 'x', kind: 'ui', holdWhenDone: 'yes' },
      })
    ).toThrow(/holdWhenDone must be a boolean/);
  });

  it('is read from the registry when asked, not when the module loads', () => {
    expect(finishesByItself('example_step', {})).toBe(false);
    register(hold);
    expect(finishesByItself('example_step', {})).toBe(true);
    resetEditionModules();
    expect(finishesByItself('example_step', {})).toBe(false);
  });

  it('holds with Continue when it turns done while on screen', async () => {
    register(hold);
    seed('example_goal', {});
    setReady(false);
    mount();
    await screen.findByTestId('stub-example_step');
    expect(continueBar()).toBeNull();

    setReady(true);
    poll('example_step');

    await waitFor(() => expect(continueBar()).not.toBeNull());
    expect(screen.getByTestId('stub-example_step')).toBeVisible();
    clickContinue();
    expect(await screen.findByTestId('stub-verify')).toBeVisible();
    expect(continueBar()).toBeNull();
  });

  it('moves on at once without the flag', async () => {
    register(plain);
    seed('example_goal', {});
    setReady(false);
    mount();
    await screen.findByTestId('stub-example_step');

    setReady(true);
    poll('example_step');

    expect(await screen.findByTestId('stub-verify')).toBeVisible();
    expect(continueBar()).toBeNull();
  });

  it('does not hold a step that is already done when reached', async () => {
    register(hold);
    seed('example_goal', {});
    setReady(true);
    mount();
    expect(await screen.findByTestId('stub-verify')).toBeVisible();
    expect(continueBar()).toBeNull();
  });

  it('drops the hold when the goal is changed', async () => {
    register(hold);
    seed('example_goal', {});
    setReady(false);
    mount();
    await screen.findByTestId('stub-example_step');
    setReady(true);
    poll('example_step');
    await waitFor(() => expect(continueBar()).not.toBeNull());

    fireEvent.click(
      screen.getAllByRole('button', {
        name: 'Change what I am setting up',
        hidden: true,
      })[0]
    );
    expect(
      await screen.findByRole('heading', {
        name: 'What do you want to do first?',
      })
    ).toBeVisible();
    expect(continueBar()).toBeNull();
  });
});
