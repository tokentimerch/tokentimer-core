import { useState } from 'react';
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  allGoals,
  allStepDefs,
  editionNextSteps,
  editionStepComponents,
  editionStepSatisfied,
  getEditionModules,
  resetEditionModules,
} from '../../src/components/onboarding/editionModules.js';
import {
  availableGoals,
  planJourney,
} from '../../src/components/onboarding/journeyPlanner.js';
import {
  finishesByItself,
  observedDoneStep,
} from '../../src/components/onboarding/heldSteps.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import {
  registerSsoEdition,
  ssoEditionModule,
} from '../../src/components/sso-setup/ssoEdition.js';
import SsoProviderStep from '../../src/components/sso-setup/SsoProviderStep.jsx';
import SsoMappingStep from '../../src/components/sso-setup/SsoMappingStep.jsx';
import { isSsoStepSatisfied } from '../../src/components/sso-setup/ssoSetupRules.js';
import apiClient from '../../src/utils/apiClient';

vi.mock('../../src/utils/apiClient', () => ({
  default: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
  API_BASE_URL: 'http://localhost:4000',
}));

const cap = (state = 'ready') => ({ id: 'sso.setup', state, blockers: [] });
const caps = (viewer, items = [cap()]) => ({ items, viewer });
const sso = ({ ready = 0, forReady = 0, items = [] } = {}) => ({
  edition: {
    sso: {
      applicable: true,
      providers: {
        total: items.length,
        enabled: items.filter(i => i.enabled).length,
        signInReady: ready,
        items,
      },
      mappings: { total: forReady, forReadyProviders: forReady },
    },
  },
});
const liveProvider = {
  slug: 'okta',
  type: 'oidc',
  displayName: 'Okta',
  enabled: true,
  signInReady: true,
};

beforeEach(() => registerSsoEdition());
afterEach(() => resetEditionModules());

describe('SSO goal registration', () => {
  it('registers one module with the goal, two steps and their components', () => {
    expect(getEditionModules().map(m => m.id)).toEqual(['sso']);
    expect(allGoals().sso_setup.label).toBe(
      'Set up single sign-on for my team'
    );
    expect(allGoals().sso_setup.steps).toEqual(['sso_provider', 'sso_mapping']);
    expect(Object.keys(allStepDefs())).toEqual(
      expect.arrayContaining(['sso_provider', 'sso_mapping'])
    );
    expect(editionStepComponents().sso_provider).toBe(SsoProviderStep);
    expect(editionStepComponents().sso_mapping).toBe(SsoMappingStep);
  });

  it('registers once even when asked twice', () => {
    expect(registerSsoEdition()).toBe(false);
    expect(getEditionModules()).toHaveLength(1);
  });

  it('requires the sso.setup capability for a system administrator', () => {
    expect(ssoEditionModule.goals.sso_setup.requires).toEqual([
      { capability: 'sso.setup', scope: 'system_admin' },
    ]);
  });
});

describe('SSO goal visibility', () => {
  const sso_goal = c => availableGoals(c).find(g => g.id === 'sso_setup');

  it('is offered to a system administrator when the capability exists', () => {
    expect(sso_goal(caps({ isSystemAdmin: true })).blocker).toBeNull();
  });

  it('is hidden from anyone who is not a system administrator', () => {
    const goal = sso_goal(
      caps({ isSystemAdmin: false, workspaceRole: 'admin' })
    );
    expect(goal.blocker).toMatchObject({
      hidden: true,
      code: 'SCOPE_REQUIRED',
    });
  });

  it('is hidden when the deployment has no sso.setup capability', () => {
    const goal = sso_goal(caps({ isSystemAdmin: true }, []));
    expect(goal.blocker).toMatchObject({
      hidden: true,
      code: 'CAPABILITY_MISSING',
    });
  });

  it('is hidden until capabilities are known', () => {
    expect(sso_goal(null).blocker).toMatchObject({ hidden: true });
  });
});

describe('SSO step rules', () => {
  it('judges the provider step by an enabled provider that can sign in', () => {
    const ctx = reality => ({ reality });
    expect(isSsoStepSatisfied('sso_provider', ctx(sso({ ready: 1 })))).toBe(
      true
    );
    expect(isSsoStepSatisfied('sso_provider', ctx(sso({ ready: 0 })))).toBe(
      false
    );
    expect(isSsoStepSatisfied('sso_provider', ctx({}))).toBe(false);
    expect(
      isSsoStepSatisfied('sso_provider', ctx({ edition: { sso: 'unknown' } }))
    ).toBe(false);
    expect(
      isSsoStepSatisfied(
        'sso_provider',
        ctx({ edition: { sso: { applicable: false } } })
      )
    ).toBe(false);
  });

  it('judges the mapping step by a mapping on a provider that can sign in', () => {
    const ctx = reality => ({ reality });
    expect(
      isSsoStepSatisfied('sso_mapping', ctx(sso({ ready: 1, forReady: 1 })))
    ).toBe(true);
    expect(
      isSsoStepSatisfied('sso_mapping', ctx(sso({ ready: 1, forReady: 0 })))
    ).toBe(false);
    expect(
      isSsoStepSatisfied('sso_mapping', ctx(sso({ ready: 0, forReady: 2 })))
    ).toBe(false);
  });

  it('has no opinion on other steps and is wired through the registry', () => {
    expect(isSsoStepSatisfied('monitor', {})).toBeUndefined();
    expect(
      editionStepSatisfied('sso_provider', { reality: sso({ ready: 1 }) })
    ).toBe(true);
  });
});

describe('SSO journey', () => {
  const plan = (reality, progress = {}) =>
    planJourney({
      intent: { goal: 'sso_setup' },
      progress,
      reality,
      capabilities: caps({ isSystemAdmin: true }),
    });

  it('starts on the provider step', () => {
    const p = plan({ ...sso(), alerts: {} });
    expect(p.steps.map(s => [s.id, s.status])).toEqual([
      ['goal', 'done'],
      ['sso_provider', 'current'],
      ['sso_mapping', 'upcoming'],
    ]);
  });

  it('moves to the mapping step once a provider can sign in', () => {
    const p = plan({ ...sso({ ready: 1, items: [liveProvider] }), alerts: {} });
    expect(p.currentStepId).toBe('sso_mapping');
  });

  it('completes with a mapping, or when the mapping step is skipped', () => {
    const done = plan({ ...sso({ ready: 1, forReady: 1 }), alerts: {} });
    expect(done.complete).toBe(true);
    const skipped = plan(
      { ...sso({ ready: 1 }), alerts: {} },
      { skipped: ['sso_mapping'] }
    );
    expect(skipped.complete).toBe(true);
  });

  it('reopens the provider step when the provider is disabled', () => {
    const p = plan({ ...sso({ ready: 0 }), alerts: {} });
    expect(p.currentStepId).toBe('sso_provider');
    expect(p.complete).toBe(false);
  });

  it('supplies the closing sentences as plain strings', () => {
    const steps = editionNextSteps('sso_setup', sso({ ready: 1, forReady: 1 }));
    expect(steps).toEqual(
      expect.arrayContaining([
        'Invite your team to sign in with SSO.',
        expect.stringMatching(/Verify sign-in and workspace access/),
      ])
    );
    expect(steps.every(s => typeof s === 'string')).toBe(true);
    expect(editionNextSteps('sso_setup', sso({ ready: 1 }))[0]).toMatch(
      /Add a group mapping/
    );
    expect(editionNextSteps('monitor_https', {})).toBeUndefined();
  });
});

describe('SSO provider step hold', () => {
  const plan = (reality, heldStepId = null) =>
    planJourney({
      intent: { goal: 'sso_setup' },
      progress: {},
      reality: { ...reality, alerts: {} },
      capabilities: caps({ isSystemAdmin: true }),
      heldStepId,
    });
  const session = { intent: { goal: 'sso_setup' }, progress: {} };
  const key = 'sso_setup:';

  it('registers the provider step as holding and the mapping step as not', () => {
    expect(ssoEditionModule.steps.sso_provider.holdWhenDone).toBe(true);
    expect(ssoEditionModule.steps.sso_mapping.holdWhenDone).toBeUndefined();
    expect(finishesByItself('sso_provider', { goal: 'sso_setup' })).toBe(true);
    expect(finishesByItself('sso_mapping', { goal: 'sso_setup' })).toBe(false);
  });

  it('notices the provider step turning ready while it is on screen', () => {
    const before = plan(sso());
    expect(before.currentStepId).toBe('sso_provider');
    const after = plan(sso({ ready: 1, items: [liveProvider] }));
    expect(after.currentStepId).toBe('sso_mapping');
    const held = observedDoneStep(
      { id: 'sso_provider', key },
      { key, plan: after, session }
    );
    expect(held).toBe('sso_provider');
  });

  it('keeps the finished provider step current until Continue, then moves on', () => {
    const reality = sso({ ready: 1, items: [liveProvider] });
    const heldPlan = plan(reality, 'sso_provider');
    expect(heldPlan.currentStepId).toBe('sso_provider');
    expect(heldPlan.steps.find(s => s.id === 'sso_provider').status).toBe(
      'done'
    );
    expect(heldPlan.steps.find(s => s.id === 'sso_mapping').status).toBe(
      'upcoming'
    );
    expect(heldPlan.complete).toBe(false);
    expect(plan(reality).currentStepId).toBe('sso_mapping');
  });

  it('does not hold a provider step that is already done on arrival', () => {
    const after = plan(sso({ ready: 1, items: [liveProvider] }));
    expect(observedDoneStep(null, { key, plan: after, session })).toBeNull();
  });

  it('does not hold the mapping step when it completes', () => {
    const done = plan(sso({ ready: 1, forReady: 1, items: [liveProvider] }));
    expect(
      observedDoneStep({ id: 'sso_mapping', key }, { key, plan: done, session })
    ).toBeNull();
  });
});

function renderStep(Step, ctx) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter>
          <Step ctx={ctx} />
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

const ctxFor = (summary, extra = {}) => ({
  summary,
  capabilities: { docsBaseUrl: 'https://tokentimer.ch/docs/self-hosted' },
  refresh: vi.fn().mockResolvedValue(undefined),
  skip: vi.fn(),
  ...extra,
});

describe('embedded SSO steps', () => {
  beforeEach(() => {
    apiClient.get.mockImplementation(async url => {
      if (url === '/api/admin/sso/group-mappings') {
        return {
          data: {
            mappings: [],
            workspaces: [{ id: 'w1', name: 'Platform' }],
            providers: [{ slug: 'okta', displayName: 'Okta', type: 'oidc' }],
          },
        };
      }
      return { data: {} };
    });
  });
  afterEach(() => vi.clearAllMocks());

  it('renders the provider wizard without the page shell', async () => {
    renderStep(SsoProviderStep, ctxFor(sso()));
    expect(
      screen.getByRole('region', { name: 'Connect your identity provider' })
    ).toBeTruthy();
    await waitFor(() => expect(screen.getByText(/Step 1 of 6/)).toBeTruthy());
    expect(screen.queryByText('Add SSO provider')).toBeNull();
    expect(
      screen
        .getByRole('link', { name: /SSO documentation/ })
        .getAttribute('href')
    ).toBe('https://tokentimer.ch/docs/self-hosted/authentication');
  });

  it('shows the live provider when a finished step is reviewed', () => {
    renderStep(
      props => <SsoProviderStep {...props} reviewing />,
      ctxFor(sso({ ready: 1, items: [liveProvider] }))
    );
    expect(screen.getByText('Okta')).toBeTruthy();
  });

  it('saves the new provider disabled, tests it, then enables it inside the guide', async () => {
    apiClient.post.mockResolvedValue({ data: { ok: true, checks: [] } });
    apiClient.put.mockResolvedValue({ data: { ok: true } });
    const ctx = ctxFor(sso());
    renderStep(SsoProviderStep, ctx);

    const continueStep = () =>
      fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    continueStep();
    continueStep();
    for (const [label, value] of [
      [/^Display name/, 'Platform SSO'],
      [/^Issuer URL/, 'https://idp.example.test'],
      [/^Client ID/, 'dashboard'],
      [/^Client secret/, 'fixture-secret'],
    ]) {
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    }
    continueStep();
    continueStep();
    fireEvent.click(screen.getByRole('button', { name: 'Save and run test' }));
    const enable = await screen.findByRole('button', {
      name: 'Enable provider',
    });
    expect(apiClient.post.mock.calls.map(([path]) => path)).toEqual([
      '/api/admin/sso/providers',
      '/api/admin/sso/providers/platform-sso/test',
    ]);
    expect(apiClient.post.mock.calls[0][1]).toMatchObject({ enabled: false });
    expect(apiClient.put).not.toHaveBeenCalled();

    fireEvent.click(enable);
    await screen.findByText(/Waiting for the provider/);
    expect(apiClient.put).toHaveBeenCalledWith(
      '/api/admin/sso/providers/platform-sso',
      { enabled: true }
    );
    expect(ctx.refresh).toHaveBeenCalledTimes(1);
    expect(
      screen.queryByRole('button', { name: 'Enable provider' })
    ).toBeNull();
  });

  it('does not offer a second provider when an enabled provider needs repair', () => {
    renderStep(
      SsoProviderStep,
      ctxFor(
        sso({
          items: [{ ...liveProvider, signInReady: false }],
        })
      )
    );
    expect(
      screen.getByRole('link', { name: 'Manage SSO providers' })
    ).toBeTruthy();
    expect(screen.queryByText(/Step 1 of 6/)).toBeNull();
  });

  it('renders the existing mappings UI and lets the person skip', async () => {
    const ctx = ctxFor(sso({ ready: 1, items: [liveProvider] }));
    renderStep(SsoMappingStep, ctx);
    await waitFor(() =>
      expect(screen.getByText(/No mappings yet/)).toBeTruthy()
    );
    expect(screen.getByRole('button', { name: /Add mapping/ })).toBeTruthy();
    screen.getByRole('button', { name: /Skip for now/ }).click();
    expect(ctx.skip).toHaveBeenCalledWith('sso_mapping');
  });

  it.each([
    {
      from: 'offline',
      to: 'okta',
      reviewing: false,
      before: 'pending',
      after: 'complete',
    },
    {
      from: 'okta',
      to: 'offline',
      reviewing: true,
      before: 'complete',
      after: 'pending',
    },
  ])(
    'refreshes readiness after editing a mapping from $from to $to',
    async ({ from, to, reviewing, before, after }) => {
      let mappings = [
        {
          id: 'm1',
          provider_slug: from,
          idp_group: 'platform-team',
          role: 'viewer',
          workspace_id: 'w1',
        },
      ];
      const offlineProvider = {
        slug: 'offline',
        type: 'oidc',
        displayName: 'Offline IdP',
        enabled: false,
        signInReady: false,
      };
      const providers = [liveProvider, offlineProvider];
      const readSummary = () =>
        sso({
          ready: 1,
          forReady: mappings.filter(mapping => mapping.provider_slug === 'okta')
            .length,
          items: providers,
        });
      apiClient.get.mockImplementation(async () => ({
        data: {
          mappings: mappings.map(mapping => ({ ...mapping })),
          workspaces: [{ id: 'w1', name: 'Platform' }],
          providers,
        },
      }));
      apiClient.put.mockImplementation(async (url, payload) => {
        mappings = [{ ...mappings[0], ...payload }];
        return { data: mappings[0] };
      });
      const refresh = vi.fn();
      function Harness({ revision }) {
        const [summary, setSummary] = useState(readSummary);
        refresh.mockImplementation(async () => {
          const current = readSummary();
          setSummary(current);
          return current;
        });
        return (
          <>
            <output aria-label='Mapping readiness' data-revision={revision}>
              {isSsoStepSatisfied('sso_mapping', { reality: summary })
                ? 'complete'
                : 'pending'}
            </output>
            <SsoMappingStep
              ctx={ctxFor(summary, { refresh })}
              reviewing={reviewing}
            />
          </>
        );
      }
      const tree = revision => (
        <ChakraProvider>
          <DashboardThemeProvider>
            <MemoryRouter>
              <Harness revision={revision} />
            </MemoryRouter>
          </DashboardThemeProvider>
        </ChakraProvider>
      );
      const view = render(tree(0));
      await screen.findByText('platform-team');
      expect(screen.getByLabelText('Mapping readiness').textContent).toBe(
        before
      );
      expect(refresh).not.toHaveBeenCalled();

      fireEvent.click(screen.getByRole('button', { name: 'Edit mapping' }));
      const dialog = await screen.findByRole('dialog');
      fireEvent.change(within(dialog).getByLabelText('Identity provider'), {
        target: { value: to },
      });
      fireEvent.click(
        within(dialog).getByRole('button', { name: 'Save changes' })
      );

      await waitFor(() =>
        expect(apiClient.put).toHaveBeenCalledWith(
          '/api/admin/sso/group-mappings/m1',
          {
            provider_slug: to,
            idp_group: 'platform-team',
            role: 'viewer',
            workspace_id: 'w1',
          }
        )
      );
      await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
      expect(mappings).toHaveLength(1);
      await waitFor(() =>
        expect(screen.getByLabelText('Mapping readiness').textContent).toBe(
          after
        )
      );
      expect(refresh).toHaveBeenCalledTimes(1);
      expect(apiClient.get).toHaveBeenCalledTimes(2);

      // Updating the parent with the refreshed summary must not start a loop.
      view.rerender(tree(1));
      expect(screen.getByLabelText('Mapping readiness').dataset.revision).toBe(
        '1'
      );
      expect(refresh).toHaveBeenCalledTimes(1);
      expect(apiClient.get).toHaveBeenCalledTimes(2);
    }
  );
});
