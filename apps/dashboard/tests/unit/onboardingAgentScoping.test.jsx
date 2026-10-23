import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { AgentStep } from '../../src/components/onboarding/certopsAgentStep.jsx';
import { FirstCertificateStep } from '../../src/components/onboarding/certopsFinalSteps.jsx';
import { planJourney } from '../../src/components/onboarding/journeyPlanner.js';
import {
  agentOnPlatform,
  pickGoalAgent,
  pickSetupAgent,
  reportedCertificates,
  scopeAgents,
  setupAgentReady,
} from '../../src/components/onboarding/certopsMatrix.js';
import {
  installerOptionsFor,
  installerOptionsKey,
} from '../../src/components/onboarding/certopsConfig.js';
import { chooseInfrastructure } from '../../src/components/onboarding/certopsScope.js';
import { finishesByItself } from '../../src/components/onboarding/heldSteps.js';
import { evaluateVerification } from '../../src/components/onboarding/verification.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import { realAgent } from './helpers/realAgentPayload.js';

afterEach(cleanup);

const caps = {
  items: [
    { id: 'certops.core', state: 'ready' },
    { id: 'alerts.contact_groups', state: 'ready' },
  ],
};

const win = realAgent('win32', { id: 'win-row', commandProfiles: [] });
const lin = realAgent('linux', {
  id: 'lin-row',
  name: 'web-01',
  hostname: 'web-01',
  commandProfiles: ['certbot'],
  supportedOperations: ['discover', 'issue'],
});

// Every pick, with the agent that would serve it.
const PICKS = [
  {
    name: 'Discover on Linux',
    goal: 'certops_observe',
    objective: 'observe',
    infra: 'linux',
    serves: lin,
  },
  {
    name: 'Discover on Windows',
    goal: 'certops_observe',
    objective: 'observe',
    infra: 'windows',
    serves: win,
  },
  {
    name: 'Automate on Linux',
    goal: 'certops_automate',
    objective: 'automate',
    infra: 'linux',
    serves: lin,
  },
  {
    name: 'Vault on Linux',
    goal: 'certops_vault',
    objective: 'vault',
    infra: 'linux',
    serves: lin,
  },
  {
    name: 'Windows IIS (automate)',
    goal: 'certops_automate',
    objective: 'automate',
    infra: 'windows',
    serves: { ...win, commandProfiles: ['acme-windows'] },
  },
  {
    name: 'AD CS on Windows',
    goal: 'certops_adcs',
    objective: 'adcs',
    infra: 'windows',
    serves: win,
  },
];

function certopsProgress(pick, extra = {}) {
  const base = {
    objective: pick.objective,
    infrastructure: pick.infra,
    configReviewed: true,
  };
  if (pick.objective === 'automate' && pick.infra === 'linux') {
    const options = {
      objective: 'automate',
      infrastructure: 'linux',
      certPath: '/etc/ssl/tokentimer/a.pem',
      reloadService: 'haproxy',
    };
    return {
      ...base,
      certPath: options.certPath,
      reloadService: options.reloadService,
      installerKey: installerOptionsKey(installerOptionsFor(options)),
      ...extra,
    };
  }
  return { ...base, ...extra };
}

function plan(pick, items, { certops = {}, progress = {} } = {}) {
  const live = items.filter(a => a.livenessState === 'live').length;
  const saved = certopsProgress(pick, progress);
  return planJourney({
    intent: { goal: pick.goal },
    progress: { certops: saved },
    capabilities: caps,
    reality: {
      alerts: { smtpConfigured: true },
      certops: {
        agents: {
          live,
          total: items.length,
          executionEnabled: items.some(a =>
            (a.supportedOperations || []).includes('issue')
          ),
          items,
        },
        certificates: { observed: 3, total: 3 },
        controllers: { clusters: [] },
        dryRun: { status: 'dry_run_complete' },
        ...certops,
      },
    },
  });
}

const status = (p, id) => p.steps.find(s => s.id === id)?.status;

describe('agent satisfaction is a function of the pick', () => {
  // The Windows agent is the one from an AD CS setup.
  it.each(PICKS.filter(p => p.infra === 'linux'))(
    '$name is not satisfied by a live Windows agent',
    pick => {
      const p = plan(pick, [win]);
      expect(status(p, 'certops_agent')).not.toBe('done');
      expect(status(p, 'certops_execution')).not.toBe('done');
      expect(status(p, 'certops_first')).not.toBe('done');
      expect(p.currentStepId).toBe('certops_agent');
    }
  );

  it('Discover on Linux with a Windows agent that reported certificates stays at the install step', () => {
    const pick = PICKS[0];
    const p = plan(pick, [win]);
    expect(status(p, 'certops_agent')).toBe('current');
    // The workspace holds 3 certificates and one live agent, neither of which
    // belongs to this pick.
    expect(status(p, 'certops_first')).toBe('upcoming');
    expect(
      reportedCertificates(
        { agents: { live: 1, items: [win] }, certificates: { observed: 3 } },
        { infrastructure: 'linux' }
      )
    ).toBe(0);
  });

  it.each(PICKS.filter(p => p.infra === 'windows'))(
    '$name is not satisfied by a live Linux agent',
    pick => {
      const p = plan(pick, [lin]);
      expect(status(p, 'certops_agent')).not.toBe('done');
      expect(status(p, 'certops_first')).not.toBe('done');
      expect(p.currentStepId).toBe('certops_agent');
    }
  );

  it.each(PICKS)('$name is satisfied by its own agent', pick => {
    expect(status(plan(pick, [pick.serves]), 'certops_agent')).toBe('done');
  });

  it.each(PICKS)('$name ignores a second agent of the other system', pick => {
    const other = pick.infra === 'linux' ? win : lin;
    expect(status(plan(pick, [other, pick.serves]), 'certops_agent')).toBe(
      'done'
    );
    expect(status(plan(pick, [pick.serves, other]), 'certops_agent')).toBe(
      'done'
    );
  });

  it('execution counts the agent of the pick, not another system that can run jobs', () => {
    const pick = PICKS[1]; // Windows discover
    const cert = { dryRun: { status: 'dry_run_complete' } };
    const plain = { ...win, supportedOperations: ['discover'] };
    const runner = { ...lin, supportedOperations: ['discover', 'issue'] };
    const p = planJourney({
      intent: { goal: 'certops_automate' },
      progress: {
        certops: {
          objective: 'automate',
          infrastructure: 'windows',
          configReviewed: true,
        },
      },
      capabilities: caps,
      reality: {
        alerts: { smtpConfigured: true },
        certops: {
          agents: {
            live: 2,
            executionEnabled: true,
            items: [{ ...plain, commandProfiles: ['acme-windows'] }, runner],
          },
          ...cert,
        },
      },
    });
    expect(pick.infra).toBe('windows');
    expect(status(p, 'certops_execution')).not.toBe('done');
  });

  it('an agent that never reported a platform cannot be vouched for', () => {
    const unknown = { ...lin, platform: null };
    expect(agentOnPlatform(unknown, 'linux')).toBe(false);
    expect(status(plan(PICKS[0], [unknown]), 'certops_agent')).toBe('current');
  });

  it('Kubernetes never has an agent, whatever the workspace holds', () => {
    expect(agentOnPlatform(lin, 'kubernetes')).toBe(false);
    expect(agentOnPlatform(win, 'kubernetes')).toBe(false);
    expect(
      scopeAgents({ live: 2, items: [lin, win] }, 'kubernetes')
    ).toMatchObject({
      live: 0,
      total: 0,
      items: [],
    });
    const p = planJourney({
      intent: { goal: 'certops_observe' },
      progress: {
        certops: chooseInfrastructure({}, 'observe', 'kubernetes'),
      },
      capabilities: caps,
      reality: {
        alerts: { smtpConfigured: true },
        certops: {
          agents: { live: 2, items: [lin, win] },
          certificates: { observed: 5, total: 5 },
          controllers: { clusters: [] },
        },
      },
    });
    expect(status(p, 'certops_agent')).toBe('current');
    expect(status(p, 'certops_first')).not.toBe('done');
  });

  it('the Kubernetes pick is satisfied by its cluster controller only', () => {
    const certops = {
      ...chooseInfrastructure({}, 'observe', 'kubernetes'),
      clusterId: 'prod-eu',
    };
    const run = clusters =>
      planJourney({
        intent: { goal: 'certops_observe' },
        progress: { certops },
        capabilities: caps,
        reality: {
          alerts: { smtpConfigured: true },
          certops: {
            agents: { live: 0, items: [] },
            certificates: { observed: 1, total: 1 },
            controllers: { clusters },
          },
        },
      });
    expect(status(run([{ clusterId: 'other' }]), 'certops_agent')).toBe(
      'current'
    );
    expect(status(run([{ clusterId: 'prod-eu' }]), 'certops_agent')).toBe(
      'done'
    );
  });
});

describe('an agent that existed before the session', () => {
  const old = { ...lin, existedBeforeSession: true };
  const pick = PICKS[0];

  it('does not finish the install step until the operator reuses it', () => {
    expect(setupAgentReady({ live: 1, items: [old] }, 'observe', 'linux')).toBe(
      false
    );
    expect(status(plan(pick, [old]), 'certops_agent')).toBe('current');
    expect(
      status(
        plan(pick, [old], { progress: { reusedAgentId: 'lin-row' } }),
        'certops_agent'
      )
    ).toBe('done');
  });

  it('a reuse choice for another agent does not count', () => {
    expect(
      status(
        plan(pick, [old], { progress: { reusedAgentId: 'other-row' } }),
        'certops_agent'
      )
    ).toBe('current');
  });

  it('a Windows agent can never be the reused one for a Linux pick', () => {
    const oldWin = { ...win, existedBeforeSession: true };
    expect(
      status(
        plan(pick, [oldWin], { progress: { reusedAgentId: 'win-row' } }),
        'certops_agent'
      )
    ).toBe('current');
  });

  it('an agent enrolled during the session counts at once', () => {
    expect(
      status(
        plan(pick, [{ ...lin, existedBeforeSession: false }]),
        'certops_agent'
      )
    ).toBe('done');
  });

  it('a new agent wins over a reusable one for every job target', () => {
    const fresh = { ...lin, id: 'fresh-row', existedBeforeSession: false };
    expect(pickGoalAgent([old, fresh], 'observe', 'linux').id).toBe(
      'fresh-row'
    );
    expect(pickSetupAgent([old, fresh], 'observe', 'linux').id).toBe(
      'fresh-row'
    );
    expect(pickGoalAgent([old, fresh], 'observe', 'linux', 'lin-row').id).toBe(
      'lin-row'
    );
  });

  it('the first certificate waits for the reuse choice', () => {
    expect(status(plan(pick, [old]), 'certops_first')).not.toBe('done');
    expect(
      status(
        plan(pick, [old], { progress: { reusedAgentId: 'lin-row' } }),
        'certops_first'
      )
    ).toBe('done');
  });

  it('reuse is the operator click, so the step does not hold for a second Continue', () => {
    const progress = {
      certops: { objective: 'observe', infrastructure: 'linux' },
    };
    expect(
      finishesByItself('certops_agent', { goal: 'certops_observe', progress })
    ).toBe(true);
    expect(
      finishesByItself('certops_agent', {
        goal: 'certops_observe',
        progress: {
          certops: { ...progress.certops, reusedAgentId: 'lin-row' },
        },
      })
    ).toBe(false);
  });

  it('picking another platform forgets the reuse choice', () => {
    const before = {
      objective: 'observe',
      infrastructure: 'linux',
      reusedAgentId: 'lin-row',
      configReviewed: true,
    };
    const after = chooseInfrastructure(before, 'observe', 'windows');
    expect(after.reusedAgentId).toBeUndefined();
    expect(after.configReviewed).toBeUndefined();
    expect(chooseInfrastructure(before, 'observe', 'linux').reusedAgentId).toBe(
      'lin-row'
    );
  });
});

function mount(Component, { goal, certops, items, summary = {}, update }) {
  const session = { intent: { goal }, progress: { certops } };
  const ctx = {
    session,
    workspaceId: '045d89e4-3c97-4029-ab18-fa6f200ebe96',
    apiUrl: 'https://tt.example.com',
    docs: (key, label) => [{ label, url: `https://docs.example/${key}` }],
    refresh: vi.fn().mockResolvedValue(undefined),
    summary: {
      certops: {
        agents: {
          live: items.filter(a => a.livenessState === 'live').length,
          total: items.length,
          items,
        },
        ...summary,
      },
    },
    controller: { update: update || vi.fn().mockResolvedValue(undefined) },
  };
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <Component ctx={ctx} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
  return ctx;
}

describe('the install step display', () => {
  const observeLinux = { objective: 'observe', infrastructure: 'linux' };

  it('Discover on Linux with only a Windows agent: not connected, agent not shown', () => {
    mount(AgentStep, {
      goal: 'certops_observe',
      certops: observeLinux,
      items: [win],
    });
    expect(screen.getByText('Waiting for an agent')).toBeVisible();
    expect(screen.queryByText('Connected')).toBeNull();
    expect(screen.queryByText(/WIN-CA01 \(win32, version/)).toBeNull();
    expect(screen.queryByTestId('reuse-agent')).toBeNull();
    expect(screen.getByTestId('other-system-agents').textContent).toBe(
      'You also have 1 Windows agent in this workspace (WIN-CA01). It cannot be used for this setup. Install an agent on the Linux server.'
    );
  });

  it.each([
    [
      'Automate on Linux',
      'certops_automate',
      { objective: 'automate', infrastructure: 'linux' },
    ],
    [
      'Vault on Linux',
      'certops_vault',
      { objective: 'vault', infrastructure: 'linux' },
    ],
  ])(
    '%s with only a Windows agent shows no connected agent',
    (_n, goal, certops) => {
      mount(AgentStep, { goal, certops, items: [win] });
      expect(screen.getByText('Waiting for an agent')).toBeVisible();
      expect(screen.queryByText('Connected')).toBeNull();
      expect(screen.queryByText(/WIN-CA01 \(win32, version/)).toBeNull();
    }
  );

  it('Windows picks with only a Linux agent show no connected agent', () => {
    for (const [goal, certops] of [
      ['certops_adcs', { objective: 'adcs', infrastructure: 'windows' }],
      ['certops_observe', { objective: 'observe', infrastructure: 'windows' }],
    ]) {
      cleanup();
      mount(AgentStep, { goal, certops, items: [lin] });
      expect(screen.getByText('Waiting for an agent')).toBeVisible();
      expect(screen.queryByText(/web-01 \(linux, version/)).toBeNull();
      expect(screen.getByTestId('other-system-agents').textContent).toMatch(
        /1 Linux agent .*web-01.*Windows server/
      );
    }
  });

  it('Kubernetes shows the controller step and never an agent', () => {
    mount(AgentStep, {
      goal: 'certops_observe',
      certops: { objective: 'observe', infrastructure: 'kubernetes' },
      items: [lin, win],
    });
    expect(screen.getByText('Install the Kubernetes controller')).toBeVisible();
    expect(screen.queryByText('Connected')).toBeNull();
    expect(screen.queryByText(/web-01|WIN-CA01/)).toBeNull();
  });

  it('names an existing matching agent and waits for the operator', () => {
    const update = vi.fn().mockResolvedValue(undefined);
    const ctx = mount(AgentStep, {
      goal: 'certops_observe',
      certops: observeLinux,
      items: [{ ...lin, existedBeforeSession: true }],
      update,
    });
    expect(screen.getByText('Existing agent found')).toBeVisible();
    expect(screen.getByTestId('reuse-agent').textContent).toMatch(
      /web-01 \(linux\) was in this workspace before the guide started/
    );
    fireEvent.click(screen.getByText('Use this agent and continue'));
    expect(update).toHaveBeenCalledTimes(1);
    const saved = update.mock.calls[0][0](ctx.session);
    expect(saved.progress.certops.reusedAgentId).toBe('lin-row');
    expect(saved.progress.certops.objective).toBe('observe');
  });

  it('after the choice, says which existing agent is reused', () => {
    mount(AgentStep, {
      goal: 'certops_observe',
      certops: { ...observeLinux, reusedAgentId: 'lin-row' },
      items: [{ ...lin, existedBeforeSession: true }],
    });
    expect(screen.getByText('Connected')).toBeVisible();
    expect(screen.queryByText('Use this agent and continue')).toBeNull();
    expect(screen.getByTestId('reused-agent').textContent).toBe(
      'Reusing the agent that was already in this workspace: web-01 (linux).'
    );
  });

  it('an agent enrolled by this guide is simply connected', () => {
    mount(AgentStep, {
      goal: 'certops_observe',
      certops: observeLinux,
      items: [{ ...lin, existedBeforeSession: false }],
    });
    expect(screen.getByText('Connected')).toBeVisible();
    expect(screen.queryByTestId('reuse-agent')).toBeNull();
    expect(screen.queryByTestId('reused-agent')).toBeNull();
  });
});

describe('the first certificate step', () => {
  const observeLinux = { objective: 'observe', infrastructure: 'linux' };

  it('does not list or count the Windows agent for a Linux pick', () => {
    mount(FirstCertificateStep, {
      goal: 'certops_observe',
      certops: observeLinux,
      items: [win],
      summary: { certificates: { observed: 4, total: 4 } },
    });
    expect(screen.getByText('No certificates reported yet')).toBeVisible();
    expect(screen.queryByText(/WIN-CA01/)).toBeNull();
    expect(screen.queryByText(/certificates? in the inventory/)).toBeNull();
  });

  it('lists the agent of the pick, not the others', () => {
    mount(FirstCertificateStep, {
      goal: 'certops_observe',
      certops: observeLinux,
      items: [win, lin],
      summary: { certificates: { observed: 4, total: 4 } },
    });
    expect(screen.getByText(/Agent web-01 last seen/)).toBeVisible();
    expect(screen.queryByText(/WIN-CA01/)).toBeNull();
  });
});

describe('the closing check', () => {
  const summary = items => ({
    certops: {
      agents: { live: items.length, total: items.length, items },
      certificates: { observed: 3, total: 3 },
      controllers: { clusters: [{ clusterId: 'other' }] },
    },
  });
  const find = (result, id) => result.checks.find(c => c.id === id);

  it('a Windows agent is not an agent connected for Linux discovery', () => {
    const result = evaluateVerification({
      goal: 'certops_observe',
      summary: summary([win]),
      infrastructure: 'linux',
    });
    expect(find(result, 'agent').status).toBe('fail');
    expect(find(result, 'certificates').status).toBe('warn');
  });

  it('the agent of the pick passes', () => {
    const result = evaluateVerification({
      goal: 'certops_observe',
      summary: summary([win, lin]),
      infrastructure: 'linux',
    });
    expect(find(result, 'agent').status).toBe('pass');
    expect(find(result, 'agent').detail).toBe('1 live');
  });

  it('a controller of another cluster does not pass the Kubernetes pick', () => {
    const result = evaluateVerification({
      goal: 'certops_observe',
      summary: summary([win, lin]),
      infrastructure: 'kubernetes',
      clusterId: 'prod-eu',
    });
    expect(find(result, 'controller').status).toBe('fail');
    expect(find(result, 'agent')).toBeUndefined();
  });

  it('a Linux agent does not pass AD CS', () => {
    const result = evaluateVerification({
      goal: 'certops_adcs',
      summary: summary([lin]),
      infrastructure: 'windows',
    });
    expect(find(result, 'agent').status).toBe('fail');
  });
});
