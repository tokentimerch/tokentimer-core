import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { AgentStep } from '../../src/components/onboarding/certopsAgentStep.jsx';
import { FirstCertificateStep } from '../../src/components/onboarding/certopsFinalSteps.jsx';
import { planJourney } from '../../src/components/onboarding/journeyPlanner.js';
import {
  agentFitsSetup,
  agentMismatch,
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
import {
  chooseInfrastructure,
  scopeCertops,
} from '../../src/components/onboarding/certopsScope.js';
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
  it('keeps a checked Vault issuer installed while stopped for publication setup', () => {
    const pick = PICKS.find(p => p.objective === 'vault');
    const offline = { ...lin, livenessState: 'offline' };
    const args = {
      certops: { dryRun: { id: 'check', status: 'dry_run_complete' } },
      progress: {
        chosenAgentId: lin.id,
        chosenAgentConfirmed: lin.id,
        dryRunJobId: 'check',
        vaultIssuerAgentId: lin.id,
        vaultPublishJobId: 'publication',
      },
    };
    expect(status(plan(pick, [offline], args), 'certops_agent')).toBe('done');
    expect(
      status(
        plan(pick, [offline], {
          ...args,
          progress: {
            ...args.progress,
            chosenAgentId: undefined,
            chosenAgentConfirmed: undefined,
          },
        }),
        'certops_agent'
      )
    ).toBe('done');
    expect(
      status(
        plan(pick, [offline], {
          ...args,
          certops: { dryRun: { id: 'other', status: 'dry_run_complete' } },
        }),
        'certops_agent'
      )
    ).not.toBe('done');
    expect(
      status(
        plan(pick, [offline], {
          ...args,
          progress: { ...args.progress, vaultPublishJobId: '' },
        }),
        'certops_agent'
      )
    ).not.toBe('done');
    expect(
      status(
        plan(pick, [{ ...offline, commandProfiles: [] }], args),
        'certops_agent'
      )
    ).not.toBe('done');
  });

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

describe('without the checkbox, a pre-existing agent is never used', () => {
  const old = { ...lin, existedBeforeSession: true };
  const pick = PICKS[0];

  it('the install step keeps waiting for a new agent', () => {
    expect(setupAgentReady({ live: 1, items: [old] }, 'observe', 'linux')).toBe(
      false
    );
    expect(status(plan(pick, [old]), 'certops_agent')).toBe('current');
    expect(status(plan(pick, [old]), 'certops_first')).not.toBe('done');
  });

  it('an agent enrolled during the session counts at once', () => {
    expect(
      status(
        plan(pick, [{ ...lin, existedBeforeSession: false }]),
        'certops_agent'
      )
    ).toBe('done');
  });

  it('summaries that do not say when the agent was created read as new', () => {
    expect(status(plan(pick, [lin]), 'certops_agent')).toBe('done');
  });

  it('a new agent is the one every job targets, the old one is ignored', () => {
    const fresh = { ...lin, id: 'fresh-row', existedBeforeSession: false };
    expect(pickGoalAgent([old], 'observe', 'linux')).toBeUndefined();
    expect(pickSetupAgent([old], 'observe', 'linux')).toBeUndefined();
    expect(pickGoalAgent([old, fresh], 'observe', 'linux').id).toBe(
      'fresh-row'
    );
    expect(pickSetupAgent([old, fresh], 'observe', 'linux').id).toBe(
      'fresh-row'
    );
  });

  it('the first certificate and the closing check ignore its reports', () => {
    const certs = {
      agents: { live: 1, items: [old] },
      certificates: { observed: 3 },
    };
    expect(reportedCertificates(certs, { infrastructure: 'linux' })).toBe(0);
    const result = evaluateVerification({
      goal: 'certops_observe',
      summary: { certops: { ...certs, controllers: { clusters: [] } } },
      infrastructure: 'linux',
    });
    expect(result.checks.find(c => c.id === 'agent').status).toBe('fail');
  });

  it('waiting for the install keeps the step watching, as before', () => {
    expect(
      finishesByItself('certops_agent', {
        goal: 'certops_observe',
        progress: {
          certops: { objective: 'observe', infrastructure: 'linux' },
        },
      })
    ).toBe(true);
  });
});

describe('with "My agent is already set up" (chosenAgentId)', () => {
  const old = { ...lin, existedBeforeSession: true };
  const pick = PICKS[0];
  const chosen = { chosenAgentId: 'lin-row' };
  const confirmed = { ...chosen, chosenAgentConfirmed: 'lin-row' };

  it('a fitting chosen agent is satisfied only after Continue', () => {
    expect(
      status(plan(pick, [old], { progress: chosen }), 'certops_agent')
    ).toBe('current');
    expect(
      status(plan(pick, [old], { progress: confirmed }), 'certops_agent')
    ).toBe('done');
  });

  it('a confirmation for another agent does not count', () => {
    expect(
      status(
        plan(pick, [old], {
          progress: { ...chosen, chosenAgentConfirmed: 'other-row' },
        }),
        'certops_agent'
      )
    ).toBe('current');
  });

  it('the chosen agent is the only one that counts, even next to a new one', () => {
    const fresh = {
      ...lin,
      id: 'fresh-row',
      existedBeforeSession: false,
    };
    const items = [fresh, old];
    expect(pickGoalAgent(items, 'observe', 'linux', 'lin-row').id).toBe(
      'lin-row'
    );
    expect(pickSetupAgent(items, 'observe', 'linux', 'lin-row').id).toBe(
      'lin-row'
    );
    expect(
      status(plan(pick, [fresh], { progress: confirmed }), 'certops_agent')
    ).toBe('current');
  });

  it('a Windows agent can never be the chosen one for a Linux pick', () => {
    const oldWin = { ...win, existedBeforeSession: true };
    expect(
      status(
        plan(pick, [oldWin], {
          progress: {
            chosenAgentId: 'win-row',
            chosenAgentConfirmed: 'win-row',
          },
        }),
        'certops_agent'
      )
    ).toBe('current');
  });

  it('a chosen agent that lost a capability no longer satisfies the step', () => {
    const adcs = PICKS[5];
    const weak = {
      ...win,
      existedBeforeSession: true,
      declaredCapabilities: ['windows-cert-store-v1'],
    };
    const progress = {
      chosenAgentId: 'win-row',
      chosenAgentConfirmed: 'win-row',
    };
    expect(status(plan(adcs, [weak], { progress }), 'certops_agent')).toBe(
      'current'
    );
    expect(
      status(
        plan(
          adcs,
          [{ ...weak, declaredCapabilities: win.declaredCapabilities }],
          {
            progress,
          }
        ),
        'certops_agent'
      )
    ).toBe('done');
  });

  it('a chosen agent that disappeared leaves the step open', () => {
    expect(
      status(plan(pick, [], { progress: confirmed }), 'certops_agent')
    ).toBe('current');
  });

  it('the first certificate waits for the confirmed choice', () => {
    expect(
      status(plan(pick, [old], { progress: chosen }), 'certops_first')
    ).not.toBe('done');
    expect(
      status(plan(pick, [old], { progress: confirmed }), 'certops_first')
    ).toBe('done');
  });

  it('the Continue button moves on at once, so the step does not hold again', () => {
    const progress = {
      certops: { objective: 'observe', infrastructure: 'linux' },
    };
    expect(
      finishesByItself('certops_agent', {
        goal: 'certops_observe',
        progress: { certops: { ...progress.certops, ...chosen } },
      })
    ).toBe(false);
  });
});

describe('the choice never leaks into another pick', () => {
  const before = {
    objective: 'observe',
    infrastructure: 'linux',
    chosenAgentId: 'lin-row',
    chosenAgentConfirmed: 'lin-row',
    installerKey: 'k',
    configReviewed: true,
  };

  it('picking another platform forgets the choice and its confirmation', () => {
    const after = chooseInfrastructure(before, 'observe', 'windows');
    expect(after.chosenAgentId).toBeUndefined();
    expect(after.chosenAgentConfirmed).toBeUndefined();
    expect(after.configReviewed).toBeUndefined();
  });

  it('picking the same platform again keeps it', () => {
    const after = chooseInfrastructure(before, 'observe', 'linux');
    expect(after.chosenAgentId).toBe('lin-row');
    expect(after.chosenAgentConfirmed).toBe('lin-row');
  });

  it('sets, changes and clears the choice with the pick', () => {
    const set = chooseInfrastructure({}, 'observe', 'linux', 'lin-row');
    expect(set.chosenAgentId).toBe('lin-row');
    const changed = chooseInfrastructure(
      before,
      'observe',
      'linux',
      'other-row'
    );
    expect(changed.chosenAgentId).toBe('other-row');
    expect(changed.chosenAgentConfirmed).toBeUndefined();
    expect(changed.installerKey).toBeUndefined();
    const cleared = chooseInfrastructure(before, 'observe', 'linux', null);
    expect(cleared.chosenAgentId).toBeUndefined();
    expect(cleared.chosenAgentConfirmed).toBeUndefined();
  });

  it('a choice made for one goal is not seen by another goal', () => {
    const adcs = chooseInfrastructure({}, 'adcs', 'windows', 'win-row');
    const next = chooseInfrastructure(adcs, 'observe', 'linux');
    expect(scopeCertops(next, 'observe').chosenAgentId).toBeUndefined();
    expect(scopeCertops(next, 'adcs').chosenAgentId).toBe('win-row');
  });

  it('the AD CS Windows choice does not satisfy Discover on Linux', () => {
    const oldWin = { ...win, existedBeforeSession: true };
    const carried = chooseInfrastructure(
      chooseInfrastructure({}, 'adcs', 'windows', 'win-row'),
      'observe',
      'linux'
    );
    const p = planJourney({
      intent: { goal: 'certops_observe' },
      progress: { certops: { ...carried, configReviewed: true } },
      capabilities: caps,
      reality: {
        alerts: { smtpConfigured: true },
        certops: { agents: { live: 1, items: [oldWin] } },
      },
    });
    expect(status(p, 'certops_agent')).toBe('current');
  });
});

describe('why an agent does not fit a pick', () => {
  it('names the other system', () => {
    expect(agentMismatch(win, 'observe', 'linux')).toBe(
      'Windows agent, this setup needs Linux'
    );
    expect(agentMismatch(lin, 'adcs', 'windows')).toBe(
      'Linux agent, this setup needs Windows'
    );
  });

  it('names the missing capability or command profile', () => {
    const weak = { ...win, declaredCapabilities: ['windows-cert-store-v1'] };
    expect(agentMismatch(weak, 'adcs', 'windows')).toBe(
      'Missing capabilities: iis-binding-v1, adcs-enroll-v1'
    );
    expect(
      agentMismatch(
        {
          ...win,
          declaredCapabilities: ['windows-cert-store-v1', 'iis-binding-v1'],
        },
        'adcs',
        'windows'
      )
    ).toBe('Missing capability: adcs-enroll-v1');
    expect(
      agentMismatch({ ...lin, commandProfiles: [] }, 'automate', 'linux')
    ).toBe('Missing command profile: certbot');
  });

  it('is null for a fitting agent, offline or not', () => {
    expect(agentMismatch(win, 'adcs', 'windows')).toBeNull();
    expect(
      agentMismatch({ ...win, livenessState: 'offline' }, 'adcs', 'windows')
    ).toBeNull();
  });

  it('Kubernetes and an agent without a platform never fit', () => {
    expect(agentFitsSetup(lin, 'observe', 'kubernetes')).toBe(false);
    expect(agentFitsSetup({ ...lin, platform: null }, 'observe', 'linux')).toBe(
      false
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

  it('Discover on Linux with only a Windows agent: not connected, nothing suggested', () => {
    mount(AgentStep, {
      goal: 'certops_observe',
      certops: observeLinux,
      items: [win],
    });
    expect(screen.getByText('Waiting for an agent')).toBeVisible();
    expect(screen.queryByText('Connected')).toBeNull();
    expect(screen.queryByText(/WIN-CA01 \(win32, version/)).toBeNull();
    expect(screen.queryByTestId('other-system-agents')).toBeNull();
    expect(screen.queryByText(/You also have/)).toBeNull();
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
      expect(screen.queryByTestId('other-system-agents')).toBeNull();
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

  const REUSE_WORDING =
    /already have a suitable agent|Existing agent found|Use this agent and continue|Reusing the agent/;

  it('a pre-existing fitting agent is never offered: the install path stays', () => {
    mount(AgentStep, {
      goal: 'certops_observe',
      certops: observeLinux,
      items: [{ ...lin, existedBeforeSession: true }],
    });
    expect(screen.getByText('Waiting for an agent')).toBeVisible();
    expect(screen.queryByText('Connected')).toBeNull();
    expect(screen.queryByText(REUSE_WORDING)).toBeNull();
    expect(screen.queryByText(/web-01 \(linux, version/)).toBeNull();
    expect(screen.getByTestId('install-steps')).toBeVisible();
    expect(screen.queryByTestId('install-folded')).toBeNull();
  });

  it('the chosen agent is named, its install commands are folded, Continue confirms', () => {
    const update = vi.fn().mockResolvedValue(undefined);
    const certops = { ...observeLinux, chosenAgentId: 'lin-row' };
    const ctx = mount(AgentStep, {
      goal: 'certops_observe',
      certops,
      items: [{ ...lin, existedBeforeSession: true }],
      update,
    });
    expect(screen.getByTestId('chosen-agent').textContent).toMatch(
      /Using your agent.*web-01 \(Linux, version 0\.18\.0\)/
    );
    expect(screen.getByTestId('install-folded')).toBeInTheDocument();
    expect(screen.getByTestId('install-folded').hasAttribute('open')).toBe(
      false
    );
    expect(screen.queryByText(REUSE_WORDING)).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(update).toHaveBeenCalledTimes(1);
    const saved = update.mock.calls[0][0](ctx.session);
    expect(saved.progress.certops.chosenAgentConfirmed).toBe('lin-row');
    expect(saved.progress.certops.chosenAgentId).toBe('lin-row');
  });

  it('once confirmed, the chosen agent shows as connected', () => {
    mount(AgentStep, {
      goal: 'certops_observe',
      certops: {
        ...observeLinux,
        chosenAgentId: 'lin-row',
        chosenAgentConfirmed: 'lin-row',
      },
      items: [{ ...lin, existedBeforeSession: true }],
    });
    expect(screen.getByText('Connected')).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Continue' })).toBeNull();
  });

  it('an offline chosen agent keeps the step waiting and says so', () => {
    mount(AgentStep, {
      goal: 'certops_observe',
      certops: { ...observeLinux, chosenAgentId: 'lin-row' },
      items: [{ ...lin, existedBeforeSession: true, livenessState: 'offline' }],
    });
    expect(screen.getByTestId('chosen-agent').textContent).toMatch(
      /Waiting for your agent.*web-01 has not checked in recently/
    );
    expect(screen.queryByRole('button', { name: 'Continue' })).toBeNull();
    expect(
      screen.getByRole('button', { name: 'Install a new agent instead' })
    ).toBeVisible();
  });

  it('a chosen agent that is gone says so and falls back to the install path', () => {
    mount(AgentStep, {
      goal: 'certops_observe',
      certops: { ...observeLinux, chosenAgentId: 'lin-row' },
      items: [],
    });
    expect(screen.getByTestId('chosen-agent').textContent).toMatch(
      /Your agent is not in this workspace/
    );
    expect(screen.getByTestId('install-steps')).toBeVisible();
    expect(screen.queryByTestId('install-folded')).toBeNull();
  });

  it('a chosen agent that stopped fitting names the gap', () => {
    mount(AgentStep, {
      goal: 'certops_adcs',
      certops: {
        objective: 'adcs',
        infrastructure: 'windows',
        chosenAgentId: 'win-row',
      },
      items: [
        {
          ...win,
          existedBeforeSession: true,
          declaredCapabilities: ['windows-cert-store-v1'],
        },
      ],
    });
    expect(screen.getByTestId('chosen-agent').textContent).toMatch(
      /does not fit this setup.*Missing capabilities: iis-binding-v1, adcs-enroll-v1/
    );
  });

  it('Install a new agent instead clears the choice', () => {
    const update = vi.fn().mockResolvedValue(undefined);
    const certops = { ...observeLinux, chosenAgentId: 'lin-row' };
    const ctx = mount(AgentStep, {
      goal: 'certops_observe',
      certops,
      items: [],
      update,
    });
    fireEvent.click(
      screen.getByRole('button', { name: 'Install a new agent instead' })
    );
    const saved = update.mock.calls[0][0](ctx.session);
    expect(saved.progress.certops.chosenAgentId).toBeUndefined();
  });
  it('an agent enrolled by this guide is simply connected', () => {
    mount(AgentStep, {
      goal: 'certops_observe',
      certops: observeLinux,
      items: [{ ...lin, existedBeforeSession: false }],
    });
    expect(screen.getByText('Connected')).toBeVisible();
    expect(screen.queryByText(REUSE_WORDING)).toBeNull();
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
