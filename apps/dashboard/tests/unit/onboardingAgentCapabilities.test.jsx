import { cleanup, render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { describe, expect, it, vi } from 'vitest';

import { AgentStep } from '../../src/components/onboarding/certopsAgentStep.jsx';
import { planJourney } from '../../src/components/onboarding/journeyPlanner.js';
import {
  agentServesSetup,
  agentsFor,
  capabilityGap,
  commandProfileFor,
  needsAgentFacts,
  pickGoalAgent,
  requiredCapabilities,
} from '../../src/components/onboarding/certopsMatrix.js';
import {
  installerOptionsFor,
  installerOptionsKey,
} from '../../src/components/onboarding/certopsConfig.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import { realAgent } from './helpers/realAgentPayload.js';
import qualifiedManifest from '../../../../packages/agent/src/capabilities/qualified-capabilities.json';

const caps = {
  items: [
    { id: 'certops.core', state: 'ready' },
    { id: 'alerts.contact_groups', state: 'ready' },
  ],
};

const AUTOMATE_LINUX = {
  objective: 'automate',
  infrastructure: 'linux',
  certPath: '/etc/ssl/tokentimer/a.pem',
  reloadService: 'haproxy',
};

// Every pick, with the agent a correct real setup produces for it.
const PICKS = [
  {
    name: 'observe on Linux',
    goal: 'certops_observe',
    certops: { objective: 'observe', infrastructure: 'linux' },
    agent: realAgent('linux'),
    required: [],
  },
  {
    name: 'observe on Windows (no IIS needed)',
    goal: 'certops_observe',
    certops: { objective: 'observe', infrastructure: 'windows' },
    agent: realAgent('win32'),
    required: [],
  },
  {
    name: 'automate on Linux',
    goal: 'certops_automate',
    certops: {
      ...AUTOMATE_LINUX,
      installerKey: installerOptionsKey(installerOptionsFor(AUTOMATE_LINUX)),
    },
    agent: realAgent('linux', { commandProfiles: ['certbot'] }),
    required: [],
  },
  {
    name: 'automate on Windows',
    goal: 'certops_automate',
    certops: { objective: 'automate', infrastructure: 'windows' },
    agent: realAgent('win32', { commandProfiles: ['acme-windows'] }),
    required: ['windows-cert-store-v1', 'iis-binding-v1'],
  },
  {
    name: 'AD CS on Windows',
    goal: 'certops_adcs',
    certops: { objective: 'adcs', infrastructure: 'windows' },
    agent: realAgent('win32'),
    required: ['windows-cert-store-v1', 'iis-binding-v1', 'adcs-enroll-v1'],
  },
  {
    name: 'Vault on Linux',
    goal: 'certops_vault',
    certops: { objective: 'vault', infrastructure: 'linux' },
    agent: realAgent('linux', { commandProfiles: ['certbot'] }),
    required: [
      'material-store-vault-kv2-v1',
      'certificate-publication-v1',
      'deploy-from-store-v1',
    ],
  },
];

const agentStepStatus = (pick, agent) =>
  planJourney({
    intent: { goal: pick.goal },
    progress: {
      certops: { ...pick.certops, configReviewed: true },
    },
    capabilities: caps,
    reality: {
      alerts: { smtpConfigured: true },
      certops: {
        agents: {
          live: agent.livenessState === 'live' ? 1 : 0,
          items: [agent],
        },
      },
    },
  }).steps.find(s => s.id === 'certops_agent').status;

function mountStep(pick, agentOrList) {
  const items = Array.isArray(agentOrList) ? agentOrList : [agentOrList];
  const session = {
    intent: { goal: pick.goal },
    progress: { certops: { ...pick.certops, configReviewed: true } },
  };
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
      },
    },
    controller: { update: vi.fn().mockResolvedValue(undefined) },
  };
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <AgentStep ctx={ctx} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

describe('required capabilities per pick', () => {
  it.each(PICKS)('$name needs exactly $required', pick => {
    expect(
      requiredCapabilities(pick.certops.objective, pick.certops.infrastructure)
    ).toEqual(pick.required);
  });

  it('asks the observe picks for nothing beyond a live agent', () => {
    expect(needsAgentFacts('observe', 'linux')).toBe(false);
    expect(needsAgentFacts('observe', 'windows')).toBe(false);
    expect(needsAgentFacts('automate', 'linux')).toBe(true);
  });

  it('only asks for capabilities the 0.18.0 agent build qualifies', () => {
    const qualified = new Set(qualifiedManifest.qualified);
    for (const pick of PICKS) {
      for (const c of pick.required) expect(qualified.has(c)).toBe(true);
    }
  });
});

describe('a real 0.18.0 agent finishes the install step', () => {
  it.each(PICKS)('$name: planner is done and the card is Connected', pick => {
    const { objective, infrastructure } = pick.certops;
    expect(
      capabilityGap(objective, infrastructure, pick.agent.declaredCapabilities)
    ).toEqual([]);
    expect(agentServesSetup(pick.agent, objective, infrastructure)).toBe(true);
    expect(agentStepStatus(pick, pick.agent)).toBe('done');

    mountStep(pick, pick.agent);
    expect(screen.getByText('Connected')).toBeVisible();
    expect(screen.queryByText(/Missing capabilities/)).toBeNull();
    expect(screen.queryByText('Needs attention')).toBeNull();
  });

  it('AD CS needs no IIS role on the host: the agent declares iis-binding-v1 on any Windows host', () => {
    // The declaration is platform gated, not role gated, so a host without the
    // IIS role still declares it and the pick is satisfiable.
    const agent = realAgent('win32');
    expect(agent.declaredCapabilities).toContain('iis-binding-v1');
    expect(agentServesSetup(agent, 'adcs', 'windows')).toBe(true);
  });
});

describe('a truly missing capability keeps the step open and says how to fix it', () => {
  const strip = (agent, ...names) => ({
    ...agent,
    declaredCapabilities: agent.declaredCapabilities.filter(
      c => !names.includes(c)
    ),
  });

  it.each([
    ['AD CS', PICKS[4], 'adcs-enroll-v1'],
    ['automate on Windows', PICKS[3], 'iis-binding-v1'],
    ['Vault', PICKS[5], 'deploy-from-store-v1'],
  ])('%s without %s', (_n, pick, missing) => {
    const agent = strip(pick.agent, missing);
    expect(agentStepStatus(pick, agent)).toBe('current');

    mountStep(pick, agent);
    expect(screen.getByText('Needs attention')).toBeVisible();
    const note = screen.getByText(/Missing capabilities/).textContent;
    expect(note).toContain(missing);
    expect(note).toMatch(/0\.18\.0 or later/);
    expect(note).toMatch(/Upgrade this agent/);
  });

  it('does not count an agent that stopped checking in', () => {
    const stale = { ...PICKS[4].agent, livenessState: 'stale' };
    expect(agentStepStatus(PICKS[4], stale)).toBe('current');
  });

  it('keeps the profile rule: a discovery-only agent cannot serve automation', () => {
    const agent = realAgent('linux');
    expect(commandProfileFor('automate', 'linux')).toBe('certbot');
    expect(agentServesSetup(agent, 'automate', 'linux')).toBe(false);
  });

  it('accepts a second agent that has what the pick needs', () => {
    const weak = strip(PICKS[4].agent, 'adcs-enroll-v1');
    const pick = PICKS[4];
    const plan = planJourney({
      intent: { goal: pick.goal },
      progress: { certops: { ...pick.certops, configReviewed: true } },
      capabilities: caps,
      reality: {
        alerts: { smtpConfigured: true },
        certops: { agents: { live: 2, items: [weak, pick.agent] } },
      },
    });
    expect(plan.steps.find(s => s.id === 'certops_agent').status).toBe('done');
  });
});

describe('several agents in one workspace', () => {
  const web01 = realAgent('linux', {
    id: 'web-01-row',
    name: 'web-01',
    hostname: 'web-01',
    commandProfiles: ['certbot'],
  });
  const ca01 = realAgent('win32', { id: 'ca-01-row' });
  const adcs = PICKS[4];
  const status = (pick, items) =>
    planJourney({
      intent: { goal: pick.goal },
      progress: { certops: { ...pick.certops, configReviewed: true } },
      capabilities: caps,
      reality: {
        alerts: { smtpConfigured: true },
        certops: {
          agents: {
            live: items.filter(a => a.livenessState === 'live').length,
            items,
          },
        },
      },
    }).steps.find(s => s.id === 'certops_agent').status;

  it('Linux agent only: the AD CS pick stays open and names the Linux agent', () => {
    expect(status(adcs, [web01])).toBe('current');
    mountStep(adcs, web01);
    expect(screen.getByText('Waiting for an agent')).toBeVisible();
    // The Linux agent is never reported as the agent for this pick.
    expect(screen.queryByText(/web-01 \(linux, version/)).toBeNull();
    expect(screen.queryByText('Connected')).toBeNull();
    expect(screen.getByTestId('other-system-agents').textContent).toBe(
      'You also have 1 Linux agent in this workspace (web-01). It cannot be used for this setup. Install an agent on the Windows server.'
    );
  });

  it('Linux and Windows agents: the Windows one satisfies the pick, in any order', () => {
    expect(status(adcs, [web01, ca01])).toBe('done');
    expect(status(adcs, [ca01, web01])).toBe('done');
    for (const items of [
      [web01, ca01],
      [ca01, web01],
    ]) {
      cleanup();
      mountStep(adcs, items);
      expect(screen.getByText('Connected')).toBeVisible();
      expect(
        screen.getByText(/WIN-CA01 \(win32, version 0\.18\.0\)/)
      ).toBeVisible();
      expect(screen.queryByText(/web-01/)).toBeNull();
      expect(screen.queryByText(/Missing capabilities/)).toBeNull();
    }
  });

  it('picks the agent that serves each pick, whatever the list order', () => {
    for (const items of [
      [web01, ca01],
      [ca01, web01],
    ]) {
      expect(pickGoalAgent(items, 'adcs', 'windows').id).toBe('ca-01-row');
      expect(pickGoalAgent(items, 'vault', 'linux').id).toBe('web-01-row');
      expect(pickGoalAgent(items, 'automate', 'windows').id).toBe('ca-01-row');
    }
    // No Windows agent: nothing is chosen, so no job is aimed at web-01.
    expect(pickGoalAgent([web01], 'adcs', 'windows')).toBeUndefined();
  });

  it('a stale Windows agent does not count', () => {
    const stale = { ...ca01, livenessState: 'stale' };
    expect(status(adcs, [web01, stale])).toBe('current');
    cleanup();
    mountStep(adcs, [web01, stale]);
    expect(screen.getByText('Needs attention')).toBeVisible();
    expect(screen.getByText('It has not checked in recently.')).toBeVisible();
  });

  it('a Linux agent does not finish a Windows observe pick', () => {
    const observeWin = PICKS[1];
    expect(status(observeWin, [web01])).toBe('current');
    expect(status(observeWin, [web01, ca01])).toBe('done');
  });

  it('a Windows agent does not finish the Vault pick, a Vault agent does not finish AD CS', () => {
    const vault = PICKS[5];
    expect(status(vault, [ca01])).toBe('current');
    expect(status(vault, [ca01, web01])).toBe('done');
    expect(status(adcs, [web01])).toBe('current');
  });

  it('execution counts only the chosen agent, not another system that can run jobs', () => {
    const exec = { ...web01, supportedOperations: ['discover', 'issue'] };
    const winIdle = { ...ca01, supportedOperations: ['discover'] };
    const agents = { live: 2, executionEnabled: true, items: [exec, winIdle] };
    const win = pickGoalAgent(agents.items, 'adcs', 'windows');
    expect(agentsFor(agents, win).executionEnabled).toBe(false);
    const lin = pickGoalAgent(agents.items, 'vault', 'linux');
    expect(agentsFor(agents, lin).executionEnabled).toBe(true);
    expect(agentsFor(agents, undefined)).toMatchObject({
      live: 0,
      executionEnabled: false,
    });
  });
});
