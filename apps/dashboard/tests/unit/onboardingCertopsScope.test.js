import { describe, expect, it } from 'vitest';
import {
  scopeCertops,
  switchObjective,
} from '../../src/components/onboarding/certopsScope.js';
import { planJourney } from '../../src/components/onboarding/journeyPlanner.js';

const ready = id => ({ id, state: 'ready', blockers: [] });
const capabilities = {
  items: [ready('certops.core'), ready('alerts.contact_groups')],
};

// What a finished "Discover certificates" run leaves behind.
const afterDiscover = {
  certops: {
    objective: 'observe',
    infrastructure: 'linux',
    configReviewed: true,
    executionAcknowledged: true,
    directories: '/etc/ssl/certs',
    tokenCreatedAt: '2026-10-19T10:00:00.000Z',
  },
};

// A live agent registered for discovery: no certbot profile, no execution.
const discoveryAgent = {
  livenessState: 'live',
  platform: 'linux',
  commandProfiles: [],
  supportedOperations: ['noop'],
};
const reality = {
  monitors: { items: [] },
  references: { tokenIds: { existing: [] } },
  alerts: { contactGroups: { defaultHasEmailRecipient: true } },
  certops: {
    agents: { live: 1, executionEnabled: false, items: [discoveryAgent] },
    certificates: { total: 3, observed: 3 },
    dryRun: null,
    issueJob: null,
  },
};

const status = plan =>
  Object.fromEntries(plan.steps.map(s => [s.id, s.status]));

describe('scopeCertops', () => {
  it('keeps everything for the same objective', () => {
    expect(scopeCertops(afterDiscover.certops, 'observe')).toBe(
      afterDiscover.certops
    );
  });

  it('keeps only host facts when the objective changes', () => {
    expect(scopeCertops(afterDiscover.certops, 'automate')).toEqual({
      infrastructure: 'linux',
      tokenCreatedAt: '2026-10-19T10:00:00.000Z',
    });
  });

  it('drops a host type the new objective does not support', () => {
    const k8s = {
      objective: 'observe',
      infrastructure: 'kubernetes',
      clusterId: 'prod',
    };
    expect(scopeCertops(k8s, 'automate')).toEqual({ clusterId: 'prod' });
  });

  it('is safe with nothing saved', () => {
    expect(scopeCertops(undefined, 'automate')).toEqual({});
    expect(switchObjective(undefined, 'observe')).toEqual({});
  });
});

describe('Discover then Automate', () => {
  const plan = goal =>
    planJourney({
      intent: { goal },
      progress: afterDiscover,
      capabilities,
      reality,
    });

  it('finishes the discovery goal as before', () => {
    const s = status(plan('certops_observe'));
    expect(s.certops_objective).toBe('done');
    expect(s.certops_config).toBe('done');
    expect(s.certops_agent).toBe('done');
    expect(s.certops_execution).toBe('done');
    expect(s.certops_first).toBe('done');
  });

  it('does not let discovery progress satisfy any automation step', () => {
    const p = plan('certops_automate');
    const s = status(p);
    // The first automation step is open again, so the user is asked again.
    expect(s.certops_objective).toBe('current');
    expect(p.currentStepId).toBe('certops_objective');
    for (const id of ['certops_config', 'certops_execution', 'certops_first']) {
      expect(s[id]).not.toBe('done');
    }
  });

  it('does not accept a discovery-only agent for automation', () => {
    const progress = {
      certops: {
        objective: 'automate',
        infrastructure: 'linux',
        configReviewed: true,
      },
    };
    const p = planJourney({
      intent: { goal: 'certops_automate' },
      progress,
      capabilities,
      reality,
    });
    expect(status(p).certops_agent).not.toBe('done');
  });

  it('accepts an agent that declared the certbot profile', () => {
    const withProfile = {
      ...reality,
      certops: {
        ...reality.certops,
        agents: {
          live: 1,
          executionEnabled: true,
          items: [{ ...discoveryAgent, commandProfiles: ['certbot'] }],
        },
      },
    };
    const progress = {
      certops: {
        objective: 'automate',
        infrastructure: 'linux',
        configReviewed: true,
      },
    };
    const p = planJourney({
      intent: { goal: 'certops_automate' },
      progress,
      capabilities,
      reality: withProfile,
    });
    expect(status(p).certops_agent).toBe('done');
  });

  it('does not count the discovery inventory as an issued certificate', () => {
    const progress = {
      certops: {
        objective: 'automate',
        infrastructure: 'linux',
        configReviewed: true,
      },
    };
    const p = planJourney({
      intent: { goal: 'certops_automate' },
      progress,
      capabilities,
      reality,
    });
    expect(status(p).certops_first).not.toBe('done');
  });
});
