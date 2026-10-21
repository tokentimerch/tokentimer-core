import { describe, expect, it } from 'vitest';
import {
  GOALS,
  availableGoals,
  goalBlocker,
  isStepSatisfied,
  planJourney,
} from '../../src/components/onboarding/journeyPlanner.js';

const ready = id => ({ id, state: 'ready', blockers: [] });
const capabilities = {
  items: [
    ready('monitoring.endpoint'),
    ready('assets.manual'),
    ready('alerts.contact_groups'),
  ],
};

const emptyReality = {
  monitors: { items: [] },
  references: { tokenIds: { existing: [] } },
  alerts: { contactGroups: { defaultHasEmailRecipient: false } },
};

function statuses(plan) {
  return Object.fromEntries(plan.steps.map(s => [s.id, s.status]));
}

describe('planJourney', () => {
  it('starts at goal selection when nothing is chosen', () => {
    const plan = planJourney({});
    expect(plan.currentStepId).toBe('goal');
    expect(plan.complete).toBe(false);
  });

  it('plans only the steps the goal needs', () => {
    const plan = planJourney({
      intent: { goal: 'monitor_https' },
      capabilities,
      reality: emptyReality,
    });
    expect(plan.steps.map(s => s.id)).toEqual([
      'goal',
      'monitor',
      'recipients',
      'verify',
    ]);
    // No agent, issuance or integration steps for a simple monitor.
    expect(plan.steps.some(s => /agent|issuer|integration/.test(s.id))).toBe(
      false
    );
    expect(statuses(plan)).toEqual({
      goal: 'done',
      monitor: 'current',
      recipients: 'upcoming',
      verify: 'upcoming',
    });
  });

  it('derives completion from reality, not from stored flags', () => {
    const reality = {
      ...emptyReality,
      monitors: { items: [{ url: 'https://example.com' }] },
      alerts: { contactGroups: { defaultHasEmailRecipient: true } },
    };
    const plan = planJourney({
      intent: { goal: 'monitor_https' },
      // A stale claim in progress must not matter.
      progress: { skipped: [], monitorDone: true },
      operationRefs: { monitorUrl: 'https://example.com' },
      capabilities,
      reality,
    });
    expect(statuses(plan)).toMatchObject({
      monitor: 'done',
      recipients: 'done',
      verify: 'current',
    });
  });

  it('reopens a step when the thing it created was removed', () => {
    const planWith = monitors =>
      planJourney({
        intent: { goal: 'monitor_https' },
        operationRefs: { monitorUrl: 'https://example.com' },
        capabilities,
        reality: { ...emptyReality, monitors: { items: monitors } },
      });
    expect(statuses(planWith([{ url: 'https://example.com' }])).monitor).toBe(
      'done'
    );
    expect(statuses(planWith([])).monitor).toBe('current');
  });

  it('matches monitor URLs case-insensitively', () => {
    expect(
      isStepSatisfied('monitor', {
        reality: { monitors: { items: [{ url: 'HTTPS://Example.com' }] } },
        refs: { monitorUrl: 'https://example.com' },
      })
    ).toBe(true);
  });

  it('lets the user skip recipients without losing later steps', () => {
    const plan = planJourney({
      intent: { goal: 'monitor_https' },
      progress: { skipped: ['recipients'] },
      operationRefs: { monitorUrl: 'https://example.com' },
      capabilities,
      reality: {
        ...emptyReality,
        monitors: { items: [{ url: 'https://example.com' }] },
      },
    });
    expect(statuses(plan)).toMatchObject({
      monitor: 'done',
      recipients: 'skipped',
      verify: 'current',
    });
  });

  it('completes only after the verification is confirmed', () => {
    const base = {
      intent: { goal: 'track_asset' },
      operationRefs: { assetTokenIds: [5] },
      capabilities,
      reality: {
        ...emptyReality,
        references: {
          tokenIds: { existing: [5] },
          assetTokenIds: { existing: [5] },
        },
        alerts: { contactGroups: { defaultHasEmailRecipient: true } },
      },
    };
    expect(planJourney(base).complete).toBe(false);
    const confirmed = planJourney({ ...base, progress: { verified: true } });
    expect(confirmed.complete).toBe(true);
    expect(confirmed.currentStepId).toBeNull();
  });

  it('is deterministic and does not mutate its inputs', () => {
    const input = {
      intent: { goal: 'monitor_https' },
      progress: { skipped: ['recipients'] },
      capabilities,
      reality: emptyReality,
    };
    const frozen = JSON.stringify(input);
    const a = planJourney(input);
    const b = planJourney(input);
    expect(a).toEqual(b);
    expect(JSON.stringify(input)).toBe(frozen);
  });
});

describe('goal availability', () => {
  it('blocks a goal with the capability reason', () => {
    const blocked = {
      items: [
        {
          id: 'monitoring.endpoint',
          state: 'role_handoff',
          blockers: [{ code: 'ROLE_REQUIRED', remediation: 'Ask an admin.' }],
        },
        ready('alerts.contact_groups'),
        ready('assets.manual'),
      ],
    };
    expect(goalBlocker('monitor_https', blocked)).toMatchObject({
      code: 'ROLE_REQUIRED',
      remediation: 'Ask an admin.',
    });
    expect(goalBlocker('track_asset', blocked)).toBeNull();
    const goals = availableGoals(blocked);
    expect(goals.find(g => g.id === 'monitor_https').blocker).not.toBeNull();
    expect(goals.find(g => g.id === 'track_asset').blocker).toBeNull();
  });

  it('never blocks on unknown capability data', () => {
    expect(goalBlocker('monitor_https', null)).toBeNull();
    expect(
      goalBlocker('monitor_https', {
        items: [{ id: 'monitoring.endpoint', state: 'unknown', blockers: [] }],
      })
    ).toBeNull();
    expect(Object.keys(GOALS).length).toBeGreaterThan(0);
  });
});

describe('asset step completion', () => {
  const asset = (refs, references) =>
    isStepSatisfied('asset', {
      reality: { ...emptyReality, references },
      refs,
    });
  const refsOf = (tokens, assets = []) => ({
    tokenIds: { existing: tokens },
    assetTokenIds: { existing: assets },
  });

  it('is not done by certificates that website monitors created', () => {
    // Website goal finished, then the asset goal is chosen.
    const refs = {
      monitorUrl: 'https://example.com',
      monitorIds: ['m1'],
      tokenIds: [7],
    };
    expect(asset(refs, refsOf([7]))).toBe(false);
    const plan = planJourney({
      intent: { goal: 'track_asset' },
      operationRefs: refs,
      capabilities,
      reality: { ...emptyReality, references: refsOf([7]) },
    });
    expect(statuses(plan).asset).toBe('current');
  });

  it('is done by an asset made through the asset step', () => {
    const refs = {
      monitorIds: ['m1'],
      tokenIds: [7, 8],
      assetTokenIds: [8],
    };
    expect(asset(refs, refsOf([7, 8], [8]))).toBe(true);
  });

  it('reopens when the asset-step asset was deleted', () => {
    const refs = { tokenIds: [7, 8], assetTokenIds: [8] };
    expect(asset(refs, refsOf([7], []))).toBe(false);
  });

  it('keeps an empty assetTokenIds as not done even with other tokens', () => {
    expect(asset({ tokenIds: [7], assetTokenIds: [] }, refsOf([7], []))).toBe(
      false
    );
  });

  it('keeps old asset-only sessions done (no assetTokenIds, no monitors)', () => {
    expect(asset({ tokenIds: [5] }, refsOf([5]))).toBe(true);
    expect(asset({ tokenIds: [5] }, refsOf([]))).toBe(false);
  });

  it('does not trust old sessions that also created monitors', () => {
    expect(asset({ monitorIds: ['m1'], tokenIds: [5] }, refsOf([5]))).toBe(
      false
    );
    expect(
      asset({ monitorUrl: 'https://example.com', tokenIds: [5] }, refsOf([5]))
    ).toBe(false);
  });

  it('tolerates a summary without the asset references', () => {
    expect(asset({ assetTokenIds: [8] }, { tokenIds: { existing: [8] } })).toBe(
      false
    );
    expect(asset({}, undefined)).toBe(false);
  });

  it('leaves the website step to monitors, never to asset tokens', () => {
    const reality = {
      ...emptyReality,
      references: refsOf([5], [5]),
    };
    expect(
      isStepSatisfied('monitor', {
        reality,
        refs: { tokenIds: [5], assetTokenIds: [5] },
      })
    ).toBe(false);
    const plan = planJourney({
      intent: { goal: 'monitor_https' },
      operationRefs: { tokenIds: [5], assetTokenIds: [5] },
      capabilities,
      reality,
    });
    expect(statuses(plan).monitor).toBe('current');
  });

  it('does not change how import steps complete', () => {
    const reality = {
      ...emptyReality,
      assets: { total: 3 },
      references: refsOf([], []),
    };
    const progress = { imported: [{ step: 'file_import', count: 3 }] };
    expect(
      isStepSatisfied('file_import', { reality, progress, refs: {} })
    ).toBe(true);
    expect(
      isStepSatisfied('integration', { reality, progress, refs: {} })
    ).toBe(false);
  });
});

describe('certops_first completion', () => {
  const base = {
    monitors: { items: [] },
    references: { tokenIds: { existing: [] } },
  };
  const done = (progress, certops) =>
    isStepSatisfied('certops_first', {
      reality: { ...base, certops },
      progress,
    });

  it('treats discovery goals as done once an agent has reported a certificate', () => {
    const p = { certops: { objective: 'observe' } };
    const agents = { live: 1 };
    expect(done(p, { agents, certificates: { total: 1, observed: 0 } })).toBe(
      false
    );
    expect(done(p, { agents, certificates: { total: 1, observed: 1 } })).toBe(
      true
    );
  });

  it('does not count a certificate that no agent of this setup can have reported', () => {
    const p = { certops: { objective: 'observe', infrastructure: 'linux' } };
    // The workspace already holds a certificate, for example from a website
    // monitor, but no agent is connected.
    const certificates = { total: 1, observed: 1 };
    expect(done(p, { certificates })).toBe(false);
    expect(done(p, { agents: { live: 0 }, certificates })).toBe(false);
    expect(done(p, { agents: { live: 1 }, certificates })).toBe(true);
  });

  it('keeps Kubernetes working through the controller instead of an agent', () => {
    const p = {
      certops: {
        objective: 'observe',
        infrastructure: 'kubernetes',
        clusterId: 'prod-eu',
      },
    };
    const certificates = { total: 2, observed: 2 };
    const clusters = id => ({ controllers: { clusters: [{ clusterId: id }] } });
    expect(done(p, { certificates })).toBe(false);
    // A live agent elsewhere is not the controller.
    expect(done(p, { agents: { live: 1 }, certificates })).toBe(false);
    expect(done(p, { ...clusters('other'), certificates })).toBe(false);
    expect(done(p, { ...clusters('prod-eu'), certificates })).toBe(true);
  });

  it('does not count a requested order as an issued certificate on Linux', () => {
    const p = { certops: { objective: 'automate', infrastructure: 'linux' } };
    // A provisioning row exists as soon as the order is requested.
    const requested = {
      certificates: { total: 1, observed: 0 },
      issueJob: { status: 'pending', mode: 'real' },
    };
    expect(done(p, requested)).toBe(false);
  });

  it('requires a real, succeeded job on Linux automation', () => {
    const p = { certops: { objective: 'automate' } };
    const job = status => ({ certificates: { observed: 1 }, issueJob: status });
    expect(done(p, job({ status: 'failed', mode: 'real' }))).toBe(false);
    expect(done(p, job({ status: 'dry_run_complete', mode: 'dry_run' }))).toBe(
      false
    );
    expect(done(p, job({ status: 'succeeded', mode: 'dry_run' }))).toBe(false);
    expect(done(p, job({ status: 'succeeded', mode: 'real' }))).toBe(true);
  });

  it('requires a succeeded real issue job on Windows too, since the wizard now builds it', () => {
    const p = { certops: { objective: 'automate', infrastructure: 'windows' } };
    const withJob = issueJob => ({ certificates: { observed: 1 }, issueJob });
    // An observed certificate alone could predate the order.
    expect(done(p, { certificates: { observed: 1 } })).toBe(false);
    expect(done(p, withJob({ status: 'succeeded', mode: 'real' }))).toBe(true);
  });
});

describe('AD CS goal', () => {
  const progress = {
    certops: { objective: 'adcs', infrastructure: 'windows' },
  };
  const adcsDone = adcs =>
    isStepSatisfied('certops_adcs', {
      reality: { monitors: { items: [] }, certops: { adcs } },
      progress,
    });
  const safeIssuer = { confirmed: true, safe: true };

  it('has its own steps and never borrows the ACME ones', () => {
    const ids = GOALS.certops_adcs.steps;
    expect(ids).toContain('certops_adcs');
    expect(ids).not.toContain('certops_first');
    expect(ids).not.toContain('certops_execution');
    expect(GOALS.certops_adcs.candidate).toBe(true);
  });

  it('is not done for an unconfirmed or unsafe issuer, or without a profile', () => {
    expect(adcsDone({ issuers: [], profiles: 0 })).toBe(false);
    expect(adcsDone({ issuers: [safeIssuer], profiles: 0 })).toBe(false);
    expect(
      adcsDone({ issuers: [{ confirmed: false, safe: true }], profiles: 1 })
    ).toBe(false);
    expect(
      adcsDone({ issuers: [{ confirmed: true, safe: false }], profiles: 1 })
    ).toBe(false);
    expect(adcsDone(undefined)).toBe(false);
  });

  it('is done once a confirmed, safe issuer has a profile', () => {
    expect(adcsDone({ issuers: [safeIssuer], profiles: 1 })).toBe(true);
  });
});
