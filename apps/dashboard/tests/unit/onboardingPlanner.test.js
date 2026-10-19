import { describe, expect, it, vi } from 'vitest';
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
      operationRefs: {},
      capabilities,
      reality: {
        ...emptyReality,
        references: { tokenIds: { existing: [5] } },
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

  it('treats discovery goals as done once an observed certificate exists', () => {
    const p = { certops: { objective: 'observe' } };
    expect(done(p, { certificates: { total: 1, observed: 0 } })).toBe(false);
    expect(done(p, { certificates: { total: 1, observed: 1 } })).toBe(true);
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

  it('falls back to inventory on Windows, where the wizard cannot verify issuance', () => {
    const p = { certops: { objective: 'automate', infrastructure: 'windows' } };
    expect(done(p, { certificates: { observed: 1 } })).toBe(true);
  });
});
