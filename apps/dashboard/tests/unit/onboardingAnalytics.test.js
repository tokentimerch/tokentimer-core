import { describe, expect, it } from 'vitest';
import {
  safeProps,
  transitionEvents,
} from '../../src/components/onboarding/analytics.js';

const plan = (statuses, extra = {}) => ({
  steps: Object.entries(statuses).map(([id, status]) => ({ id, status })),
  currentStepId: Object.keys(statuses)[0],
  complete: false,
  ...extra,
});

describe('safeProps', () => {
  it('drops anything that could identify a person or asset', () => {
    expect(
      safeProps({
        goal: 'monitor_https',
        step: 'monitor',
        url: 'https://internal.example.com',
        email: 'a@b.co',
        id: '11111111-1111-4111-8111-111111111111',
        name: 'Prod DB key',
        ok: true,
        count: 3,
      })
    ).toEqual({ goal: 'monitor_https', step: 'monitor', ok: true });
  });

  it('rejects free text and mixed case, which ids and names tend to be', () => {
    expect(safeProps({ step: 'Has Spaces' })).toEqual({});
    expect(safeProps({ step: 'UPPER' })).toEqual({});
    expect(safeProps({ step: '' })).toEqual({});
    expect(safeProps(null)).toEqual({});
  });
});

describe('transitionEvents', () => {
  it('sends nothing on a plain load', () => {
    expect(transitionEvents(null, plan({ goal: 'current' }), null)).toEqual([]);
  });

  it('reports a resumed goal once, with only enum values', () => {
    const next = plan(
      { goal: 'done', monitor: 'current' },
      { currentStepId: 'monitor' }
    );
    expect(transitionEvents(null, next, 'monitor_https')).toEqual([
      ['resumed', { goal: 'monitor_https', step: 'monitor' }],
    ]);
  });

  it('reports a goal choice and each step as it completes', () => {
    const a = plan({ goal: 'current' });
    const b = plan({
      goal: 'done',
      monitor: 'current',
      recipients: 'upcoming',
    });
    expect(transitionEvents(a, b, 'monitor_https', null)).toEqual([
      ['goal_chosen', { goal: 'monitor_https' }],
    ]);
    const c = plan({ goal: 'done', monitor: 'done', recipients: 'current' });
    expect(transitionEvents(b, c, 'monitor_https', 'monitor_https')).toEqual([
      ['step_done', { goal: 'monitor_https', step: 'monitor' }],
    ]);
  });

  it('reports skips and completion, and not an unchanged plan', () => {
    const a = plan({ goal: 'done', recipients: 'current', verify: 'upcoming' });
    const same = plan({
      goal: 'done',
      recipients: 'current',
      verify: 'upcoming',
    });
    expect(transitionEvents(a, same, 'alerting', 'alerting')).toEqual([]);
    const b = plan({ goal: 'done', recipients: 'skipped', verify: 'current' });
    expect(transitionEvents(a, b, 'alerting', 'alerting')).toEqual([
      ['step_skipped', { goal: 'alerting', step: 'recipients' }],
    ]);
    const done = plan(
      { goal: 'done', recipients: 'skipped', verify: 'done' },
      { complete: true }
    );
    expect(transitionEvents(b, done, 'alerting', 'alerting')).toEqual([
      ['step_done', { goal: 'alerting', step: 'verify' }],
      ['completed', { goal: 'alerting' }],
    ]);
  });

  it('never carries a url, name or id even if a step id looks odd', () => {
    const evs = transitionEvents(
      plan({ goal: 'done', a: 'current' }),
      plan({ goal: 'done', a: 'done' }),
      'monitor_https',
      'monitor_https'
    );
    for (const [, props] of evs) {
      expect(JSON.stringify(safeProps(props))).not.toMatch(
        /https?:|@|[0-9a-f]{8}-/
      );
    }
  });
});
