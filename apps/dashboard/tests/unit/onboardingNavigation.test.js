import { describe, expect, it } from 'vitest';
import { resolveNavigation } from '../../src/components/onboarding/stepNavigation.js';

const plan = (statuses, extra = {}) => {
  const steps = Object.entries(statuses).map(([id, status]) => ({
    id,
    status,
  }));
  const current = steps.find(s => s.status === 'current');
  return {
    steps,
    currentStepId: current ? current.id : null,
    complete: false,
    ...extra,
  };
};

describe('resolveNavigation', () => {
  const p = plan({
    goal: 'done',
    monitor: 'done',
    recipients: 'current',
    verify: 'upcoming',
  });

  it('shows the current step when nothing was asked for', () => {
    const n = resolveNavigation(p, null);
    expect(n).toMatchObject({
      viewing: null,
      shownId: 'recipients',
      previousId: 'monitor',
      nextId: null,
    });
  });

  it('lets the user go back to a finished step and forward again', () => {
    const back = resolveNavigation(p, 'monitor');
    expect(back).toMatchObject({
      viewing: 'monitor',
      shownId: 'monitor',
      previousId: 'goal',
      returnId: 'recipients',
    });
    // The next step is the current one, so "next" is the same as returning.
    expect(back.nextId).toBe(null);
  });

  it('can step through several finished steps', () => {
    const longer = plan({
      goal: 'done',
      a: 'done',
      b: 'done',
      c: 'current',
    });
    expect(resolveNavigation(longer, 'a').nextId).toBe('b');
    expect(resolveNavigation(longer, 'b').nextId).toBe(null);
    expect(resolveNavigation(longer, 'b').previousId).toBe('a');
  });

  it('can reach the choice of goal as the first step', () => {
    const n = resolveNavigation(p, 'goal');
    expect(n.viewing).toBe('goal');
    expect(n.previousId).toBe(null);
  });

  it('never reaches a step that is still upcoming', () => {
    expect(resolveNavigation(p, 'verify').viewing).toBe(null);
    expect(resolveNavigation(p, 'verify').shownId).toBe('recipients');
  });

  it('ignores an unknown step, as after a goal change', () => {
    expect(resolveNavigation(p, 'gone').viewing).toBe(null);
  });

  it('treats the current step as not being a review', () => {
    expect(resolveNavigation(p, 'recipients').viewing).toBe(null);
  });

  it('includes skipped steps', () => {
    const skipped = plan({ goal: 'done', smtp: 'skipped', verify: 'current' });
    expect(resolveNavigation(skipped, 'smtp').viewing).toBe('smtp');
  });

  it('goes back into a finished journey from the done screen', () => {
    const done = plan(
      { goal: 'done', monitor: 'done', verify: 'done' },
      { complete: true }
    );
    expect(resolveNavigation(done, null)).toMatchObject({
      shownId: null,
      previousId: 'verify',
    });
    expect(resolveNavigation(done, 'verify')).toMatchObject({
      viewing: 'verify',
      nextId: null,
    });
  });

  it('is safe without a plan', () => {
    expect(resolveNavigation(null, null)).toMatchObject({
      viewing: null,
      shownId: null,
      previousId: null,
    });
  });
});
