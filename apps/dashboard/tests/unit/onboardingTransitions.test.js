import { describe, expect, it } from 'vitest';
import {
  clearGoal,
  skipStep,
} from '../../src/components/onboarding/sessionTransitions.js';
import { planJourney } from '../../src/components/onboarding/journeyPlanner.js';

const session = {
  intent: { goal: 'import_integration', provider: 'github' },
  progress: {
    verified: true,
    skipped: ['recipients'],
    pending: { id: 'op', kind: 'monitor', identityKey: '{}' },
    imported: [{ step: 'integration', provider: 'github', count: 4 }],
    certops: { objective: 'observe', configReviewed: true },
    notificationsReviewed: true,
  },
};

describe('clearGoal', () => {
  it('clears the goal but keeps facts the server already holds', () => {
    const patch = clearGoal(session);
    expect(patch.intent.goal).toBe('');
    expect(patch.progress.imported).toEqual(session.progress.imported);
    expect(patch.progress.certops).toEqual(session.progress.certops);
    expect(patch.progress.notificationsReviewed).toBe(true);
    expect(patch.status).toBe('in_progress');
  });

  it('drops flags that belonged to the old goal', () => {
    const { progress } = clearGoal(session);
    expect(progress.verified).toBeUndefined();
    expect(progress.skipped).toBeUndefined();
    // A pending operation must not follow the user to a different goal.
    expect(progress.pending).toBeUndefined();
  });

  it('does not mutate the session and tolerates an empty one', () => {
    const frozen = JSON.stringify(session);
    clearGoal(session);
    expect(JSON.stringify(session)).toBe(frozen);
    expect(clearGoal({}).progress).toEqual({
      imported: [],
      certops: {},
      notificationsReviewed: false,
    });
  });

  it('sends the planner back to goal selection', () => {
    const patch = clearGoal(session);
    const plan = planJourney({
      intent: patch.intent,
      progress: patch.progress,
    });
    expect(plan.currentStepId).toBe('goal');
  });
});

describe('skipStep', () => {
  it('adds a step once and keeps the rest of progress', () => {
    const once = skipStep(
      { progress: { verified: false, skipped: ['a'] } },
      'b'
    );
    expect(once.progress.skipped).toEqual(['a', 'b']);
    expect(once.progress.verified).toBe(false);
    expect(
      skipStep({ progress: { skipped: ['a'] } }, 'a').progress.skipped
    ).toEqual(['a']);
    expect(skipStep({}, 'x').progress.skipped).toEqual(['x']);
  });
});
