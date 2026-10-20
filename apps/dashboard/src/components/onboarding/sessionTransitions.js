// Pure session transitions for the wizard page. Kept separate from the
// component so the rules about what survives a change are testable.

import { GOALS } from './modules.js';
import { switchObjective } from './certopsScope.js';

/**
 * Leaving the current goal clears only the goal and its step flags. Facts the
 * server already holds (imports, agent and certificate progress, the chosen
 * provider) are kept, because the next goal may be satisfied by them and the
 * planner re-derives status from reality anyway.
 */
export function clearGoal(session) {
  const progress = session.progress || {};
  return {
    intent: { ...session.intent, goal: '' },
    progress: {
      imported: progress.imported || [],
      certops: progress.certops || {},
      notificationsReviewed: progress.notificationsReviewed === true,
    },
    status: 'in_progress',
  };
}

/**
 * Progress to keep when the chosen goal changes. Imports stay, step flags are
 * reset, and a certificate goal swaps in its own objective's saved progress
 * while parking the previous one.
 */
export function progressForGoalChange(progress, goalId) {
  const objective = GOALS[goalId]?.certopsObjective;
  return {
    imported: progress?.imported || [],
    certops: objective
      ? switchObjective(progress?.certops, objective)
      : progress?.certops || {},
  };
}

export function skipStep(session, stepId) {
  return {
    progress: {
      ...session.progress,
      skipped: Array.from(
        new Set([...(session.progress?.skipped || []), stepId])
      ),
    },
  };
}
