// Steps that finish by themselves while the person watches them: a job
// succeeds, an agent checks in, a controller reports. The guide keeps such a
// step on screen once it turns done, so the result can be read, and moves on
// only when the person presses Continue.
import { allGoals, editionStepHolds } from './editionModules.js';
import { scopeCertops } from './certopsScope.js';
import { canTickGoal } from './groupAttachment.js';

const WAITING_STEPS = new Set([
  'recipients',
  'certops_agent',
  'certops_execution',
  'certops_first',
  'certops_adcs',
  'certops_vault',
]);

// These render their own Continue (it is disabled until the step is done).
const OWN_CONTINUE = new Set(['recipients']);

/**
 * Whether this step can turn done without a click on the step itself.
 * Steps where the person's own button finishes the work keep moving on at
 * once, as before.
 */
export function finishesByItself(stepId, { goal, progress } = {}) {
  // Edition steps opt in with holdWhenDone; core steps never come from there.
  if (editionStepHolds(stepId)) return true;
  if (!WAITING_STEPS.has(stepId)) return false;
  // Ticks alone never finish the step: the operator's Continue confirms them,
  // and the page then moves on. Other goals confirm with a click as well.
  if (stepId === 'recipients') return canTickGoal(goal);
  // Reusing an existing agent is the person's own click, which is the
  // Continue: the step moves on at once.
  if (stepId === 'certops_agent') {
    const objective = allGoals()[goal]?.certopsObjective;
    return !scopeCertops(progress?.certops, objective).reusedAgentId;
  }
  if (stepId === 'certops_execution') {
    // Observe-only goals acknowledge with a button instead of waiting.
    const objective = allGoals()[goal]?.certopsObjective;
    return (
      scopeCertops(progress?.certops, objective).executionAcknowledged !== true
    );
  }
  return true;
}

export const hasOwnContinue = stepId => OWN_CONTINUE.has(stepId);

/** Journey identity: a new goal or platform starts without any hold. */
export function journeyKey(intent, progress) {
  const goal = intent?.goal || '';
  const objective = allGoals()[goal]?.certopsObjective;
  const infra = objective
    ? scopeCertops(progress?.certops, objective).infrastructure || ''
    : '';
  return `${goal}:${infra}`;
}

/**
 * The step to keep open: the one that was shown a moment ago, if it has just
 * turned done in the latest plan and is one that finishes by itself. Arriving
 * on an already-done step never matches, because nothing was shown before.
 * @param {{ id: string, key: string }|null} shown
 * @returns {string|null}
 */
export function observedDoneStep(shown, { key, plan, session }) {
  if (!shown?.id || shown.key !== key || !plan) return null;
  if (plan.currentStepId === shown.id) return null;
  const step = plan.steps.find(s => s.id === shown.id);
  if (step?.status !== 'done') return null;
  return finishesByItself(shown.id, {
    goal: session?.intent?.goal,
    progress: session?.progress,
  })
    ? shown.id
    : null;
}
