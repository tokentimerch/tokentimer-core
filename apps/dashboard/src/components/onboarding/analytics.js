import { trackEvent } from '../../utils/analytics';

// Only these values may leave the wizard. Names, hostnames, URLs, ids and free
// text are never sent, so events are built from fixed enums instead of
// forwarding whatever a step happens to hold.
const SAFE_VALUE = /^[a-z][a-z0-9_]{0,48}$/;

export function safeProps(props) {
  const out = {};
  for (const [key, value] of Object.entries(props || {})) {
    if (typeof value === 'boolean') out[key] = value;
    else if (typeof value === 'string' && SAFE_VALUE.test(value))
      out[key] = value;
  }
  return out;
}

export function trackOnboarding(name, props) {
  trackEvent(`onboarding_${name}`, safeProps(props));
}

/**
 * Events for the change between two plans, so a transition is reported once
 * and a plain reload reports nothing. `goal` is the chosen goal id or null.
 */
export function transitionEvents(previous, next, goal, previousGoal = null) {
  if (!next) return [];
  const events = [];
  if (!previous) {
    if (goal) events.push(['resumed', { goal, step: next.currentStepId }]);
    return events;
  }
  if (!previousGoal && goal) events.push(['goal_chosen', { goal }]);
  const before = new Map(previous.steps.map(s => [s.id, s.status]));
  for (const step of next.steps) {
    const was = before.get(step.id);
    if (!was || was === step.status) continue;
    if (step.status === 'done' && step.id !== 'goal')
      events.push(['step_done', { goal, step: step.id }]);
    if (step.status === 'skipped')
      events.push(['step_skipped', { goal, step: step.id }]);
  }
  if (!previous.complete && next.complete) events.push(['completed', { goal }]);
  return events;
}
