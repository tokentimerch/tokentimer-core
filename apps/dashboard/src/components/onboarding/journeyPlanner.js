// Deterministic journey planner. The journey is never stored: it is derived
// from what the user asked for (intent), where they got to (progress), what
// the deployment allows (capabilities) and what really exists (reality).
// Adding steps later therefore needs no data migration.

export const PLANNER_VERSION = 1;

export const GOALS = {
  monitor_https: {
    label: 'Monitor a website certificate',
    description:
      'Track the HTTPS certificate of a site and get alerted before it expires.',
    steps: ['monitor', 'recipients', 'verify'],
    requires: ['monitoring.endpoint', 'alerts.contact_groups'],
  },
  track_asset: {
    label: 'Track an API key, secret or license',
    description: 'Record one asset by hand and get alerted before it expires.',
    steps: ['asset', 'recipients', 'verify'],
    requires: ['assets.manual', 'alerts.contact_groups'],
  },
};

export const STEP_DEFS = {
  goal: { title: 'What do you want to track?', kind: 'ui' },
  monitor: { title: 'Add the website to monitor', kind: 'ui' },
  asset: { title: 'Add your first asset', kind: 'ui' },
  recipients: { title: 'Choose who gets alerted', kind: 'ui' },
  verify: { title: 'Check that it is working', kind: 'verify' },
};

const ACTIVE_STATES = new Set(['ready', 'unknown']);

function findCapability(capabilities, id) {
  return (capabilities?.items || []).find(c => c.id === id) || null;
}

/** Why a goal cannot be started, or null when it can. */
export function goalBlocker(goalId, capabilities) {
  const goal = GOALS[goalId];
  if (!goal) return { code: 'UNKNOWN_GOAL' };
  // No capability data yet: do not block, the server enforces anyway.
  if (!capabilities?.items) return null;
  for (const id of goal.requires) {
    const cap = findCapability(capabilities, id);
    if (cap && !ACTIVE_STATES.has(cap.state)) {
      return {
        code: cap.blockers?.[0]?.code || cap.state.toUpperCase(),
        remediation: cap.blockers?.[0]?.remediation || null,
        capability: id,
        state: cap.state,
      };
    }
  }
  return null;
}

export function availableGoals(capabilities) {
  return Object.keys(GOALS).map(id => ({
    id,
    ...GOALS[id],
    blocker: goalBlocker(id, capabilities),
  }));
}

/**
 * Whether a step is already satisfied by verified backend state. Never reads
 * session flags: a deleted monitor or removed recipient reopens the step.
 */
export function isStepSatisfied(stepId, { reality, refs = {} } = {}) {
  if (!reality) return false;
  switch (stepId) {
    case 'monitor': {
      const url = refs.monitorUrl;
      return Boolean(
        url &&
        reality.monitors?.items?.some(
          m => m.url?.toLowerCase() === String(url).toLowerCase()
        )
      );
    }
    case 'asset':
      return (reality.references?.tokenIds?.existing || []).length > 0;
    case 'recipients':
      return reality.alerts?.contactGroups?.defaultHasEmailRecipient === true;
    default:
      return false;
  }
}

/**
 * @returns {{ steps: Array, currentStepId: string|null, complete: boolean }}
 */
export function planJourney({
  intent = {},
  progress = {},
  operationRefs = {},
  capabilities = null,
  reality = null,
} = {}) {
  const goalId = intent.goal;
  const goal = GOALS[goalId];
  if (!goal) {
    return {
      steps: [{ id: 'goal', ...STEP_DEFS.goal, status: 'current' }],
      currentStepId: 'goal',
      complete: false,
    };
  }

  const skipped = new Set(progress.skipped || []);
  const blocked = goalBlocker(goalId, capabilities);

  const steps = [{ id: 'goal', ...STEP_DEFS.goal, status: 'done' }];
  let currentAssigned = false;

  for (const id of goal.steps) {
    const def = STEP_DEFS[id];
    let status;
    if (id === 'verify') {
      // Verify is only meaningful once everything before it is satisfied.
      const earlierDone = steps.every(
        s => s.id === 'goal' || s.status === 'done' || s.status === 'skipped'
      );
      status = earlierDone && !currentAssigned ? 'current' : 'upcoming';
    } else if (isStepSatisfied(id, { reality, refs: operationRefs })) {
      status = 'done';
    } else if (skipped.has(id)) {
      status = 'skipped';
    } else if (!currentAssigned) {
      status = 'current';
    } else {
      status = 'upcoming';
    }
    if (status === 'current') currentAssigned = true;
    steps.push({ id, ...def, status });
  }

  const verifyStep = steps.find(s => s.id === 'verify');
  const verified =
    progress.verified === true && verifyStep?.status === 'current';
  if (verified) verifyStep.status = 'done';

  const current = steps.find(s => s.status === 'current') || null;
  return {
    steps,
    currentStepId: current ? current.id : null,
    blocked,
    complete: steps.every(s => s.status === 'done' || s.status === 'skipped'),
  };
}
