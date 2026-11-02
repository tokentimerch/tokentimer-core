// Extension point for editions: an edition can register extra goals, steps,
// step components and "done" rules for the setup guide. With nothing
// registered every reader returns the core tables themselves, so the guide
// behaves exactly as before.
//
// Call site: the edition's dashboard entry imports a module that calls
// registerEditionModule(...) before the app renders. Registration is
// synchronous and one-time; ids must not collide with core or with another
// module.
//
//   registerEditionModule({
//     id: 'example',
//     areas: [{ id: 'example_area', label: 'Example' }],
//     steps: {
//       example_step: {
//         title: 'Do the thing',
//         kind: 'ui',
//         // Optional, default false. Set it on a step that can turn done by
//         // itself while the person watches (a provider becoming ready, a
//         // job finishing): the guide then keeps it on screen with a
//         // Continue button instead of jumping to the next step. Leave it
//         // off for steps whose own button finishes the work.
//         holdWhenDone: true,
//       },
//     },
//     goals: {
//       example_goal: {
//         label, description, time, steps: ['example_step', 'verify'],
//         area: 'example_area',
//         // Capability ids (strings) or { capability, scope } objects. A goal
//         // whose capability is missing, or whose scope the viewer lacks, is
//         // hidden from the picker.
//         requires: [{ capability: 'example.setup', scope: 'system_admin' }],
//       },
//     },
//     components: { example_step: ExampleStep },
//     isStepSatisfied: (stepId, ctx) => boolean | undefined,
//     nextSteps: (goalId, summary) => string[] | undefined,
//   });

import { GOALS, STEP_DEFS, GOAL_AREAS } from './modules.js';

const ID = /^[a-z][a-z0-9_]{0,39}$/;
const STEP_KINDS = new Set(['ui', 'verify', 'runbook']);
const SCOPES = new Set([
  'system_admin',
  'workspace_admin',
  'workspace_manager',
]);

const registry = [];
// Merged tables are rebuilt only when the registry changes.
let merged = null;

function fail(message) {
  throw new Error(`Edition module: ${message}`);
}

function checkId(kind, id) {
  if (typeof id !== 'string' || !ID.test(id)) {
    fail(`${kind} id "${id}" must match ${ID}`);
  }
}

/** Normalizes one `requires` entry to { capability, scope|null }. */
export function normalizeRequirement(entry) {
  if (typeof entry === 'string') return { capability: entry, scope: null };
  return { capability: entry?.capability, scope: entry?.scope || null };
}

function validate(mod) {
  if (!mod || typeof mod !== 'object') fail('a module object is required');
  checkId('module', mod.id);
  if (registry.some(m => m.id === mod.id)) {
    fail(`module "${mod.id}" is already registered`);
  }

  const takenSteps = new Set([
    ...Object.keys(STEP_DEFS),
    ...registry.flatMap(m => Object.keys(m.steps)),
  ]);
  const takenGoals = new Set([
    ...Object.keys(GOALS),
    ...registry.flatMap(m => Object.keys(m.goals)),
  ]);
  const takenAreas = new Set([
    ...GOAL_AREAS.map(a => a.id),
    ...registry.flatMap(m => m.areas.map(a => a.id)),
  ]);

  const areas = mod.areas || [];
  const steps = mod.steps || {};
  const goals = mod.goals || {};
  const components = mod.components || {};

  const ownAreas = new Set();
  for (const area of areas) {
    checkId('area', area?.id);
    if (takenAreas.has(area.id) || ownAreas.has(area.id)) {
      fail(`area "${area.id}" is already registered`);
    }
    if (!area.label) fail(`area "${area.id}" needs a label`);
    ownAreas.add(area.id);
  }

  for (const [id, def] of Object.entries(steps)) {
    checkId('step', id);
    if (takenSteps.has(id)) fail(`step "${id}" is already registered`);
    if (!def?.title) fail(`step "${id}" needs a title`);
    if (!STEP_KINDS.has(def.kind)) fail(`step "${id}" has an unknown kind`);
    if (
      def.holdWhenDone !== undefined &&
      typeof def.holdWhenDone !== 'boolean'
    ) {
      fail(`step "${id}" holdWhenDone must be a boolean`);
    }
  }
  for (const [id, component] of Object.entries(components)) {
    if (!Object.prototype.hasOwnProperty.call(steps, id)) {
      fail(`component "${id}" does not belong to a step of this module`);
    }
    if (typeof component !== 'function' && typeof component !== 'object') {
      fail(`component "${id}" must be a React component`);
    }
  }
  for (const id of Object.keys(steps)) {
    if (!components[id]) fail(`step "${id}" has no component`);
  }

  const allSteps = new Set([...takenSteps, ...Object.keys(steps)]);
  const allAreas = new Set([...takenAreas, ...ownAreas]);
  for (const [id, goal] of Object.entries(goals)) {
    checkId('goal', id);
    if (takenGoals.has(id)) fail(`goal "${id}" is already registered`);
    if (!goal?.label || !goal.description) {
      fail(`goal "${id}" needs a label and a description`);
    }
    if (!Array.isArray(goal.steps) || goal.steps.length === 0) {
      fail(`goal "${id}" needs at least one step`);
    }
    for (const stepId of goal.steps) {
      if (!allSteps.has(stepId)) {
        fail(`goal "${id}" uses the unknown step "${stepId}"`);
      }
    }
    if (!allAreas.has(goal.area)) {
      fail(`goal "${id}" uses the unknown area "${goal.area}"`);
    }
    for (const entry of goal.requires || []) {
      const { capability, scope } = normalizeRequirement(entry);
      if (typeof capability !== 'string' || !capability) {
        fail(`goal "${id}" has a requirement without a capability`);
      }
      if (scope && !SCOPES.has(scope)) {
        fail(`goal "${id}" requires the unknown scope "${scope}"`);
      }
    }
  }

  for (const hook of ['isStepSatisfied', 'nextSteps']) {
    if (mod[hook] !== undefined && typeof mod[hook] !== 'function') {
      fail(`${hook} must be a function`);
    }
  }

  return {
    id: mod.id,
    areas: areas.map(a => ({ ...a })),
    steps: { ...steps },
    goals: Object.fromEntries(
      Object.entries(goals).map(([id, goal]) => [
        id,
        // An edition goal always declares its requirements, so the planner
        // can tell it from a core goal that is simply unrestricted.
        { ...goal, requires: goal.requires || [], edition: mod.id },
      ])
    ),
    components: { ...components },
    isStepSatisfied: mod.isStepSatisfied,
    nextSteps: mod.nextSteps,
  };
}

export function registerEditionModule(mod) {
  registry.push(validate(mod));
  merged = null;
}

/** For tests only. */
export function resetEditionModules() {
  registry.length = 0;
  merged = null;
}

export function getEditionModules() {
  return Object.freeze([...registry]);
}

function mergedTables() {
  if (!merged) {
    merged = {
      goals: Object.assign({}, GOALS, ...registry.map(m => m.goals)),
      steps: Object.assign({}, STEP_DEFS, ...registry.map(m => m.steps)),
      areas: [...GOAL_AREAS, ...registry.flatMap(m => m.areas)],
      components: Object.assign({}, ...registry.map(m => m.components)),
    };
  }
  return merged;
}

// Readers. With an empty registry they return the core tables unchanged.
export function allGoals() {
  return registry.length ? mergedTables().goals : GOALS;
}
export function allStepDefs() {
  return registry.length ? mergedTables().steps : STEP_DEFS;
}
export function allGoalAreas() {
  return registry.length ? mergedTables().areas : GOAL_AREAS;
}
export function editionStepComponents() {
  return registry.length ? mergedTables().components : {};
}

/**
 * `true`/`false` when an edition module owns the step and judged it,
 * `undefined` when no module has an opinion. A throwing rule counts as not
 * done so one faulty module cannot break the guide.
 */
export function editionStepSatisfied(stepId, ctx) {
  const owner = registry.find(m => Object.hasOwn(m.steps, stepId));
  if (!owner?.isStepSatisfied) return undefined;
  try {
    const result = owner.isStepSatisfied(stepId, ctx);
    return result === undefined ? undefined : result === true;
  } catch {
    return false;
  }
}

/**
 * Whether a registered edition step asked to be held once it turns done.
 * Read from the registry on every call; false when nothing is registered.
 */
export function editionStepHolds(stepId) {
  return registry.some(
    m => Object.hasOwn(m.steps, stepId) && m.steps[stepId].holdWhenDone === true
  );
}

/** Suggestions for an edition goal, or `undefined` for any other goal. */
export function editionNextSteps(goalId, summary) {
  const owner = registry.find(m => Object.hasOwn(m.goals, goalId));
  if (!owner?.nextSteps) return undefined;
  try {
    const result = owner.nextSteps(goalId, summary);
    return Array.isArray(result)
      ? result.filter(t => typeof t === 'string' && t)
      : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Whether the viewer meets a requirement scope. The viewer comes from the
 * capabilities response; an unreadable viewer never satisfies a scope.
 */
export function viewerHasScope(scope, viewer) {
  if (!scope) return true;
  const role = viewer?.workspaceRole;
  switch (scope) {
    case 'system_admin':
      return viewer?.isSystemAdmin === true;
    case 'workspace_admin':
      return role === 'admin';
    case 'workspace_manager':
      return role === 'admin' || role === 'workspace_manager';
    default:
      return false;
  }
}
