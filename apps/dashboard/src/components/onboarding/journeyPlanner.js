// Deterministic journey planner. The journey is never stored: it is derived
// from what the user asked for (intent), where they got to (progress), what
// the deployment allows (capabilities) and what really exists (reality).
// Adding steps later therefore needs no data migration.

import { existingAssetStepIds } from './assetRefs.js';
import {
  agentsFor,
  effectiveInfrastructure,
  pickGoalAgent,
  reportedCertificates,
  setupAgentReady,
} from './certopsMatrix.js';
import { installerOptionsFor, installerOptionsKey } from './certopsConfig.js';
import { GOALS, STEP_DEFS } from './modules.js';
import {
  allGoals,
  allStepDefs,
  editionStepSatisfied,
  normalizeRequirement,
  viewerHasScope,
} from './editionModules.js';
import { recipientsSatisfied } from './groupAttachment.js';
import { scopeCertops } from './certopsScope.js';
import { GUIDED_IMPORT_STEPS } from './importFlow.js';

export { GOALS, STEP_DEFS };
export const PLANNER_VERSION = 2;

// With the guided import steps parked, the import dialog already asks for the
// contact groups and shows its own result, so these goals end right after a
// successful import and skip the alerts and verify steps.
const MODAL_IMPORT_STEPS = {
  import_file: ['file_import'],
  import_integration: ['integration'],
};

/** The steps a goal runs, for the chosen import path. */
export function stepsForGoal(goalId, guidedImportSteps = GUIDED_IMPORT_STEPS) {
  const goal = allGoals()[goalId];
  if (!goal) return [];
  if (!guidedImportSteps && MODAL_IMPORT_STEPS[goalId])
    return MODAL_IMPORT_STEPS[goalId];
  return goal.steps;
}

const ACTIVE_STATES = new Set(['ready', 'unknown']);
// "candidate" features can be planned but are always labelled as such.
const PLANNABLE_STATES = new Set(['ready', 'unknown', 'candidate', 'runbook']);

function findCapability(capabilities, id) {
  return (capabilities?.items || []).find(c => c.id === id) || null;
}

/** Why a goal cannot be started, or null when it can. */
export function goalBlocker(goalId, capabilities) {
  const goal = allGoals()[goalId];
  if (!goal) return { code: 'UNKNOWN_GOAL' };
  // An edition goal that declares requirements cannot be vouched for without
  // capability data, so it stays hidden. Core goals are not blocked: the
  // server enforces anyway.
  const edition = Boolean(goal.edition);
  if (!capabilities?.items) {
    return edition && goal.requires.length
      ? { code: 'CAPABILITY_UNKNOWN', hidden: true }
      : null;
  }
  for (const entry of goal.requires) {
    const { capability: id, scope } = normalizeRequirement(entry);
    const cap = findCapability(capabilities, id);
    // An edition goal never silently passes on a capability this deployment
    // does not know; it is hidden, and other goals are unaffected.
    if (edition) {
      if (!cap || cap.state === 'hidden') {
        return { code: 'CAPABILITY_MISSING', capability: id, hidden: true };
      }
      if (!viewerHasScope(scope, capabilities.viewer)) {
        return { code: 'SCOPE_REQUIRED', capability: id, scope, hidden: true };
      }
    }
    if (!cap) continue;
    const allowed = goal.candidate ? PLANNABLE_STATES : ACTIVE_STATES;
    // A host-side prerequisite (for example CertOps disabled) is still a
    // plannable runbook for goals that are about setting that up.
    const plannable = goal.area === 'certops' ? PLANNABLE_STATES : allowed;
    if (!plannable.has(cap.state)) {
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
  const goals = allGoals();
  return Object.keys(goals).map(id => ({
    id,
    ...goals[id],
    blocker: goalBlocker(id, capabilities),
    candidate: Boolean(goals[id].candidate),
  }));
}

/** Providers the user may scan with, based on capability facts. */
export function availableProviders(capabilities, allProviders) {
  return Object.keys(allProviders).map(id => {
    const cap = findCapability(capabilities, `integrations.${id}`);
    const blocked = cap && !ACTIVE_STATES.has(cap.state);
    return {
      id,
      ...allProviders[id],
      blocker: blocked
        ? {
            code: cap.blockers?.[0]?.code || cap.state.toUpperCase(),
            remediation: cap.blockers?.[0]?.remediation || null,
          }
        : null,
    };
  });
}

/**
 * Whether the install step is satisfied for this pick. It is a function of
 * the pick (platform and what it needs from an agent) and of the agents that
 * fit it, never of the workspace as a whole: an agent on another system does
 * not count, and one that was already in the workspace before the session
 * counts only after the operator chose to reuse it.
 */
function agentStepDone(certops, saved, objective) {
  const agents = certops?.agents;
  // The Kubernetes controller is not an agent: it counts once it has
  // reported from a cluster (the one named in the guide, when it names one).
  if (saved.infrastructure === 'kubernetes') {
    return (certops?.controllers?.clusters || []).some(
      c => !saved.clusterId || c.clusterId === saved.clusterId
    );
  }
  const infra = effectiveInfrastructure(
    objective || saved.objective,
    saved.infrastructure
  );
  // An agent keeps the write path and reload grant it was installed with.
  // When this setup needs others, the installer has to run again, so the
  // step stays open until the operator says it did.
  const neededKey = installerOptionsKey(
    installerOptionsFor({
      objective,
      infrastructure: infra,
      certPath: saved.certPath,
      reloadService: saved.reloadService,
    })
  );
  if (neededKey && saved.installerKey !== neededKey) return false;
  // One live agent must carry what the goal uses: the command profile
  // (reported at registration, so a discovery-only agent never claims an
  // order), the capabilities (re-declared on every check-in) and the right
  // system. This is the same rule the status card shows.
  return setupAgentReady(agents, objective, infra, {
    reusedAgentId: saved.reusedAgentId,
  });
}

function certopsDone(stepId, { reality, progress, objective }) {
  const certops = reality?.certops;
  // Only progress saved for this goal's objective counts.
  const saved = scopeCertops(progress?.certops, objective);
  switch (stepId) {
    case 'certops_objective':
      return (
        Boolean(saved.objective) &&
        (!objective || saved.objective === objective)
      );
    case 'certops_agent':
      return agentStepDone(certops, saved, objective);
    case 'certops_config':
      // Kubernetes has no file to prepare, but the page still needs a click:
      // choosing a platform must not skip steps the operator never saw.
      return saved.configReviewed === true;
    case 'certops_execution': {
      // Observe-only goals never enable execution, so they acknowledge instead.
      if (saved.executionAcknowledged === true) return true;
      // Stage 3 is a signed dry run that ended as dry_run_complete. The job
      // id is stored, but whether it passed is read from the server. Only the
      // agent of this pick counts as having execution enabled.
      const infra = effectiveInfrastructure(
        objective || saved.objective,
        saved.infrastructure
      );
      const agent = pickGoalAgent(
        certops?.agents?.items,
        objective || saved.objective,
        infra,
        saved.reusedAgentId
      );
      const executionEnabled = Array.isArray(certops?.agents?.items)
        ? agentsFor(certops.agents, agent).executionEnabled === true
        : certops?.agents?.executionEnabled === true;
      return executionEnabled && certops?.dryRun?.status === 'dry_run_complete';
    }
    case 'certops_first': {
      const goalObjective = objective || saved.objective;
      // Automation only counts once the order really succeeded, because a
      // requested order already creates an inventory row. Same on Windows.
      if (goalObjective === 'automate' || goalObjective === 'vault') {
        return (
          certops?.issueJob?.status === 'succeeded' &&
          certops?.issueJob?.mode === 'real'
        );
      }
      // Reported by the agent of this pick, not by any agent of the workspace.
      return (
        agentStepDone(certops, saved, objective) &&
        reportedCertificates(certops, {
          infrastructure: effectiveInfrastructure(
            goalObjective,
            saved.infrastructure
          ),
          clusterId: saved.clusterId,
        }) > 0
      );
    }
    case 'certops_adcs': {
      // What the guide can see: a confirmed, safe issuer and a profile on it.
      // Enrollment itself needs a real CA and is not verified here.
      const adcs = certops?.adcs;
      return (
        (adcs?.issuers || []).some(i => i.confirmed && i.safe) &&
        (adcs?.profiles || 0) > 0
      );
    }
    case 'certops_vault':
      return (
        certops?.distribution?.groups > 0 && certops?.distribution?.verified
      );
    default:
      return false;
  }
}

/**
 * Whether a step is already satisfied by verified backend state. Never reads
 * session flags for things that exist on the server: a deleted monitor or
 * removed recipient reopens the step.
 */
export function isStepSatisfied(
  stepId,
  { reality, refs = {}, progress, objective, goal } = {}
) {
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
      // Only assets made through this step count, not website certificates.
      return existingAssetStepIds(refs, reality.references || {}).length > 0;
    case 'file_import':
    case 'integration': {
      // Imports hand back no ids, so verify against the server's own count:
      // if the workspace now holds fewer assets than were imported, some were
      // deleted and the step reopens.
      const imported = (progress?.imported || [])
        .filter(i => i.step === stepId)
        .reduce((sum, i) => sum + (i.count || 0), 0);
      return imported > 0 && (reality.assets?.total || 0) >= imported;
    }
    case 'recipients':
      // Judged per goal on what this session created, never on the mere
      // existence of a workspace default group.
      return recipientsSatisfied({ goal, refs, progress, reality });
    case 'notifications':
      return progress?.notificationsReviewed === true;
    case 'smtp':
      return reality.alerts?.smtpConfigured === true;
    default: {
      const edition = editionStepSatisfied(stepId, {
        reality,
        refs,
        progress,
        objective,
        goal,
      });
      return edition === undefined
        ? certopsDone(stepId, { reality, progress, objective })
        : edition;
    }
  }
}

/**
 * @returns {{ steps: Array, currentStepId: string|null, complete: boolean, blocked: object|null }}
 */
export function planJourney({
  intent = {},
  progress = {},
  operationRefs = {},
  capabilities = null,
  reality = null,
  heldStepId = null,
  guidedImportSteps = GUIDED_IMPORT_STEPS,
} = {}) {
  const goalId = intent.goal;
  const goal = allGoals()[goalId];
  if (!goal) {
    return {
      steps: [{ id: 'goal', ...allStepDefs().goal, status: 'current' }],
      currentStepId: 'goal',
      complete: false,
      blocked: null,
    };
  }

  const skipped = new Set(progress.skipped || []);
  const blocked = goalBlocker(goalId, capabilities);
  // Steps that do not apply to the chosen platform (for example the agent
  // configuration on Kubernetes) are removed from the journey, not skipped.
  const variant =
    goal.variants?.[
      scopeCertops(progress.certops, goal.certopsObjective).infrastructure
    ] || {};
  const omitted = new Set(variant.omit || []);
  // Steps the user does not need are removed, not skipped.
  const stepIds = stepsForGoal(goalId, guidedImportSteps).filter(id => {
    if (omitted.has(id)) return false;
    if (id === 'smtp') {
      // Only ask about email delivery when it is not already working, and
      // never when the deployment manages it (unknown is treated as needed).
      return reality?.alerts?.smtpConfigured !== true;
    }
    return true;
  });

  const stepDefs = allStepDefs();
  const steps = [{ id: 'goal', ...stepDefs.goal, status: 'done' }];
  let currentAssigned = false;

  for (const id of stepIds) {
    const def = stepDefs[id];
    let status;
    if (id === 'verify') {
      const earlierDone = steps.every(
        s => s.id === 'goal' || s.status === 'done' || s.status === 'skipped'
      );
      status = earlierDone && !currentAssigned ? 'current' : 'upcoming';
    } else if (
      isStepSatisfied(id, {
        reality,
        refs: operationRefs,
        progress,
        objective: goal.certopsObjective,
        goal: goalId,
      })
    ) {
      status = 'done';
    } else if (skipped.has(id)) {
      status = 'skipped';
    } else if (!currentAssigned) {
      status = 'current';
    } else {
      status = 'upcoming';
    }
    if (status === 'current') currentAssigned = true;
    steps.push({
      id,
      ...def,
      title: variant.titles?.[id] || def.title,
      status,
    });
  }

  // A finished step the person is still on stays the current one, shown as
  // done, until they continue. Later steps wait.
  const held =
    heldStepId && heldStepId !== 'verify'
      ? steps.find(s => s.id === heldStepId && s.status === 'done')
      : null;
  if (held) {
    const at = steps.indexOf(held);
    for (const s of steps.slice(at + 1)) {
      if (s.status === 'current') s.status = 'upcoming';
    }
  }

  const verifyStep = steps.find(s => s.id === 'verify');
  const verified =
    progress.verified === true && verifyStep?.status === 'current';
  if (verified) verifyStep.status = 'done';

  const current = held || steps.find(s => s.status === 'current') || null;
  return {
    steps,
    currentStepId: current ? current.id : null,
    blocked,
    complete:
      !held && steps.every(s => s.status === 'done' || s.status === 'skipped'),
  };
}
