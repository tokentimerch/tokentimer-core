// Deterministic journey planner. The journey is never stored: it is derived
// from what the user asked for (intent), where they got to (progress), what
// the deployment allows (capabilities) and what really exists (reality).
// Adding steps later therefore needs no data migration.

import { existingAssetStepIds } from './assetRefs.js';
import { commandProfileFor, reportedCertificates } from './certopsMatrix.js';
import { GOALS, STEP_DEFS } from './modules.js';
import { scopeCertops } from './certopsScope.js';

export { GOALS, STEP_DEFS };
export const PLANNER_VERSION = 2;

const ACTIVE_STATES = new Set(['ready', 'unknown']);
// "candidate" features can be planned but are always labelled as such.
const PLANNABLE_STATES = new Set(['ready', 'unknown', 'candidate', 'runbook']);

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
  return Object.keys(GOALS).map(id => ({
    id,
    ...GOALS[id],
    blocker: goalBlocker(id, capabilities),
    candidate: Boolean(GOALS[id].candidate),
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
    case 'certops_agent': {
      const agents = certops?.agents;
      // The Kubernetes controller is not an agent: it counts once it has
      // reported from a cluster (the one named in the guide, when it names one).
      if (saved.infrastructure === 'kubernetes') {
        return (certops?.controllers?.clusters || []).some(
          c => !saved.clusterId || c.clusterId === saved.clusterId
        );
      }
      if ((agents?.live || 0) === 0) return false;
      // AD CS enrolls only through an agent that declared the capability.
      if (objective === 'adcs') {
        return (agents.items || []).some(
          a =>
            a.livenessState === 'live' &&
            (a.declaredCapabilities || []).includes('adcs-enroll-v1')
        );
      }
      // An agent registered for discovery declares no command profile, so it
      // can never claim an issuance order. Command profiles are only reported
      // at registration, which makes it a different agent setup, not a setting.
      const profile = commandProfileFor(
        objective,
        saved.infrastructure || 'linux'
      );
      if (!profile) return true;
      return (agents.items || []).some(
        a =>
          a.livenessState === 'live' &&
          (a.commandProfiles || []).includes(profile)
      );
    }
    case 'certops_config':
      // The Kubernetes controller has no agent configuration file.
      return (
        saved.configReviewed === true || saved.infrastructure === 'kubernetes'
      );
    case 'certops_execution':
      // Observe-only goals never enable execution, so they acknowledge instead.
      // The Kubernetes controller has no execution switch to acknowledge.
      if (saved.executionAcknowledged === true) return true;
      if (saved.infrastructure === 'kubernetes') return true;
      // Stage 3 is a signed dry run that ended as dry_run_complete. The job
      // id is stored, but whether it passed is read from the server.
      return (
        certops?.agents?.executionEnabled === true &&
        certops?.dryRun?.status === 'dry_run_complete'
      );
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
      return (
        reportedCertificates(certops, {
          infrastructure: saved.infrastructure,
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
  { reality, refs = {}, progress, objective } = {}
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
      // An email recipient or a verified webhook both count; falls back for
      // older summaries that only reported email.
      return (
        (reality.alerts?.contactGroups?.defaultHasRecipient ??
          reality.alerts?.contactGroups?.defaultHasEmailRecipient) === true
      );
    case 'notifications':
      return progress?.notificationsReviewed === true;
    case 'smtp':
      return reality.alerts?.smtpConfigured === true;
    default:
      return certopsDone(stepId, { reality, progress, objective });
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
} = {}) {
  const goalId = intent.goal;
  const goal = GOALS[goalId];
  if (!goal) {
    return {
      steps: [{ id: 'goal', ...STEP_DEFS.goal, status: 'current' }],
      currentStepId: 'goal',
      complete: false,
      blocked: null,
    };
  }

  const skipped = new Set(progress.skipped || []);
  const blocked = goalBlocker(goalId, capabilities);
  // Steps the user does not need are removed, not skipped.
  const stepIds = goal.steps.filter(id => {
    if (id === 'smtp') {
      // Only ask about email delivery when it is not already working, and
      // never when the deployment manages it (unknown is treated as needed).
      return reality?.alerts?.smtpConfigured !== true;
    }
    return true;
  });

  const steps = [{ id: 'goal', ...STEP_DEFS.goal, status: 'done' }];
  let currentAssigned = false;

  for (const id of stepIds) {
    const def = STEP_DEFS[id];
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
