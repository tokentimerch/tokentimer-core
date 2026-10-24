// CertOps progress belongs to one objective (discover, automate, vault, AD CS).
// Without scoping, flags saved for one goal satisfy the steps of another: a
// finished "Discover" run would mark the Automate configuration as reviewed.
//
// The active objective's progress stays flat on `certops`, because the API
// reads its job ids from there. When another objective becomes active, the
// previous one is parked under `byObjective` and restored on the way back.

import { isSupported } from './certopsMatrix.js';

// Facts about the host or an in-flight token, not about a goal's steps.
const HOST_KEYS = ['infrastructure', 'clusterId', 'tokenCreatedAt'];
const PARKED_KEY = 'byObjective';

function withoutParked(certops) {
  const { [PARKED_KEY]: _parked, ...rest } = certops;
  return rest;
}

/**
 * The CertOps progress that applies to `objective`. Progress saved earlier for
 * this objective is restored from the parked copy; otherwise progress saved for
 * a different objective contributes only host facts, and only those that are
 * still valid for the objective.
 */
export function scopeCertops(certops, objective) {
  const saved = certops || {};
  if (!objective || saved.objective === objective) return saved;
  const kept = {};
  for (const key of HOST_KEYS) {
    if (saved[key] !== undefined) kept[key] = saved[key];
  }
  if (kept.infrastructure && !isSupported(objective, kept.infrastructure)) {
    delete kept.infrastructure;
  }
  const parked = saved[PARKED_KEY]?.[objective];
  if (parked && parked.objective === objective) return { ...kept, ...parked };
  return kept;
}

/**
 * The value to store when `objective` is written to. The previous objective's
 * progress is parked rather than dropped, so switching goals and coming back
 * loses nothing. Old sessions without parked copies behave as before.
 */
export function mergeCertops(certops, objective, patch = {}) {
  const saved = certops || {};
  if (!objective) return { ...saved, ...patch };
  const parked = { ...(saved[PARKED_KEY] || {}) };
  if (saved.objective && saved.objective !== objective) {
    parked[saved.objective] = withoutParked(saved);
  }
  delete parked[objective];
  const next = { ...withoutParked(scopeCertops(saved, objective)), ...patch };
  if (Object.keys(parked).length > 0) next[PARKED_KEY] = parked;
  return next;
}

/** The value to store when the chosen objective changes. */
export function switchObjective(certops, objective) {
  return mergeCertops(certops, objective);
}

// Marks that only mean something for the platform they were made on.
const VARIANT_KEYS = [
  'configReviewed',
  'executionAcknowledged',
  'installerKey',
  'clusterId',
  'tokenCreatedAt',
  'agentLaterAt',
  'chosenAgentId',
  'chosenAgentConfirmed',
  'chosenIssuerId',
  'chosenIssuerConfirmed',
  'dryRunJobId',
  'issueJobId',
  'issueAttempt',
  'issueReloadService',
];

/**
 * The value to store when the platform is chosen. Picking another platform
 * drops the previous one's step marks, so none of its steps shows as done for
 * the new one. Picking the same platform again changes nothing.
 *
 * `agentId` is the existing agent the operator opted to reuse for this pick:
 * a string sets it, null clears it, and leaving it out keeps what the same
 * platform already had. A choice never outlives the platform it was made for.
 */
export function chooseInfrastructure(
  certops,
  objective,
  infrastructure,
  agentId
) {
  const before = scopeCertops(certops, objective);
  const changed = before.infrastructure !== infrastructure;
  const next = mergeCertops(certops, objective, { objective, infrastructure });
  if (changed) for (const key of VARIANT_KEYS) delete next[key];
  if (
    agentId !== undefined &&
    (agentId || undefined) !== before.chosenAgentId
  ) {
    // The installer confirmation was about the previous agent.
    delete next.installerKey;
    delete next.chosenAgentConfirmed;
  }
  if (agentId) next.chosenAgentId = agentId;
  else if (agentId === null) delete next.chosenAgentId;
  return next;
}

/**
 * The value to store when the operator ticks "My Microsoft CA issuer is
 * already set up" and picks an issuer (a string), or unticks it (null).
 * Picking another issuer drops the confirmation that was about the previous
 * one; Continue on the step confirms the new choice.
 */
export function chooseIssuer(certops, objective, issuerId) {
  const before = scopeCertops(certops, objective);
  const next = mergeCertops(certops, objective, { objective });
  if ((issuerId || undefined) !== before.chosenIssuerId) {
    delete next.chosenIssuerConfirmed;
  }
  if (issuerId) next.chosenIssuerId = issuerId;
  else delete next.chosenIssuerId;
  return next;
}
