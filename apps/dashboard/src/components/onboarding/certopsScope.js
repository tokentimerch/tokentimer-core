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
