// CertOps progress belongs to one objective (discover, automate, vault).
// Without scoping, flags saved for one goal satisfy the steps of another: a
// finished "Discover" run would mark the Automate configuration as reviewed.

import { isSupported } from './certopsMatrix.js';

// Facts about the host or an in-flight token, not about a goal's steps.
const HOST_KEYS = ['infrastructure', 'clusterId', 'tokenCreatedAt'];

/**
 * The CertOps progress that applies to `objective`. Progress saved for a
 * different objective contributes only host facts, and only those that are
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
  return kept;
}

/**
 * The value to store when the chosen objective changes. Nothing the user did
 * for the previous objective is carried into the new one.
 */
export function switchObjective(certops, objective) {
  const scoped = scopeCertops(certops, objective);
  return scoped === (certops || {}) ? scoped : { ...scoped };
}
