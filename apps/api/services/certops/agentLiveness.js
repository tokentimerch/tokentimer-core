"use strict";

/**
 * Single source of truth for the CertOps agent liveness/offline threshold.
 *
 * Historically this 10-minute default (and its CERTOPS_AGENT_OFFLINE_AFTER_MS
 * override) was independently duplicated in agentRegistry.js (API read path,
 * computes `livenessState` live) and certops-worker.js (the periodic
 * stale-agent sweep that persists `status = 'offline'`), kept in sync only by
 * a code comment. Both now import this module instead, so the two paths
 * cannot silently drift apart if the env override is ever changed. The
 * per-agent downtime alert transition (agent-health alerting) also imports
 * this module, so "when the UI shows offline" and "when an alert fires" are
 * always the same instant.
 *
 * Do not make this configurable per-agent; it is a system-wide default by
 * design (see task decisions for this feature).
 */
const DEFAULT_AGENT_OFFLINE_AFTER_MS = 10 * 60 * 1000;

function resolveAgentOfflineAfterMs(env = process.env) {
  const raw = env.CERTOPS_AGENT_OFFLINE_AFTER_MS;
  if (raw == null || String(raw).trim() === "") {
    return DEFAULT_AGENT_OFFLINE_AFTER_MS;
  }
  const parsed = Number.parseInt(String(raw).trim(), 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    return DEFAULT_AGENT_OFFLINE_AFTER_MS;
  }
  return parsed;
}

/**
 * Shared liveness classification, used by the API read path, the worker
 * sweep's own pre-check, and agent-health alert transition detection so all
 * three agree on what "live" vs "stale/offline" means for a given
 * (lastSeenAt, createdAt) pair.
 *
 * @returns {'live'|'stale'} never null: callers that need a 'retired' state
 *   (agentRegistry.js) or a persisted-status distinction layer that on top.
 */
function classifyAgentLiveness({ lastSeenAt, createdAt, now = Date.now(), offlineAfterMs }) {
  const threshold = Number.isSafeInteger(offlineAfterMs)
    ? offlineAfterMs
    : resolveAgentOfflineAfterMs();
  const referenceAt = lastSeenAt || createdAt;
  const referenceMs = referenceAt ? new Date(referenceAt).getTime() : NaN;
  if (!Number.isFinite(referenceMs)) return null;
  return now - referenceMs >= threshold ? "stale" : "live";
}

module.exports = {
  DEFAULT_AGENT_OFFLINE_AFTER_MS,
  resolveAgentOfflineAfterMs,
  classifyAgentLiveness,
};
