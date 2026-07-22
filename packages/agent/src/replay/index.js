"use strict";

/**
 * Persisted consumed-nonce replay cache (CertOps Phase 4 runtime, ADR-0003).
 *
 * ADR-0003: "Agents keep a bounded replay cache keyed by nonce + jobId and
 * reject jobs outside [issuedAt, expiresAt]". This module owns the
 * nonce+jobId half; the time-window half lives in the signing module
 * (checkJobTimeWindow) so each can be tested in isolation.
 *
 * Persistence: the store is a JSON file written with mode 0o600, following
 * the config module's permission conventions (mode asserted at write time
 * and re-asserted via chmod; best-effort on win32, where POSIX modes are not
 * meaningful -- see packages/agent/src/config/index.js for the same caveat).
 * Persisting across restarts matters because a job's validity window can
 * outlive an agent process: without persistence, restarting the agent would
 * reopen the replay window for every not-yet-expired captured job.
 *
 * Fail-loud choices (documented per task spec):
 *   - A corrupted/unreadable store file throws at load. A tampered replay
 *     store is a security signal (someone may be trying to reset the cache
 *     to enable a replay), not a recoverable glitch, so it must surface to
 *     the operator instead of being silently recreated. A missing file is
 *     fine: that is simply a fresh store.
 *   - When the cache is full (after sweeping expired entries) new jobs are
 *     REJECTED with job_replay_rejected rather than evicting the oldest
 *     unexpired nonces. Silently evicting an unexpired nonce would reopen
 *     the replay window for exactly the job whose nonce was evicted: an
 *     attacker who can flood the agent with jobs could push a captured
 *     job's nonce out of the cache and then replay it. Refusing new work is
 *     the safe failure mode; the bound exists only to keep the store's disk
 *     and memory footprint predictable.
 *
 * Rejection results use the exact shape the policy module produces
 * ({ allowed: false, rejectionReason, detail }) so downstream evidence/
 * result reporting handles them uniformly.
 *
 * This module is self-contained (node builtins only, plain-data API) per
 * the packages/agent module conventions.
 */

const fs = require("node:fs");
const path = require("node:path");

const REPLAY_REJECTION_REASON = "job_replay_rejected";

const STORE_SCHEMA_VERSION = 1;
const DEFAULT_MAX_ENTRIES = 5000;

/**
 * @param {string} detail
 * @returns {{ allowed: false, rejectionReason: string, detail: string }}
 */
function rejectReplay(detail) {
  return { allowed: false, rejectionReason: REPLAY_REJECTION_REASON, detail };
}

/**
 * Composite cache key per ADR-0003 (nonce + jobId). Both components are
 * length-delimited so distinct pairs can never collide via concatenation
 * ambiguity (e.g. nonce "a:b" + jobId "c" vs nonce "a" + jobId "b:c").
 *
 * @param {string} nonce
 * @param {string} jobId
 * @returns {string}
 */
function cacheKey(nonce, jobId) {
  return `${nonce.length}:${nonce}|${jobId.length}:${jobId}`;
}

function assertEntryInput({ nonce, jobId, expiresAt }, methodName) {
  if (typeof nonce !== "string" || nonce.length === 0) {
    throw new Error(`replay: ${methodName} requires a non-empty nonce string`);
  }
  if (typeof jobId !== "string" || jobId.length === 0) {
    throw new Error(`replay: ${methodName} requires a non-empty jobId string`);
  }
  const expiresAtMs =
    typeof expiresAt === "number" ? expiresAt : Date.parse(expiresAt);
  if (!Number.isFinite(expiresAtMs)) {
    throw new Error(
      `replay: ${methodName} requires expiresAt as epoch ms or a parseable date-time string`,
    );
  }
  return expiresAtMs;
}

/**
 * Loads the persisted store file. Missing file => fresh empty store.
 * Anything else that prevents a well-formed load (unreadable file, invalid
 * JSON, wrong shape, wrong schema version) throws with a clear message --
 * see the module doc comment for why corruption is treated as a security
 * signal rather than silently recreated.
 *
 * @param {string} storePath
 * @returns {Map<string, { nonce: string, jobId: string, expiresAtMs: number }>}
 */
function loadStore(storePath) {
  let raw;
  try {
    raw = fs.readFileSync(storePath, "utf8");
  } catch (err) {
    if (err && err.code === "ENOENT") return new Map();
    throw new Error(
      `replay: replay store at ${storePath} exists but could not be read ` +
        `(${err.message}). Refusing to start with an unreadable replay ` +
        "store: silently recreating it would reopen the replay window. " +
        "Investigate before deleting the file manually.",
    );
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `replay: replay store at ${storePath} contains invalid JSON ` +
        `(${err.message}). A corrupted replay store is a tamper signal; ` +
        "refusing to silently recreate it.",
    );
  }

  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    parsed.schemaVersion !== STORE_SCHEMA_VERSION ||
    !Array.isArray(parsed.entries)
  ) {
    throw new Error(
      `replay: replay store at ${storePath} has an unexpected shape ` +
        `(expected { schemaVersion: ${STORE_SCHEMA_VERSION}, entries: [] }). ` +
        "A malformed replay store is a tamper signal; refusing to silently recreate it.",
    );
  }

  const entries = new Map();
  parsed.entries.forEach((entry, index) => {
    if (
      entry === null ||
      typeof entry !== "object" ||
      typeof entry.nonce !== "string" ||
      typeof entry.jobId !== "string" ||
      !Number.isFinite(entry.expiresAtMs)
    ) {
      throw new Error(
        `replay: replay store at ${storePath} has a malformed entry at ` +
          `index ${index}; refusing to load a partially corrupted store.`,
      );
    }
    entries.set(cacheKey(entry.nonce, entry.jobId), {
      nonce: entry.nonce,
      jobId: entry.jobId,
      expiresAtMs: entry.expiresAtMs,
    });
  });
  return entries;
}

/**
 * Creates a persisted replay cache.
 *
 * @param {object} params
 * @param {string} params.storePath JSON file path for the persisted store;
 *   written with mode 0o600 (config-module convention; best-effort on win32)
 * @param {number} [params.maxEntries=5000] hard bound on stored entries;
 *   when reached (after sweeping expired entries), new jobs are rejected
 *   rather than evicting unexpired nonces (see module doc for why)
 * @param {() => number} [params.now] clock injection for tests; defaults to
 *   Date.now
 * @returns {{
 *   check: (entry: { nonce: string, jobId: string, expiresAt: number|string }) =>
 *     ({ allowed: true } | { allowed: false, rejectionReason: string, detail: string }),
 *   consume: (entry: { nonce: string, jobId: string, expiresAt: number|string }) =>
 *     ({ allowed: true } | { allowed: false, rejectionReason: string, detail: string }),
 *   sweep: (nowMs?: number) => number,
 *   size: () => number,
 * }}
 */
function createReplayCache({
  storePath,
  maxEntries = DEFAULT_MAX_ENTRIES,
  now = Date.now,
} = {}) {
  if (typeof storePath !== "string" || storePath.length === 0) {
    throw new Error("replay: createReplayCache requires a storePath string");
  }
  if (!Number.isInteger(maxEntries) || maxEntries <= 0) {
    throw new Error(
      "replay: createReplayCache maxEntries must be a positive integer",
    );
  }
  if (typeof now !== "function") {
    throw new Error("replay: createReplayCache now must be a function");
  }

  // Fail-loud load: throws on corruption, tolerates only ENOENT.
  const entries = loadStore(storePath);

  function persist() {
    const dir = path.dirname(storePath);
    // 0700 dir / 0600 file per the config module's conventions; chmod is
    // best-effort on win32 (no POSIX mode semantics there).
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const serialized = JSON.stringify({
      schemaVersion: STORE_SCHEMA_VERSION,
      entries: [...entries.values()],
    });
    fs.writeFileSync(storePath, `${serialized}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    try {
      fs.chmodSync(storePath, 0o600);
    } catch (_err) {
      // Best-effort on win32; see packages/agent/src/config/index.js.
    }
  }

  /**
   * Drops entries whose expiresAt has passed. Expired nonces are safe to
   * forget: checkJobTimeWindow independently rejects any job past its
   * expiresAt (plus tolerance), so an expired nonce can never be replayed
   * successfully anyway. This is what keeps the store's growth bounded in
   * normal operation.
   *
   * @param {number} [nowMs] defaults to the injected clock
   * @returns {number} number of entries removed
   */
  function sweep(nowMs = now()) {
    if (!Number.isFinite(nowMs)) {
      throw new Error("replay: sweep requires a finite nowMs");
    }
    let removed = 0;
    for (const [key, entry] of entries) {
      if (entry.expiresAtMs < nowMs) {
        entries.delete(key);
        removed += 1;
      }
    }
    if (removed > 0) persist();
    return removed;
  }

  /**
   * Read-only replay check: has this nonce+jobId pair been consumed before?
   * Does not record anything; call consume() after all other verification
   * gates pass and immediately before execution.
   *
   * @param {{ nonce: string, jobId: string, expiresAt: number|string }} entry
   * @returns {{ allowed: true } | { allowed: false, rejectionReason: string, detail: string }}
   */
  function check({ nonce, jobId, expiresAt }) {
    assertEntryInput({ nonce, jobId, expiresAt }, "check");
    if (entries.has(cacheKey(nonce, jobId))) {
      return rejectReplay(
        `Job ${jobId} presented an already-consumed nonce; replay rejected.`,
      );
    }
    return { allowed: true };
  }

  /**
   * Records the nonce+jobId pair as consumed and persists the store.
   * A duplicate consume (same pair already recorded) is itself a replay and
   * is rejected, making the check+consume sequence safe even if a caller
   * skips check(). Capacity is enforced here fail-loud: when the store is
   * still full after sweeping expired entries, the NEW job is rejected with
   * job_replay_rejected; unexpired nonces are never evicted (see module doc
   * for why silent eviction would reopen the replay window).
   *
   * @param {{ nonce: string, jobId: string, expiresAt: number|string }} entry
   * @returns {{ allowed: true } | { allowed: false, rejectionReason: string, detail: string }}
   */
  function consume({ nonce, jobId, expiresAt }) {
    const expiresAtMs = assertEntryInput({ nonce, jobId, expiresAt }, "consume");
    const key = cacheKey(nonce, jobId);

    if (entries.has(key)) {
      return rejectReplay(
        `Job ${jobId} presented an already-consumed nonce; replay rejected.`,
      );
    }

    if (entries.size >= maxEntries) {
      sweep();
      if (entries.size >= maxEntries) {
        return rejectReplay(
          `Replay cache is full (${entries.size}/${maxEntries} unexpired ` +
            "entries); rejecting new job rather than evicting unexpired " +
            "nonces, which would reopen the replay window.",
        );
      }
    }

    entries.set(key, { nonce, jobId, expiresAtMs });
    persist();
    return { allowed: true };
  }

  function size() {
    return entries.size;
  }

  return { check, consume, sweep, size };
}

module.exports = {
  REPLAY_REJECTION_REASON,
  DEFAULT_MAX_ENTRIES,
  createReplayCache,
};
