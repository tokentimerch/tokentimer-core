"use strict";

/**
 * Durable local outbox for job outcomes pending control-plane transmission.
 *
 * Separates real-world execution success/failure from reportResult /
 * reportEvidence network delivery (B8). After a job finishes, the exact
 * outcome (+ any buffered evidence bodies) is persisted under the agent's
 * state directory BEFORE any network call. Transmission then retries the
 * same persisted entry idempotently until the server acknowledges it; the
 * entry is cleared only after a successful POST. A restart drains
 * un-acknowledged entries before new claim polling resumes.
 *
 * Storage conventions match src/config: 0700 directory, 0600 files,
 * atomic write + rename. Entries are public result/evidence payloads only
 * (never private keys). Permission enforcement is delegated to the shared
 * src/platform module: POSIX chmod, or a real restricted ACL on win32
 * (inheritance removed, owner-plus-SYSTEM only, verified against a
 * trusted-owner allowlist), rather than a best-effort chmod that silently
 * did nothing on win32.
 */

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { applyRestrictivePermissions } = require("../platform/index.js");
const { fsyncDirectorySync } = require("../platform/durability.js");

const OUTBOX_DIR_NAME = "outbox";
const DEAD_LETTER_DIR_NAME = "dead-letter";
const ENTRY_FILE_SUFFIX = ".json";
const MAX_ENTRY_BYTES = 512 * 1024;

// A transmission failure's real cause (transient network blip vs a
// permanent server-side rejection of this exact payload) is not reliably
// determinable from the HTTP status alone in general -- e.g. 409 covers
// both "retry the lease, it just changed owner" and "this result can
// never match, stop asking." Where a reliable signal DOES exist (a 4xx
// HTTP status surfaced on the thrown error, see defaultIsPermanentFailure
// below) it is used to quarantine immediately; otherwise a repeatedly-failing
// entry still backs off exponentially and, as a last resort, is
// quarantined once it has been retried MAX_ATTEMPTS_BEFORE_QUARANTINE
// times without ever getting a clear permanent/transient signal, so one
// poisoned entry cannot grow the outbox directory forever.
const RETRY_BACKOFF_BASE_MS = 15_000;
const RETRY_BACKOFF_MAX_MS = 30 * 60_000;
// +/-20% randomized jitter on every backoff so a fleet of agents that
// all started failing around the same time (e.g. a control-plane outage)
// does not synchronize into thundering-herd retry waves every interval.
const RETRY_JITTER_RATIO = 0.2;

// An entry that has failed this many times without being classified
// permanent by the isPermanent classifier (default
// defaultIsPermanentFailure) is quarantined anyway: at 30 minutes of
// backoff between the later attempts, 10 attempts is several hours of
// genuine retry effort, well past what a transient blip or even a
// multi-hour outage needs, while still bounding how long a truly-stuck
// entry can keep growing the outbox directory. Tune here if that
// trade-off needs to shift.
const MAX_ATTEMPTS_BEFORE_QUARANTINE = 10;

// Retention limits so a permanently-stuck outbox cannot grow the
// directory (and therefore the cost of every future listOutboxEntries
// scan) without bound across the life of an agent installation. These
// are enforced by pruneStaleOutboxEntries, which is NOT called
// automatically from drainOutbox's hot path (see its doc comment).
const MAX_OUTBOX_ENTRIES = 5000;
const MAX_OUTBOX_AGE_MS = 7 * 24 * 60 * 60_000;

/**
 * @param {number} attempts number of prior failed transmission attempts
 * @returns {number} milliseconds to wait before the next attempt, with
 *   +/-20% jitter applied so retries across many agents do not
 *   synchronize into thundering-herd waves. Always a positive integer.
 */
function computeRetryBackoffMs(attempts) {
  const exponent = Math.max(0, Number.isFinite(attempts) ? attempts : 0);
  const base = Math.min(RETRY_BACKOFF_BASE_MS * 2 ** exponent, RETRY_BACKOFF_MAX_MS);
  const jitterFactor = 1 - RETRY_JITTER_RATIO + Math.random() * (2 * RETRY_JITTER_RATIO);
  return Math.max(1, Math.round(base * jitterFactor));
}

function fsyncParentDirectory(filePath) {
  // fsync on a directory is the durable part of an atomic rename on POSIX.
  // Windows cannot open a directory this way at all, so the fsync is
  // recorded as a durability limit (see src/platform/durability.js) rather
  // than being swallowed by an empty catch: the agent reports what it
  // could not guarantee instead of pretending it succeeded.
  fsyncDirectorySync(path.dirname(filePath));
}

function writeFileAtomically(filePath, contents, mode) {
  const temporaryPath = `${filePath}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`;
  let fd;
  try {
    fd = fs.openSync(temporaryPath, "wx", mode);
    fs.writeFileSync(fd, contents, "utf8");
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(temporaryPath, filePath);
    // POSIX re-asserts the mode; win32 gets a real restricted ACL. A
    // failure here is fatal: an unprotected outbox entry is not an
    // acceptable outcome of a successful write.
    applyRestrictivePermissions(filePath, { kind: "file", mode });
    fsyncParentDirectory(filePath);
  } catch (err) {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch (_err) {
        // Best effort close.
      }
    }
    try {
      fs.unlinkSync(temporaryPath);
    } catch (_err) {
      // May already be renamed or absent.
    }
    throw err;
  }
}

/**
 * @param {string} configDir
 * @returns {string}
 */
function resolveOutboxDir(configDir) {
  return path.join(configDir, OUTBOX_DIR_NAME);
}

/**
 * Ensures the outbox directory exists with restrictive permissions,
 * re-asserting them on every call. POSIX: 0700. win32: a real ACL with
 * inheritance removed, granting only the agent's own identity plus SYSTEM.
 * @param {string} outboxDir
 * @returns {string} outboxDir
 */
function ensureOutboxDir(outboxDir) {
  fs.mkdirSync(outboxDir, { recursive: true, mode: 0o700 });
  applyRestrictivePermissions(outboxDir, { kind: "directory", mode: 0o700 });
  return outboxDir;
}

function entryPath(outboxDir, id) {
  return path.join(outboxDir, `${id}${ENTRY_FILE_SUFFIX}`);
}

/**
 * @param {string} outboxDir
 * @returns {string}
 */
function resolveDeadLetterDir(outboxDir) {
  return path.join(outboxDir, DEAD_LETTER_DIR_NAME);
}

/**
 * Ensures the dead-letter subdirectory exists with the same restrictive
 * permissions treatment as the main outbox directory (0700 POSIX / a
 * real restricted ACL on win32), re-asserted on every call.
 * @param {string} deadLetterDir
 * @returns {string} deadLetterDir
 */
function ensureDeadLetterDir(deadLetterDir) {
  fs.mkdirSync(deadLetterDir, { recursive: true, mode: 0o700 });
  applyRestrictivePermissions(deadLetterDir, { kind: "directory", mode: 0o700 });
  return deadLetterDir;
}

function validateEntry(entry) {
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
    throw new Error("tokentimer-agent: outbox entry must be an object");
  }
  if (typeof entry.id !== "string" || entry.id.length === 0 || entry.id.length > 128) {
    throw new Error("tokentimer-agent: outbox entry.id must be a 1-128 char string");
  }
  if (!/^[A-Za-z0-9_.:-]+$/.test(entry.id)) {
    throw new Error("tokentimer-agent: outbox entry.id has an invalid format");
  }
  if (typeof entry.createdAt !== "string" || entry.createdAt.length === 0) {
    throw new Error("tokentimer-agent: outbox entry.createdAt is required");
  }
  if (entry.result === null || typeof entry.result !== "object" || Array.isArray(entry.result)) {
    throw new Error("tokentimer-agent: outbox entry.result must be an object");
  }
  if (!Array.isArray(entry.evidence)) {
    throw new Error("tokentimer-agent: outbox entry.evidence must be an array");
  }
  return entry;
}

/**
 * Persists an outcome+evidence entry BEFORE any network transmission.
 * @param {string} outboxDir
 * @param {{
 *   id?: string,
 *   createdAt?: string,
 *   result: object,
 *   evidence?: object[],
 * }} partial
 * @returns {{ id: string, createdAt: string, result: object, evidence: object[] }}
 */
function enqueueOutboxEntry(outboxDir, partial) {
  ensureOutboxDir(outboxDir);
  const id =
    typeof partial.id === "string" && partial.id.length > 0
      ? partial.id
      : `outbox-${crypto.randomBytes(12).toString("hex")}`;
  const entry = validateEntry({
    id,
    createdAt: partial.createdAt || new Date().toISOString(),
    result: partial.result,
    evidence: Array.isArray(partial.evidence) ? partial.evidence : [],
  });
  const serialized = `${JSON.stringify(entry)}\n`;
  if (Buffer.byteLength(serialized, "utf8") > MAX_ENTRY_BYTES) {
    throw new Error(
      `tokentimer-agent: outbox entry exceeds ${MAX_ENTRY_BYTES} bytes`,
    );
  }
  writeFileAtomically(entryPath(outboxDir, entry.id), serialized, 0o600);
  return entry;
}

/**
 * The one full-directory read per listing. Factored into its own named
 * function (rather than an inline fs.readdirSync call) so callers/tests
 * can spy on this single choke point to confirm a drain pass performs
 * exactly one listing per directory instead of the readFileSync/JSON.parse
 * fan-out below, which happens once per entry regardless.
 * @param {string} dir
 * @returns {string[]} entry filenames, or [] if the directory is
 *   missing/unreadable
 */
function readEntryDirNames(dir) {
  if (!fs.existsSync(dir)) return [];
  try {
    return fs.readdirSync(dir);
  } catch (_err) {
    return [];
  }
}

/**
 * Reads and validates every entry file directly inside `dir` (non-
 * recursive), skipping symlinks, oversized/undersized files, and
 * corrupt JSON. Shared by listOutboxEntries and listDeadLetterEntries.
 * @param {string} dir
 * @returns {Array<object>} unsorted, validated entries
 */
function readEntriesFromDir(dir) {
  const names = readEntryDirNames(dir);
  const entries = [];
  for (const name of names) {
    if (!name.endsWith(ENTRY_FILE_SUFFIX) || name.endsWith(".tmp")) continue;
    const filePath = path.join(dir, name);
    let raw;
    try {
      const stats = fs.lstatSync(filePath);
      if (stats.isSymbolicLink() || !stats.isFile()) continue;
      if (stats.size < 1 || stats.size > MAX_ENTRY_BYTES) continue;
      raw = fs.readFileSync(filePath, "utf8");
    } catch (_err) {
      continue;
    }
    try {
      entries.push(validateEntry(JSON.parse(raw)));
    } catch (_err) {
      // Leave corrupt files for operators; skip them during drain.
    }
  }
  return entries;
}

function sortEntriesByCreatedAtThenId(entries) {
  entries.sort((a, b) => {
    if (a.createdAt < b.createdAt) return -1;
    if (a.createdAt > b.createdAt) return 1;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });
  return entries;
}

/**
 * Lists every pending entry in the main outbox directory (NOT
 * dead-letter). One readEntryDirNames call per invocation; drainOutbox
 * calls this exactly once per drain pass rather than once at the start
 * and again at the end (see its doc comment).
 * @param {string} outboxDir
 * @returns {Array<{ id: string, createdAt: string, result: object, evidence: object[] }>}
 */
function listOutboxEntries(outboxDir) {
  return sortEntriesByCreatedAtThenId(readEntriesFromDir(outboxDir));
}

/**
 * Lists every quarantined (permanently-failed or attempt-exhausted)
 * entry, so operators/tests can inspect what drainOutbox gave up on.
 * @param {string} outboxDir
 * @returns {Array<object>}
 */
function listDeadLetterEntries(outboxDir) {
  return sortEntriesByCreatedAtThenId(readEntriesFromDir(resolveDeadLetterDir(outboxDir)));
}

/**
 * Clears an entry only after the control plane acknowledged transmission.
 * @param {string} outboxDir
 * @param {string} id
 * @returns {boolean} true when a file was removed
 */
function acknowledgeOutboxEntry(outboxDir, id) {
  const filePath = entryPath(outboxDir, id);
  try {
    fs.unlinkSync(filePath);
    fsyncParentDirectory(filePath);
    return true;
  } catch (err) {
    if (err && err.code === "ENOENT") return false;
    throw err;
  }
}

/**
 * Moves a permanently-failing (or attempt-exhausted) entry file out of
 * the main outbox directory into outbox/dead-letter/, atomically (a
 * single rename, never copy+delete) so a crash mid-quarantine cannot
 * duplicate or lose the entry. Callers must persist any final
 * diagnostic fields (attempts/lastErrorMessage/lastAttemptAt) onto the
 * entry file BEFORE calling this -- rename preserves file content
 * verbatim, it does not merge anything in.
 * @param {string} outboxDir
 * @param {string} id
 * @returns {boolean} true when a file was moved
 */
function quarantineOutboxEntry(outboxDir, id) {
  const deadLetterDir = ensureDeadLetterDir(resolveDeadLetterDir(outboxDir));
  const source = entryPath(outboxDir, id);
  const destination = entryPath(deadLetterDir, id);
  try {
    fs.renameSync(source, destination);
  } catch (err) {
    if (err && err.code === "ENOENT") return false;
    throw err;
  }
  // Re-assert restrictive permissions and fsync both parent directories
  // (source, to durably record the removal; destination, to durably
  // record the arrival) for the same reasons writeFileAtomically does.
  applyRestrictivePermissions(destination, { kind: "file", mode: 0o600 });
  fsyncParentDirectory(destination);
  fsyncParentDirectory(source);
  return true;
}

/**
 * Transmits one persisted entry: evidence bodies first (in order), then
 * the terminal result. Safe to retry: the same payloads are re-sent.
 *
 * @param {object} entry
 * @param {{ reportEvidence: Function, reportResult: Function }} client
 * @returns {Promise<void>}
 */
async function transmitOutboxEntry(entry, client) {
  const validated = validateEntry(entry);
  for (const evidenceBody of validated.evidence) {
    await client.reportEvidence(evidenceBody);
  }
  await client.reportResult(validated.result);
}

/**
 * True once an entry's backoff window has elapsed (or it has never
 * failed before, i.e. no nextRetryAt yet) and it is due for another
 * transmission attempt.
 * @param {object} entry
 * @param {number} nowMs
 * @returns {boolean}
 */
function isDueForRetry(entry, nowMs) {
  if (typeof entry.nextRetryAt !== "string") return true;
  const dueAtMs = Date.parse(entry.nextRetryAt);
  return !Number.isFinite(dueAtMs) || dueAtMs <= nowMs;
}

/**
 * Persists updated backoff bookkeeping (attempts/nextRetryAt/last error)
 * on a failed entry in place, so the next drain -- on this process or
 * after a restart -- knows to wait rather than retry immediately.
 * Best-effort: if the rewrite itself fails, the entry is simply retried
 * every tick again (as it always was), never lost.
 * @param {string} outboxDir
 * @param {object} entry
 * @param {Error} err
 * @param {number} nowMs
 * @returns {object} the updated entry (attempts already incremented),
 *   regardless of whether the on-disk rewrite itself succeeded
 */
function recordTransmissionFailure(outboxDir, entry, err, nowMs) {
  const priorAttempts = Number.isFinite(entry.attempts) && entry.attempts >= 0 ? entry.attempts : 0;
  const attempts = priorAttempts + 1;
  const updated = {
    ...entry,
    attempts,
    lastAttemptAt: new Date(nowMs).toISOString(),
    lastErrorMessage: err && typeof err.message === "string" ? err.message.slice(0, 500) : "unknown error",
    nextRetryAt: new Date(nowMs + computeRetryBackoffMs(priorAttempts)).toISOString(),
  };
  const serialized = `${JSON.stringify(updated)}\n`;
  if (Buffer.byteLength(serialized, "utf8") > MAX_ENTRY_BYTES) return updated;
  try {
    writeFileAtomically(entryPath(outboxDir, entry.id), serialized, 0o600);
  } catch (_err) {
    // Best effort; see doc comment above.
  }
  return updated;
}

/**
 * Default permanent-vs-transient classifier for a transmission failure.
 *
 * Heuristic: looks for a numeric HTTP-style status on the thrown error
 * (`err.statusCode`, then `err.status`, then `err.code`, in that order --
 * AgentProtocolError from packages/agent/src/protocol sets `.status` on
 * every HTTP_ERROR-coded failure, e.g. `reportResult failed with HTTP
 * ${status}`). Any 4xx status is treated as permanent EXCEPT:
 *   - 408 (request timeout) and 429 (rate limited): both are transport-
 *     layer signals to slow down and retry, not a rejection of this
 *     entry's content.
 *   - 401/403: this codebase's agent credential is re-read fresh from
 *     disk on every single request, including every retry
 *     (`getCredential: () => readCredential(configDir)` in
 *     packages/agent/src/index.js, invoked via resolveCredential() at
 *     the top of every reportResult/reportEvidence call). There is no
 *     in-process layer that intercepts a 401/403 before it reaches the
 *     outbox, but an out-of-band credential fix (re-registration,
 *     rotated credential file written by an operator or another agent
 *     process) is picked up automatically by the very next drain of
 *     this SAME entry with zero outbox-level changes needed. That
 *     makes 401/403 "recoverable via re-auth elsewhere" in the sense
 *     that matters here: quarantining on the agent's own credential
 *     being temporarily wrong would permanently lose a result that a
 *     credential fix could still deliver, so retry-with-backoff (like
 *     408/429) is the safer default.
 *
 * Limits: a network error (no response at all, e.g.
 * AGENT_PROTOCOL_ERROR_CODES.NETWORK_ERROR) carries no status and always
 * falls through as transient, which is correct. A non-AgentProtocolError
 * thrown by a custom client (no statusCode/status/code at all) also
 * falls through as transient -- this heuristic can only ever say "yes,
 * definitely permanent," never "yes, definitely transient." Callers with
 * a more precise signal (e.g. a server-provided error code in the
 * response body) should pass their own `isPermanent` in drainOutbox's
 * options instead of relying on this default.
 *
 * @param {Error} err
 * @returns {boolean}
 */
function defaultIsPermanentFailure(err) {
  const statusCandidate = err?.statusCode ?? err?.status ?? err?.code;
  const statusCode = Number(statusCandidate);
  if (!Number.isInteger(statusCode) || statusCode < 400 || statusCode > 499) return false;
  if (statusCode === 401 || statusCode === 403 || statusCode === 408 || statusCode === 429) return false;
  return true;
}

/**
 * Attempts to deliver every pending outbox entry that is currently due
 * for retry, in a single pass over one listOutboxEntries call (never a
 * second full-directory scan, including for `remaining`; see the
 * in-memory bookkeeping below).
 *
 * On transmission failure the entry is left on disk with its backoff
 * bumped (never silently discarded) UNLESS the failure is classified
 * permanent (via `isPermanent`, default defaultIsPermanentFailure) or the
 * entry has now failed MAX_ATTEMPTS_BEFORE_QUARANTINE times, in which
 * case it is moved to outbox/dead-letter/ instead: a payload the server
 * will never accept, or that has already had hours of genuine retry
 * effort, gains nothing from being rescanned on every future poll tick
 * forever. Later entries are still attempted so one stuck job never
 * blocks unrelated acknowledgements.
 *
 * @param {string} outboxDir
 * @param {{ reportEvidence: Function, reportResult: Function }} client
 * @param {{
 *   onError?: (err: Error, entry: object) => void,
 *   now?: () => number,
 *   isPermanent?: (err: Error, updatedEntry: object) => boolean,
 * }} [options]
 * @returns {Promise<{ transmitted: number, deferred: number, quarantined: number, remaining: number }>}
 */
async function drainOutbox(
  outboxDir,
  client,
  { onError, now = () => Date.now(), isPermanent = defaultIsPermanentFailure } = {},
) {
  const pending = listOutboxEntries(outboxDir);
  const nowMs = now();
  let transmitted = 0;
  let deferred = 0;
  let quarantined = 0;
  // Every entry in `pending` starts out counted as remaining; a
  // successful transmission or a quarantine removes it from the main
  // outbox directory, so both decrement this in-memory count instead of
  // re-listing the directory to find out what is left.
  let remaining = pending.length;

  for (const entry of pending) {
    if (!isDueForRetry(entry, nowMs)) {
      deferred += 1;
      continue;
    }
    try {
      await transmitOutboxEntry(entry, client);
      acknowledgeOutboxEntry(outboxDir, entry.id);
      transmitted += 1;
      remaining -= 1;
    } catch (err) {
      const updated = recordTransmissionFailure(outboxDir, entry, err, nowMs);
      if (typeof onError === "function") onError(err, entry);
      let permanent = false;
      try {
        permanent = isPermanent(err, updated) === true;
      } catch (_classifierErr) {
        // A broken classifier must never crash the drain; fall back to
        // the normal backoff-and-retry path for this entry.
        permanent = false;
      }
      if (permanent || updated.attempts >= MAX_ATTEMPTS_BEFORE_QUARANTINE) {
        if (quarantineOutboxEntry(outboxDir, entry.id)) {
          quarantined += 1;
          remaining -= 1;
        }
      }
    }
  }
  return { transmitted, deferred, quarantined, remaining };
}

/**
 * Quarantines (never deletes outright) main-outbox entries that are past
 * their useful retention window: anything older than MAX_OUTBOX_AGE_MS,
 * plus -- if the directory has grown past MAX_OUTBOX_ENTRIES -- the
 * oldest entries beyond that cap, oldest-first, until the cap is
 * satisfied. Reuses the same dead-letter mechanism as permanent-failure
 * quarantine (step 1) rather than unlinking: this is a retention policy
 * for stuck/abandoned data, not a claim that the data is worthless, and
 * an operator should still be able to inspect it via
 * listDeadLetterEntries.
 *
 * Every entry still in the main outbox directory has, by definition,
 * never successfully transmitted (a successful transmission removes the
 * file via acknowledgeOutboxEntry), so no extra "never transmitted"
 * check is needed beyond "still present in listOutboxEntries".
 *
 * NOT called from drainOutbox automatically. This performs its own full
 * listOutboxEntries scan, which is exactly the O(n) cost this same
 * change just removed from drainOutbox's hot path (the old
 * double-listing bug); calling it unconditionally on every drain tick
 * would silently reintroduce that regression. Callers that want
 * retention enforced should invoke this themselves on a slow, rate-
 * limited cadence -- see shouldRunPrunePass for a minimal in-memory
 * example -- rather than it running on every poll interval.
 *
 * @param {string} outboxDir
 * @param {number} nowMs
 * @returns {{ quarantined: number }}
 */
function pruneStaleOutboxEntries(outboxDir, nowMs) {
  const entries = listOutboxEntries(outboxDir); // ascending by createdAt, oldest first
  const overflowCount = Math.max(0, entries.length - MAX_OUTBOX_ENTRIES);
  const idsToQuarantine = new Set();
  entries.forEach((entry, index) => {
    const createdAtMs = Date.parse(entry.createdAt);
    const isAgedOut = Number.isFinite(createdAtMs) && nowMs - createdAtMs > MAX_OUTBOX_AGE_MS;
    const isCountOverflow = index < overflowCount;
    if (isAgedOut || isCountOverflow) idsToQuarantine.add(entry.id);
  });
  let quarantined = 0;
  for (const id of idsToQuarantine) {
    if (quarantineOutboxEntry(outboxDir, id)) quarantined += 1;
  }
  return { quarantined };
}

// In-memory-only rate limiter for shouldRunPrunePass. Not persisted
// across restarts: a process restart allows one immediate prune pass,
// which is an acceptable one-time cost against the alternative of
// wiring file-based state into every agent installation for this.
const PRUNE_MIN_INTERVAL_MS = 60 * 60_000;
let lastPruneRunAtMs = -Infinity;

/**
 * Opt-in rate limiter for callers that want to invoke
 * pruneStaleOutboxEntries opportunistically (e.g. from the same poll
 * loop that calls drainOutbox) without paying its full-scan cost on
 * every tick. Returns true (and records `nowMs` as the last run) at
 * most once per PRUNE_MIN_INTERVAL_MS.
 * @param {number} nowMs
 * @returns {boolean}
 */
function shouldRunPrunePass(nowMs) {
  if (nowMs - lastPruneRunAtMs < PRUNE_MIN_INTERVAL_MS) return false;
  lastPruneRunAtMs = nowMs;
  return true;
}

/**
 * Creates a protocol-client shim that buffers reportEvidence calls instead
 * of sending them, so step evidence can be persisted with the terminal
 * result in one outbox entry.
 *
 * @returns {{
 *   reportEvidence: (body: object) => Promise<void>,
 *   takeEvidence: () => object[],
 * }}
 */
function createEvidenceBuffer() {
  const buffered = [];
  return {
    reportEvidence(body) {
      buffered.push(body);
      return Promise.resolve();
    },
    takeEvidence() {
      return buffered.splice(0, buffered.length);
    },
  };
}

module.exports = {
  OUTBOX_DIR_NAME,
  DEAD_LETTER_DIR_NAME,
  MAX_ATTEMPTS_BEFORE_QUARANTINE,
  MAX_OUTBOX_ENTRIES,
  MAX_OUTBOX_AGE_MS,
  resolveOutboxDir,
  resolveDeadLetterDir,
  ensureOutboxDir,
  ensureDeadLetterDir,
  enqueueOutboxEntry,
  listOutboxEntries,
  listDeadLetterEntries,
  acknowledgeOutboxEntry,
  quarantineOutboxEntry,
  transmitOutboxEntry,
  drainOutbox,
  pruneStaleOutboxEntries,
  shouldRunPrunePass,
  createEvidenceBuffer,
  computeRetryBackoffMs,
  isDueForRetry,
  defaultIsPermanentFailure,
};
