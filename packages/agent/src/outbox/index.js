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
const ENTRY_FILE_SUFFIX = ".json";
const MAX_ENTRY_BYTES = 512 * 1024;

// A transmission failure's real cause (transient network blip vs a
// permanent server-side rejection of this exact payload) is not reliably
// determinable from the HTTP status alone -- e.g. 409 covers both "retry
// the lease, it just changed owner" and "this result can never match,
// stop asking." Rather than guess, every failure backs off the same way:
// retries never stop (nothing is ever silently discarded), but a
// repeatedly-failing entry is retried less and less often instead of
// spamming a log line every single poll tick forever.
const RETRY_BACKOFF_BASE_MS = 15_000;
const RETRY_BACKOFF_MAX_MS = 30 * 60_000;

/**
 * @param {number} attempts number of prior failed transmission attempts
 * @returns {number} milliseconds to wait before the next attempt
 */
function computeRetryBackoffMs(attempts) {
  const exponent = Math.max(0, Number.isFinite(attempts) ? attempts : 0);
  return Math.min(RETRY_BACKOFF_BASE_MS * 2 ** exponent, RETRY_BACKOFF_MAX_MS);
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
 * @param {string} outboxDir
 * @returns {Array<{ id: string, createdAt: string, result: object, evidence: object[] }>}
 */
function listOutboxEntries(outboxDir) {
  if (!fs.existsSync(outboxDir)) return [];
  let names;
  try {
    names = fs.readdirSync(outboxDir);
  } catch (_err) {
    return [];
  }
  const entries = [];
  for (const name of names) {
    if (!name.endsWith(ENTRY_FILE_SUFFIX) || name.endsWith(".tmp")) continue;
    const filePath = path.join(outboxDir, name);
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
  entries.sort((a, b) => {
    if (a.createdAt < b.createdAt) return -1;
    if (a.createdAt > b.createdAt) return 1;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });
  return entries;
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
  if (Buffer.byteLength(serialized, "utf8") > MAX_ENTRY_BYTES) return;
  try {
    writeFileAtomically(entryPath(outboxDir, entry.id), serialized, 0o600);
  } catch (_err) {
    // Best effort; see doc comment above.
  }
}

/**
 * Attempts to deliver every pending outbox entry that is currently due
 * for retry. On transmission failure the entry is left on disk with its
 * backoff bumped (never discarded); later entries are still attempted so
 * one stuck job does not block unrelated acknowledgements. A repeatedly
 * failing entry -- permanent rejection or a long-lived outage, the two
 * are not reliably distinguishable from an HTTP status alone -- is
 * retried less and less often instead of every single poll tick forever,
 * so one poisoned entry cannot spam the log indefinitely.
 *
 * @param {string} outboxDir
 * @param {{ reportEvidence: Function, reportResult: Function }} client
 * @param {{ onError?: (err: Error, entry: object) => void, now?: () => number }} [options]
 * @returns {Promise<{ transmitted: number, deferred: number, remaining: number }>}
 */
async function drainOutbox(outboxDir, client, { onError, now = () => Date.now() } = {}) {
  const pending = listOutboxEntries(outboxDir);
  const nowMs = now();
  let transmitted = 0;
  let deferred = 0;
  for (const entry of pending) {
    if (!isDueForRetry(entry, nowMs)) {
      deferred += 1;
      continue;
    }
    try {
      await transmitOutboxEntry(entry, client);
      acknowledgeOutboxEntry(outboxDir, entry.id);
      transmitted += 1;
    } catch (err) {
      recordTransmissionFailure(outboxDir, entry, err, nowMs);
      if (typeof onError === "function") onError(err, entry);
    }
  }
  return {
    transmitted,
    deferred,
    remaining: listOutboxEntries(outboxDir).length,
  };
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
  resolveOutboxDir,
  ensureOutboxDir,
  enqueueOutboxEntry,
  listOutboxEntries,
  acknowledgeOutboxEntry,
  transmitOutboxEntry,
  drainOutbox,
  createEvidenceBuffer,
  computeRetryBackoffMs,
  isDueForRetry,
};
