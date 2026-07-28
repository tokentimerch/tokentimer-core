"use strict";

/**
 * Local side-effect journal for CertOps job attempts.
 *
 * Records that a job attempt reached a side-effect-capable stage so a crash
 * mid-job cannot be silently re-executed on restart. Journal entries live
 * under `<stateDir>/job-journal/` as JSON files (0600), matching the agent
 * state-directory conventions used by outbox / registration-pending files.
 *
 * Private-key / secret material MUST never be written here — only ids,
 * claim references, timestamps, and stage names.
 */

const fs = require("node:fs");
const path = require("node:path");

const JOURNAL_DIR_NAME = "job-journal";
const JOURNAL_FILE_MODE = 0o600;
const JOURNAL_DIR_MODE = 0o700;

const TERMINAL_STATUSES = Object.freeze([
  "succeeded",
  "failed",
  "rejected",
  "blocked",
  "dry_run_complete",
  "orphaned_unknown_effect",
]);

/**
 * @param {string} stateDir agent config/state directory
 * @returns {string}
 */
function journalDirFor(stateDir) {
  if (typeof stateDir !== "string" || stateDir.length === 0) {
    throw new Error("job-journal: stateDir must be a non-empty string");
  }
  return path.join(stateDir, JOURNAL_DIR_NAME);
}

/**
 * @param {string} stateDir
 * @param {string} jobId
 * @param {string} attemptId
 * @returns {string}
 */
function journalPathFor(stateDir, jobId, attemptId) {
  if (typeof jobId !== "string" || jobId.length === 0) {
    throw new Error("job-journal: jobId is required");
  }
  if (typeof attemptId !== "string" || attemptId.length === 0) {
    throw new Error("job-journal: attemptId is required");
  }
  // Sanitize path segments (ids already match protocol patterns in production).
  const safeJob = jobId.replace(/[^A-Za-z0-9_.:-]/g, "_");
  const safeAttempt = attemptId.replace(/[^A-Za-z0-9_.:-]/g, "_");
  return path.join(journalDirFor(stateDir), `${safeJob}-${safeAttempt}.json`);
}

/**
 * Ensures the journal directory exists with restrictive mode.
 * @param {string} stateDir
 */
function ensureJournalDir(stateDir) {
  const dir = journalDirFor(stateDir);
  fs.mkdirSync(dir, { recursive: true, mode: JOURNAL_DIR_MODE });
  try {
    fs.chmodSync(dir, JOURNAL_DIR_MODE);
  } catch (_err) {
    // win32 may ignore mode bits
  }
  return dir;
}

/**
 * Writes (or refreshes) a side-effect marker before the first external
 * mutation of a job attempt. Idempotent for the same jobId/attemptId.
 *
 * @param {object} params
 * @param {string} params.stateDir
 * @param {string} params.jobId
 * @param {string} params.attemptId
 * @param {string|null} [params.claimId]
 * @param {string} params.stage e.g. "keygen" | "dns" | "acme" | "deploy" | "reload"
 * @param {() => Date} [params.now]
 * @returns {{ path: string, created: boolean, entry: object }}
 */
function markSideEffectReached({
  stateDir,
  jobId,
  attemptId,
  claimId = null,
  stage,
  now = () => new Date(),
} = {}) {
  if (typeof stage !== "string" || stage.length === 0 || stage.length > 64) {
    throw new Error("job-journal: stage must be a non-empty string <= 64 chars");
  }
  ensureJournalDir(stateDir);
  const filePath = journalPathFor(stateDir, jobId, attemptId);
  if (fs.existsSync(filePath)) {
    const existing = readJournalFile(filePath);
    return { path: filePath, created: false, entry: existing };
  }
  const entry = {
    jobId,
    attemptId,
    claimId: typeof claimId === "string" && claimId.length > 0 ? claimId : null,
    stage,
    timestamp: now().toISOString(),
    reconciled: false,
  };
  const tmp = `${filePath}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(entry)}\n`, { mode: JOURNAL_FILE_MODE });
  try {
    fs.chmodSync(tmp, JOURNAL_FILE_MODE);
  } catch (_err) {
    // win32
  }
  fs.renameSync(tmp, filePath);
  return { path: filePath, created: true, entry };
}

/**
 * @param {string} filePath
 * @returns {object|null}
 */
function readJournalFile(filePath) {
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return null;
    }
    return parsed;
  } catch (_err) {
    return null;
  }
}

/**
 * Scans the journal directory for unresolved entries.
 *
 * @param {string} stateDir
 * @returns {Array<object & { path: string }>}
 */
function scanUnresolvedJournalEntries(stateDir) {
  const dir = journalDirFor(stateDir);
  if (!fs.existsSync(dir)) return [];
  let names;
  try {
    names = fs.readdirSync(dir);
  } catch (_err) {
    return [];
  }
  const unresolved = [];
  for (const name of names) {
    if (!name.endsWith(".json")) continue;
    const filePath = path.join(dir, name);
    const entry = readJournalFile(filePath);
    if (!entry) continue;
    if (entry.reconciled === true) continue;
    unresolved.push({ ...entry, path: filePath });
  }
  return unresolved;
}

/**
 * True when any unresolved journal entry exists for this jobId
 * (any attempt). Used to refuse silently starting a fresh attempt.
 *
 * @param {string} stateDir
 * @param {string} jobId
 * @returns {boolean}
 */
function hasUnresolvedJournalForJob(stateDir, jobId) {
  if (typeof jobId !== "string" || jobId.length === 0) return false;
  return scanUnresolvedJournalEntries(stateDir).some(
    (entry) => entry.jobId === jobId,
  );
}

/**
 * Clears a journal entry once the attempt reaches a terminal reported state.
 *
 * @param {object} params
 * @param {string} params.stateDir
 * @param {string} params.jobId
 * @param {string} params.attemptId
 * @param {string} params.status terminal outcome status
 * @returns {{ cleared: boolean, reason?: string }}
 */
function clearJournalOnTerminal({ stateDir, jobId, attemptId, status } = {}) {
  if (!TERMINAL_STATUSES.includes(status)) {
    return { cleared: false, reason: "status not terminal" };
  }
  const filePath = journalPathFor(stateDir, jobId, attemptId);
  try {
    fs.unlinkSync(filePath);
    return { cleared: true };
  } catch (err) {
    if (err && err.code === "ENOENT") {
      return { cleared: false, reason: "absent" };
    }
    throw err;
  }
}

/**
 * Operator-facing summary for unresolved journals at startup.
 * @param {Array<object>} entries
 * @returns {string}
 */
function formatUnresolvedJournalReport(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    return "job-journal: no unresolved side-effect markers";
  }
  const lines = entries.map(
    (e) =>
      `jobId=${e.jobId} attemptId=${e.attemptId} stage=${e.stage} ` +
      `timestamp=${e.timestamp} claimId=${e.claimId || "null"}`,
  );
  return (
    `job-journal: ${entries.length} unresolved side-effect marker(s) requiring ` +
    `operator reconciliation (do not auto-re-execute):\n  - ${lines.join("\n  - ")}`
  );
}

module.exports = {
  JOURNAL_DIR_NAME,
  TERMINAL_STATUSES,
  journalDirFor,
  journalPathFor,
  ensureJournalDir,
  markSideEffectReached,
  scanUnresolvedJournalEntries,
  hasUnresolvedJournalForJob,
  clearJournalOnTerminal,
  formatUnresolvedJournalReport,
};
