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
 *
 * Windows CNG container reconciliation: for a windows-iis renewal attempt,
 * recordWindowsCngContainer additionally attaches the CNG key container
 * name (and target store) that attempt's keygen stage created, onto the
 * same entry markSideEffectReached wrote. index.js's own startup sweep
 * (reconcileOrphanedWindowsCngContainers) reads this to autonomously free
 * a container that a hard crash left orphaned -- never enrolled to any
 * certificate in the recorded store -- rather than only ever reporting it
 * to an operator via formatUnresolvedJournalReport, which is still done
 * for the job-attempt-outcome question this module was originally built
 * for (see markWindowsCngContainerReconciled's own doc comment for why
 * these are deliberately two separate lifecycles).
 */

const fs = require("node:fs");
const path = require("node:path");
const { applyRestrictivePermissions } = require("../platform/index.js");

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
 * Ensures the journal directory exists with restrictive permissions,
 * re-asserting them on every call. POSIX: 0700. win32: a real ACL with
 * inheritance removed, granting only the agent's own identity plus SYSTEM.
 * @param {string} stateDir
 */
function ensureJournalDir(stateDir) {
  const dir = journalDirFor(stateDir);
  fs.mkdirSync(dir, { recursive: true, mode: JOURNAL_DIR_MODE });
  applyRestrictivePermissions(dir, { kind: "directory", mode: JOURNAL_DIR_MODE });
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
  // POSIX re-asserts the mode; win32 gets a real restricted ACL. A failure
  // here is fatal: an unprotected journal entry is not an acceptable
  // outcome of a successful write.
  applyRestrictivePermissions(tmp, { kind: "file", mode: JOURNAL_FILE_MODE });
  fs.renameSync(tmp, filePath);
  return { path: filePath, created: true, entry };
}

/** Boring, closed alphabet for a CNG key container name -- mirrors
 * ../windows-cert-store's own CONTAINER_NAME_PATTERN (duplicated, not
 * imported, per this package's self-contained-module convention: the
 * journal must stay a plain-data format that never depends on a sibling
 * module's internals). */
const WINDOWS_CNG_CONTAINER_NAME_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
/** Mirrors ../windows-cert-store's WINDOWS_STORE_NAME_PATTERN. */
const WINDOWS_STORE_NAME_PATTERN = /^[A-Za-z0-9 _.-]{1,64}$/;

/**
 * Attaches (or refreshes) the CNG key container identifier a windows-iis
 * renewal created for this attempt, onto an ALREADY-EXISTING journal entry
 * (one markSideEffectReached already wrote for the "keygen" stage).
 * No-op (returns null) if no entry exists yet for this jobId/attemptId --
 * this function only ever enriches a journal entry, it never creates one,
 * since a crash before markSideEffectReached("keygen") ran leaves nothing
 * to enrich and nothing this agent could have created either.
 *
 * `store` (the job's target windows-iis store, e.g. "My" or "WebHosting")
 * is recorded alongside the container name because markSideEffectReached
 * is idempotent per attempt: the entry's own `stage` field freezes at
 * whichever stage was reached FIRST for this attempt ("keygen", always,
 * for this job type) and is never advanced by later onBeforeMutation
 * calls in the same attempt, so `stage` alone cannot tell a later
 * reconciliation pass how far the job actually got before crashing. Store
 * membership (does ANY certificate in "My" or this target store reference
 * the container?) is the only reliable, independently-verifiable signal
 * of whether `certreq -accept` ever actually ran for this container.
 *
 * This is what lets a startup reconciliation pass (see index.js's
 * reconcileOrphanedWindowsCngContainers) actually FREE an orphaned CNG key
 * container after a hard crash, rather than merely reporting that some
 * side effect happened: without the container name recorded here, the
 * journal only knows a mutation started, never which key container it
 * created.
 *
 * @param {object} params
 * @param {string} params.stateDir
 * @param {string} params.jobId
 * @param {string} params.attemptId
 * @param {string} params.containerName
 * @param {string} [params.store] the job's target windows-iis store.
 * @returns {{ path: string, entry: object }|null}
 */
function recordWindowsCngContainer({ stateDir, jobId, attemptId, containerName, store }) {
  if (
    typeof containerName !== "string" ||
    !WINDOWS_CNG_CONTAINER_NAME_PATTERN.test(containerName)
  ) {
    throw new Error(
      `job-journal: containerName must match ${WINDOWS_CNG_CONTAINER_NAME_PATTERN} (got ${JSON.stringify(containerName)})`,
    );
  }
  if (store !== undefined && !WINDOWS_STORE_NAME_PATTERN.test(store)) {
    throw new Error(
      `job-journal: store must match ${WINDOWS_STORE_NAME_PATTERN} (got ${JSON.stringify(store)})`,
    );
  }
  const filePath = journalPathFor(stateDir, jobId, attemptId);
  const existing = readJournalFile(filePath);
  if (existing === null) return null;

  const entry = {
    ...existing,
    windowsCngContainerName: containerName,
    ...(store !== undefined ? { windowsCngStore: store } : {}),
  };
  const tmp = `${filePath}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(entry)}\n`, { mode: JOURNAL_FILE_MODE });
  applyRestrictivePermissions(tmp, { kind: "file", mode: JOURNAL_FILE_MODE });
  fs.renameSync(tmp, filePath);
  return { path: filePath, entry };
}

/**
 * Marks a journal entry's recorded CNG key container as already reconciled
 * (freed, or confirmed still legitimately bound) by a startup sweep, so a
 * later restart does not repeat the same certutil call against a container
 * that either no longer exists or is now known to be in legitimate use.
 * Does NOT clear/resolve the journal entry itself: the underlying job
 * attempt's outcome with the control plane is still unknown and still
 * requires the existing operator-reconciliation path (decision: container
 * lifecycle and job-attempt lifecycle are separate concerns; freeing a
 * dead key container does not retroactively tell this agent whether the
 * control plane ever saw a result for the attempt).
 *
 * @param {object} params
 * @param {string} params.stateDir
 * @param {string} params.jobId
 * @param {string} params.attemptId
 * @returns {{ path: string, entry: object }|null}
 */
function markWindowsCngContainerReconciled({ stateDir, jobId, attemptId }) {
  const filePath = journalPathFor(stateDir, jobId, attemptId);
  const existing = readJournalFile(filePath);
  if (existing === null) return null;

  const entry = { ...existing, windowsCngContainerReconciledAt: new Date().toISOString() };
  const tmp = `${filePath}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(entry)}\n`, { mode: JOURNAL_FILE_MODE });
  applyRestrictivePermissions(tmp, { kind: "file", mode: JOURNAL_FILE_MODE });
  fs.renameSync(tmp, filePath);
  return { path: filePath, entry };
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
  WINDOWS_CNG_CONTAINER_NAME_PATTERN,
  WINDOWS_STORE_NAME_PATTERN,
  journalDirFor,
  journalPathFor,
  ensureJournalDir,
  markSideEffectReached,
  recordWindowsCngContainer,
  markWindowsCngContainerReconciled,
  scanUnresolvedJournalEntries,
  hasUnresolvedJournalForJob,
  clearJournalOnTerminal,
  formatUnresolvedJournalReport,
};
