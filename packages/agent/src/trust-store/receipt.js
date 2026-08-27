"use strict";

/**
 * Agent-local trust-anchor ownership receipt: a restart-safe, ACL-protected,
 * atomic-write ledger recording which (store, fingerprintSha256) pairs this
 * agent installed into a machine trust store, so a later revoke-trust can
 * prove ownership before deleting anything. One JSON file per row.
 * See docs/adr/0012-certops-windows-execution-surface-and-trust-anchors.md.
 *
 * A row has no field capable of holding private key material (store name,
 * fingerprint, job id, generation, state, timestamps only), and is still
 * deep-scanned by the shared private-key detector before every write.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const { applyRestrictivePermissions } = require("../platform/index.js");
const { fsyncDirectorySync } = require("../platform/durability.js");
const {
  assertNoPrivateKeyMaterial,
} = require("../../vendor/log-scrub/secret-material.js");

/** Mirrors trust-result-contract.schema.json's `store` pattern. */
const STORE_PATTERN = /^[A-Za-z0-9 _.-]{1,64}$/;
/** SHA-256 hex, lowercase, matching trust-job-payload.schema.json's
 * fingerprintSha256 pattern. */
const FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/;
/** Mirrors signed-dispatch-payload.schema.json's jobId pattern. */
const JOB_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;

/**
 * Receipt lifecycle states, deliberately matching the server-side
 * installation row's `transition_state` column so this agent-local mirror
 * doesn't drift into a parallel vocabulary:
 *   - pending_install / pending_remove: mutation attempted (intent written
 *     and fsynced) but not yet confirmed complete.
 *   - installed: the ownership proof a later revoke-trust requires.
 *   - removed: the remove mutation completed and was confirmed.
 */
const RECEIPT_STATES = Object.freeze([
  "pending_install",
  "installed",
  "pending_remove",
  "removed",
]);

const MAX_RECEIPT_ROW_BYTES = 16 * 1024;

function buildError(message, code) {
  const error = new Error(`tokentimer-agent trust-store/receipt: ${message}`);
  if (code) error.code = code;
  return error;
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function isIsoDateString(value) {
  return isNonEmptyString(value) && Number.isFinite(Date.parse(value));
}

function assertStore(value) {
  if (!isNonEmptyString(value) || !STORE_PATTERN.test(value)) {
    throw buildError(`store must match ${STORE_PATTERN} (got ${JSON.stringify(value)})`);
  }
}

function assertFingerprint(value) {
  if (!isNonEmptyString(value) || !FINGERPRINT_PATTERN.test(value)) {
    throw buildError(
      `fingerprintSha256 must be a 64-hex-char lowercase SHA-256 string (got ${JSON.stringify(value)})`,
    );
  }
}

function assertJobId(value) {
  if (!isNonEmptyString(value) || !JOB_ID_PATTERN.test(value)) {
    throw buildError(`jobId must match ${JOB_ID_PATTERN} (got ${JSON.stringify(value)})`);
  }
}

function assertTransitionGeneration(value) {
  if (!Number.isInteger(value) || value < 1) {
    throw buildError(`transitionGeneration must be an integer >= 1 (got ${JSON.stringify(value)})`);
  }
}

/**
 * Deterministic receipt id for one (store, fingerprintSha256) pair: sha256 of
 * the pair, hex. Doubles as the on-disk filename (`<id>.json`) and the
 * `receipt.id` reported in the trust-result contract, so the two cannot drift.
 * @param {string} store
 * @param {string} fingerprintSha256
 * @returns {string}
 */
function receiptId(store, fingerprintSha256) {
  assertStore(store);
  assertFingerprint(fingerprintSha256);
  return crypto
    .createHash("sha256")
    .update(`${store}\u0000${fingerprintSha256}`, "utf8")
    .digest("hex");
}

function receiptRowPath(receiptDir, store, fingerprintSha256) {
  return path.join(receiptDir, `${receiptId(store, fingerprintSha256)}.json`);
}

/**
 * Last-resort custody guard: rows never carry key material by construction,
 * but every row is still deep-scanned before it is written or returned, in
 * case a future field addition forgets that.
 * @param {Record<string, *>} row
 * @returns {Record<string, *>}
 */
function guardRow(row) {
  for (const item of Object.values(row)) {
    assertNoPrivateKeyMaterial(item);
  }
  return row;
}

/**
 * Validates a full receipt row shape, on write and on re-read, so a corrupted
 * on-disk row can never be silently trusted.
 * @param {*} row
 * @returns {object} the validated row, field order normalized
 */
function validateReceiptRow(row) {
  if (row === null || typeof row !== "object") {
    throw buildError("receipt row must be an object");
  }
  assertStore(row.store);
  assertFingerprint(row.fingerprintSha256);
  assertJobId(row.jobId);
  assertTransitionGeneration(row.transitionGeneration);
  if (!RECEIPT_STATES.includes(row.state)) {
    throw buildError(`state must be one of ${RECEIPT_STATES.join(", ")}`);
  }
  if (!isIsoDateString(row.intentWrittenAt)) {
    throw buildError("intentWrittenAt must be a parseable ISO date string");
  }
  if (row.finalizedAt !== null && row.finalizedAt !== undefined) {
    if (!isIsoDateString(row.finalizedAt)) {
      throw buildError("finalizedAt must be a parseable ISO date string or null");
    }
  }
  const expectedId = receiptId(row.store, row.fingerprintSha256);
  if (isNonEmptyString(row.id) && row.id !== expectedId) {
    throw buildError(
      `receipt row id ${JSON.stringify(row.id)} does not match the deterministic id ` +
        `${JSON.stringify(expectedId)} derived from its own (store, fingerprintSha256)`,
    );
  }
  return guardRow({
    id: expectedId,
    store: row.store,
    fingerprintSha256: row.fingerprintSha256,
    jobId: row.jobId,
    transitionGeneration: row.transitionGeneration,
    state: row.state,
    intentWrittenAt: row.intentWrittenAt,
    finalizedAt: row.finalizedAt ?? null,
  });
}

function fsyncParentDirectory(filePath) {
  fsyncDirectorySync(path.dirname(filePath));
}

/**
 * Atomic sibling-temp-file-plus-rename write: open with `wx` (exclusive
 * create), write, fsync fd, close, rename, re-apply the restrictive
 * permission, fsync the containing directory. Any failure unlinks the temp
 * file and rethrows, so a torn receipt can never be mistaken for valid.
 * @param {string} filePath
 * @param {string} contents
 * @param {number} mode
 * @returns {void}
 */
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
    applyRestrictivePermissions(filePath, { kind: "file", mode });
    fsyncParentDirectory(filePath);
  } catch (err) {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        // best-effort close
      }
    }
    try {
      fs.unlinkSync(temporaryPath);
    } catch {
      // may already have been renamed, or never existed
    }
    throw err;
  }
}

/**
 * Ensures the receipt directory exists with the platform-appropriate
 * restrictive protection: a root-owned 0700 directory on Linux, the
 * SYSTEM-ACL model on Windows.
 * @param {string} receiptDir
 * @returns {void}
 */
function ensureReceiptDir(receiptDir) {
  fs.mkdirSync(receiptDir, { recursive: true, mode: 0o700 });
  applyRestrictivePermissions(receiptDir, { kind: "directory", mode: 0o700 });
}

/**
 * Reads one receipt row: null if it doesn't exist, `{ corrupt: true, error }`
 * if it exists but fails to parse or validate. Both refuse removal for
 * revoke-trust but map to different `receipt.state` wire values (`missing`
 * vs `corrupt`), so they stay distinct. Never throws; corruption is a
 * reportable outcome, not a program bug.
 * @param {string} receiptDir
 * @param {string} store
 * @param {string} fingerprintSha256
 * @returns {{ row: object }|{ corrupt: true, error: Error }|null}
 */
function readReceipt(receiptDir, store, fingerprintSha256) {
  const rowPath = receiptRowPath(receiptDir, store, fingerprintSha256);
  let raw;
  try {
    const stats = fs.lstatSync(rowPath);
    if (stats.isSymbolicLink() || !stats.isFile()) {
      return { corrupt: true, error: buildError(`receipt at ${rowPath} is not a regular file`) };
    }
    if (stats.size > MAX_RECEIPT_ROW_BYTES) {
      return {
        corrupt: true,
        error: buildError(`receipt at ${rowPath} exceeds ${MAX_RECEIPT_ROW_BYTES} bytes`),
      };
    }
    raw = fs.readFileSync(rowPath, "utf8");
  } catch (err) {
    if (err && err.code === "ENOENT") return null;
    return { corrupt: true, error: err };
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return { corrupt: true, error: buildError(`receipt at ${rowPath} is not valid JSON: ${err.message}`) };
  }
  try {
    return { row: validateReceiptRow(parsed) };
  } catch (err) {
    return { corrupt: true, error: err };
  }
}

/**
 * Writes the pre-mutation intent record (`pending_install` or
 * `pending_remove`), written and fsynced before the OS-level mutation is
 * attempted. Refuses to overwrite an existing row for a different
 * jobId/transitionGeneration still in a pending state (two concurrent
 * attempts racing the same (store, fingerprint)); the executor (./index.js)
 * normally serializes this, so this is a last-resort guard.
 *
 * `reclaimStalePending` lifts that refusal for a row the caller has already
 * confirmed (via a live re-probe) never reached the OS - otherwise a receipt
 * orphaned by a crash would permanently block every future job for that
 * (store, fingerprint).
 * @param {object} input
 * @param {string} input.receiptDir
 * @param {string} input.store
 * @param {string} input.fingerprintSha256
 * @param {string} input.jobId
 * @param {number} input.transitionGeneration
 * @param {"pending_install"|"pending_remove"} input.intentState
 * @param {boolean} [input.reclaimStalePending]
 * @param {() => Date} [input.now]
 * @returns {object} the persisted row
 */
function writeIntentReceipt({
  receiptDir,
  store,
  fingerprintSha256,
  jobId,
  transitionGeneration,
  intentState,
  reclaimStalePending = false,
  now = () => new Date(),
}) {
  if (intentState !== "pending_install" && intentState !== "pending_remove") {
    throw buildError(`intentState must be "pending_install" or "pending_remove" (got ${JSON.stringify(intentState)})`);
  }
  const existing = readReceipt(receiptDir, store, fingerprintSha256);
  if (
    existing !== null &&
    !("corrupt" in existing) &&
    (existing.row.state === "pending_install" || existing.row.state === "pending_remove") &&
    (existing.row.jobId !== jobId || existing.row.transitionGeneration !== transitionGeneration) &&
    !reclaimStalePending
  ) {
    throw buildError(
      `refusing to overwrite an existing ${existing.row.state} receipt for ` +
        `(store=${store}, fingerprint=${fingerprintSha256}) owned by a different ` +
        `jobId/transitionGeneration (existing: ${existing.row.jobId}/${existing.row.transitionGeneration}, ` +
        `incoming: ${jobId}/${transitionGeneration})`,
    );
  }
  const row = validateReceiptRow({
    store,
    fingerprintSha256,
    jobId,
    transitionGeneration,
    state: intentState,
    intentWrittenAt: now().toISOString(),
    finalizedAt: null,
  });

  ensureReceiptDir(receiptDir);
  const rowPath = receiptRowPath(receiptDir, store, fingerprintSha256);
  writeFileAtomically(rowPath, `${JSON.stringify(row, null, 2)}\n`, 0o600);
  return row;
}

/**
 * Finalizes a receipt AFTER the OS-level mutation completes, a second atomic
 * write transitioning `pending_install` -> `installed` or `pending_remove` ->
 * `removed`. Requires a prior intent row for the SAME
 * jobId/transitionGeneration in the matching pending state, so a finalize can
 * never fabricate a transition that was never attempted.
 * @param {object} input
 * @param {string} input.receiptDir
 * @param {string} input.store
 * @param {string} input.fingerprintSha256
 * @param {string} input.jobId must match the intent row's jobId.
 * @param {number} input.transitionGeneration must match the intent row's.
 * @param {() => Date} [input.now]
 * @returns {object} the persisted, finalized row
 */
function finalizeReceipt({ receiptDir, store, fingerprintSha256, jobId, transitionGeneration, now = () => new Date() }) {
  const existing = readReceipt(receiptDir, store, fingerprintSha256);
  if (existing === null) {
    throw buildError(
      `cannot finalize: no intent receipt exists for (${store}, ${fingerprintSha256}); ` +
        "writeIntentReceipt must run before finalizeReceipt",
      "RECEIPT_MISSING",
    );
  }
  if ("corrupt" in existing) {
    throw buildError(
      `cannot finalize: existing receipt for (${store}, ${fingerprintSha256}) is corrupt: ${existing.error.message}`,
      "RECEIPT_CORRUPT",
    );
  }
  const { row } = existing;
  if (row.jobId !== jobId || row.transitionGeneration !== transitionGeneration) {
    throw buildError(
      `cannot finalize: existing receipt for (${store}, ${fingerprintSha256}) was written for ` +
        `jobId=${row.jobId}/generation=${row.transitionGeneration}, not jobId=${jobId}/generation=${transitionGeneration}`,
      "RECEIPT_GENERATION_MISMATCH",
    );
  }
  const nextState = row.state === "pending_install" ? "installed" : row.state === "pending_remove" ? "removed" : null;
  if (!nextState) {
    throw buildError(
      `cannot finalize: existing receipt for (${store}, ${fingerprintSha256}) is in terminal state ` +
        `${row.state}, not a pending state`,
      "RECEIPT_NOT_PENDING",
    );
  }

  const finalized = validateReceiptRow({
    ...row,
    state: nextState,
    finalizedAt: now().toISOString(),
  });
  ensureReceiptDir(receiptDir);
  const rowPath = receiptRowPath(receiptDir, store, fingerprintSha256);
  writeFileAtomically(rowPath, `${JSON.stringify(finalized, null, 2)}\n`, 0o600);
  return finalized;
}

/**
 * Lists every persisted receipt's `<id>.json` basename for the startup sweep.
 * The sweep re-reads each row fresh when it is evaluated, rather than acting on
 * a possibly-stale snapshot.
 * @param {string} receiptDir
 * @returns {string[]}
 */
function listReceiptIds(receiptDir) {
  let entries;
  try {
    entries = fs.readdirSync(receiptDir);
  } catch (err) {
    if (err && err.code === "ENOENT") return [];
    throw err;
  }
  return entries.filter((name) => name.endsWith(".json")).map((name) => name.slice(0, -".json".length));
}

/**
 * Reads a receipt row directly by its deterministic id, for the startup
 * sweep's iteration over listReceiptIds. Same shape as readReceipt.
 * @param {string} receiptDir
 * @param {string} id
 * @returns {{ row: object }|{ corrupt: true, error: Error }|null}
 */
function readReceiptById(receiptDir, id) {
  const rowPath = path.join(receiptDir, `${id}.json`);
  let raw;
  try {
    const stats = fs.lstatSync(rowPath);
    if (stats.isSymbolicLink() || !stats.isFile()) {
      return { corrupt: true, error: buildError(`receipt at ${rowPath} is not a regular file`) };
    }
    if (stats.size > MAX_RECEIPT_ROW_BYTES) {
      return { corrupt: true, error: buildError(`receipt at ${rowPath} exceeds ${MAX_RECEIPT_ROW_BYTES} bytes`) };
    }
    raw = fs.readFileSync(rowPath, "utf8");
  } catch (err) {
    if (err && err.code === "ENOENT") return null;
    return { corrupt: true, error: err };
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return { corrupt: true, error: buildError(`receipt at ${rowPath} is not valid JSON: ${err.message}`) };
  }
  try {
    return { row: validateReceiptRow(parsed) };
  } catch (err) {
    return { corrupt: true, error: err };
  }
}

/**
 * Classifies one receipt row's recovery outcome. A pure function over the
 * row's persisted state, never a live store-presence check (bare presence
 * would let revoke-trust delete material an unrelated owner depends on).
 * @param {object} row a validated receipt row.
 * @returns {"crash_before_mutation"|"confirmed_installed"|"confirmed_removed"}
 */
function classifyRecoveryOutcome(row) {
  const validated = validateReceiptRow(row);
  if (validated.state === "pending_install" || validated.state === "pending_remove") {
    return "crash_before_mutation";
  }
  if (validated.state === "installed") return "confirmed_installed";
  return "confirmed_removed";
}

/**
 * Startup sweep entry point: iterates every persisted receipt and reports its
 * recovery classification, without mutating any store (the retry decision
 * belongs to ./index.js). A corrupt row is reported, never thrown.
 * @param {object} input
 * @param {string} input.receiptDir
 * @returns {{
 *   rows: Array<{ id: string, store: string, fingerprintSha256: string, outcome: string, row: object }>,
 *   corrupt: Array<{ id: string, error: string }>,
 * }}
 */
function sweepReceipts({ receiptDir }) {
  const rows = [];
  const corrupt = [];
  for (const id of listReceiptIds(receiptDir)) {
    const result = readReceiptById(receiptDir, id);
    if (result === null) continue;
    if ("corrupt" in result) {
      corrupt.push({ id, error: result.error.message });
      continue;
    }
    rows.push({
      id,
      store: result.row.store,
      fingerprintSha256: result.row.fingerprintSha256,
      outcome: classifyRecoveryOutcome(result.row),
      row: result.row,
    });
  }
  return { rows, corrupt };
}

module.exports = {
  STORE_PATTERN,
  FINGERPRINT_PATTERN,
  JOB_ID_PATTERN,
  RECEIPT_STATES,
  MAX_RECEIPT_ROW_BYTES,
  receiptId,
  receiptRowPath,
  isIsoDateString,
  validateReceiptRow,
  ensureReceiptDir,
  writeFileAtomically,
  readReceipt,
  readReceiptById,
  writeIntentReceipt,
  finalizeReceipt,
  listReceiptIds,
  classifyRecoveryOutcome,
  sweepReceipts,
};
