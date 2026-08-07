"use strict";

/**
 * Superseded-certificate retention ledger (ADR-0012 decision 18).
 *
 * A rotation on a Windows IIS/http.sys binding (../windows-iis) leaves the
 * certificate it just replaced sitting in the machine store and its CNG key
 * container (../windows-cert-store) still present. This module is the
 * "restart-safe, agent-local superseded-material ledger" decision 18
 * requires: one persisted row per superseded certificate, written at
 * cutover, swept at startup and on the reconciliation schedule, governing
 * exactly when that predecessor material becomes safe to delete.
 *
 * This module owns:
 *   - the ledger row schema and its atomic, ACL-protected persistence
 *     (decision 10's ACL matrix, decision 18's atomic-write requirement)
 *   - the "earlier of two clocks" cleanup-deadline computation
 *   - the six-condition eligibility check, evaluated as a PURE function
 *     over plain-data inputs (this module never queries http.sys, the
 *     certificate store, or performs a TLS handshake itself; a caller
 *     supplies those facts as a context object, exactly like the sibling
 *     ../windows-iis module receives its bind/verify facts as arguments
 *     rather than discovering them internally)
 *   - the sweep loop and its per-reason deferred-count metric
 *
 * This module does NOT own: deleting the actual store certificate or CNG
 * key container (a caller-injected performCleanup callback does that; the
 * real agent would wire it to ../windows-cert-store's
 * removeCertificateAndKeyContainer) or discovering bindings/shared-key-
 * container facts (../windows-discovery's discoverWindowsCertificateInventory,
 * which a caller would use to build gatherContext's facts).
 *
 * Zero-custody preserving: this module never receives, generates, or
 * returns private key material; every field in a ledger row is a
 * thumbprint, container id, timestamp, or enum string.
 *
 * Persistence layout: one JSON file per row, named `<oldThumbprint>.json`,
 * inside the caller-supplied ledger directory (expected to be a
 * subdirectory of the agent's ACL-protected state dir, matching decision
 * 10's "agent-created state" ACL). One file per row (rather than one big
 * ledger file) means concurrent rows never contend on the same atomic
 * write, and a torn write to one row can never corrupt an unrelated row.
 *
 * Status: this module (row schema, atomic persistence, deadline math, the
 * six-condition eligibility check, and the sweep loop itself) is real,
 * tested against injected context/clock, and verified end-to-end on a
 * real Windows host as a standalone unit (ledger lifecycle, sweep,
 * active-reference deferral, restart survival, retention boundary
 * values). packages/agent/src/index.js's real renew path writes a row via
 * createLedgerRow on every verified IIS cutover (see
 * recordSupersededWindowsCertificate there), and index.js's own
 * runWindowsRetentionSweep is now the periodic caller this module's own
 * sweep loop needs: it gathers the live http.sys/store facts via
 * ../windows-discovery, performs the actual delete via
 * ../windows-cert-store's removeCertificateAndKeyContainer, and is wired
 * into runAgent's poll-loop set (config `windows.sweepIntervalMs`,
 * default 6 hours) whenever execution is enabled. `config.windows`'s
 * `supersededRetentionHours` is validated by ../config/index.js's
 * validateWindowsObject (default 168 hours / 7 days), independent of this
 * module's own validateRetentionHours (kept as two call sites rather than
 * one import, matching the loader's existing style of owning its own copy
 * of the bounds it validates against).
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const { applyRestrictivePermissions } = require("../platform/index.js");
const { fsyncDirectorySync } = require("../platform/durability.js");

const MIN_RETENTION_HOURS = 24;
const MAX_RETENTION_HOURS = 720;
/** Named, not "small and fixed": reuses the program's one documented
 * clock-skew tolerance constant (decision 18), not a newly invented one. */
const CLOCK_SKEW_GRACE_SECONDS = 300;

const THUMBPRINT_PATTERN = /^[0-9A-Fa-f]{40}$/;
/** CNG key container names this module accepts are exactly the ones
 * ../windows-cert-store's buildContainerName produces. */
const CONTAINER_NAME_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
/** Opaque job/rollback-journal reference identifiers; boring alphabet,
 * same discipline as every other identifier this package persists. */
const JOURNAL_REF_PATTERN = /^[A-Za-z0-9_.:-]{1,256}$/;
/** Windows certificate store names this module accepts are exactly the
 * ones ../windows-cert-store's WINDOWS_STORE_NAME_PATTERN accepts (kept as
 * an independent literal, not an import, matching this module's documented
 * decoupling from its sibling modules: it receives facts, it does not call
 * into them). Recorded per-row so a later sweep knows which store to
 * re-query for keyContainerSharedWithSurvivor, without this module itself
 * ever touching the store. */
const WINDOWS_STORE_NAME_PATTERN = /^[A-Za-z0-9 _.-]{1,64}$/;

const OWNERSHIP_PROVENANCE_VALUES = Object.freeze(["tokentimer_installed", "preexisting"]);
const LIFECYCLE_STATE_VALUES = Object.freeze([
  "pending_retention",
  "eligible",
  "deferred",
  "removed",
]);
/** The exact six deferral reasons decision 18 names; a sweep must use one
 * of these, never a free-text string, so the per-reason metric it also
 * requires stays a bounded, known set of buckets. */
const DEFERRAL_REASONS = Object.freeze([
  "ownership_unrecorded",
  "binding_still_present",
  "active_reference_present",
  "shared_key_container",
  "replacement_handshake_failed",
  "deadline_not_reached",
]);

const MAX_LEDGER_ROW_BYTES = 16 * 1024;

function buildError(message, code) {
  const error = new Error(`tokentimer-agent windows-retention: ${message}`);
  if (code) error.code = code;
  return error;
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function isIsoDateString(value) {
  return isNonEmptyString(value) && Number.isFinite(Date.parse(value));
}

/**
 * Validates and normalizes `windows.supersededRetentionHours` (decision 18):
 * an integer in [24, 720]. Zero (and anything else out of range) is
 * REJECTED at load time, never silently clamped, because zero collapses
 * retention to unconditional immediate deletion.
 * @param {*} hours
 * @returns {number}
 */
function validateRetentionHours(hours) {
  if (
    typeof hours !== "number" ||
    !Number.isInteger(hours) ||
    hours < MIN_RETENTION_HOURS ||
    hours > MAX_RETENTION_HOURS
  ) {
    throw buildError(
      `windows.supersededRetentionHours must be an integer in [${MIN_RETENTION_HOURS}, ${MAX_RETENTION_HOURS}] ` +
        `(got ${JSON.stringify(hours)})`,
      "INVALID_RETENTION_HOURS",
    );
  }
  return hours;
}

function assertThumbprint(value, fieldName) {
  if (!isNonEmptyString(value) || !THUMBPRINT_PATTERN.test(value)) {
    throw buildError(`${fieldName} must be a 40-hex-char SHA-1 thumbprint (got ${JSON.stringify(value)})`);
  }
}

function normalizeThumbprint(value) {
  return value.toUpperCase();
}

/**
 * Computes the cleanup deadline for one ledger row: the EARLIER of
 * verifiedCutoverAt + retentionHours, and oldNotAfter + a fixed 300-second
 * clock-skew grace. "Earlier", not "later" -- a certificate already past
 * its own notAfter provides no rollback value regardless of how recently
 * it was replaced.
 * @param {{ verifiedCutoverAt: string, oldNotAfter: string, retentionHours: number }} row
 * @returns {Date}
 */
function computeCleanupDeadline({ verifiedCutoverAt, oldNotAfter, retentionHours }) {
  if (!isIsoDateString(verifiedCutoverAt)) {
    throw buildError(`verifiedCutoverAt must be a parseable ISO date string (got ${JSON.stringify(verifiedCutoverAt)})`);
  }
  if (!isIsoDateString(oldNotAfter)) {
    throw buildError(`oldNotAfter must be a parseable ISO date string (got ${JSON.stringify(oldNotAfter)})`);
  }
  validateRetentionHours(retentionHours);

  const retentionDeadlineMs = Date.parse(verifiedCutoverAt) + retentionHours * 60 * 60 * 1000;
  const expiryDeadlineMs = Date.parse(oldNotAfter) + CLOCK_SKEW_GRACE_SECONDS * 1000;
  return new Date(Math.min(retentionDeadlineMs, expiryDeadlineMs));
}

function fsyncParentDirectory(filePath) {
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

function ensureLedgerDir(ledgerDir) {
  fs.mkdirSync(ledgerDir, { recursive: true, mode: 0o700 });
  applyRestrictivePermissions(ledgerDir, { kind: "directory", mode: 0o700 });
}

function ledgerRowPath(ledgerDir, oldThumbprint) {
  return path.join(ledgerDir, `${normalizeThumbprint(oldThumbprint)}.json`);
}

/**
 * Validates one journal reference entry: `{ ref: string, active: boolean }`.
 * @param {*} entry
 * @param {number} index
 * @returns {{ ref: string, active: boolean }}
 */
function validateJournalRef(entry, index) {
  if (entry === null || typeof entry !== "object") {
    throw buildError(`jobOrRollbackJournalRefs[${index}] must be an object`);
  }
  if (!isNonEmptyString(entry.ref) || !JOURNAL_REF_PATTERN.test(entry.ref)) {
    throw buildError(`jobOrRollbackJournalRefs[${index}].ref must match ${JOURNAL_REF_PATTERN}`);
  }
  if (typeof entry.active !== "boolean") {
    throw buildError(`jobOrRollbackJournalRefs[${index}].active must be a boolean`);
  }
  return { ref: entry.ref, active: entry.active };
}

/**
 * Validates a full ledger row shape (used both when creating a new row and
 * when re-reading a persisted one, so a corrupted on-disk row can never be
 * silently trusted).
 * @param {*} row
 * @returns {object} the validated row, field order normalized
 */
function validateLedgerRow(row) {
  if (row === null || typeof row !== "object") {
    throw buildError("ledger row must be an object");
  }
  assertThumbprint(row.oldThumbprint, "oldThumbprint");
  assertThumbprint(row.replacementThumbprint, "replacementThumbprint");
  if (!isNonEmptyString(row.cngKeyContainerId) || !CONTAINER_NAME_PATTERN.test(row.cngKeyContainerId)) {
    throw buildError(`cngKeyContainerId must match ${CONTAINER_NAME_PATTERN}`);
  }
  if (!isIsoDateString(row.verifiedCutoverAt)) {
    throw buildError("verifiedCutoverAt must be a parseable ISO date string");
  }
  if (!isIsoDateString(row.oldNotAfter)) {
    throw buildError("oldNotAfter must be a parseable ISO date string");
  }
  if (!OWNERSHIP_PROVENANCE_VALUES.includes(row.ownershipProvenance)) {
    throw buildError(`ownershipProvenance must be one of ${OWNERSHIP_PROVENANCE_VALUES.join(", ")}`);
  }
  if (row.store !== null && row.store !== undefined) {
    if (!isNonEmptyString(row.store) || !WINDOWS_STORE_NAME_PATTERN.test(row.store)) {
      throw buildError(`store must match ${WINDOWS_STORE_NAME_PATTERN} or be null (got ${JSON.stringify(row.store)})`);
    }
  }
  if (!Array.isArray(row.jobOrRollbackJournalRefs)) {
    throw buildError("jobOrRollbackJournalRefs must be an array");
  }
  const jobOrRollbackJournalRefs = row.jobOrRollbackJournalRefs.map(validateJournalRef);
  if (!LIFECYCLE_STATE_VALUES.includes(row.lifecycleState)) {
    throw buildError(`lifecycleState must be one of ${LIFECYCLE_STATE_VALUES.join(", ")}`);
  }
  if (row.deferralReason !== null && row.deferralReason !== undefined) {
    if (!DEFERRAL_REASONS.includes(row.deferralReason)) {
      throw buildError(`deferralReason must be one of ${DEFERRAL_REASONS.join(", ")} or null`);
    }
  }
  return {
    oldThumbprint: normalizeThumbprint(row.oldThumbprint),
    replacementThumbprint: normalizeThumbprint(row.replacementThumbprint),
    cngKeyContainerId: row.cngKeyContainerId,
    verifiedCutoverAt: row.verifiedCutoverAt,
    oldNotAfter: row.oldNotAfter,
    ownershipProvenance: row.ownershipProvenance,
    store: row.store ?? null,
    jobOrRollbackJournalRefs,
    lifecycleState: row.lifecycleState,
    deferralReason: row.deferralReason ?? null,
  };
}

/**
 * Creates and persists a new ledger row at cutover, in `pending_retention`
 * state. Decision 18: "Each superseded certificate gets one persisted
 * ledger row, written in the same operation that completes cutover
 * verification." Callers call this immediately after ../windows-iis's
 * deployIisBinding returns ok: true with a non-null outgoingThumbprint.
 *
 * @param {object} input
 * @param {string} input.ledgerDir
 * @param {string} input.oldThumbprint the superseded (outgoing) thumbprint.
 * @param {string} input.replacementThumbprint the newly bound thumbprint.
 * @param {string} input.cngKeyContainerId the old certificate's CNG key
 *   container identifier (../windows-cert-store's buildContainerName output).
 * @param {string} input.verifiedCutoverAt ISO timestamp, set once, at
 *   successful cutover verification.
 * @param {string} input.oldNotAfter the old certificate's own notAfter, ISO.
 * @param {"tokentimer_installed"|"preexisting"} input.ownershipProvenance
 * @param {string|null} [input.store] the Windows certificate store
 *   (e.g. "My", "WebHosting") the superseded certificate lives in; a
 *   sweep's gatherContext needs this to know where to look when computing
 *   keyContainerSharedWithSurvivor and performing the eventual cleanup.
 *   Optional/nullable for backward compatibility with rows persisted
 *   before this field existed.
 * @param {{ ref: string, active: boolean }[]} [input.jobOrRollbackJournalRefs]
 * @returns {object} the persisted row
 */
function createLedgerRow({
  ledgerDir,
  oldThumbprint,
  replacementThumbprint,
  cngKeyContainerId,
  verifiedCutoverAt,
  oldNotAfter,
  ownershipProvenance,
  store = null,
  jobOrRollbackJournalRefs = [],
}) {
  const row = validateLedgerRow({
    oldThumbprint,
    replacementThumbprint,
    cngKeyContainerId,
    verifiedCutoverAt,
    oldNotAfter,
    ownershipProvenance,
    store,
    jobOrRollbackJournalRefs,
    lifecycleState: "pending_retention",
    deferralReason: null,
  });

  ensureLedgerDir(ledgerDir);
  const rowPath = ledgerRowPath(ledgerDir, row.oldThumbprint);
  if (fs.existsSync(rowPath)) {
    throw buildError(
      `a ledger row already exists for thumbprint ${row.oldThumbprint} (${rowPath}); ` +
        "each superseded certificate gets exactly one row",
      "ROW_ALREADY_EXISTS",
    );
  }
  writeFileAtomically(rowPath, `${JSON.stringify(row, null, 2)}\n`, 0o600);
  return row;
}

/**
 * Reads one ledger row, returning null when it does not exist. A
 * present-but-corrupted row fails loudly (never silently ignored): decision
 * 18's whole premise is that this row is the sole durable record of a
 * cleanup decision, so a corrupted row must stop the sweep for that row,
 * not be treated as "no row" (which would re-run cutover-time logic that
 * cannot be safely repeated) or "eligible" (which would delete without the
 * checks the row exists to gate).
 * @param {string} ledgerDir
 * @param {string} oldThumbprint
 * @returns {object|null}
 */
function readLedgerRow(ledgerDir, oldThumbprint) {
  const rowPath = ledgerRowPath(ledgerDir, oldThumbprint);
  let raw;
  try {
    const stats = fs.lstatSync(rowPath);
    if (stats.isSymbolicLink() || !stats.isFile()) {
      throw buildError(`ledger row at ${rowPath} is not a regular file`);
    }
    if (stats.size > MAX_LEDGER_ROW_BYTES) {
      throw buildError(`ledger row at ${rowPath} exceeds ${MAX_LEDGER_ROW_BYTES} bytes`);
    }
    raw = fs.readFileSync(rowPath, "utf8");
  } catch (err) {
    if (err && err.code === "ENOENT") return null;
    throw err;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw buildError(`ledger row at ${rowPath} is not valid JSON: ${err.message}`);
  }
  return validateLedgerRow(parsed);
}

/**
 * Lists every persisted ledger row's oldThumbprint, for the sweep to
 * iterate over. Returns thumbprints only (not full rows) so the sweep
 * re-reads each row fresh via readLedgerRow at the moment it is evaluated,
 * rather than acting on a possibly-stale snapshot.
 * @param {string} ledgerDir
 * @returns {string[]}
 */
function listLedgerThumbprints(ledgerDir) {
  let entries;
  try {
    entries = fs.readdirSync(ledgerDir);
  } catch (err) {
    if (err && err.code === "ENOENT") return [];
    throw err;
  }
  return entries
    .filter((name) => name.endsWith(".json"))
    .map((name) => name.slice(0, -".json".length))
    .filter((thumbprint) => THUMBPRINT_PATTERN.test(thumbprint));
}

/**
 * Persists an updated ledger row (lifecycleState/deferralReason
 * transitions, or a journal reference being closed). Always rewrites the
 * WHOLE row atomically; there is no partial-field update path, so a row on
 * disk is always a single, complete, internally consistent JSON document.
 * @param {string} ledgerDir
 * @param {object} row a full row object (e.g. the output of readLedgerRow
 *   with fields changed).
 * @returns {object} the persisted row
 */
function writeLedgerRow(ledgerDir, row) {
  const validated = validateLedgerRow(row);
  ensureLedgerDir(ledgerDir);
  const rowPath = ledgerRowPath(ledgerDir, validated.oldThumbprint);
  writeFileAtomically(rowPath, `${JSON.stringify(validated, null, 2)}\n`, 0o600);
  return validated;
}

/**
 * Marks a specific journal reference as closed (decision 18: "once that
 * rollback either completes or is abandoned by its own protocol, the
 * reference is explicitly marked closed, in the same write that closes the
 * rollback journal entry itself"). No-op if the ref is not found or already
 * closed, since closing twice is not an error, just redundant.
 * @param {string} ledgerDir
 * @param {string} oldThumbprint
 * @param {string} ref
 * @returns {object|null} the updated row, or null if no row exists
 */
function closeJournalReference(ledgerDir, oldThumbprint, ref) {
  const row = readLedgerRow(ledgerDir, oldThumbprint);
  if (row === null) return null;
  const updatedRefs = row.jobOrRollbackJournalRefs.map((entry) =>
    entry.ref === ref ? { ...entry, active: false } : entry,
  );
  return writeLedgerRow(ledgerDir, { ...row, jobOrRollbackJournalRefs: updatedRefs });
}

/**
 * Evaluates the six-condition eligibility check for one ledger row
 * (decision 18: "Deletion requires every one of the following, not any one
 * of them"). Pure function: every fact is supplied by the caller via
 * `context`, since this module does not itself query http.sys, the
 * certificate store, or perform a TLS handshake.
 *
 * @param {object} row a validated ledger row (see validateLedgerRow).
 * @param {object} context
 * @param {number} context.retentionHours validated
 *   `windows.supersededRetentionHours`, the agent-local policy value in
 *   effect for this sweep (not stored per-row: it is agent-local policy,
 *   ADR-0002, not per-certificate data).
 * @param {boolean} context.bindingStillReferencesOldThumbprint whether any
 *   IIS/http.sys binding on this host still references row.oldThumbprint.
 * @param {boolean} context.keyContainerSharedWithSurvivor whether
 *   row.cngKeyContainerId is still referenced by a second, distinct
 *   certificate/ownership record.
 * @param {boolean} context.replacementPassesHandshakeNow whether
 *   row.replacementThumbprint remains correctly bound AND independently
 *   passes a local TLS handshake right now (re-checked at sweep time, not
 *   only trusted from cutover).
 * @param {() => Date} [context.now] injectable clock, default real Date.
 * @returns {
 *   | { eligible: true }
 *   | { eligible: false, reason: (typeof DEFERRAL_REASONS)[number] }
 * }
 */
function evaluateEligibility(row, {
  retentionHours,
  bindingStillReferencesOldThumbprint,
  keyContainerSharedWithSurvivor,
  replacementPassesHandshakeNow,
  now = () => new Date(),
}) {
  const validatedRow = validateLedgerRow(row);
  validateRetentionHours(retentionHours);
  for (const [name, value] of [
    ["bindingStillReferencesOldThumbprint", bindingStillReferencesOldThumbprint],
    ["keyContainerSharedWithSurvivor", keyContainerSharedWithSurvivor],
    ["replacementPassesHandshakeNow", replacementPassesHandshakeNow],
  ]) {
    if (typeof value !== "boolean") {
      throw buildError(`context.${name} must be a boolean`);
    }
  }

  // Ownership: an agent must never delete material it did not install.
  if (validatedRow.ownershipProvenance !== "tokentimer_installed") {
    return { eligible: false, reason: "ownership_unrecorded" };
  }
  if (bindingStillReferencesOldThumbprint) {
    return { eligible: false, reason: "binding_still_present" };
  }
  if (validatedRow.jobOrRollbackJournalRefs.some((entry) => entry.active)) {
    return { eligible: false, reason: "active_reference_present" };
  }
  if (keyContainerSharedWithSurvivor) {
    return { eligible: false, reason: "shared_key_container" };
  }
  if (!replacementPassesHandshakeNow) {
    return { eligible: false, reason: "replacement_handshake_failed" };
  }

  const deadline = computeCleanupDeadline({
    verifiedCutoverAt: validatedRow.verifiedCutoverAt,
    oldNotAfter: validatedRow.oldNotAfter,
    retentionHours,
  });
  const instant = now();
  if (instant.getTime() < deadline.getTime()) {
    return { eligible: false, reason: "deadline_not_reached" };
  }

  return { eligible: true };
}

/**
 * Runs one sweep pass over every persisted ledger row: for each row not
 * already `removed`, re-evaluates eligibility via a caller-supplied
 * `gatherContext` (the live facts evaluateEligibility needs), and either
 * calls the caller-supplied `performCleanup` and marks the row `removed`,
 * or persists the deferral reason and leaves the row for the next sweep.
 *
 * A blocked cleanup for one row is never treated as an error for the
 * sweep as a whole: decision 18 explicitly makes this the safe failure
 * mode ("a still-bound predecessor is the safe failure mode, not the
 * confidentiality-costing one"). Sweep-wide failures are reported per row
 * in the returned summary, never thrown, so one bad row cannot abort the
 * rest of the sweep.
 *
 * @param {object} input
 * @param {string} input.ledgerDir
 * @param {number} input.retentionHours validated `windows.supersededRetentionHours`.
 * @param {(row: object) => Promise<{
 *   bindingStillReferencesOldThumbprint: boolean,
 *   keyContainerSharedWithSurvivor: boolean,
 *   replacementPassesHandshakeNow: boolean,
 * }>} input.gatherContext supplies the live facts for one row.
 * @param {(row: object) => Promise<void>} input.performCleanup deletes the
 *   old certificate/key container from the store; throwing here defers the
 *   row (a failed delete must not be recorded as removed).
 * @param {() => Date} [input.now]
 * @returns {Promise<{
 *   removed: string[],
 *   deferred: { oldThumbprint: string, reason: string }[],
 *   deferredCountByReason: Record<string, number>,
 * }>}
 */
async function sweepLedger({ ledgerDir, retentionHours, gatherContext, performCleanup, now = () => new Date() }) {
  validateRetentionHours(retentionHours);
  const removed = [];
  const deferred = [];
  const deferredCountByReason = Object.fromEntries(DEFERRAL_REASONS.map((reason) => [reason, 0]));

  for (const oldThumbprint of listLedgerThumbprints(ledgerDir)) {
    const row = readLedgerRow(ledgerDir, oldThumbprint);
    if (row === null || row.lifecycleState === "removed") continue;

    const context = await gatherContext(row);
    const result = evaluateEligibility(row, { ...context, retentionHours, now });

    if (result.eligible) {
      try {
        await performCleanup(row);
      } catch (err) {
        // Eligibility held, but the actual delete failed (e.g. a
        // transient store/filesystem error): this is NOT one of decision
        // 18's six named deferral reasons (those gate ELIGIBILITY, not the
        // delete operation itself), so the row is marked `eligible` and
        // retried as a delete attempt on the next sweep, rather than
        // mislabeled under an unrelated deferral reason or silently
        // dropped. The error is intentionally not persisted into the
        // ledger row (rows carry cleanup-decision facts, not error logs);
        // a caller wanting to observe it should do so via its own logging
        // around performCleanup.
        writeLedgerRow(ledgerDir, { ...row, lifecycleState: "eligible", deferralReason: null });
        deferred.push({ oldThumbprint: row.oldThumbprint, reason: "cleanup_failed" });
        void err;
        continue;
      }
      writeLedgerRow(ledgerDir, { ...row, lifecycleState: "removed", deferralReason: null });
      removed.push(row.oldThumbprint);
      continue;
    }

    writeLedgerRow(ledgerDir, {
      ...row,
      lifecycleState: "deferred",
      deferralReason: result.reason,
    });
    deferred.push({ oldThumbprint: row.oldThumbprint, reason: result.reason });
    deferredCountByReason[result.reason] += 1;
  }

  return { removed, deferred, deferredCountByReason };
}

module.exports = {
  MIN_RETENTION_HOURS,
  MAX_RETENTION_HOURS,
  CLOCK_SKEW_GRACE_SECONDS,
  THUMBPRINT_PATTERN,
  CONTAINER_NAME_PATTERN,
  JOURNAL_REF_PATTERN,
  WINDOWS_STORE_NAME_PATTERN,
  OWNERSHIP_PROVENANCE_VALUES,
  LIFECYCLE_STATE_VALUES,
  DEFERRAL_REASONS,
  MAX_LEDGER_ROW_BYTES,
  validateRetentionHours,
  assertThumbprint,
  normalizeThumbprint,
  computeCleanupDeadline,
  isIsoDateString,
  validateLedgerRow,
  createLedgerRow,
  readLedgerRow,
  writeLedgerRow,
  listLedgerThumbprints,
  closeJournalReference,
  ledgerRowPath,
  evaluateEligibility,
  sweepLedger,
};


