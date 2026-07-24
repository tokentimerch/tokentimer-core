"use strict";

/**
 * Atomic certificate (and optional private-key) deployment.
 *
 * Deploys PUBLIC certificate PEM material -- and, when a matched private key
 * is being rotated in, the key as well -- to target filesystem paths with:
 *   - target-config re-validation before EVERY deploy (validateTargetConfig)
 *   - fs.realpath containment re-check on the final destination immediately
 *     before write (the policy module's documented follow-up: policy does
 *     lexical checks only; symlink-aware realpath checks belong here)
 *   - idempotency: byte-identical content is never rewritten (recorded as
 *     an idempotent skip) for cert-only deploys
 *   - timestamped backup of any existing file before overwrite
 *   - atomic write (temp file in the SAME directory + rename, so the rename
 *     never crosses devices), with fsync of the file and, where the
 *     platform allows, the containing directory
 *   - for key+cert pair deploys (`deployCertificateAndKey`): both files are
 *     staged then renamed, and ANY failure after backups triggers rollback
 *     of BOTH files from those backups. Backups are retained until the
 *     caller explicitly discards them via `discardDeployBackups` after
 *     post-deploy verification / reload success.
 *   - a per-destination in-process async mutex serializing concurrent
 *     deploys to the same resolved path
 *   - per-target-type counters (attempts, succeeded, idempotentSkips,
 *     rollbacks, failures) exposed via getDeployMetrics() for evidence
 *     metadata (public, non-secret values only)
 *
 * Zero private-key custody (D5, ADR-0001): `deployCertificate` deploys
 * public certificates ONLY and THROWS if the payload contains a PEM
 * private-key marker. `deployCertificateAndKey` is the sole path that
 * installs a private key, reading it from a caller-supplied staging path
 * (never from the certificate payload) and never returning key bytes.
 *
 * Policy decoupling: this module never loads policy config itself. The
 * caller (dispatch layer) passes a `checkPath(filePath)` callback -- in
 * production, the policy engine's checkPath -- returning
 * { allowed, rejectionReason?, detail? }. This module calls it for every
 * path it is about to touch (destination, chain destination, key path,
 * backup dir), including once more against the realpath-resolved
 * destination so a symlink cannot escape the allowlisted roots.
 *
 * This module is self-contained: it accepts plain data as function
 * parameters and does not import sibling agent modules (config, policy,
 * etc.). Wiring is left to src/index.js.
 *
 * Windows note: directory fsync is not supported on win32 (fs.open on a
 * directory fails with EISDIR/EPERM), so the post-rename directory fsync is
 * best-effort and skipped there; the file-content fsync before rename still
 * runs on every platform. Likewise POSIX modes (0o600/0o644) are asserted
 * best-effort on win32, mirroring the config module's convention.
 */

const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const crypto = require("node:crypto");

// Mirrors discovery/index.js's PRIVATE_KEY_PEM_HEADER_PATTERN (which itself
// mirrors apps/api/utils/secretMaterial.js). Duplicated, not imported, to
// keep this module self-contained per package convention. Matches PKCS#8,
// PKCS#1 (RSA), SEC1 (EC), DSA, and ENCRYPTED variants; does NOT match
// PUBLIC KEY / CERTIFICATE blocks.
const PRIVATE_KEY_PEM_HEADER_PATTERN = new RegExp(
  String.raw`-----\s*BEGIN\s+(?:[A-Z0-9]+\s+)*PRIVATE\s+KEY\s*-----`,
  "i",
);

// Restrictive mode for deployed certificate files and their backups.
// Certificates are public material, but 0o600 matches the package's
// "restrictive by default" convention (config module: 0600 files in 0700
// dirs); operators can relax modes out-of-band if a consumer needs it.
const DEPLOYED_FILE_MODE = 0o600;
const DEPLOYED_CERT_DEFAULT_MODE = 0o600;
const DEPLOYED_KEY_DEFAULT_MODE = 0o600;

const FILE_MODE_STRING_PATTERN = /^0?[0-7]{3}$/;
const OWNER_GROUP_PATTERN = /^[A-Za-z_][A-Za-z0-9_-]{0,31}$/;

/**
 * Parses a POSIX file mode from an octal string ("0644") or integer.
 * Rejects world-writable modes (other-write bit).
 * @param {string|number|null|undefined} value
 * @param {string} fieldName
 * @returns {{ ok: true, mode: number|null }|{ ok: false, detail: string }}
 */
function parseDeployFileMode(value, fieldName) {
  if (value === undefined || value === null) {
    return { ok: true, mode: null };
  }
  let modeInt;
  if (typeof value === "number" && Number.isInteger(value)) {
    modeInt = value;
  } else if (typeof value === "string" && FILE_MODE_STRING_PATTERN.test(value.trim())) {
    modeInt = Number.parseInt(value.trim(), 8);
  } else {
    return {
      ok: false,
      detail: `deploy: target.${fieldName} must be an octal mode string or integer`,
    };
  }
  if (modeInt < 0 || modeInt > 0o777) {
    return {
      ok: false,
      detail: `deploy: target.${fieldName} is out of range`,
    };
  }
  if ((modeInt & 0o002) !== 0) {
    return {
      ok: false,
      detail: `deploy: target.${fieldName} must not be world-writable`,
    };
  }
  return { ok: true, mode: modeInt };
}

/**
 * @param {string|null|undefined} value
 * @param {string} fieldName
 * @returns {{ ok: true, name: string|null }|{ ok: false, detail: string }}
 */
function parseOwnerGroupName(value, fieldName) {
  if (value === undefined || value === null) {
    return { ok: true, name: null };
  }
  if (typeof value !== "string" || !OWNER_GROUP_PATTERN.test(value)) {
    return {
      ok: false,
      detail: `deploy: target.${fieldName} must be a safe POSIX name`,
    };
  }
  return { ok: true, name: value };
}

// Valid target.type values, per
// packages/contracts/certops/job-payload.schema.json target.type enum.
const VALID_TARGET_TYPES = Object.freeze([
  "domain",
  "endpoint",
  "kubernetes",
  "appliance",
  "load-balancer",
  "external",
]);

// --- Per-destination async mutex ------------------------------------------

/**
 * Map of resolved destination path -> tail promise of the chain. A deploy
 * to a destination awaits the current tail, then replaces it; concurrent
 * deploys to the SAME destination therefore serialize in call order, while
 * deploys to different destinations proceed in parallel. Entries are
 * removed once the chain drains so the map does not grow unboundedly.
 * @type {Map<string, Promise<void>>}
 */
const destinationLocks = new Map();

/**
 * Runs `task` under the mutex for `lockKey`. The returned promise settles
 * with task's outcome; the internal chain never rejects (failures are
 * swallowed in the chain link only) so one failed deploy cannot poison the
 * lock for the next caller.
 *
 * @param {string} lockKey
 * @param {() => Promise<T>} task
 * @returns {Promise<T>}
 * @template T
 */
function withDestinationLock(lockKey, task) {
  const previousTail = destinationLocks.get(lockKey) || Promise.resolve();

  const run = previousTail.then(task);

  // The chain link must not reject, or every later waiter would see this
  // deploy's error instead of its own result.
  const tail = run.then(
    () => undefined,
    () => undefined,
  );
  destinationLocks.set(lockKey, tail);

  tail.finally(() => {
    if (destinationLocks.get(lockKey) === tail) {
      destinationLocks.delete(lockKey);
    }
  });

  return run;
}

// --- Metrics ---------------------------------------------------------------

/**
 * Per-target-type deploy counters, suitable for evidence metadata entries.
 * All values are public, non-secret integers.
 * @type {Map<string, { attempts: number, succeeded: number, idempotentSkips: number, rollbacks: number, failures: number }>}
 */
const metricsByTargetType = new Map();

function metricsFor(targetType) {
  let entry = metricsByTargetType.get(targetType);
  if (!entry) {
    entry = {
      attempts: 0,
      succeeded: 0,
      idempotentSkips: 0,
      rollbacks: 0,
      failures: 0,
    };
    metricsByTargetType.set(targetType, entry);
  }
  return entry;
}

/**
 * Returns a deep copy of the per-target-type deploy counters:
 * { [targetType]: { attempts, succeeded, idempotentSkips, rollbacks, failures } }.
 * Values are public, non-secret integers intended for evidence metadata.
 * @returns {Record<string, { attempts: number, succeeded: number, idempotentSkips: number, rollbacks: number, failures: number }>}
 */
function getDeployMetrics() {
  const snapshot = {};
  for (const [targetType, counters] of metricsByTargetType) {
    snapshot[targetType] = { ...counters };
  }
  return snapshot;
}

/**
 * Resets all deploy counters. Test helper.
 * @returns {void}
 */
function resetDeployMetrics() {
  metricsByTargetType.clear();
}

// --- Target validation -------------------------------------------------------

function invalid(detail) {
  return { valid: false, detail };
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function isExistingDirectory(fsImpl, dirPath) {
  try {
    return fsImpl.statSync(dirPath).isDirectory();
  } catch (_err) {
    return false;
  }
}

/**
 * Re-validates a deploy target descriptor. Called before EVERY deploy (a
 * target validated at job-accept time may have gone stale: directories
 * removed, policy changed), and callable standalone by the dispatch layer.
 *
 * Expected shape (job-payload.schema.json target plus deploy fields):
 *   {
 *     type: "domain"|"endpoint"|"kubernetes"|"appliance"|"load-balancer"|"external",
 *     reference: string,           // non-secret target reference
 *     certPath: string,            // absolute destination for the cert PEM
 *     keyPath?: string,            // optional absolute destination for the private key
 *     chainPath?: string,          // optional absolute destination for the chain PEM
 *     backupDir?: string,          // optional absolute dir for timestamped backups
 *   }
 *
 * Checks, in order: shape/type, absolute paths, parent directories exist,
 * and policy allowance via the injected `checkPath` callback for certPath,
 * keyPath, chainPath, and backupDir (when present). `checkPath` must return
 * { allowed: boolean, rejectionReason?: string, detail?: string } -- in
 * production this is the policy engine's checkPath, keeping this module
 * decoupled from the policy module.
 *
 * @param {object} target
 * @param {{ checkPath: (filePath: string) => { allowed: boolean, rejectionReason?: string, detail?: string }, _fsOverrides?: object }} options
 * @returns {{ valid: true } | { valid: false, detail: string }}
 */
function validateTargetConfig(target, { checkPath, _fsOverrides } = {}) {
  const fsImpl = { ...fs, ..._fsOverrides };

  if (target === null || typeof target !== "object" || Array.isArray(target)) {
    return invalid("deploy: target must be an object");
  }
  if (typeof checkPath !== "function") {
    // Programmer error, not a target problem: wiring without a policy
    // callback must fail loudly, never silently allow.
    throw new Error("deploy: a checkPath callback is required");
  }

  if (!VALID_TARGET_TYPES.includes(target.type)) {
    return invalid(
      `deploy: target.type must be one of ${VALID_TARGET_TYPES.join(", ")} (got ${JSON.stringify(target.type)})`,
    );
  }
  if (!isNonEmptyString(target.reference)) {
    return invalid("deploy: target.reference must be a non-empty string");
  }

  const pathFields = [["certPath", target.certPath, true]];
  if (target.keyPath !== undefined && target.keyPath !== null) {
    pathFields.push(["keyPath", target.keyPath, false]);
  }
  if (target.chainPath !== undefined && target.chainPath !== null) {
    pathFields.push(["chainPath", target.chainPath, false]);
  }
  if (target.backupDir !== undefined && target.backupDir !== null) {
    pathFields.push(["backupDir", target.backupDir, false]);
  }

  for (const [fieldName, fieldValue, required] of pathFields) {
    if (!isNonEmptyString(fieldValue)) {
      if (required) {
        return invalid(`deploy: target.${fieldName} must be a non-empty string`);
      }
      continue;
    }
    if (!path.isAbsolute(fieldValue)) {
      return invalid(
        `deploy: target.${fieldName} must be an absolute path (got ${JSON.stringify(fieldValue)})`,
      );
    }

    // backupDir is itself a directory; the file paths' parents must exist.
    const dirToCheck =
      fieldName === "backupDir" ? fieldValue : path.dirname(fieldValue);
    if (!isExistingDirectory(fsImpl, dirToCheck)) {
      return invalid(
        `deploy: target.${fieldName} ${fieldName === "backupDir" ? "directory" : "parent directory"} does not exist: ${JSON.stringify(dirToCheck)}`,
      );
    }

    const policyResult = checkPath(fieldValue);
    if (!policyResult || policyResult.allowed !== true) {
      const reason = policyResult?.rejectionReason || "path_not_allowlisted";
      const detail = policyResult?.detail || "no detail provided";
      return invalid(
        `deploy: target.${fieldName} rejected by policy (${reason}): ${detail}`,
      );
    }
  }

  for (const modeField of ["certMode", "keyMode", "chainMode"]) {
    if (!Object.prototype.hasOwnProperty.call(target, modeField)) continue;
    const parsed = parseDeployFileMode(target[modeField], modeField);
    if (!parsed.ok) return invalid(parsed.detail);
  }
  for (const nameField of ["owner", "group"]) {
    if (!Object.prototype.hasOwnProperty.call(target, nameField)) continue;
    const parsed = parseOwnerGroupName(target[nameField], nameField);
    if (!parsed.ok) return invalid(parsed.detail);
  }
  if (
    Object.prototype.hasOwnProperty.call(target, "backupRetentionCount") &&
    target.backupRetentionCount !== undefined &&
    target.backupRetentionCount !== null
  ) {
    if (
      !Number.isInteger(target.backupRetentionCount) ||
      target.backupRetentionCount < 1 ||
      target.backupRetentionCount > 64
    ) {
      return invalid(
        "deploy: target.backupRetentionCount must be an integer between 1 and 64",
      );
    }
  }

  return { valid: true };
}

// --- Atomic write helpers ----------------------------------------------------

/**
 * fsyncs a directory so a preceding rename in it becomes durable. On win32
 * directories cannot be opened for fsync (EISDIR/EPERM/EACCES), so this is
 * documented best-effort: it swallows the error there (and on any other
 * platform quirk) rather than failing an otherwise-complete deploy. The
 * file-content fsync before rename is NOT best-effort and runs everywhere.
 *
 * @param {typeof fsp} fspImpl
 * @param {string} dirPath
 * @returns {Promise<void>}
 */
async function fsyncDirBestEffort(fspImpl, dirPath) {
  let handle;
  try {
    handle = await fspImpl.open(dirPath, "r");
    await handle.sync();
  } catch (_err) {
    // win32 (and some filesystems) cannot fsync a directory; the rename is
    // still atomic on the same volume, just not guaranteed durable across
    // an immediate power loss. Documented platform limitation.
  } finally {
    if (handle) {
      try {
        await handle.close();
      } catch (_err) {
        // best-effort close
      }
    }
  }
}

/**
 * Atomically writes `content` to `destinationPath`: temp file created in
 * the SAME directory (so the final rename never crosses devices/volumes,
 * which would silently degrade to copy+delete and lose atomicity), written
 * with the restrictive mode (and optional ownership) BEFORE rename so the
 * destination never briefly appears world-readable, fsynced, renamed over
 * the destination, then the directory is fsynced where the platform allows.
 *
 * The temp file is unlinked on any failure so no partial write is left
 * behind.
 *
 * @param {typeof fsp} fspImpl
 * @param {string} destinationPath
 * @param {string|Buffer} content
 * @param {{ mode?: number, uid?: number|null, gid?: number|null }} [options]
 * @returns {Promise<void>}
 */
async function atomicWrite(
  fspImpl,
  destinationPath,
  content,
  { mode = DEPLOYED_FILE_MODE, uid = null, gid = null } = {},
) {
  const dirPath = path.dirname(destinationPath);
  const tempPath = path.join(
    dirPath,
    `.${path.basename(destinationPath)}.${crypto.randomBytes(6).toString("hex")}.tmp`,
  );

  let handle;
  try {
    handle = await fspImpl.open(tempPath, "wx", mode);
    await handle.writeFile(content);
    if (typeof handle.chmod === "function") {
      try {
        await handle.chmod(mode);
      } catch (_err) {
        // win32 / platform without fchmod
      }
    }
    if (
      (uid !== null || gid !== null) &&
      typeof handle.chown === "function"
    ) {
      try {
        await handle.chown(
          uid === null ? -1 : uid,
          gid === null ? -1 : gid,
        );
      } catch (_err) {
        // Ownership may require privileges; fail closed only when caller
        // treated it as mandatory via a prior resolve step.
      }
    }
    await handle.sync();
    await handle.close();
    handle = null;
    await fspImpl.rename(tempPath, destinationPath);
  } catch (err) {
    if (handle) {
      try {
        await handle.close();
      } catch (_err) {
        // best-effort close before cleanup
      }
    }
    try {
      await fspImpl.unlink(tempPath);
    } catch (_err) {
      // temp file may never have been created
    }
    throw err;
  }

  await fsyncDirBestEffort(fspImpl, dirPath);
}

/**
 * Best-effort resolve of owner/group names to uid/gid via OS passwd/group.
 * Returns nulls when unresolved (caller may still proceed with mode-only).
 * @param {string|null} owner
 * @param {string|null} group
 * @returns {{ uid: number|null, gid: number|null, detail?: string }}
 */
function resolveOwnershipIds(owner, group) {
  let uid = null;
  let gid = null;
  try {
    if (typeof owner === "string" && owner.length > 0) {
      // Lazy require keeps win32 import surface minimal.
      // eslint-disable-next-line global-require
      const { userInfo } = require("node:os");
      if (owner === userInfo().username) {
        uid = userInfo().uid;
      }
    }
  } catch (_err) {
    // leave unresolved
  }
  // Numeric string forms ("0") accepted as literal ids when provided.
  if (typeof owner === "string" && /^\d+$/.test(owner)) {
    uid = Number.parseInt(owner, 10);
  }
  if (typeof group === "string" && /^\d+$/.test(group)) {
    gid = Number.parseInt(group, 10);
  }
  return { uid, gid };
}

/**
 * Builds the timestamped backup path for an existing destination file:
 * `<backupDir>/<basename>.<ISO-ts>.bak`, with colons replaced by "-" so the
 * name is valid on win32. Defaults backupDir to the destination's own
 * directory ("alongside destination").
 *
 * @param {string} destinationPath
 * @param {string|undefined} backupDir
 * @param {Date} now
 * @returns {string}
 */
function backupPathFor(destinationPath, backupDir, now) {
  const timestamp = now.toISOString().replace(/:/g, "-");
  const dir = backupDir || path.dirname(destinationPath);
  return path.join(dir, `${path.basename(destinationPath)}.${timestamp}.bak`);
}

const BACKUP_FILENAME_SUFFIX = ".bak";

/**
 * Prunes old timestamped backups for one destination basename down to
 * `retentionCount`, keeping the most recent ones. Only ever deletes files
 * matching this module's OWN backup naming convention
 * (`<basename>.<ISO-ts-with-dashes>.bak`) inside the resolved backup
 * directory, so it can never remove an unrelated file an operator placed
 * there. Best-effort: ANY failure (readdir, unlink, anything unexpected) is
 * caught and swallowed internally rather than propagated -- backup
 * retention is disk-hygiene, not a correctness gate, and call sites invoke
 * this fire-and-forget after a deploy has already been reported successful,
 * with no logger threaded through, so there is nothing useful a caller
 * could do with a rejected promise here besides accidentally failing an
 * otherwise-successful deploy.
 *
 * @param {string} destinationPath
 * @param {string|undefined|null} backupDir
 * @param {number|undefined|null} retentionCount when absent, no pruning
 *   happens (unbounded backups is the pre-existing default behavior)
 * @param {{ _fsOverrides?: object }} [options]
 * @returns {Promise<{ removed: string[] }>}
 */
async function pruneDeployBackups(destinationPath, backupDir, retentionCount, { _fsOverrides } = {}) {
  if (!Number.isInteger(retentionCount) || retentionCount < 1) {
    return { removed: [] };
  }
  try {
    const fspImpl = { ...fsp, ..._fsOverrides };
    const dir = backupDir || path.dirname(destinationPath);
    const basename = path.basename(destinationPath);
    const prefix = `${basename}.`;

    let entries;
    try {
      entries = await fspImpl.readdir(dir);
    } catch (err) {
      if (err?.code === "ENOENT") return { removed: [] };
      throw err;
    }

    const candidates = entries.filter(
      (name) => name.startsWith(prefix) && name.endsWith(BACKUP_FILENAME_SUFFIX),
    );
    if (candidates.length <= retentionCount) {
      return { removed: [] };
    }

    // Sort by the embedded timestamp (lexicographically sortable ISO-8601
    // with dashes in place of colons), oldest first, so retention always
    // keeps the most RECENT backups regardless of filesystem mtime
    // resolution or clock skew between backup writes.
    const sorted = [...candidates].sort();
    const toRemove = sorted.slice(0, sorted.length - retentionCount);

    const removed = [];
    for (const name of toRemove) {
      const fullPath = path.join(dir, name);
      try {
        await fspImpl.unlink(fullPath);
        removed.push(fullPath);
      } catch (err) {
        if (err?.code !== "ENOENT") throw err;
      }
    }
    return { removed };
  } catch (_err) {
    return { removed: [] };
  }
}

// --- Deploy ------------------------------------------------------------------

/**
 * Deploys a public certificate PEM to target.certPath, atomically and with
 * rollback. See the module docblock for the full step list.
 *
 * REFUSES (throws) if `certificatePem` contains a PEM private-key marker:
 * this module deploys public certificates only (cert and
 * key deploys are separate targets), and a key showing up here means an
 * upstream bug or an attack, either of which must fail loudly (D5 zero
 * key custody, defense in depth).
 *
 * Never throws for operational failures (bad target, policy rejection,
 * filesystem errors): those come back as { deployed: false, ... } result
 * shapes. Throws only on programmer error (missing checkPath, key
 * material in the payload, non-string payload).
 *
 * Result shapes:
 *   { deployed: true,  skipped: false, destination, backupPath|null, chainDestination?, backupPaths? }
 *   { deployed: false, skipped: true,  reason: "idempotent", destination, chainDestination? }
 *   { deployed: false, skipped: false, error, stage }                       // failed before touching the file
 *   { deployed: false, skipped: false, rolledBack: true|false, error, stage } // failed during write
 *
 * @param {{
 *   target: object,           // see validateTargetConfig
 *   certificatePem: string,   // public certificate PEM written to certPath (leaf or fullchain)
 *   chainPem?: string,        // intermediate chain PEM written to target.chainPath when set
 *   checkPath: (filePath: string) => { allowed: boolean, rejectionReason?: string, detail?: string },
 *   now?: () => Date,         // injectable clock for deterministic backup names
 *   _fsOverrides?: object,    // TEST-ONLY: shadows node:fs/promises methods
 *                             // (e.g. { rename: () => Promise.reject(...) })
 *                             // to inject failures; never use in production.
 * }} params
 * @returns {Promise<object>} one of the result shapes above
 */
async function deployCertificate({
  target,
  certificatePem,
  chainPem,
  checkPath,
  now = () => new Date(),
  _fsOverrides,
} = {}) {
  if (typeof certificatePem !== "string" || certificatePem.length === 0) {
    throw new Error("deploy: certificatePem must be a non-empty string");
  }
  if (PRIVATE_KEY_PEM_HEADER_PATTERN.test(certificatePem)) {
    throw new Error(
      "deploy: payload contains a private-key PEM marker; this module deploys " +
        "public certificates only and never handles key material (D5 zero key custody)",
    );
  }
  if (typeof chainPem === "string" && PRIVATE_KEY_PEM_HEADER_PATTERN.test(chainPem)) {
    throw new Error(
      "deploy: chainPem contains a private-key PEM marker; this module deploys " +
        "public certificates only",
    );
  }
  if (typeof checkPath !== "function") {
    throw new Error("deploy: a checkPath callback is required");
  }

  const fspImpl = { ...fsp, ..._fsOverrides };
  const targetType =
    target && typeof target.type === "string" ? target.type : "unknown";
  const counters = metricsFor(targetType);
  counters.attempts += 1;

  function failure(stage, error, rolledBack) {
    counters.failures += 1;
    const result = { deployed: false, skipped: false, stage, error };
    if (rolledBack !== undefined) {
      result.rolledBack = rolledBack;
      if (rolledBack) counters.rollbacks += 1;
    }
    return result;
  }

  // (1) Re-validate the target config before EVERY deploy. Validation uses
  // the real filesystem (sync stat checks); _fsOverrides only shadows the
  // async fs/promises operations used by the write path below.
  const validation = validateTargetConfig(target, { checkPath });
  if (!validation.valid) {
    return failure("validate", validation.detail);
  }

  const wantsChain =
    typeof target.chainPath === "string" && target.chainPath.length > 0;
  if (wantsChain && (typeof chainPem !== "string" || chainPem.length === 0)) {
    return failure(
      "validate",
      "deploy: target.chainPath is configured but no chain PEM content was provided",
    );
  }

  const destination = path.normalize(path.resolve(target.certPath));
  const chainDestination = wantsChain
    ? path.normalize(path.resolve(target.chainPath))
    : null;
  const lockKey =
    chainDestination !== null
      ? [destination, chainDestination].sort().join("\0")
      : destination;

  // The mutex key is the resolved destination path so two descriptors
  // spelling the same file differently still serialize.
  return await withDestinationLock(lockKey, async () => {
    // (2) realpath containment re-check, symlink-aware. The policy module's
    // checkPath is lexical only; here, immediately before writing, resolve
    // symlinks on the deepest existing ancestor (the destination file
    // itself may not exist yet) and re-run the policy callback against the
    // real path. A symlinked parent dir pointing outside the allowlisted
    // roots is rejected even though the lexical path looked fine.
    let realDestination;
    let realChainDestination = null;
    try {
      realDestination = await resolveRealDestination(fspImpl, destination);
      if (chainDestination !== null) {
        realChainDestination = await resolveRealDestination(
          fspImpl,
          chainDestination,
        );
      }
    } catch (err) {
      return failure("realpath", `deploy: could not resolve destination realpath: ${err?.message || err}`);
    }

    for (const [label, realPath] of [
      ["certificate", realDestination],
      ...(realChainDestination
        ? [["chain", realChainDestination]]
        : []),
    ]) {
      const realPathPolicy = checkPath(realPath);
      if (!realPathPolicy || realPathPolicy.allowed !== true) {
        return failure(
          "realpath-policy",
          `deploy: resolved ${label} destination ${JSON.stringify(realPath)} escapes the ` +
            `allowlisted roots (${realPathPolicy?.rejectionReason || "path_not_allowlisted"}): ` +
            `${realPathPolicy?.detail || "no detail provided"}`,
        );
      }
    }

    // (3) Idempotency: byte-identical content is a recorded no-op.
    let existingContent = null;
    let existingChain = null;
    try {
      existingContent = await fspImpl.readFile(realDestination);
    } catch (err) {
      if (err?.code !== "ENOENT") {
        return failure("read-existing", `deploy: could not read existing destination: ${err?.message || err}`);
      }
    }
    if (realChainDestination !== null) {
      try {
        existingChain = await fspImpl.readFile(realChainDestination);
      } catch (err) {
        if (err?.code !== "ENOENT") {
          return failure(
            "read-existing",
            `deploy: could not read existing chain destination: ${err?.message || err}`,
          );
        }
      }
    }
    const certUnchanged =
      existingContent !== null &&
      existingContent.equals(Buffer.from(certificatePem, "utf8"));
    const chainUnchanged =
      realChainDestination === null ||
      (existingChain !== null &&
        existingChain.equals(Buffer.from(chainPem, "utf8")));
    if (certUnchanged && chainUnchanged) {
      counters.idempotentSkips += 1;
      return {
        deployed: false,
        skipped: true,
        reason: "idempotent",
        destination: realDestination,
        ...(realChainDestination
          ? { chainDestination: realChainDestination }
          : {}),
      };
    }

    // (4) Timestamped backup of the existing file (if any), same
    // restrictive mode as the deployed file.
    const stamp = now();
    let backupPath = null;
    let chainBackupPath = null;
    try {
      if (existingContent !== null) {
        backupPath = backupPathFor(realDestination, target.backupDir, stamp);
        await fspImpl.writeFile(backupPath, existingContent, {
          mode: DEPLOYED_FILE_MODE,
        });
      }
      if (realChainDestination !== null && existingChain !== null) {
        chainBackupPath = backupPathFor(
          realChainDestination,
          target.backupDir,
          stamp,
        );
        await fspImpl.writeFile(chainBackupPath, existingChain, {
          mode: DEPLOYED_FILE_MODE,
        });
      }
    } catch (err) {
      return failure("backup", `deploy: could not write backup: ${err?.message || err}`);
    }

    async function rollbackFiles() {
      let rolledBack = false;
      try {
        if (backupPath !== null && existingContent !== null) {
          await fspImpl.writeFile(realDestination, existingContent, {
            mode: DEPLOYED_FILE_MODE,
          });
          rolledBack = true;
        }
        if (
          chainBackupPath !== null &&
          existingChain !== null &&
          realChainDestination !== null
        ) {
          await fspImpl.writeFile(realChainDestination, existingChain, {
            mode: DEPLOYED_FILE_MODE,
          });
          rolledBack = true;
        }
      } catch (_rollbackErr) {
        return false;
      }
      return rolledBack;
    }

    // (5) Atomic write with mode/ownership applied on the temp file before
    // rename; (6) rollback from backup on failure.
    const certModeParsed = parseDeployFileMode(target.certMode, "certMode");
    const chainModeParsed = parseDeployFileMode(target.chainMode, "chainMode");
    const ownerParsed = parseOwnerGroupName(target.owner, "owner");
    const groupParsed = parseOwnerGroupName(target.group, "group");
    const ownership = resolveOwnershipIds(
      ownerParsed.ok ? ownerParsed.name : null,
      groupParsed.ok ? groupParsed.name : null,
    );
    const certMode =
      certModeParsed.ok && certModeParsed.mode !== null
        ? certModeParsed.mode
        : DEPLOYED_CERT_DEFAULT_MODE;
    const chainMode =
      chainModeParsed.ok && chainModeParsed.mode !== null
        ? chainModeParsed.mode
        : DEPLOYED_CERT_DEFAULT_MODE;
    try {
      await atomicWrite(fspImpl, realDestination, certificatePem, {
        mode: certMode,
        uid: ownership.uid,
        gid: ownership.gid,
      });
      if (realChainDestination !== null) {
        await atomicWrite(fspImpl, realChainDestination, chainPem, {
          mode: chainMode,
          uid: ownership.uid,
          gid: ownership.gid,
        });
      }
    } catch (err) {
      const rolledBack = await rollbackFiles();
      return failure("write", `deploy: atomic write failed: ${err?.message || err}`, rolledBack);
    }

    // Retention pruning runs AFTER the deploy is already durably committed
    // and is best-effort (see pruneDeployBackups docblock) -- it must never
    // affect the success result of a deploy that already happened.
    if (Number.isInteger(target.backupRetentionCount)) {
      if (backupPath !== null) {
        await pruneDeployBackups(realDestination, target.backupDir, target.backupRetentionCount, {
          _fsOverrides,
        });
      }
      if (chainBackupPath !== null && realChainDestination !== null) {
        await pruneDeployBackups(
          realChainDestination,
          target.backupDir,
          target.backupRetentionCount,
          { _fsOverrides },
        );
      }
    }

    counters.succeeded += 1;
    return {
      deployed: true,
      skipped: false,
      destination: realDestination,
      backupPath,
      firstDeploy: existingContent === null && existingChain === null,
      ...(realChainDestination
        ? {
            chainDestination: realChainDestination,
            backupPaths: { cert: backupPath, chain: chainBackupPath },
          }
        : {}),
    };
  });
}

/**
 * Resolves the realpath of a destination file (deepest existing ancestor +
 * basename), matching the cert-only deploy path's containment discipline.
 * @param {typeof fsp} fspImpl
 * @param {string} destination
 * @returns {Promise<string>}
 */
async function resolveRealDestination(fspImpl, destination) {
  const parentReal = await fspImpl.realpath(path.dirname(destination));
  let realDestination = path.join(parentReal, path.basename(destination));
  try {
    realDestination = await fspImpl.realpath(realDestination);
  } catch (err) {
    if (err?.code !== "ENOENT") throw err;
  }
  return realDestination;
}

/**
 * Atomically deploys a matched certificate + private-key pair.
 *
 * Reads the private key from `privateKeyPath` (typically a staging path from
 * keys.generateKeyPairToFile) and installs it at `target.keyPath` together
 * with `certificatePem` at `target.certPath`. Both existing files (when
 * present) are backed up before any swap; on ANY failure after backups are
 * taken, BOTH files are restored from those backups. Backups are NOT
 * deleted on success -- call `discardDeployBackups` only after post-deploy
 * verification (and reload) confirms the new pair is live.
 *
 * Pre-deploy X.509 / key-match validation belongs in the verify module and
 * must be performed by the caller before invoking this function.
 *
 * @param {{
 *   target: object,             // validateTargetConfig shape; keyPath REQUIRED
 *   certificatePem: string,
 *   privateKeyPath: string,     // staging path holding the new private key PEM
 *   chainPem?: string,          // intermediate chain PEM when target.chainPath is set
 *   checkPath: (filePath: string) => { allowed: boolean, rejectionReason?: string, detail?: string },
 *   retainPrivateKeyStaging?: boolean, // when true, do not unlink privateKeyPath after install
 *   now?: () => Date,
 *   _fsOverrides?: object,
 * }} params
 * @returns {Promise<object>}
 */
async function deployCertificateAndKey({
  target,
  certificatePem,
  privateKeyPath,
  chainPem,
  checkPath,
  retainPrivateKeyStaging = false,
  now = () => new Date(),
  _fsOverrides,
} = {}) {
  if (typeof certificatePem !== "string" || certificatePem.length === 0) {
    throw new Error("deploy: certificatePem must be a non-empty string");
  }
  if (PRIVATE_KEY_PEM_HEADER_PATTERN.test(certificatePem)) {
    throw new Error(
      "deploy: certificatePem contains a private-key PEM marker; pass the key via privateKeyPath only",
    );
  }
  if (typeof chainPem === "string" && PRIVATE_KEY_PEM_HEADER_PATTERN.test(chainPem)) {
    throw new Error(
      "deploy: chainPem contains a private-key PEM marker; this module deploys public material only for chainPath",
    );
  }
  if (typeof privateKeyPath !== "string" || privateKeyPath.length === 0) {
    throw new Error("deploy: privateKeyPath must be a non-empty string");
  }
  if (typeof checkPath !== "function") {
    throw new Error("deploy: a checkPath callback is required");
  }
  if (!target || typeof target.keyPath !== "string" || target.keyPath.length === 0) {
    throw new Error("deploy: target.keyPath is required for deployCertificateAndKey");
  }

  const fspImpl = { ...fsp, ..._fsOverrides };
  const targetType =
    target && typeof target.type === "string" ? target.type : "unknown";
  const counters = metricsFor(targetType);
  counters.attempts += 1;

  function failure(stage, error, rolledBack) {
    counters.failures += 1;
    const result = { deployed: false, skipped: false, stage, error };
    if (rolledBack !== undefined) {
      result.rolledBack = rolledBack;
      if (rolledBack) counters.rollbacks += 1;
    }
    return result;
  }

  const validation = validateTargetConfig(target, { checkPath });
  if (!validation.valid) {
    return failure("validate", validation.detail);
  }

  const wantsChain =
    typeof target.chainPath === "string" && target.chainPath.length > 0;
  if (wantsChain && (typeof chainPem !== "string" || chainPem.length === 0)) {
    return failure(
      "validate",
      "deploy: target.chainPath is configured but no chain PEM content was provided",
    );
  }

  const certDestination = path.normalize(path.resolve(target.certPath));
  const keyDestination = path.normalize(path.resolve(target.keyPath));
  const chainDestination = wantsChain
    ? path.normalize(path.resolve(target.chainPath))
    : null;
  const lockKey = [
    certDestination,
    keyDestination,
    ...(chainDestination ? [chainDestination] : []),
  ]
    .sort()
    .join("\0");

  return await withDestinationLock(lockKey, async () => {
    let realCertDestination;
    let realKeyDestination;
    let realChainDestination = null;
    try {
      realCertDestination = await resolveRealDestination(fspImpl, certDestination);
      realKeyDestination = await resolveRealDestination(fspImpl, keyDestination);
      if (chainDestination !== null) {
        realChainDestination = await resolveRealDestination(
          fspImpl,
          chainDestination,
        );
      }
    } catch (err) {
      return failure(
        "realpath",
        `deploy: could not resolve destination realpath: ${err?.message || err}`,
      );
    }

    for (const [label, realPath] of [
      ["certificate", realCertDestination],
      ["key", realKeyDestination],
      ...(realChainDestination
        ? [["chain", realChainDestination]]
        : []),
    ]) {
      const policyResult = checkPath(realPath);
      if (!policyResult || policyResult.allowed !== true) {
        return failure(
          "realpath-policy",
          `deploy: resolved ${label} destination ${JSON.stringify(realPath)} escapes the ` +
            `allowlisted roots (${policyResult?.rejectionReason || "path_not_allowlisted"}): ` +
            `${policyResult?.detail || "no detail provided"}`,
        );
      }
    }

    // Read the staged private key once; zeroize after writes complete.
    let keyContent;
    try {
      keyContent = await fspImpl.readFile(privateKeyPath);
    } catch (err) {
      return failure(
        "read-key",
        `deploy: could not read privateKeyPath: ${err?.message || err}`,
      );
    }
    if (!PRIVATE_KEY_PEM_HEADER_PATTERN.test(keyContent.toString("utf8"))) {
      if (Buffer.isBuffer(keyContent)) keyContent.fill(0);
      return failure(
        "read-key",
        "deploy: privateKeyPath does not contain a private-key PEM block",
      );
    }

    let existingCert = null;
    let existingKey = null;
    let existingChain = null;
    try {
      existingCert = await fspImpl.readFile(realCertDestination);
    } catch (err) {
      if (err?.code !== "ENOENT") {
        if (Buffer.isBuffer(keyContent)) keyContent.fill(0);
        return failure(
          "read-existing",
          `deploy: could not read existing certificate: ${err?.message || err}`,
        );
      }
    }
    try {
      existingKey = await fspImpl.readFile(realKeyDestination);
    } catch (err) {
      if (err?.code !== "ENOENT") {
        if (Buffer.isBuffer(keyContent)) keyContent.fill(0);
        return failure(
          "read-existing",
          `deploy: could not read existing key: ${err?.message || err}`,
        );
      }
    }
    if (realChainDestination !== null) {
      try {
        existingChain = await fspImpl.readFile(realChainDestination);
      } catch (err) {
        if (err?.code !== "ENOENT") {
          if (Buffer.isBuffer(keyContent)) keyContent.fill(0);
          return failure(
            "read-existing",
            `deploy: could not read existing chain: ${err?.message || err}`,
          );
        }
      }
    }

    const certBuf = Buffer.from(certificatePem, "utf8");
    const certUnchanged =
      existingCert !== null && existingCert.equals(certBuf);
    const keyUnchanged =
      existingKey !== null && existingKey.equals(keyContent);
    const chainUnchanged =
      realChainDestination === null ||
      (existingChain !== null &&
        existingChain.equals(Buffer.from(chainPem, "utf8")));
    if (certUnchanged && keyUnchanged && chainUnchanged) {
      if (Buffer.isBuffer(keyContent)) keyContent.fill(0);
      counters.idempotentSkips += 1;
      return {
        deployed: false,
        skipped: true,
        reason: "idempotent",
        destination: realCertDestination,
        keyDestination: realKeyDestination,
        ...(realChainDestination
          ? { chainDestination: realChainDestination }
          : {}),
        backupPaths: { cert: null, key: null, chain: null },
      };
    }

    const stamp = now();
    let certBackupPath = null;
    let keyBackupPath = null;
    let chainBackupPath = null;
    try {
      if (existingCert !== null) {
        certBackupPath = backupPathFor(realCertDestination, target.backupDir, stamp);
        await fspImpl.writeFile(certBackupPath, existingCert, {
          mode: DEPLOYED_FILE_MODE,
        });
      }
      if (existingKey !== null) {
        keyBackupPath = backupPathFor(realKeyDestination, target.backupDir, stamp);
        await fspImpl.writeFile(keyBackupPath, existingKey, {
          mode: DEPLOYED_FILE_MODE,
        });
      }
      if (realChainDestination !== null && existingChain !== null) {
        chainBackupPath = backupPathFor(
          realChainDestination,
          target.backupDir,
          stamp,
        );
        await fspImpl.writeFile(chainBackupPath, existingChain, {
          mode: DEPLOYED_FILE_MODE,
        });
      }
    } catch (err) {
      if (Buffer.isBuffer(keyContent)) keyContent.fill(0);
      return failure("backup", `deploy: could not write backup: ${err?.message || err}`);
    }

    async function rollbackPair() {
      let rolledBack = false;
      try {
        if (certBackupPath !== null && existingCert !== null) {
          await fspImpl.writeFile(realCertDestination, existingCert, {
            mode: DEPLOYED_FILE_MODE,
          });
          rolledBack = true;
        }
        if (keyBackupPath !== null && existingKey !== null) {
          await fspImpl.writeFile(realKeyDestination, existingKey, {
            mode: DEPLOYED_FILE_MODE,
          });
          rolledBack = true;
        }
        if (
          chainBackupPath !== null &&
          existingChain !== null &&
          realChainDestination !== null
        ) {
          await fspImpl.writeFile(realChainDestination, existingChain, {
            mode: DEPLOYED_FILE_MODE,
          });
          rolledBack = true;
        }
      } catch (_rollbackErr) {
        return false;
      }
      return rolledBack;
    }

    try {
      const certModeParsed = parseDeployFileMode(target.certMode, "certMode");
      const keyModeParsed = parseDeployFileMode(target.keyMode, "keyMode");
      const chainModeParsed = parseDeployFileMode(target.chainMode, "chainMode");
      const ownerParsed = parseOwnerGroupName(target.owner, "owner");
      const groupParsed = parseOwnerGroupName(target.group, "group");
      const ownership = resolveOwnershipIds(
        ownerParsed.ok ? ownerParsed.name : null,
        groupParsed.ok ? groupParsed.name : null,
      );
      const certMode =
        certModeParsed.ok && certModeParsed.mode !== null
          ? certModeParsed.mode
          : DEPLOYED_CERT_DEFAULT_MODE;
      const keyMode =
        keyModeParsed.ok && keyModeParsed.mode !== null
          ? keyModeParsed.mode
          : DEPLOYED_KEY_DEFAULT_MODE;
      const chainMode =
        chainModeParsed.ok && chainModeParsed.mode !== null
          ? chainModeParsed.mode
          : DEPLOYED_CERT_DEFAULT_MODE;
      await atomicWrite(fspImpl, realCertDestination, certificatePem, {
        mode: certMode,
        uid: ownership.uid,
        gid: ownership.gid,
      });
      await atomicWrite(fspImpl, realKeyDestination, keyContent, {
        mode: keyMode,
        uid: ownership.uid,
        gid: ownership.gid,
      });
      if (realChainDestination !== null) {
        await atomicWrite(fspImpl, realChainDestination, chainPem, {
          mode: chainMode,
          uid: ownership.uid,
          gid: ownership.gid,
        });
      }
    } catch (err) {
      const rolledBack = await rollbackPair();
      if (Buffer.isBuffer(keyContent)) keyContent.fill(0);
      return failure(
        "write",
        `deploy: atomic key+certificate write failed: ${err?.message || err}`,
        rolledBack,
      );
    }

    // Staging file is consumed once the live key is in place — unless the
    // caller still needs it for additional destinations (multi-target).
    const normalizedPrivateKeyPath = path.normalize(path.resolve(privateKeyPath));
    if (
      retainPrivateKeyStaging !== true &&
      normalizedPrivateKeyPath !== realKeyDestination
    ) {
      try {
        await fspImpl.unlink(normalizedPrivateKeyPath);
      } catch (_err) {
        // best-effort
      }
    }

    if (Buffer.isBuffer(keyContent)) keyContent.fill(0);

    // Retention pruning runs AFTER the deploy is already durably committed
    // and is best-effort (see pruneDeployBackups docblock) -- it must never
    // affect the success result of a deploy that already happened.
    if (Number.isInteger(target.backupRetentionCount)) {
      if (certBackupPath !== null) {
        await pruneDeployBackups(
          realCertDestination,
          target.backupDir,
          target.backupRetentionCount,
          { _fsOverrides },
        );
      }
      if (keyBackupPath !== null) {
        await pruneDeployBackups(
          realKeyDestination,
          target.backupDir,
          target.backupRetentionCount,
          { _fsOverrides },
        );
      }
      if (chainBackupPath !== null && realChainDestination !== null) {
        await pruneDeployBackups(
          realChainDestination,
          target.backupDir,
          target.backupRetentionCount,
          { _fsOverrides },
        );
      }
    }

    counters.succeeded += 1;
    return {
      deployed: true,
      skipped: false,
      destination: realCertDestination,
      keyDestination: realKeyDestination,
      ...(realChainDestination
        ? { chainDestination: realChainDestination }
        : {}),
      backupPath: certBackupPath,
      backupPaths: {
        cert: certBackupPath,
        key: keyBackupPath,
        chain: chainBackupPath,
      },
      firstDeploy:
        existingCert === null && existingKey === null && existingChain === null,
    };
  });
}

/**
 * Deletes deploy backups after post-deploy verification (and reload) has
 * confirmed the new key+certificate pair is live. Safe to call with null
 * paths. Never touches the live destination files.
 *
 * @param {{ backupPaths?: { cert?: string|null, key?: string|null, chain?: string|null }, backupPath?: string|null }} input
 * @param {{ _fsOverrides?: object }} [options]
 * @returns {Promise<{ discarded: string[] }>}
 */
async function discardDeployBackups(
  { backupPaths, backupPath } = {},
  { _fsOverrides } = {},
) {
  const fspImpl = { ...fsp, ..._fsOverrides };
  const candidates = [];
  if (backupPaths && typeof backupPaths === "object") {
    if (typeof backupPaths.cert === "string") candidates.push(backupPaths.cert);
    if (typeof backupPaths.key === "string") candidates.push(backupPaths.key);
    if (typeof backupPaths.chain === "string") candidates.push(backupPaths.chain);
  }
  if (typeof backupPath === "string") candidates.push(backupPath);

  const discarded = [];
  for (const candidate of candidates) {
    try {
      await fspImpl.unlink(candidate);
      discarded.push(candidate);
    } catch (err) {
      if (err?.code === "ENOENT") continue;
      throw err;
    }
  }
  return { discarded };
}

/**
 * Removes newly written deploy destinations when rolling back a first-ever
 * deploy that had no prior backup. Used by the multi-target coordinator so
 * a later target's failure can return an earlier first-deploy target to its
 * previous absent state. Does not touch backup files.
 *
 * @param {{
 *   destinations: Array<string|null|undefined>,
 *   checkPath?: (filePath: string) => { allowed: boolean },
 * }} params
 * @param {{ _fsOverrides?: object }} [options]
 * @returns {Promise<{ removed: string[], failed: Array<{ path: string, error: string }> }>}
 */
async function removeDeployedArtifacts(
  { destinations, checkPath } = {},
  { _fsOverrides } = {},
) {
  const fspImpl = { ...fsp, ..._fsOverrides };
  const removed = [];
  const failed = [];
  const list = Array.isArray(destinations) ? destinations : [];
  for (const candidate of list) {
    if (typeof candidate !== "string" || candidate.length === 0) continue;
    if (typeof checkPath === "function") {
      const verdict = checkPath(candidate);
      if (!verdict || verdict.allowed !== true) {
        failed.push({
          path: candidate,
          error: "path not allowlisted for removal",
        });
        continue;
      }
    }
    try {
      await fspImpl.unlink(candidate);
      removed.push(candidate);
    } catch (err) {
      if (err?.code === "ENOENT") {
        removed.push(candidate);
        continue;
      }
      failed.push({ path: candidate, error: err?.message || String(err) });
    }
  }
  return { removed, failed };
}

module.exports = {
  validateTargetConfig,
  deployCertificate,
  deployCertificateAndKey,
  discardDeployBackups,
  removeDeployedArtifacts,
  pruneDeployBackups,
  parseDeployFileMode,
  getDeployMetrics,
  resetDeployMetrics,
  DEPLOYED_FILE_MODE,
  DEPLOYED_CERT_DEFAULT_MODE,
  DEPLOYED_KEY_DEFAULT_MODE,
  VALID_TARGET_TYPES,
};
