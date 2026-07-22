"use strict";

/**
 * Atomic certificate deployment (CertOps M5).
 *
 * Deploys PUBLIC certificate PEM material to a target filesystem path with:
 *   - target-config re-validation before EVERY deploy (validateTargetConfig)
 *   - fs.realpath containment re-check on the final destination immediately
 *     before write (the policy module's documented follow-up: policy does
 *     lexical checks only; symlink-aware realpath checks belong here)
 *   - idempotency: byte-identical content is never rewritten (recorded as
 *     an idempotent skip)
 *   - timestamped backup of any existing file before overwrite
 *   - atomic write (temp file in the SAME directory + rename, so the rename
 *     never crosses devices), with fsync of the file and, where the
 *     platform allows, the containing directory
 *   - automatic rollback (restore backup) on any failure after backup
 *   - a per-destination in-process async mutex serializing concurrent
 *     deploys to the same resolved path
 *   - per-target-type counters (attempts, succeeded, idempotentSkips,
 *     rollbacks, failures) exposed via getDeployMetrics() for evidence
 *     metadata (public, non-secret values only)
 *
 * Zero private-key custody (D5, ADR-0001): this module deploys public
 * certificates ONLY. M5 Dev B scope deploys public certs; cert and key
 * deploys are separate targets. As defense in depth, deployCertificate
 * THROWS if the payload contains a PEM private-key marker, regardless of
 * what the caller claims the payload is.
 *
 * Policy decoupling: this module never loads policy config itself. The
 * caller (dispatch layer) passes a `checkPath(filePath)` callback -- in
 * production, the policy engine's checkPath -- returning
 * { allowed, rejectionReason?, detail? }. This module calls it for every
 * path it is about to touch (destination, chain destination, backup dir),
 * including once more against the realpath-resolved destination so a
 * symlink cannot escape the allowlisted roots.
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
 *     chainPath?: string,          // optional absolute destination for the chain PEM
 *     backupDir?: string,          // optional absolute dir for timestamped backups
 *   }
 *
 * Checks, in order: shape/type, absolute paths, parent directories exist,
 * and policy allowance via the injected `checkPath` callback for certPath,
 * chainPath, and backupDir (when present). `checkPath` must return
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
 * with the restrictive mode, fsynced, renamed over the destination, then
 * the directory is fsynced where the platform allows.
 *
 * The temp file is unlinked on any failure so no partial write is left
 * behind.
 *
 * @param {typeof fsp} fspImpl
 * @param {string} destinationPath
 * @param {string|Buffer} content
 * @returns {Promise<void>}
 */
async function atomicWrite(fspImpl, destinationPath, content) {
  const dirPath = path.dirname(destinationPath);
  const tempPath = path.join(
    dirPath,
    `.${path.basename(destinationPath)}.${crypto.randomBytes(6).toString("hex")}.tmp`,
  );

  let handle;
  try {
    handle = await fspImpl.open(tempPath, "wx", DEPLOYED_FILE_MODE);
    await handle.writeFile(content);
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

// --- Deploy ------------------------------------------------------------------

/**
 * Deploys a public certificate PEM to target.certPath, atomically and with
 * rollback. See the module docblock for the full step list.
 *
 * REFUSES (throws) if `certificatePem` contains a PEM private-key marker:
 * this module deploys public certificates only (M5 Dev B scope; cert and
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
 *   { deployed: true,  skipped: false, destination, backupPath|null }
 *   { deployed: false, skipped: true,  reason: "idempotent", destination }
 *   { deployed: false, skipped: false, error, stage }                       // failed before touching the file
 *   { deployed: false, skipped: false, rolledBack: true|false, error, stage } // failed during write
 *
 * @param {{
 *   target: object,           // see validateTargetConfig
 *   certificatePem: string,   // public certificate PEM (cert or cert+chain)
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

  const destination = path.normalize(path.resolve(target.certPath));

  // The mutex key is the resolved destination path so two descriptors
  // spelling the same file differently still serialize.
  return await withDestinationLock(destination, async () => {
    // (2) realpath containment re-check, symlink-aware. The policy module's
    // checkPath is lexical only; here, immediately before writing, resolve
    // symlinks on the deepest existing ancestor (the destination file
    // itself may not exist yet) and re-run the policy callback against the
    // real path. A symlinked parent dir pointing outside the allowlisted
    // roots is rejected even though the lexical path looked fine.
    let realDestination;
    try {
      const parentReal = await fspImpl.realpath(path.dirname(destination));
      realDestination = path.join(parentReal, path.basename(destination));
      // If the destination itself exists and is a symlink, resolve it too.
      try {
        realDestination = await fspImpl.realpath(realDestination);
      } catch (err) {
        if (err?.code !== "ENOENT") throw err;
      }
    } catch (err) {
      return failure("realpath", `deploy: could not resolve destination realpath: ${err?.message || err}`);
    }

    const realPathPolicy = checkPath(realDestination);
    if (!realPathPolicy || realPathPolicy.allowed !== true) {
      return failure(
        "realpath-policy",
        `deploy: resolved destination ${JSON.stringify(realDestination)} escapes the ` +
          `allowlisted roots (${realPathPolicy?.rejectionReason || "path_not_allowlisted"}): ` +
          `${realPathPolicy?.detail || "no detail provided"}`,
      );
    }

    // (3) Idempotency: byte-identical content is a recorded no-op.
    let existingContent = null;
    try {
      existingContent = await fspImpl.readFile(realDestination);
    } catch (err) {
      if (err?.code !== "ENOENT") {
        return failure("read-existing", `deploy: could not read existing destination: ${err?.message || err}`);
      }
    }
    if (existingContent !== null && existingContent.equals(Buffer.from(certificatePem, "utf8"))) {
      counters.idempotentSkips += 1;
      return {
        deployed: false,
        skipped: true,
        reason: "idempotent",
        destination: realDestination,
      };
    }

    // (4) Timestamped backup of the existing file (if any), same
    // restrictive mode as the deployed file.
    let backupPath = null;
    if (existingContent !== null) {
      backupPath = backupPathFor(realDestination, target.backupDir, now());
      try {
        await fspImpl.writeFile(backupPath, existingContent, {
          mode: DEPLOYED_FILE_MODE,
        });
      } catch (err) {
        return failure("backup", `deploy: could not write backup: ${err?.message || err}`);
      }
    }

    // (5) Atomic write; (6) rollback from backup on failure.
    try {
      await atomicWrite(fspImpl, realDestination, certificatePem);
    } catch (err) {
      let rolledBack = false;
      if (backupPath !== null) {
        try {
          await fspImpl.writeFile(realDestination, existingContent, {
            mode: DEPLOYED_FILE_MODE,
          });
          rolledBack = true;
        } catch (_rollbackErr) {
          // Rollback itself failed; surface the original error with
          // rolledBack: false so the operator knows the backup file still
          // holds the previous content.
        }
      }
      return failure("write", `deploy: atomic write failed: ${err?.message || err}`, rolledBack);
    }

    // Re-assert the restrictive mode (best-effort on win32, mirroring the
    // config module's convention).
    try {
      await fspImpl.chmod(realDestination, DEPLOYED_FILE_MODE);
    } catch (_err) {
      // best-effort on win32
    }

    counters.succeeded += 1;
    return {
      deployed: true,
      skipped: false,
      destination: realDestination,
      backupPath,
    };
  });
}

module.exports = {
  validateTargetConfig,
  deployCertificate,
  getDeployMetrics,
  resetDeployMetrics,
  DEPLOYED_FILE_MODE,
  VALID_TARGET_TYPES,
};
