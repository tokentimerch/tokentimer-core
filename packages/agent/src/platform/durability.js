"use strict";

/**
 * Durability limits the host cannot satisfy.
 *
 * An atomic write is rename-plus-directory-fsync on POSIX. Windows cannot open
 * a directory handle for fsync at all, so the directory fsync is impossible
 * there: the rename is still atomic on the same volume, but its durability is
 * not guaranteed across an immediate power loss. That was previously swallowed
 * by an empty catch, which made a Windows deploy indistinguishable from a
 * fully durable one in the evidence trail.
 *
 * This module keeps the swallow (failing a completed deploy over a missing
 * directory fsync would be worse) but records the limitation so it can be
 * attached to evidence. The agent states what it could not guarantee instead
 * of implying a guarantee it never had.
 */

const DIRECTORY_FSYNC_UNSUPPORTED = "directory_fsync_unsupported";

/** @type {Map<string, { code: string, platform: string, detail: string, occurrences: number }>} */
const limits = new Map();

/**
 * @param {{ code: string, platform?: string, detail: string }} limit
 * @returns {void}
 */
function noteDurabilityLimit({ code, platform = process.platform, detail }) {
  const existing = limits.get(code);
  if (existing) {
    existing.occurrences += 1;
    return;
  }
  limits.set(code, { code, platform, detail, occurrences: 1 });
}

/**
 * Snapshot of the durability limitations observed so far. Values are public
 * and non-secret, suitable for evidence metadata.
 *
 * @returns {Array<{ code: string, platform: string, detail: string, occurrences: number }>}
 */
function getDurabilityLimits() {
  return [...limits.values()].map((limit) => ({ ...limit }));
}

/** Test helper. */
function resetDurabilityLimits() {
  limits.clear();
}

/**
 * Flattens the recorded limits into scalar evidence metadata entries. Returns
 * an empty array on a host with no limitations, so POSIX evidence is unchanged.
 *
 * @returns {Array<{ name: string, value: string|number|boolean }>}
 */
function durabilityMetadataEntries() {
  return getDurabilityLimits().flatMap((limit) => [
    { name: `durabilityLimit_${limit.code}`, value: true },
    { name: `durabilityLimit_${limit.code}_platform`, value: limit.platform },
  ]);
}

function describeDirectoryFsyncLimit(platform, err) {
  return {
    code: DIRECTORY_FSYNC_UNSUPPORTED,
    platform,
    detail:
      platform === "win32"
        ? "win32 cannot open a directory for fsync, so the rename that " +
          "committed this write is atomic but not power-loss durable"
        : `directory fsync failed (${err && err.code ? err.code : "unknown"}), ` +
          "so the rename that committed this write is atomic but not " +
          "power-loss durable",
  };
}

/**
 * fsyncs a directory so a preceding rename in it becomes durable, recording a
 * durability limit instead of silently swallowing the failure.
 *
 * @param {string} dirPath
 * @param {{ fsImpl?: typeof import("node:fs"), platform?: string }} [options]
 * @returns {{ durable: boolean, limit: null | { code: string, platform: string, detail: string } }}
 */
function fsyncDirectorySync(
  dirPath,
  { fsImpl = require("node:fs"), platform = process.platform } = {},
) {
  let fd;
  try {
    fd = fsImpl.openSync(dirPath, "r");
    fsImpl.fsyncSync(fd);
    return { durable: true, limit: null };
  } catch (err) {
    const limit = describeDirectoryFsyncLimit(platform, err);
    noteDurabilityLimit(limit);
    return { durable: false, limit };
  } finally {
    if (fd !== undefined) {
      try {
        fsImpl.closeSync(fd);
      } catch (_err) {
        // Best-effort close; the fsync outcome is already recorded.
      }
    }
  }
}

/**
 * Promise-based counterpart of fsyncDirectorySync for the deploy module's
 * injected fs/promises implementation.
 *
 * @param {object} fspImpl node:fs/promises-compatible implementation
 * @param {string} dirPath
 * @param {{ platform?: string }} [options]
 * @returns {Promise<{ durable: boolean, limit: null | object }>}
 */
async function fsyncDirectory(fspImpl, dirPath, { platform = process.platform } = {}) {
  let handle;
  try {
    handle = await fspImpl.open(dirPath, "r");
    await handle.sync();
    return { durable: true, limit: null };
  } catch (err) {
    const limit = describeDirectoryFsyncLimit(platform, err);
    noteDurabilityLimit(limit);
    return { durable: false, limit };
  } finally {
    if (handle) {
      try {
        await handle.close();
      } catch (_err) {
        // Best-effort close; the fsync outcome is already recorded.
      }
    }
  }
}

module.exports = {
  DIRECTORY_FSYNC_UNSUPPORTED,
  durabilityMetadataEntries,
  fsyncDirectory,
  fsyncDirectorySync,
  getDurabilityLimits,
  noteDurabilityLimit,
  resetDurabilityLimits,
};
