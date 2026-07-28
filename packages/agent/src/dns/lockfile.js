"use strict";

/**
 * Cross-process file lock for DNS-01 hook invocations.
 *
 * Each `certops-dns-hook` run is a fresh process, so the in-memory mutex in
 * src/dns/index.js cannot serialize concurrent challenges on the same
 * zone+record. This module provides flock-equivalent semantics via
 * O_EXCL create (atomic on POSIX and Windows for exclusive create) plus a
 * stale-lock reclaim window.
 *
 * Lock files live under os.tmpdir()/certops-dns-locks/ and are keyed by a
 * sanitized `${provider}:${zone}:${recordName}` string. No credentials are
 * ever written into lock files.
 */

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const DEFAULT_STALE_MS = 5 * 60 * 1000;
const DEFAULT_WAIT_TIMEOUT_MS = 2 * 60 * 1000;
const DEFAULT_POLL_MS = 50;

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

/**
 * @param {string} key
 * @returns {string}
 */
function lockFilePathForKey(key) {
  const digest = crypto.createHash("sha256").update(key).digest("hex").slice(0, 32);
  const dir = path.join(os.tmpdir(), "certops-dns-locks");
  return path.join(dir, `${digest}.lock`);
}

/**
 * Acquires an exclusive lock for `key`, runs `task`, then releases.
 * Retries until `waitTimeoutMs` if another process holds the lock.
 *
 * @template T
 * @param {string} key
 * @param {() => Promise<T>} task
 * @param {{
 *   lockDir?: string,
 *   staleMs?: number,
 *   waitTimeoutMs?: number,
 *   pollMs?: number,
 *   now?: () => number,
 *   sleep?: (ms: number) => Promise<void>,
 * }} [options]
 * @returns {Promise<T>}
 */
async function withFileLock(key, task, options = {}) {
  if (!isNonEmptyString(key)) {
    throw new Error("dns: withFileLock requires a non-empty key");
  }
  if (typeof task !== "function") {
    throw new Error("dns: withFileLock requires a task function");
  }

  const staleMs =
    Number.isInteger(options.staleMs) && options.staleMs > 0
      ? options.staleMs
      : DEFAULT_STALE_MS;
  const waitTimeoutMs =
    Number.isInteger(options.waitTimeoutMs) && options.waitTimeoutMs > 0
      ? options.waitTimeoutMs
      : DEFAULT_WAIT_TIMEOUT_MS;
  const pollMs =
    Number.isInteger(options.pollMs) && options.pollMs > 0
      ? options.pollMs
      : DEFAULT_POLL_MS;
  const now = typeof options.now === "function" ? options.now : () => Date.now();
  const sleep =
    typeof options.sleep === "function"
      ? options.sleep
      : (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  const lockPath = options.lockDir
    ? path.join(options.lockDir, `${crypto.createHash("sha256").update(key).digest("hex").slice(0, 32)}.lock`)
    : lockFilePathForKey(key);

  fs.mkdirSync(path.dirname(lockPath), { recursive: true });

  const startedAt = now();
  let handle = null;

  for (;;) {
    try {
      handle = fs.openSync(lockPath, "wx");
      fs.writeFileSync(
        handle,
        JSON.stringify({ pid: process.pid, acquiredAt: now(), key }),
        "utf8",
      );
      break;
    } catch (err) {
      if (!err || err.code !== "EEXIST") {
        throw err;
      }

      let stale = false;
      try {
        const stat = fs.statSync(lockPath);
        stale = now() - stat.mtimeMs > staleMs;
      } catch (statErr) {
        if (statErr && statErr.code === "ENOENT") {
          // Race: lock released between our create and this stat; retry.
          continue;
        }
        throw statErr;
      }

      if (stale) {
        // Reclaim by atomic rename rather than unlink-by-path: renaming a
        // stale lock file to a per-attempt-unique name is atomic on both
        // POSIX and Windows, so at most one concurrent waiter can ever win
        // the rename for a given on-disk lock file instance. A plain
        // stat-then-unlink here would race: waiter B could stat, decide
        // stale, then waiter A reclaims (unlinks the stale file and creates
        // a fresh lock) before B's unlink runs; B's unlink-by-path would
        // then delete A's brand-new lock, and both A and B would end up
        // believing they hold the lock and run the task concurrently --
        // exactly the merge-then-REPLACE clobbering scenario this lock
        // exists to prevent.
        const reclaimPath = `${lockPath}.reclaim.${process.pid}.${crypto
          .randomBytes(8)
          .toString("hex")}`;
        try {
          fs.renameSync(lockPath, reclaimPath);
        } catch (renameErr) {
          if (renameErr && renameErr.code === "ENOENT") {
            // Another waiter already reclaimed or released it first; retry
            // without touching anything we no longer own.
            continue;
          }
          throw renameErr;
        }
        try {
          fs.unlinkSync(reclaimPath);
        } catch (unlinkErr) {
          if (!unlinkErr || unlinkErr.code !== "ENOENT") {
            throw unlinkErr;
          }
        }
        continue;
      }

      if (now() - startedAt >= waitTimeoutMs) {
        throw new Error(
          `dns: timed out after ${waitTimeoutMs} ms waiting for lock ${JSON.stringify(key)}`,
        );
      }
      await sleep(pollMs);
    }
  }

  try {
    return await task();
  } finally {
    try {
      if (handle !== null) {
        fs.closeSync(handle);
      }
    } catch {
      // ignore close errors; unlink is what matters
    }
    try {
      fs.unlinkSync(lockPath);
    } catch (unlinkErr) {
      if (!unlinkErr || unlinkErr.code !== "ENOENT") {
        // Best-effort release; log rather than throw from a finally block,
        // which would otherwise replace/mask task()'s own thrown error
        // (or its return value) with this cleanup failure.
        process.stderr.write(
          `dns: failed to release lock ${JSON.stringify(key)} at ${lockPath}: ${unlinkErr.message}\n`,
        );
      }
    }
  }
}

module.exports = {
  withFileLock,
  lockFilePathForKey,
  DEFAULT_STALE_MS,
  DEFAULT_WAIT_TIMEOUT_MS,
  DEFAULT_POLL_MS,
};
