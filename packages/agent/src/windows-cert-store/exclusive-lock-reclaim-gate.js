"use strict";

/**
 * Pathname-socket reclaim gate helpers (Darwin / other file-kind IPC).
 * Extracted so unit tests can run on Windows and Linux CI where the
 * file-kind reclaim path itself is skipped.
 */

const fs = require("node:fs");

/** Abandoned reclaim-gate directories older than this may be stolen. */
const MAX_RECLAIM_GATE_AGE_MS = 30 * 1000;

/**
 * Exclusive reclaim-gate acquisition. `mkdir` is the fast path. An aged
 * abandoned gate is stolen with `rename` (only one rename wins), then the
 * stolen inode is age-checked again so a concurrent peer cannot yank a
 * freshly created live gate via a stale pre-steal `stat`.
 * @param {string} gatePath
 * @returns {boolean}
 */
function tryAcquireReclaimGate(gatePath) {
  try {
    fs.mkdirSync(gatePath);
    return true;
  } catch (err) {
    if (!err || err.code !== "EEXIST") return false;
    let st;
    try {
      st = fs.statSync(gatePath);
    } catch {
      try {
        fs.mkdirSync(gatePath);
        return true;
      } catch {
        return false;
      }
    }
    if (Date.now() - st.mtimeMs <= MAX_RECLAIM_GATE_AGE_MS) {
      return false;
    }
    const stolenPath =
      `${gatePath}.stolen-${process.pid}-${Date.now().toString(36)}-` +
      Math.random().toString(16).slice(2, 10);
    try {
      fs.renameSync(gatePath, stolenPath);
    } catch {
      return false;
    }
    // Re-check age on the inode we uniquely own. If another reclaimer had
    // already replaced the gate with a young directory, put it back.
    try {
      const stolenSt = fs.statSync(stolenPath);
      if (Date.now() - stolenSt.mtimeMs <= MAX_RECLAIM_GATE_AGE_MS) {
        try {
          fs.renameSync(stolenPath, gatePath);
        } catch {
          try {
            fs.rmdirSync(stolenPath);
          } catch {
            // litter
          }
        }
        return false;
      }
      try {
        fs.rmdirSync(stolenPath);
      } catch {
        // litter; still try to take the live gate name
      }
    } catch {
      return false;
    }
    try {
      fs.mkdirSync(gatePath);
      return true;
    } catch {
      return false;
    }
  }
}

function releaseReclaimGate(gatePath) {
  try {
    fs.rmdirSync(gatePath);
  } catch {
    // best-effort
  }
}

module.exports = {
  MAX_RECLAIM_GATE_AGE_MS,
  tryAcquireReclaimGate,
  releaseReclaimGate,
};
