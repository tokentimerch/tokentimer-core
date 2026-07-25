"use strict";

/**
 * Local NTP synchronization check for the heartbeat's `ntpSynced` field
 * (ADR-0003 clock-drift awareness).
 *
 * This is deliberately separate from `../clock`: that module estimates the
 * MAGNITUDE of clock skew from control-plane HTTP Date headers, while this
 * module answers a different, OS-level question -- "does this host believe
 * its own clock is actively synchronized right now?" -- which the Date
 * header estimator cannot see (a host can be perfectly NTP-synced yet still
 * show transient header-based skew from one slow response, and vice versa,
 * a host with NTP disabled can happen to sample a near-zero offset).
 *
 * Detection strategy: `timedatectl show -p NTPSynchronized --value` is the
 * systemd-native way to ask this, and matches the agent's only supported
 * install target (Linux with systemd; see docs/certops/agent.md "Supported
 * platform / tool version matrix"). Any host where the command is missing,
 * errors, times out, or prints something unrecognized reports `null`
 * ("unknown") rather than a guessed true/false: the agent-protocol schema
 * defines `ntpSynced` as boolean|null exactly so an agent that cannot
 * determine sync state can say so honestly instead of defaulting to a
 * value that could mask real drift.
 */

const childProcess = require("node:child_process");
const { buildMinimalSubprocessEnv } = require("../exec-env");

/** Must never stall the heartbeat loop; timedatectl is effectively instant. */
const DEFAULT_TIMEOUT_MS = 5000;

const NTP_SYNCHRONIZED_ARGV = Object.freeze([
  "timedatectl",
  "show",
  "-p",
  "NTPSynchronized",
  "--value",
]);

/**
 * @param {object} [options]
 * @param {Function} [options.execFileImpl] injection point for tests;
 *   defaults to node:child_process.execFile. Must have the same
 *   (file, args, options, callback) signature.
 * @param {number} [options.timeoutMs] exec timeout in ms, default 5000.
 * @returns {Promise<boolean|null>} true/false when timedatectl reports a
 *   definite answer, null when sync state cannot be determined (missing
 *   binary, non-systemd host, timeout, nonzero exit, or unparseable output).
 */
function checkNtpSynced({
  execFileImpl = childProcess.execFile,
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  if (typeof execFileImpl !== "function") {
    throw new Error("ntp: execFileImpl must be a function");
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error(
      `ntp: timeoutMs must be a positive integer, got ${JSON.stringify(timeoutMs)}`,
    );
  }

  const [file, ...args] = NTP_SYNCHRONIZED_ARGV;

  return new Promise((resolve) => {
    try {
      execFileImpl(
        file,
        args,
        {
          timeout: timeoutMs,
          // No `shell`: argv is fixed and contains no interpolated input,
          // but every agent subprocess call follows this convention
          // regardless.
          windowsHide: true,
          maxBuffer: 64 * 1024,
          env: buildMinimalSubprocessEnv(),
        },
        (error, stdout) => {
          if (error) {
            // ENOENT (no timedatectl / non-systemd host), a timeout
            // (SIGTERM, error.killed), or a nonzero exit are all
            // operational outcomes, not programmer errors: report
            // "unknown" instead of guessing.
            resolve(null);
            return;
          }
          const value = String(stdout || "").trim().toLowerCase();
          if (value === "yes") {
            resolve(true);
          } else if (value === "no") {
            resolve(false);
          } else {
            resolve(null);
          }
        },
      );
    } catch (_) {
      // A synchronous throw from execFileImpl (real execFile only fails via
      // the callback; this only guards unusual test doubles) is still just
      // "cannot determine sync state" from this function's contract.
      resolve(null);
    }
  });
}

module.exports = {
  DEFAULT_TIMEOUT_MS,
  NTP_SYNCHRONIZED_ARGV,
  checkNtpSynced,
};
