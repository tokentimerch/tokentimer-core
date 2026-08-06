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
 * Detection strategy is platform-specific, but the fail-to-null contract is
 * shared: any host where the command is missing, errors, times out, or
 * prints something unrecognized reports `null` ("unknown") rather than a
 * guessed true/false. The agent-protocol schema defines `ntpSynced` as
 * boolean|null exactly so an agent that cannot determine sync state can say
 * so honestly instead of defaulting to a value that could mask real drift.
 *
 * - Linux: `timedatectl show -p NTPSynchronized --value` is the
 *   systemd-native, locale-independent way to ask this (see
 *   docs/certops/agent.md "Supported platform / tool version matrix").
 * - win32: there is no timedatectl equivalent that returns a plain
 *   boolean, and `w32tm /query /status`'s labelled fields are localized
 *   (confirmed on a real non-Latin-1 locale host), so this uses
 *   `w32tm /query /source` instead: on a healthy Windows Time service it
 *   prints only the active time source name on one line, with no other
 *   decoration to localize. `Local CMOS Clock` and `Free-running System
 *   Clock` are w32tm's own documented tokens for "no external source is
 *   configured" (i.e. the hardware clock, unsynced); any other source
 *   (an NTP server, a domain hierarchy peer, or a hypervisor's time-sync
 *   integration service such as `VM IC Time Synchronization Provider`)
 *   counts as synced. A stopped W32Time service exits non-zero and falls
 *   through to `null`, same as any other command failure.
 */

const childProcess = require("node:child_process");
const { buildMinimalSubprocessEnv } = require("../exec-env");

/** Must never stall the heartbeat loop; both commands are effectively instant. */
const DEFAULT_TIMEOUT_MS = 5000;

const NTP_SYNCHRONIZED_ARGV = Object.freeze([
  "timedatectl",
  "show",
  "-p",
  "NTPSynchronized",
  "--value",
]);

const WIN32_NTP_SOURCE_ARGV = Object.freeze(["w32tm", "/query", "/source"]);

/** w32tm's own documented tokens for "no external time source configured". */
const WIN32_UNSYNCED_SOURCES = Object.freeze([
  "local cmos clock",
  "free-running system clock",
]);

function parseLinuxNtpSynchronized(stdout) {
  const value = String(stdout || "").trim().toLowerCase();
  if (value === "yes") return true;
  if (value === "no") return false;
  return null;
}

function parseWin32NtpSource(stdout) {
  const value = String(stdout || "").trim().toLowerCase();
  if (!value) return null;
  return !WIN32_UNSYNCED_SOURCES.includes(value);
}

/**
 * @param {object} [options]
 * @param {Function} [options.execFileImpl] injection point for tests;
 *   defaults to node:child_process.execFile. Must have the same
 *   (file, args, options, callback) signature.
 * @param {number} [options.timeoutMs] exec timeout in ms, default 5000.
 * @param {string} [options.platform] defaults to process.platform.
 * @returns {Promise<boolean|null>} true/false on a definite answer, null
 *   when sync state cannot be determined (missing binary, unsupported
 *   host, stopped time service, timeout, nonzero exit, or unparseable
 *   output).
 */
function checkNtpSynced({
  execFileImpl = childProcess.execFile,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  platform = process.platform,
} = {}) {
  if (typeof execFileImpl !== "function") {
    throw new Error("ntp: execFileImpl must be a function");
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error(
      `ntp: timeoutMs must be a positive integer, got ${JSON.stringify(timeoutMs)}`,
    );
  }

  const argv = platform === "win32" ? WIN32_NTP_SOURCE_ARGV : NTP_SYNCHRONIZED_ARGV;
  const parse = platform === "win32" ? parseWin32NtpSource : parseLinuxNtpSynchronized;
  const [file, ...args] = argv;

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
            // ENOENT (missing binary / unsupported host), a stopped time
            // service (nonzero exit), or a timeout (SIGTERM, error.killed)
            // are all operational outcomes, not programmer errors: report
            // "unknown" instead of guessing.
            resolve(null);
            return;
          }
          resolve(parse(stdout));
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
  WIN32_NTP_SOURCE_ARGV,
  WIN32_UNSYNCED_SOURCES,
  checkNtpSynced,
};
