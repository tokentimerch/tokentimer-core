"use strict";

// The worker owns only token observation; the caller runs cleanup after the
// child has exited. Never send credentials as arguments or log worker output.
const { fork } = require("node:child_process");
const path = require("node:path");
const { workDeadline } = require("./azure-natural-token-expiry.cjs");

function safeFacts(value) {
  const fields = ["issuedAt", "expiresAt", "observedExpiredAt", "renewedAt", "renewedExpiresAt",
    "azureStatusBefore", "azureStatusExpired", "azureStatusAfter", "forced401", "clockOverridden", "pinnedVersion"];
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).sort().join(",") !== fields.sort().join(",")) return false;
  if (![value.issuedAt, value.expiresAt, value.observedExpiredAt, value.renewedAt, value.renewedExpiresAt]
    .every(Number.isSafeInteger)) return false;
  return value.azureStatusBefore === 200 && value.azureStatusExpired === 401 && value.azureStatusAfter === 200 &&
    value.forced401 === false && value.clockOverridden === false && /^[a-f0-9]{32}$/.test(value.pinnedVersion);
}

function runBoundedWorker({ workerPath, budget, signal }) {
  if (!path.isAbsolute(workerPath)) throw new Error("AZURE_EXPIRY_WORKER_PATH_INVALID");
  const deadline = workDeadline(budget || {}, Date.now());
  if (signal?.aborted) return Promise.reject(new Error("AZURE_EXPIRY_CANCELLED"));
  return new Promise((resolve, reject) => {
    const child = fork(workerPath, [], { stdio: ["ignore", "ignore", "ignore", "ipc"],
      detached: process.platform !== "win32",
      env: { ...process.env, TT_EXPIRY_WORK_DEADLINE_MS: String(deadline),
        TT_EXPIRY_JOB_DEADLINE_MS: String(budget.jobDeadlineMs),
        TT_EXPIRY_RESOURCE_DEADLINE_MS: String(budget.resourceDeadlineMs),
        TT_EXPIRY_CLEANUP_RESERVE_MS: String(budget.cleanupReserveMs) } });
    let stopReason, result, started = false;
    const stop = reason => {
      if (!stopReason) stopReason = reason;
      if (child.exitCode === null && child.signalCode === null) {
        try {
          if (process.platform === "win32") {
            if (!child.kill("SIGKILL")) throw new Error("kill failed");
          } else process.kill(-child.pid, "SIGKILL");
        } catch { stopReason = "AZURE_EXPIRY_WORKER_STOP_FAILED"; }
      }
    };
    const timer = setTimeout(() => stop("AZURE_EXPIRY_DEADLINE"), Math.max(1, deadline - Date.now()));
    const abort = () => stop("AZURE_EXPIRY_CANCELLED");
    signal?.addEventListener("abort", abort, { once: true });
    child.on("spawn", () => { started = true; if (signal?.aborted) abort(); });
    child.on("message", value => { result = value; });
    child.on("error", () => { stopReason = "AZURE_EXPIRY_WORKER_FAILED"; });
    child.on("close", (code, childSignal) => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      if (stopReason) return reject(new Error(stopReason));
      if (!started || code !== 0 || childSignal || !safeFacts(result))
        return reject(new Error("AZURE_EXPIRY_WORKER_FAILED"));
      resolve(result);
    });
  });
}
module.exports = { runBoundedWorker };
