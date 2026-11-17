"use strict";

// The worker owns only token observation; the caller runs cleanup after the
// child has exited. Never send credentials as arguments or log worker output.
const { fork } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { workDeadline } = require("./azure-natural-token-expiry.cjs");
const DRAIN_TIMEOUT_MS = 2000;

function hasLiveGroup(group) {
  for (const name of fs.readdirSync("/proc")) {
    if (!/^[0-9]+$/.test(name)) continue;
    let stat;
    try { stat = fs.readFileSync(`/proc/${name}/stat`, "utf8"); }
    catch (error) { if (error.code === "ENOENT" || error.code === "ESRCH") continue; throw error; }
    const end = stat.lastIndexOf(")");
    if (end < 0) throw new Error("invalid proc stat");
    const fields = stat.slice(end + 2).trim().split(/\s+/);
    if (!fields[0] || !/^[0-9]+$/.test(fields[2] || "")) throw new Error("invalid proc fields");
    // Zombies cannot run or mutate resources; they may await an external reaper.
    if (Number(fields[2]) === group && fields[0] !== "Z" && fields[0] !== "X") return true;
  }
  return false;
}

async function groupDrained(group) {
  if (process.platform !== "linux" || !Number.isSafeInteger(group) || group <= 0) return false;
  const until = Date.now() + DRAIN_TIMEOUT_MS;
  do {
    try { if (!hasLiveGroup(group)) return true; } catch { return false; }
    await new Promise(resolve => setTimeout(resolve, 50));
  } while (Date.now() < until);
  return false;
}

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

// Caller contract: authenticate the job startedAt (+90 minutes) and the owned
// resource expiresAt (existing two-hour TTL), reserving at least ten minutes
// for cleanup. Pass these same absolute budget values to supervisor and worker;
// Date.now() plus a fresh ceiling is not the original deadline. All descendants
// must stay in this supervised process group; detached children are not covered.
// Begin cleanup only after verified drainage; this helper performs no cleanup.
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
    child.on("close", async (code, childSignal) => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      if (started && !(await groupDrained(child.pid)))
        return reject(new Error("AZURE_EXPIRY_DRAIN_UNVERIFIED"));
      if (stopReason) return reject(new Error(stopReason));
      if (!started || code !== 0 || childSignal || !safeFacts(result))
        return reject(new Error("AZURE_EXPIRY_WORKER_FAILED"));
      resolve(result);
    });
  });
}
module.exports = { runBoundedWorker };
