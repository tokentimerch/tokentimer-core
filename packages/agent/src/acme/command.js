/**
 * Run an ACME client with bounded output and cancellation of its owned process tree.
 * The production agent uses this runner under its execution lease. POSIX commands
 * receive a dedicated process group; Windows cleanup targets the started tree.
 * Injected runners are a test seam, while native process tests verify real teardown. */
"use strict";

const childProcess = require("node:child_process");

/** Run one allowlisted command without a shell or inherited agent secrets.
 * A native POSIX child owns a fresh process group: its PGID cannot be reused
 * while any descendant remains. This lets cancellation drain that exact group
 * even when the original tool has already exited. Windows termination targets
 * a wrapper's live PID; its Job Object owns descendants even after launcher exit.
 */
function execWithoutShell(execFileImpl, argv, timeoutMs, env, signal) {
  if (signal?.aborted) {
    return Promise.resolve({exitCode: null, stdout: "", stderr: "", execError: new Error("ACME command cancelled before execution")});
  }
  return new Promise((resolve) => {
    let child;
    let killTimer;
    let deadlineTimer;
    let settled = false;
    let stoppedError;
    const native = execFileImpl === childProcess.execFile;
    const group = native && process.platform !== "win32";
    const windowsJob = native && process.platform === "win32";

    function terminate(force) {
      if (!child?.pid) return;
      // A detached group's remaining descendants still belong to us after its
      // leader exits. Checking the leader's exitCode here would leak them.
      if (group) {
        try { process.kill(-child.pid, force ? "SIGKILL" : "SIGTERM"); }
        catch (error) { if (error.code !== "ESRCH") throw error; }
        return;
      }
      if (child.exitCode !== null || child.signalCode !== null) return;
      if (native && process.platform === "win32") {
        const result = childProcess.spawnSync("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], {windowsHide: true, stdio: "ignore", timeout: 5000});
        if (result.error || result.status !== 0) child.kill("SIGKILL");
      } else {
        child.kill(force ? "SIGKILL" : "SIGTERM");
      }
    }

    function finish(error, stdout = "", stderr = "") {
      if (settled) return;
      error = error || stoppedError;
      // A quick leader exit may finish before the escalation timer. Reap its
      // owned group immediately rather than allowing detached hook children.
      if (group && (error || signal?.aborted)) {
        try { terminate(true); } catch (killError) { error = killError; }
      }
      settled = true;
      clearTimeout(killTimer);
      clearTimeout(deadlineTimer);
      signal?.removeEventListener("abort", abort);
      resolve({exitCode: error ? (typeof error.code === "number" ? error.code : null) : 0, stdout, stderr, execError: error || null});
    }

    function abort() {
      if (settled || killTimer) return;
      stoppedError ||= new Error(signal?.aborted ? "ACME execution lease cancelled" : "ACME command timed out");
      try { terminate(false); } catch (error) { finish(error); return; }
      killTimer = setTimeout(() => {
        try { terminate(true); } catch (error) { finish(error); }
      }, 2000);
    }

    try {
      if (group || windowsJob) {
        // POSIX uses a process group; Windows assigns a suspended child to a
        // kill-on-close Job Object before allowing it to execute.
        child = windowsJob
          ? childProcess.spawn(require("node:path").join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", require("node:path").join(__dirname, "windows-command.ps1")], {windowsHide: true, env, stdio: ["pipe", "pipe", "pipe"]})
          : childProcess.spawn(argv[0], argv.slice(1), {detached: true, windowsHide: true, env, stdio: ["ignore", "pipe", "pipe"]});
        if (windowsJob) {
          child.stdin.on("error", () => {}); // Spawn/close handlers report wrapper failure.
          child.stdin.end(JSON.stringify({executable: argv[0], arguments: argv.slice(1)}));
        }
        const stdout = [], stderr = [];
        let bytes = 0;
        const collect = target => chunk => {
          bytes += chunk.length;
          if (bytes > 10 * 1024 * 1024) { stoppedError ||= new Error("ACME command output exceeded its bound"); abort(); }
          else target.push(chunk);
        };
        child.stdout.on("data", collect(stdout));
        child.stderr.on("data", collect(stderr));
        child.once("error", error => finish(error));
        child.once("close", (code, killedSignal) => {
          const error = code === 0 ? null : Object.assign(new Error("ACME command exited unsuccessfully"), {code, signal: killedSignal});
          finish(error, Buffer.concat(stdout).toString("utf8"), Buffer.concat(stderr).toString("utf8"));
        });
      } else {
        child = execFileImpl(argv[0], argv.slice(1), {
          timeout: native ? 0 : timeoutMs,
          windowsHide: true,
          maxBuffer: 10 * 1024 * 1024,
          env,
        }, finish);
      }
      if (!settled) {
        if (native) deadlineTimer = setTimeout(abort, timeoutMs);
        if (signal) {
          signal.addEventListener("abort", abort, {once: true});
          if (signal.aborted) abort();
        }
      }
    } catch (error) { finish(error); }
  });
}
module.exports = {execWithoutShell};
