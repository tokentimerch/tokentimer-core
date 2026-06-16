"use strict";

const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

function createRunnerError(message, code, details = {}) {
  const error = new Error(message);
  error.code = code;
  Object.assign(error, details);
  return error;
}

function createToolWorkspace() {
  const parent = process.env.DOMAIN_CHECKER_TOOL_TMPDIR || os.tmpdir();
  try {
    return fs.mkdtempSync(path.join(parent, "tokentimer-domain-checker-"));
  } catch (error) {
    throw createRunnerError(
      "Domain checker tools need a writable temporary directory",
      "DOMAIN_CHECKER_TOOL_WORKDIR_UNAVAILABLE",
      { cause: error },
    );
  }
}

function createToolEnv(home) {
  const configHome = path.join(home, ".config");
  const cacheHome = path.join(home, ".cache");
  const dataHome = path.join(home, ".local", "share");
  for (const directory of [home, configHome, cacheHome, dataHome]) {
    fs.mkdirSync(directory, { recursive: true });
  }
  return {
    PATH: process.env.PATH || "/usr/local/bin:/usr/bin:/bin",
    HOME: home,
    XDG_CONFIG_HOME: configHome,
    XDG_CACHE_HOME: cacheHome,
    XDG_DATA_HOME: dataHome,
    TMPDIR: home,
  };
}

async function runBinary({
  bin,
  args,
  timeoutMs,
  signal,
  onLine,
  maxStdoutBytes = 1024 * 1024,
  maxStderrBytes = 8192,
}) {
  if (!bin || typeof bin !== "string") {
    throw createRunnerError(
      "Binary path is required",
      "DOMAIN_CHECKER_TOOL_MISSING",
    );
  }
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== "string")) {
    throw createRunnerError(
      "Binary arguments must be a string array",
      "DOMAIN_CHECKER_INVALID_ARGS",
    );
  }

  const startedAt = Date.now();
  let stdoutBytes = 0;
  let stderr = "";
  let stdoutBuffer = "";
  let timedOut = false;
  const toolHome = createToolWorkspace();
  const effectiveArgs = args;
  const isWindows = process.platform === "win32";

  const child = spawn(bin, effectiveArgs, {
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
    env: createToolEnv(toolHome),
    // Own process group on POSIX so the whole tree (incl. grandchildren)
    // can be killed, not just the direct child.
    detached: !isWindows,
  });

  const killTree = (signalName) => {
    if (isWindows) {
      if (signalName === "SIGKILL") {
        try {
          spawn("taskkill", ["/PID", String(child.pid), "/T", "/F"], {
            stdio: "ignore",
          });
        } catch (_err) {
          try {
            child.kill("SIGKILL");
          } catch (_e) {
            /* already gone */
          }
        }
      } else {
        try {
          child.kill(signalName);
        } catch (_e) {
          /* already gone */
        }
      }
      return;
    }
    try {
      process.kill(-child.pid, signalName);
    } catch (_err) {
      try {
        child.kill(signalName);
      } catch (_e) {
        /* already gone */
      }
    }
  };

  // SIGTERM with SIGKILL escalation scheduled IMMEDIATELY (not after the
  // close event): a child that ignores SIGTERM must not hang the runner.
  let killEscalation = null;
  const terminate = () => {
    killTree("SIGTERM");
    if (!killEscalation) {
      killEscalation = setTimeout(() => killTree("SIGKILL"), 2000);
      killEscalation.unref?.();
    }
  };

  const timeout = setTimeout(
    () => {
      timedOut = true;
      terminate();
    },
    Math.max(1000, Number(timeoutMs) || 90000),
  );

  const abortHandler = () => {
    terminate();
  };
  if (signal) {
    if (signal.aborted) abortHandler();
    else signal.addEventListener("abort", abortHandler, { once: true });
  }

  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");

  child.stdout.on("data", (chunk) => {
    stdoutBytes += Buffer.byteLength(chunk, "utf8");
    if (stdoutBytes > maxStdoutBytes) {
      terminate();
      return;
    }
    stdoutBuffer += chunk;
    let newlineIndex;
    while ((newlineIndex = stdoutBuffer.indexOf("\n")) >= 0) {
      const line = stdoutBuffer.slice(0, newlineIndex).trim();
      stdoutBuffer = stdoutBuffer.slice(newlineIndex + 1);
      if (line && typeof onLine === "function") onLine(line);
    }
  });

  child.stderr.on("data", (chunk) => {
    if (stderr.length < maxStderrBytes) {
      stderr += chunk.slice(0, maxStderrBytes - stderr.length);
    }
  });

  const exitCode = await new Promise((resolve, reject) => {
    child.once("error", (error) => {
      reject(
        createRunnerError(error.message, "DOMAIN_CHECKER_TOOL_MISSING", {
          cause: error,
          args: effectiveArgs,
          stderr,
        }),
      );
    });
    child.once("close", (code) => resolve(code));
  }).finally(() => {
    clearTimeout(timeout);
    if (killEscalation) clearTimeout(killEscalation);
    if (signal) signal.removeEventListener("abort", abortHandler);
    fs.rmSync(toolHome, { recursive: true, force: true });
  });

  const trailingLine = stdoutBuffer.trim();
  if (trailingLine && typeof onLine === "function") onLine(trailingLine);

  const durationMs = Date.now() - startedAt;
  if (signal?.aborted) {
    throw createRunnerError(
      "Discovery process was aborted",
      "DOMAIN_CHECKER_ABORTED",
      {
        durationMs,
        args: effectiveArgs,
        stderr: stderr.slice(0, maxStderrBytes),
      },
    );
  }
  if (timedOut) {
    throw createRunnerError(
      "Discovery process timed out",
      "DOMAIN_CHECKER_TOOL_TIMEOUT",
      {
        durationMs,
        args: effectiveArgs,
        stderr: stderr.slice(0, maxStderrBytes),
      },
    );
  }
  if (stdoutBytes > maxStdoutBytes) {
    throw createRunnerError(
      "Discovery process output exceeded the safety limit",
      "DOMAIN_CHECKER_OUTPUT_LIMIT",
      {
        durationMs,
        args: effectiveArgs,
        stderr: stderr.slice(0, maxStderrBytes),
      },
    );
  }
  if (exitCode !== 0) {
    throw createRunnerError(
      `Discovery process exited with status ${exitCode}`,
      "DOMAIN_CHECKER_BINARY_FAILED",
      {
        durationMs,
        exitCode,
        args: effectiveArgs,
        stderr: stderr.slice(0, maxStderrBytes),
      },
    );
  }

  return { durationMs, stderr: stderr.slice(0, maxStderrBytes) };
}

module.exports = { runBinary };
