const { spawn } = require("child_process");

const GRACEFUL_SHUTDOWN_MS = 2000;
const HARD_SHUTDOWN_MS = GRACEFUL_SHUTDOWN_MS + 3000;

function isPackageManagerCommand(command) {
  return /^(pnpm|npm|npx|yarn)$/.test(command);
}

const WINDOWS_CMD_SAFE_ARG_PATTERN = /^[A-Za-z0-9@._:/=+\-]+$/;

// Intended only for known package-manager invocations with simple args
// (pnpm --filter @scope/pkg script). Not for arbitrary user-supplied commands,
// paths with spaces, or shell metacharacters.

function createWindowsPackageManagerCommandLine(command, args = []) {
  return [command, ...args].map(assertSafeWindowsCmdArg).join(" ");
}

function assertSafeWindowsCmdArg(value) {
  const text = String(value);
  if (!WINDOWS_CMD_SAFE_ARG_PATTERN.test(text)) {
    throw new Error(
      `Unsafe Windows command argument "${text}" cannot be passed through cmd.exe`,
    );
  }

  return text;
}

function spawnCommand(command, args = [], options = {}) {
  const spawnOptions = {
    ...options,
    detached:
      process.platform === "win32" ? options.detached : options.detached ?? true,
  };

  if (process.platform === "win32" && isPackageManagerCommand(command)) {
    const commandLine = createWindowsPackageManagerCommandLine(command, args);
    return spawn(
      process.env.ComSpec || "cmd.exe",
      ["/d", "/s", "/c", commandLine],
      {
        ...spawnOptions,
        windowsHide: true,
      },
    );
  }

  return spawn(command, args, spawnOptions);
}

function killProcessTree(child, { gracefulMs = GRACEFUL_SHUTDOWN_MS } = {}) {
  if (!child || child.exitCode !== null || !child.pid) return;

  if (process.platform === "win32") {
    const pid = child.pid;
    const graceful = spawn("taskkill", ["/pid", String(pid), "/t"], {
      stdio: "ignore",
      windowsHide: true,
    });
    graceful.on("error", () => {});

    setTimeout(() => {
      if (child.exitCode !== null) return;

      const force = spawn("taskkill", ["/pid", String(pid), "/t", "/f"], {
        stdio: "ignore",
        windowsHide: true,
      });
      force.on("error", () => {});
    }, gracefulMs).unref();
    return;
  }

  try {
    process.kill(-child.pid, "SIGTERM");
  } catch (error) {
    if (error.code !== "ESRCH") {
      child.kill("SIGTERM");
    }
  }
}

module.exports = {
  GRACEFUL_SHUTDOWN_MS,
  HARD_SHUTDOWN_MS,
  createWindowsPackageManagerCommandLine,
  killProcessTree,
  spawnCommand,
};
