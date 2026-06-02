const { spawn } = require("child_process");

function isPackageManagerCommand(command) {
  return /^(pnpm|npm|npx|yarn)$/.test(command);
}

const WINDOWS_CMD_SAFE_ARG_PATTERN = /^[A-Za-z0-9@._:/=+\-]+$/;

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
  if (process.platform === "win32" && isPackageManagerCommand(command)) {
    const commandLine = createWindowsPackageManagerCommandLine(command, args);
    return spawn(
      process.env.ComSpec || "cmd.exe",
      ["/d", "/s", "/c", commandLine],
      {
        ...options,
        windowsHide: true,
      },
    );
  }

  return spawn(command, args, options);
}

function killProcessTree(child) {
  if (!child || child.exitCode !== null || !child.pid) return;

  if (process.platform === "win32") {
    const killer = spawn(
      "taskkill",
      ["/pid", String(child.pid), "/t", "/f"],
      {
        stdio: "ignore",
        windowsHide: true,
      },
    );
    killer.on("error", () => {});
    return;
  }

  child.kill("SIGTERM");
}

module.exports = {
  createWindowsPackageManagerCommandLine,
  killProcessTree,
  spawnCommand,
};
