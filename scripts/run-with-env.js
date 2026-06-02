#!/usr/bin/env node

const { loadRootEnv } = require("./load-root-env");
const { killProcessTree, spawnCommand } = require("./process-utils");

loadRootEnv();

const [command, ...args] = process.argv.slice(2);

if (!command) {
  console.error("Usage: node scripts/run-with-env.js <command> [...args]");
  process.exit(1);
}

let child;
let shuttingDown = false;
try {
  child = spawnCommand(command, args, {
    env: process.env,
    stdio: "inherit",
    windowsHide: true,
  });
} catch (error) {
  console.error(`[run-with-env] failed to start ${command}: ${error.message}`);
  process.exit(1);
}

function stopChild(signal) {
  if (shuttingDown) return;
  shuttingDown = true;

  console.log(`[run-with-env] received ${signal}, stopping ${command}`);
  killProcessTree(child);

  setTimeout(() => process.exit(0), 1000).unref();
}

child.on("error", (error) => {
  console.error(`[run-with-env] failed to start ${command}: ${error.message}`);
  process.exit(1);
});

child.on("exit", (code, signal) => {
  if (shuttingDown) {
    process.exit(0);
  }

  if (signal) {
    console.error(`[run-with-env] ${command} exited from signal ${signal}`);
    process.exit(1);
  }

  process.exit(code ?? 0);
});

process.on("SIGINT", () => stopChild("SIGINT"));
process.on("SIGTERM", () => stopChild("SIGTERM"));
