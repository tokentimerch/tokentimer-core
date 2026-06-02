#!/usr/bin/env node

const { loadRootEnv } = require("./load-root-env");
const { spawnCommand } = require("./process-utils");

loadRootEnv();

const [command, ...args] = process.argv.slice(2);

if (!command) {
  console.error("Usage: node scripts/run-with-env.js <command> [...args]");
  process.exit(1);
}

let child;
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

child.on("error", (error) => {
  console.error(`[run-with-env] failed to start ${command}: ${error.message}`);
  process.exit(1);
});

child.on("exit", (code, signal) => {
  if (signal) {
    console.error(`[run-with-env] ${command} exited from signal ${signal}`);
    process.exit(1);
  }

  process.exit(code ?? 0);
});
