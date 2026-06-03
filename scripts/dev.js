#!/usr/bin/env node

const { loadRootEnv } = require("./load-root-env");
const { startDevPostgres } = require("./start-dev-postgres");
const { assertDevPortsAvailable } = require("./check-dev-ports");
const {
  HARD_SHUTDOWN_MS,
  killProcessTree,
  spawnCommand,
} = require("./process-utils");

const repoRoot = loadRootEnv();
const children = new Map();
let shuttingDown = false;
const skipPostgres = process.argv.includes("--no-db");

const services = [
  {
    name: "api",
    args: ["--filter", "@tokentimer/api", "dev"],
  },
  {
    name: "worker",
    args: ["--filter", "@tokentimer/worker", "dev"],
  },
  {
    name: "dashboard",
    args: ["--filter", "@tokentimer/dashboard", "dev"],
  },
];

function stopAll(exitCode) {
  if (shuttingDown) return;
  shuttingDown = true;

  for (const child of children.values()) {
    killProcessTree(child);
  }

  setTimeout(() => process.exit(exitCode), HARD_SHUTDOWN_MS).unref();
}

function startServices() {
  for (const service of services) {
    console.log(`[dev] starting ${service.name}`);

    let child;
    try {
      child = spawnCommand("pnpm", service.args, {
        cwd: repoRoot,
        env: process.env,
        stdio: "inherit",
        windowsHide: true,
      });
    } catch (error) {
      console.error(`[dev] ${service.name} failed to start: ${error.message}`);
      stopAll(1);
      break;
    }

    children.set(service.name, child);

    child.on("error", (error) => {
      console.error(`[dev] ${service.name} failed to start: ${error.message}`);
      stopAll(1);
    });

    child.on("exit", (code, signal) => {
      children.delete(service.name);
      if (shuttingDown) return;

      const detail = signal ? `signal ${signal}` : `code ${code}`;
      console.error(`[dev] ${service.name} exited with ${detail}`);
      stopAll(code && code > 0 ? code : 1);
    });
  }
}

async function main() {
  if (!skipPostgres) {
    try {
      startDevPostgres(repoRoot);
    } catch (error) {
      console.error(`[dev] ${error.message}`);
      console.error(
        "[dev] Use pnpm run dev:noDB if you manage PostgreSQL yourself.",
      );
      process.exit(error.exitCode || 1);
    }
  }

  try {
    await assertDevPortsAvailable({
      apiPort: Number(process.env.PORT || 4000),
      dashboardPort: Number(process.env.DASHBOARD_PORT || 5173),
    });
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }

  startServices();
}

process.on("SIGINT", () => {
  console.log("[dev] stopping");
  stopAll(0);
});

process.on("SIGTERM", () => {
  console.log("[dev] stopping");
  stopAll(0);
});

main().catch((error) => {
  console.error(`[dev] ${error.message}`);
  process.exit(1);
});
