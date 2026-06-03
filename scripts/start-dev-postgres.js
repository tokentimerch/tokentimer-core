#!/usr/bin/env node

const path = require("path");
const { spawnSync } = require("child_process");

const COMPOSE_FILE = "deploy/compose/docker-compose.postgres.yml";

function startDevPostgres(repoRoot, { stdio = "inherit" } = {}) {
  const composePath = path.join(repoRoot, COMPOSE_FILE);

  console.log("[dev] starting PostgreSQL");

  const result = spawnSync(
    "docker",
    ["compose", "-f", composePath, "up", "-d", "--wait"],
    {
      cwd: repoRoot,
      env: process.env,
      stdio,
    },
  );

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    const error = new Error("PostgreSQL failed to start");
    error.exitCode = result.status || 1;
    throw error;
  }

  console.log("[dev] PostgreSQL ready");
}

if (require.main === module) {
  const { loadRootEnv } = require("./load-root-env");
  const repoRoot = loadRootEnv();

  try {
    startDevPostgres(repoRoot);
  } catch (error) {
    console.error(`[dev] ${error.message}`);
    process.exit(error.exitCode || 1);
  }
}

module.exports = {
  COMPOSE_FILE,
  startDevPostgres,
};
