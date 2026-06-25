#!/usr/bin/env node
"use strict";

const path = require("path");
const { spawnSync } = require("child_process");

const repoRoot = path.resolve(__dirname, "..");
const composeDir = path.join(repoRoot, "deploy", "compose");

const COMPOSE_STACKS = [
  {
    label: "full stack (docker-compose.yml)",
    file: path.join(composeDir, "docker-compose.yml"),
  },
  {
    label: "dev stack (docker-compose.dev.yml)",
    file: path.join(composeDir, "docker-compose.dev.yml"),
  },
  {
    label: "postgres-only (docker-compose.postgres.yml)",
    file: path.join(composeDir, "docker-compose.postgres.yml"),
  },
];

function downStack({ label, file }) {
  console.log(`[docker:down] stopping ${label}`);
  const result = spawnSync(
    "docker",
    ["compose", "-f", file, "down", "--remove-orphans"],
    {
      cwd: repoRoot,
      stdio: "inherit",
      shell: process.platform === "win32",
    },
  );
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.exit(result.status || 1);
  }
}

if (require.main === module) {
  for (const stack of COMPOSE_STACKS) {
    downStack(stack);
  }
  console.log("[docker:down] local infra stopped");
}

module.exports = { COMPOSE_STACKS, downStack };
