#!/usr/bin/env node
"use strict";

const { spawnSync } = require("child_process");
const path = require("path");
const { existsSync } = require("fs");

const repoRoot = path.resolve(__dirname, "..");
const isWin = process.platform === "win32";

function run(command, args, envPatch = {}) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    stdio: "inherit",
    shell: isWin,
    env: {
      ...process.env,
      CI: process.env.CI || "true",
      CONTRACT_API_REQUIRED: process.env.CONTRACT_API_REQUIRED || "0",
      TT_IMAGE_TAG: process.env.TT_IMAGE_TAG || "ci-local",
      ...envPatch,
    },
  });
  return typeof result.status === "number" ? result.status : 1;
}

function ensureInstall(cwd) {
  const modulesMarker = path.join(cwd, "node_modules", ".modules.yaml");
  const forceInstall = process.env.TT_FORCE_INSTALL === "1";
  if (!forceInstall && existsSync(modulesMarker)) {
    console.log(
      `==> Dependencies already present in ${cwd}, skipping install.`,
    );
    return 0;
  }
  console.log(`==> Installing dependencies in ${cwd}...`);
  return run(
    "pnpm",
    [
      "install",
      "--frozen-lockfile",
      "--ignore-scripts",
      "--prefer-offline",
      "--child-concurrency=1",
    ],
    {},
  );
}

let code = ensureInstall(repoRoot);
if (code !== 0) process.exit(code);

code = run("pnpm", ["run", "check:contracts"]);
if (code !== 0) process.exit(code);

code = run("pnpm", ["run", "check:contracts:integrity"]);
if (code !== 0) process.exit(code);

code = run("pnpm", ["run", "test:contracts"]);
if (code !== 0) process.exit(code);

code = run("pnpm", ["run", "test:baseline"]);
if (code !== 0) process.exit(code);

const integrationEnvPatch =
  process.env.TT_SKIP_COMPOSE_BUILD === undefined
    ? { TT_SKIP_COMPOSE_BUILD: "1" }
    : { TT_SKIP_COMPOSE_BUILD: process.env.TT_SKIP_COMPOSE_BUILD };

code = run(
  "pnpm",
  ["run", "test:local:integration:complete"],
  integrationEnvPatch,
);
process.exit(code);
