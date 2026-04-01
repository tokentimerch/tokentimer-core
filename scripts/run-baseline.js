#!/usr/bin/env node
"use strict";

const { spawnSync } = require("child_process");
const path = require("path");

const isWin = process.platform === "win32";
const repoRoot = path.resolve(__dirname, "..");

function run(command, args, envPatch = {}) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    stdio: "inherit",
    shell: isWin,
    env: { ...process.env, ...envPatch },
  });
  return typeof result.status === "number" ? result.status : 1;
}

let code = run("pnpm", ["run", "check:contracts"]);
if (code !== 0) process.exit(code);

code = run("pnpm", ["run", "check:contracts:integrity"]);
if (code !== 0) process.exit(code);

code = run("pnpm", ["run", "test:contracts"]);
process.exit(code);
