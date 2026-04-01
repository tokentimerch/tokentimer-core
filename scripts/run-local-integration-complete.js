#!/usr/bin/env node
"use strict";

const { spawnSync } = require("child_process");
const path = require("path");

const isWin = process.platform === "win32";
const repoRoot = path.resolve(__dirname, "..");

const result = spawnSync("node", ["scripts/run-tests-local.js", "all"], {
  cwd: repoRoot,
  stdio: "inherit",
  shell: isWin,
  env: { ...process.env, NODE_ENV: process.env.NODE_ENV || "test" },
});

process.exit(typeof result.status === "number" ? result.status : 1);
