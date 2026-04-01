#!/usr/bin/env node
"use strict";

const { spawnSync } = require("child_process");
const path = require("path");

const isWin = process.platform === "win32";
const repoRoot = path.resolve(__dirname, "..");
const suite = process.argv[2] || process.env.TT_TEST_SUITE || "core";

const result = spawnSync("bash", ["scripts/run-tests.sh"], {
  cwd: repoRoot,
  stdio: "inherit",
  shell: isWin,
  env: {
    ...process.env,
    NODE_ENV: process.env.NODE_ENV || "test",
    TT_TEST_SUITE: suite,
  },
});

process.exit(typeof result.status === "number" ? result.status : 1);
