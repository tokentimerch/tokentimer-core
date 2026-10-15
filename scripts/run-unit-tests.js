#!/usr/bin/env node
"use strict";

const { spawnSync } = require("child_process");
const { readdirSync } = require("fs");
const path = require("path");

const unitDir = path.join(__dirname, "..", "tests", "unit");
const files = readdirSync(unitDir)
  .filter((name) => name.endsWith(".test.js"))
  .map((name) => path.join(unitDir, name))
  .sort();

if (files.length === 0) {
  console.error("No unit test files found in tests/unit");
  process.exit(1);
}

const concurrency = process.env.TEST_CONCURRENCY;
if (concurrency && !/^[1-9][0-9]?$/.test(concurrency)) throw new Error("TEST_CONCURRENCY must be 1..99");
const result = spawnSync(process.execPath, ["--test", ...(concurrency ? [`--test-concurrency=${concurrency}`] : []), ...files], {
  stdio: "inherit",
  env: { ...process.env, NODE_ENV: "test" },
});

process.exit(typeof result.status === "number" ? result.status : 1);
