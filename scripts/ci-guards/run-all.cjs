#!/usr/bin/env node
"use strict";

// Discovery/runner for this directory's CI guards: globs every other
// *.cjs file in this directory, runs each with `node`, and reports all
// failures together rather than stopping at the first one - a guard
// suite is only useful if a broken guard doesn't hide the next one.
// Wired as `pnpm verify:ci-guards` in the root package.json.

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const here = __dirname;
const selfName = path.basename(__filename);

function discoverGuards() {
  return fs
    .readdirSync(here, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".cjs") && entry.name !== selfName)
    .map((entry) => entry.name)
    .sort();
}

function runGuard(name) {
  const abs = path.join(here, name);
  const result = spawnSync(process.execPath, [abs], {
    encoding: "utf8",
  });
  return {
    name,
    exitCode: result.status,
    stdout: result.stdout || "",
    stderr: result.stderr || "",
    error: result.error || null,
  };
}

function main() {
  const guards = discoverGuards();
  if (guards.length === 0) {
    console.error("::error::run-all: no guard scripts found in scripts/ci-guards/");
    process.exit(1);
  }

  const results = guards.map(runGuard);
  const failed = results.filter((r) => r.error || r.exitCode !== 0);

  for (const r of results) {
    if (r.stdout.trim()) process.stdout.write(r.stdout);
    if (r.stderr.trim()) process.stderr.write(r.stderr);
  }

  console.log("");
  console.log(`run-all: ${results.length} guard(s) run, ${failed.length} failed`);
  for (const r of results) {
    const status = r.error || r.exitCode !== 0 ? "FAIL" : "ok";
    console.log(`  [${status}] ${r.name}`);
  }

  if (failed.length > 0) {
    console.error(
      `::error::run-all: ${failed.length} guard(s) failed: ${failed.map((r) => r.name).join(", ")}`,
    );
    process.exit(1);
  }
}

main();
