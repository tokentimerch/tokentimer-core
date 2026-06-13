#!/usr/bin/env node
"use strict";

// Asserts that pnpm-lock.yaml actually resolves the security-patched versions
// pinned in pnpm-workspace.yaml overrides. This catches the failure mode where
// override configuration moves (or is duplicated) and silently stops applying.
// Mirror of the tokentimer-cloud checker, with the core override set.

const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..");
const lockPath = path.join(repoRoot, "pnpm-lock.yaml");
const pkgPath = path.join(repoRoot, "package.json");

// name -> { major: expected version } ; major "*" means any major.
// Keep in sync with the overrides block in pnpm-workspace.yaml.
const REQUIRED_PINS = {
  tar: { "*": "7.5.7" },
  "fast-xml-parser": { "*": "5.7.3" },
  minimatch: { "*": "9.0.9" },
  "brace-expansion": { "*": "2.0.3" },
  "path-to-regexp": { "*": "8.4.0" },
  yaml: { "*": "1.10.3" },
  rollup: { "*": "4.60.0" },
  flatted: { "*": "3.4.2" },
  "serialize-javascript": { "*": "7.0.5" },
  picomatch: { 2: "2.3.2", 4: "4.0.4" },
  ajv: { 6: "6.15.0" },
  lodash: { "*": "4.18.1" },
  "follow-redirects": { "*": "1.16.0" },
  postcss: { "*": "8.5.12" },
  qs: { "*": "6.15.2" },
  "ip-address": { "*": "10.2.0" },
};

function fail(message) {
  console.error(`check-lockfile-overrides: ${message}`);
  process.exit(1);
}

if (!fs.existsSync(lockPath)) {
  fail("pnpm-lock.yaml not found");
}

// Guard against introducing a second override location: pnpm-workspace.yaml
// is canonical.
const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
if (pkg.pnpm && pkg.pnpm.overrides) {
  fail(
    "package.json contains pnpm.overrides; the canonical override location is pnpm-workspace.yaml (remove the package.json set to avoid two diverging sources)",
  );
}

const lock = fs.readFileSync(lockPath, "utf8");
const problems = [];
let checked = 0;

for (const [name, pins] of Object.entries(REQUIRED_PINS)) {
  // Match resolved package keys, e.g. "  lodash@4.18.1:" or
  // "  'brace-expansion@2.0.3':" and dependency specs "lodash: 4.18.1".
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const keyPattern = new RegExp(`^\\s+'?${escaped}@(\\d+)((?:\\.\\d+)+[^':\\s(]*)'?:`, "gm");
  const found = new Set();
  let match;
  while ((match = keyPattern.exec(lock)) !== null) {
    found.add(`${match[1]}${match[2]}`);
  }
  for (const version of found) {
    checked++;
    const major = version.split(".")[0];
    const expected = pins[major] ?? pins["*"];
    if (expected === undefined) {
      continue; // major not covered by a pin
    }
    if (version !== expected) {
      problems.push(`${name}@${version} resolved in lockfile but override requires ${expected}`);
    }
  }
}

if (problems.length > 0) {
  for (const problem of problems) {
    console.error(`check-lockfile-overrides: ${problem}`);
  }
  fail(`${problems.length} security override pin(s) not honored by pnpm-lock.yaml`);
}

console.log(`check-lockfile-overrides: ok (${checked} resolved version(s) checked against required pins)`);
