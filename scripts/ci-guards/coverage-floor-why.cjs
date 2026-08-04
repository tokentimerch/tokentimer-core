#!/usr/bin/env node
"use strict";

// Guard: enforces mandatory why: rationale on every coverage floor.
// scripts/coverage-floors.cjs is the single source of truth for per-package
// coverage floors (consumed by scripts/check-coverage-threshold.js via
// --config/--package); this guard asserts every numeric threshold value in
// that file has a `// why:`
// comment directly above it (or as the last line of a short comment block
// directly above it) explaining the number.
//
// This cannot verify a why: comment is a GOOD reason, only that a reason
// was written down at all. The actual rule this exists to support:
//
//   NEVER LOWER A COVERAGE FLOOR TO MAKE CI GREEN.
//
// A floor may only move for a real reason (see the header of
// scripts/coverage-floors.cjs for the specific list). "The number is red,
// lower the number until it is green" is not a valid why: and a human
// reviewer, not this guard, is responsible for catching that in review;
// this guard only guarantees the reviewer has something to actually read.

const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..");
const CONFIG_PATH = path.join(repoRoot, "scripts", "coverage-floors.cjs");

// Matches a numeric object-literal property, e.g. `  lines: 50,` or
// `    functions: 45`. Deliberately simple/line-oriented (this guard scans
// exactly one small, hand-maintained config file, not arbitrary JS).
const NUMERIC_KEY_RE = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*-?\d+(\.\d+)?\s*,?\s*$/;

function relConfigPath() {
  return path.relative(repoRoot, CONFIG_PATH).replace(/\\/g, "/");
}

function hasWhyCommentAbove(lines, index) {
  const LOOKBACK_LIMIT = 10;
  for (
    let i = index - 1;
    i >= 0 && i >= index - LOOKBACK_LIMIT;
    i -= 1
  ) {
    const trimmed = lines[i].trim();
    if (trimmed === "") continue;
    if (!trimmed.startsWith("//")) return false;
    if (/^\/\/\s*why:/i.test(trimmed)) return true;
    // Keep walking upward through a multi-line comment block that ends
    // (closest to the key) in a why: line; a block with unrelated
    // commentary above a why: line is still acceptable.
  }
  return false;
}

function main() {
  if (!fs.existsSync(CONFIG_PATH)) {
    console.error(
      `::error file=${relConfigPath()}::coverage-floor-why: config file not found`,
    );
    process.exit(1);
  }

  const text = fs.readFileSync(CONFIG_PATH, "utf8");
  const lines = text.split("\n");
  const problems = [];
  let numericKeysFound = 0;

  for (let i = 0; i < lines.length; i += 1) {
    const match = lines[i].match(NUMERIC_KEY_RE);
    if (!match) continue;
    numericKeysFound += 1;
    if (!hasWhyCommentAbove(lines, i)) {
      problems.push(
        `${relConfigPath()}:${i + 1}: threshold "${match[1]}" has no ` +
          "// why: comment directly above it",
      );
    }
  }

  if (numericKeysFound === 0) {
    console.error(
      `::error file=${relConfigPath()}::coverage-floor-why: no numeric ` +
        "threshold keys found; the config file may be malformed or the " +
        "guard's pattern needs updating",
    );
    process.exit(1);
  }

  if (problems.length > 0) {
    for (const problem of problems) {
      console.error(`::error::coverage-floor-why: ${problem}`);
    }
    process.exit(1);
  }

  console.log(
    `coverage-floor-why: ok (${numericKeysFound} threshold(s), all have a why: comment)`,
  );
}

main();
