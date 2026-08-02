#!/usr/bin/env node
"use strict";

// Quality/CI backlog item 12 (bonus): a quick structural snapshot of the
// test suite's shape, so a restack/rebase that silently drops a test file
// (or an entire describe block, or every it() inside one) shows up as a
// number that moved, not as silence.
//
// This is intentionally a snapshot printer, not a gate: unlike the skip
// inventory (item 2), there is no "correct" test count to diff against, so
// this does not fail CI on its own. Run it before and after a restack/rebase
// and compare the numbers by eye, or pipe --json into your own diff.
//
// Definitions (line-oriented heuristics, not a JS parser, same tradeoff as
// scripts/generate-skip-inventory.cjs):
//   test files    every *.test.js / *.spec.js file under tests/, packages/,
//                 apps/ (identical discovery to generate-skip-inventory.cjs,
//                 so the two scripts can never disagree about what counts as
//                 a test file)
//   tests         every describe(...) call: a named grouping of test cases
//   subtests      every it(...) / test(...) call: one leaf test case,
//                 counted whether or not it is skipped
//   fuzz targets  every it(...) / test(...) call whose body invokes
//                 fast-check's fc.assert(...) or fc.property(...), a
//                 property-based test that throws many generated inputs at
//                 one code path rather than asserting one fixed example
//   skips         delegates to generate-skip-inventory.cjs's own count, so
//                 this script's skip number and the skip inventory's skip
//                 number can never drift apart from each other
//
// Usage:
//   pnpm qa:stats            human-readable summary
//   pnpm qa:stats --json     machine-readable summary

const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..");
const { buildInventory } = require("./generate-skip-inventory.cjs");

const SEARCH_DIRS = ["tests", "packages", "apps"];
const IGNORED_DIR_NAMES = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "coverage",
  ".coverage",
  ".build",
]);

function isTestFile(name) {
  return /\.test\.jsx?$/.test(name) || /\.spec\.jsx?$/.test(name);
}

function walk(dir, out) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (_err) {
    return;
  }
  for (const entry of entries) {
    if (IGNORED_DIR_NAMES.has(entry.name)) continue;
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(abs, out);
    } else if (entry.isFile() && isTestFile(entry.name)) {
      out.push(abs);
    }
  }
}

function discoverTestFiles() {
  const out = [];
  for (const dirName of SEARCH_DIRS) {
    walk(path.join(repoRoot, dirName), out);
  }
  return out.sort();
}

// describe(...) / describe.skip(...) / describe.only(...): a suite grouping.
const DESCRIBE_RE = /\bdescribe(?:\.(?:skip|only))?\s*\(/g;
// it(...) / test(...) with their .skip/.only variants: one leaf test case.
const IT_OR_TEST_RE = /\b(?:it|test)(?:\.(?:skip|only))?\s*\(/g;
// fast-check's two entry points for a property-based assertion.
const FUZZ_CALL_RE = /\bfc\.(?:assert|property)\s*\(/g;

function countMatches(text, regex) {
  const matches = text.match(regex);
  return matches ? matches.length : 0;
}

function scanFile(absPath) {
  const text = fs.readFileSync(absPath, "utf8");
  return {
    tests: countMatches(text, DESCRIBE_RE),
    subtests: countMatches(text, IT_OR_TEST_RE),
    fuzzTargets: countMatches(text, FUZZ_CALL_RE),
  };
}

function buildStats() {
  const files = discoverTestFiles();
  let tests = 0;
  let subtests = 0;
  let fuzzTargets = 0;
  const perFile = [];
  for (const file of files) {
    const result = scanFile(file);
    tests += result.tests;
    subtests += result.subtests;
    fuzzTargets += result.fuzzTargets;
    perFile.push({
      file: path.relative(repoRoot, file).replace(/\\/g, "/"),
      ...result,
    });
  }
  const skips = buildInventory().length;
  return {
    generatedAt: new Date().toISOString(),
    testFileCount: files.length,
    testCount: tests,
    subtestCount: subtests,
    fuzzTargetCount: fuzzTargets,
    skipCount: skips,
    perFile,
  };
}

function renderHuman(stats) {
  const lines = [];
  lines.push("qa:stats snapshot");
  lines.push(`  test files:   ${stats.testFileCount}`);
  lines.push(`  tests:        ${stats.testCount}  (describe(...) blocks)`);
  lines.push(`  subtests:     ${stats.subtestCount}  (it(...)/test(...) cases)`);
  lines.push(`  fuzz targets: ${stats.fuzzTargetCount}  (fc.assert/fc.property calls)`);
  lines.push(`  skips:        ${stats.skipCount}  (see docs/certops/skip-inventory.generated.md)`);
  return lines.join("\n");
}

function main() {
  const args = process.argv.slice(2);
  const asJson = args.includes("--json");
  const stats = buildStats();

  if (asJson) {
    console.log(JSON.stringify(stats, null, 2));
  } else {
    console.log(renderHuman(stats));
  }
}

if (require.main === module) {
  main();
}

module.exports = { buildStats, renderHuman, discoverTestFiles };
