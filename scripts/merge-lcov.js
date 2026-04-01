#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

function readIfExists(filePath) {
  try {
    if (!fs.existsSync(filePath)) return "";
    return fs.readFileSync(filePath, "utf8");
  } catch (_) {
    return "";
  }
}

function normalizeLcov(content) {
  return String(content || "")
    .replace(/\r\n/g, "\n")
    .trim();
}

function main() {
  const [, , backendLcov, frontendLcov, outputLcov] = process.argv;
  if (!backendLcov || !frontendLcov || !outputLcov) {
    console.error(
      "Usage: node scripts/merge-lcov.js <backend-lcov> <frontend-lcov> <output-lcov>",
    );
    process.exit(1);
  }

  const backend = normalizeLcov(readIfExists(path.resolve(backendLcov)));
  const frontend = normalizeLcov(readIfExists(path.resolve(frontendLcov)));

  if (!backend && !frontend) {
    console.error("merge-lcov: no lcov data found to merge");
    process.exit(1);
  }

  const merged = [backend, frontend].filter(Boolean).join("\n");
  fs.mkdirSync(path.dirname(path.resolve(outputLcov)), { recursive: true });
  fs.writeFileSync(path.resolve(outputLcov), `${merged}\n`, "utf8");
  console.log(
    `merge-lcov: wrote merged lcov to ${outputLcov} (${merged.split("\n").length} lines)`,
  );
}

main();
