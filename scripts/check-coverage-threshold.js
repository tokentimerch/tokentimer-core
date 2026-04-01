#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

function argValue(flag, fallback = null) {
  const idx = process.argv.indexOf(flag);
  if (idx === -1) return fallback;
  const next = process.argv[idx + 1];
  return next == null ? fallback : next;
}

function parseNum(flag, fallback) {
  const raw = argValue(flag, String(fallback));
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

function parseLcovTotals(text) {
  const lines = String(text || "").split(/\r?\n/);
  let lf = 0;
  let lh = 0;
  let brf = 0;
  let brh = 0;
  let fnf = 0;
  let fnh = 0;
  for (const line of lines) {
    if (line.startsWith("LF:")) lf += Number(line.slice(3)) || 0;
    else if (line.startsWith("LH:")) lh += Number(line.slice(3)) || 0;
    else if (line.startsWith("BRF:")) brf += Number(line.slice(4)) || 0;
    else if (line.startsWith("BRH:")) brh += Number(line.slice(4)) || 0;
    else if (line.startsWith("FNF:")) fnf += Number(line.slice(4)) || 0;
    else if (line.startsWith("FNH:")) fnh += Number(line.slice(4)) || 0;
  }
  return { lf, lh, brf, brh, fnf, fnh };
}

function pct(hit, found) {
  if (!found) return 100;
  return (hit / found) * 100;
}

function main() {
  const lcovPath = path.resolve(argValue("--lcov", "coverage/lcov.info"));
  const minLines = parseNum("--lines", 0);
  const minBranches = parseNum("--branches", 0);
  const minFunctions = parseNum("--functions", 0);
  const minStatements = parseNum("--statements", minLines);

  if (!fs.existsSync(lcovPath)) {
    console.error(`coverage-check: lcov file not found at ${lcovPath}`);
    process.exit(1);
  }

  const content = fs.readFileSync(lcovPath, "utf8");
  const totals = parseLcovTotals(content);
  const linesPct = pct(totals.lh, totals.lf);
  const branchesPct = pct(totals.brh, totals.brf);
  const functionsPct = pct(totals.fnh, totals.fnf);
  const statementsPct = linesPct;

  const report = {
    lines: Number(linesPct.toFixed(2)),
    branches: Number(branchesPct.toFixed(2)),
    functions: Number(functionsPct.toFixed(2)),
    statements: Number(statementsPct.toFixed(2)),
  };

  console.log("coverage-check:", report);

  const failures = [];
  if (report.lines < minLines)
    failures.push(`lines ${report.lines} < ${minLines}`);
  if (report.branches < minBranches) {
    failures.push(`branches ${report.branches} < ${minBranches}`);
  }
  if (report.functions < minFunctions) {
    failures.push(`functions ${report.functions} < ${minFunctions}`);
  }
  if (report.statements < minStatements) {
    failures.push(`statements ${report.statements} < ${minStatements}`);
  }

  if (failures.length > 0) {
    console.error("coverage-check failed:", failures.join("; "));
    process.exit(1);
  }
}

main();
