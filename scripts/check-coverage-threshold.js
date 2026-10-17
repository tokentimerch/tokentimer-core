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

function parseLcovTotals(text, packageName, lcovPath) {
  const lines = String(text || "").split(/\r?\n/);
  const totals = { lf: 0, lh: 0, brf: 0, brh: 0, fnf: 0, fnh: 0 };
  let record = null;
  let sources = 0;
  const selected = (source) => {
    const normalized = source.replaceAll("\\", "/");
    if (packageName === "backend")
      return /(?:^|\/)(?:apps\/(?:api|worker)|packages\/config)\//.test(normalized);
    if (packageName === "frontend") {
      // Vitest's dashboard-relative report uses SF:src/...; c8 reports may
      // instead carry repository-relative or absolute source paths.
      return /(?:^|\/)apps\/dashboard\//.test(normalized) ||
        (normalized.startsWith("src/") &&
          path.resolve(path.dirname(lcovPath)) ===
            path.resolve(__dirname, "../apps/dashboard/coverage"));
    }
    return true;
  };
  for (const line of lines) {
    if (line.startsWith("SF:")) {
      if (record || !line.slice(3).trim()) throw new Error("invalid LCOV source record");
      record = { source: line.slice(3) };
    } else if (/^(?:LF|LH|BRF|BRH|FNF|FNH):/.test(line)) {
      const match = /^(LF|LH|BRF|BRH|FNF|FNH):(\d+)$/.exec(line);
      if (!match) throw new Error("invalid LCOV coverage count");
      const [, field, raw] = match;
      const key = field.toLowerCase();
      if (!record || record[key] !== undefined ||
          !Number.isSafeInteger(Number(raw))) throw new Error("invalid LCOV coverage count");
      record[key] = Number(raw);
    } else if (line === "end_of_record") {
      if (!record || record.lf === undefined || record.lh === undefined)
        throw new Error("LCOV record lacks instrumented line evidence");
      for (const [found, hit] of [["lf", "lh"], ["brf", "brh"], ["fnf", "fnh"]]) {
        if ((record[found] === undefined) !== (record[hit] === undefined))
          throw new Error("incomplete LCOV coverage count pair");
        if ((record[hit] ?? 0) > (record[found] ?? 0))
          throw new Error("inconsistent LCOV coverage counts");
      }
      if (selected(record.source)) {
        if (record.lf > 0) sources++;
        for (const key of Object.keys(totals)) totals[key] += record[key] ?? 0;
      }
      record = null;
    }
  }
  if (record) throw new Error("unterminated LCOV source record");
  if (sources === 0 || totals.lf === 0)
    throw new Error("no instrumented source lines for selected package");
  return totals;
}

function pct(hit, found) {
  if (!found) return 100;
  return (hit / found) * 100;
}

// Loads per-package floors from scripts/coverage-floors.cjs (the
// `why:`-commented, guarded config file; see
// scripts/ci-guards/coverage-floor-why.cjs) when --config and --package
// are both given. Explicit --lines/--branches/--functions/--statements
// flags still take precedence when present, so direct ad hoc invocations
// keep working unchanged.
function loadConfigFloors() {
  const configPath = argValue("--config");
  const pkg = argValue("--package");
  if (!configPath || !pkg) return null;
  const resolved = path.resolve(configPath);
  const config = require(resolved);
  const floors = config[pkg];
  if (!floors) {
    console.error(
      `coverage-check: package "${pkg}" not found in ${resolved} (available: ${Object.keys(config).join(", ")})`,
    );
    process.exit(1);
  }
  return floors;
}

function main() {
  const lcovPath = path.resolve(argValue("--lcov", "coverage/lcov.info"));
  const configFloors = loadConfigFloors();
  const minLines = parseNum("--lines", configFloors ? configFloors.lines : 0);
  const minBranches = parseNum(
    "--branches",
    configFloors ? configFloors.branches : 0,
  );
  const minFunctions = parseNum(
    "--functions",
    configFloors ? configFloors.functions : 0,
  );
  const minStatements = parseNum(
    "--statements",
    configFloors ? configFloors.statements : minLines,
  );

  if (!fs.existsSync(lcovPath)) {
    console.error(`coverage-check: lcov file not found at ${lcovPath}`);
    process.exit(1);
  }

  const content = fs.readFileSync(lcovPath, "utf8");
  let totals;
  try {
    totals = parseLcovTotals(content, argValue("--package"), lcovPath);
  } catch (error) {
    console.error(`coverage-check: ${error.message}`);
    process.exit(1);
  }
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
