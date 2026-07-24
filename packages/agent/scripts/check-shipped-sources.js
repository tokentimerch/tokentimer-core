"use strict";

/**
 * Validates that every shipped agent JavaScript file:
 *   1. Parses under the current Node (node --check)
 *   2. Does not require/import paths that resolve outside packages/agent
 *
 * The installer copies only this package directory, so monorepo-relative
 * imports (packages/log-scrub, apps/api, packages/contracts, ...) are
 * release blockers. Keep shared helpers under packages/agent/vendor instead.
 */

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const packageRoot = path.resolve(__dirname, "..");
const sourceRoots = [
  path.join(packageRoot, "bin"),
  path.join(packageRoot, "src"),
  path.join(packageRoot, "vendor"),
];

const REQUIRE_PATTERN =
  /(?:require\s*\(\s*|import\s*\(\s*|from\s+)(['"])([^'"]+)\1/g;

function collectShippedJavaScript(directory) {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) return collectShippedJavaScript(entryPath);
    if (entry.isFile() && entry.name.endsWith(".js") && !entry.name.endsWith(".test.js")) {
      return [entryPath];
    }
    if (entry.isFile() && entry.name.endsWith(".cjs")) {
      return [entryPath];
    }
    return [];
  });
}

function isBuiltinOrPackageName(specifier) {
  if (specifier.startsWith("node:")) return true;
  if (!specifier.startsWith(".") && !specifier.startsWith("/")) return true;
  return false;
}

function assertImportStaysInsidePackage(filePath, specifier) {
  if (isBuiltinOrPackageName(specifier)) return null;
  const resolved = path.resolve(path.dirname(filePath), specifier);
  const relative = path.relative(packageRoot, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    return `escapes package root via ${specifier} -> ${resolved}`;
  }
  return null;
}

const files = sourceRoots.flatMap(collectShippedJavaScript).sort();
const importErrors = [];

for (const file of files) {
  const result = spawnSync(process.execPath, ["--check", file], { stdio: "inherit" });
  if (result.status !== 0) process.exit(result.status || 1);

  const source = fs.readFileSync(file, "utf8");
  REQUIRE_PATTERN.lastIndex = 0;
  let match;
  while ((match = REQUIRE_PATTERN.exec(source))) {
    const specifier = match[2];
    const problem = assertImportStaysInsidePackage(file, specifier);
    if (problem) {
      importErrors.push(`${path.relative(packageRoot, file)}: ${problem}`);
    }
  }
}

if (importErrors.length > 0) {
  process.stderr.write(
    "check-shipped-sources: shipped agent sources must be self-contained.\n" +
      "The installer only copies packages/agent; fix these monorepo-relative imports:\n" +
      importErrors.map((line) => `  - ${line}`).join("\n") +
      "\n",
  );
  process.exit(1);
}

process.stdout.write(
  `Validated ${files.length} shipped agent JavaScript files (syntax + self-contained imports).\n`,
);
