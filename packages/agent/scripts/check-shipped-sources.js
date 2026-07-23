"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const packageRoot = path.resolve(__dirname, "..");
const sourceRoots = [path.join(packageRoot, "bin"), path.join(packageRoot, "src")];

function collectShippedJavaScript(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) return collectShippedJavaScript(entryPath);
    if (entry.isFile() && entry.name.endsWith(".js") && !entry.name.endsWith(".test.js")) {
      return [entryPath];
    }
    return [];
  });
}

const files = sourceRoots.flatMap(collectShippedJavaScript).sort();
for (const file of files) {
  const result = spawnSync(process.execPath, ["--check", file], { stdio: "inherit" });
  if (result.status !== 0) process.exit(result.status || 1);
}

process.stdout.write(`Validated ${files.length} shipped agent JavaScript files.\n`);
