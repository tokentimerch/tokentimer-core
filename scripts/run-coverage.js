#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const { pathToFileURL } = require("node:url");

const repoRoot = path.resolve(__dirname, "..");
const coverageRoot = path.join(repoRoot, ".coverage");
const v8Dir = path.join(coverageRoot, "v8");
const suite =
  process.argv[2] && !process.argv[2].startsWith("--")
    ? process.argv[2]
    : "core";
const cleanOnly = process.argv.includes("--clean-only");
const collectOnly = process.argv.includes("--collect-only");

const containerCoverageDirs = [
  {
    dir: path.join(coverageRoot, "v8-api"),
    pathMap: [["file:///app/apps/api/", pathToFileURL(path.join(repoRoot, "apps", "api") + path.sep).href]],
  },
  {
    dir: path.join(coverageRoot, "v8-worker-delivery"),
    pathMap: [["file:///app/apps/worker/", pathToFileURL(path.join(repoRoot, "apps", "worker") + path.sep).href]],
  },
  {
    dir: path.join(coverageRoot, "v8-worker-endpoint"),
    pathMap: [["file:///app/apps/worker/", pathToFileURL(path.join(repoRoot, "apps", "worker") + path.sep).href]],
  },
  {
    dir: path.join(coverageRoot, "v8-worker-sync"),
    pathMap: [["file:///app/apps/worker/", pathToFileURL(path.join(repoRoot, "apps", "worker") + path.sep).href]],
  },
];

function run(cmd, args, envPatch = {}) {
  const res = spawnSync(cmd, args, {
    cwd: repoRoot,
    stdio: "inherit",
    shell: process.platform === "win32",
    env: { ...process.env, ...envPatch },
  });
  return typeof res.status === "number" ? res.status : 1;
}

function cleanCoverageDirs() {
  fs.rmSync(path.join(repoRoot, "coverage"), { recursive: true, force: true });
  fs.rmSync(coverageRoot, { recursive: true, force: true });
  fs.mkdirSync(v8Dir, { recursive: true });
  for (const { dir } of containerCoverageDirs) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

// V8 files are serialized JSON. A raw Windows path would insert unescaped
// backslashes; canonical file URLs preserve JSON and c8's source identity.
function remapContainerCoverage(content, pathMap = containerCoverageDirs.flatMap((entry) => entry.pathMap)) {
  for (const [from, to] of pathMap) content = content.replaceAll(from, () => to);
  return content;
}

function mergeContainerCoverage({ directories = containerCoverageDirs, destination = v8Dir } = {}) {
  let merged = 0;
  for (const { dir } of directories) {
    if (!fs.existsSync(dir)) continue;
    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json"));
    for (const file of files) {
      const src = path.join(dir, file);
      // Workers can import API helpers, so every raw file needs all mappings.
      const content = remapContainerCoverage(fs.readFileSync(src, "utf8"));
      const dest = path.join(destination, `container-${path.basename(dir)}-${file}`);
      fs.writeFileSync(dest, content, "utf8");
      merged++;
    }
  }
  if (merged > 0) {
    console.log(
      `==> Merged ${merged} container coverage file(s) into ${destination}`,
    );
  }
  return merged;
}

function main() {
  cleanCoverageDirs();
  if (cleanOnly) return 0;

  const collectCode = run("bash", ["scripts/run-tests.sh"], {
    NODE_V8_COVERAGE: v8Dir,
    TT_TEST_SUITE: suite,
  });

  mergeContainerCoverage();

  if (collectOnly || collectCode !== 0) return collectCode;

  return run("pnpm", [
    "dlx",
    "c8@10.1.3",
    "report",
    "--temp-directory",
    ".coverage/v8",
    "--reporter=text",
    "--reporter=html",
    "--reporter=lcov",
    "--exclude=tests/**",
    "--exclude=node_modules/**",
    "--exclude=coverage/**",
  ]);
}

if (require.main === module) process.exit(main());
module.exports = { remapContainerCoverage, mergeContainerCoverage };
