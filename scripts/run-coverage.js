#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

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
    pathMap: [["file:///app/", `file://${repoRoot}/apps/api/`]],
  },
  {
    dir: path.join(coverageRoot, "v8-worker-delivery"),
    pathMap: [["file:///app/apps/worker/", `file://${repoRoot}/apps/worker/`]],
  },
  {
    dir: path.join(coverageRoot, "v8-worker-endpoint"),
    pathMap: [["file:///app/apps/worker/", `file://${repoRoot}/apps/worker/`]],
  },
  {
    dir: path.join(coverageRoot, "v8-worker-sync"),
    pathMap: [["file:///app/apps/worker/", `file://${repoRoot}/apps/worker/`]],
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

function mergeContainerCoverage() {
  let merged = 0;
  for (const { dir, pathMap } of containerCoverageDirs) {
    if (!fs.existsSync(dir)) continue;
    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json"));
    for (const file of files) {
      const src = path.join(dir, file);
      let content = fs.readFileSync(src, "utf8");
      for (const [from, to] of pathMap) {
        content = content.replaceAll(from, to);
      }
      const dest = path.join(v8Dir, `container-${path.basename(dir)}-${file}`);
      fs.writeFileSync(dest, content, "utf8");
      merged++;
    }
  }
  if (merged > 0) {
    console.log(
      `==> Merged ${merged} container coverage file(s) into ${v8Dir}`,
    );
  }
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

process.exit(main());
