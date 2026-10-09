#!/usr/bin/env node
"use strict";

/*
 * Build tokentimer-adcs-cmc for the Windows AD CS path. Unsigned only;
 * Authenticode signing remains a release-gate obligation (same posture as
 * tokentimer-verify). AD CS enrollment is Windows-only, so the default
 * host build targets windows/amd64 when cross-compiling from another OS.
 */

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const moduleDir = __dirname;
const distDir = path.join(moduleDir, "dist");

function hostTarget() {
  const goos = process.platform === "win32" ? "windows" : process.platform === "darwin" ? "darwin" : "linux";
  const goarch = process.arch === "arm64" ? "arm64" : "amd64";
  const outName = goos === "windows" ? "tokentimer-adcs-cmc.exe" : "tokentimer-adcs-cmc";
  return { goos, goarch, outName };
}

function windowsTarget() {
  return { goos: "windows", goarch: "amd64", outName: "tokentimer-adcs-cmc-windows-amd64.exe" };
}

function build(target) {
  const outPath = path.join(distDir, target.outName);
  fs.mkdirSync(distDir, { recursive: true });
  const env = {
    ...process.env,
    CGO_ENABLED: "0",
    GOOS: target.goos,
    GOARCH: target.goarch,
  };
  const args = ["build", "-trimpath", "-ldflags", "-s -w", "-o", outPath, "."];
  console.log(
    `tokentimer-adcs-cmc build: GOOS=${target.goos} GOARCH=${target.goarch} -> ${path.relative(moduleDir, outPath)}`,
  );
  const result = spawnSync("go", args, { cwd: moduleDir, env, stdio: "inherit" });
  if (result.error) {
    console.error(`tokentimer-adcs-cmc build: failed to invoke go: ${result.error.message}`);
    process.exit(1);
  }
  if (result.status !== 0) {
    console.error(`tokentimer-adcs-cmc build: go build exited with status ${result.status}`);
    process.exit(result.status || 1);
  }
  return outPath;
}

function main() {
  const wantWindows = process.argv.includes("--windows");
  const targets = wantWindows ? [windowsTarget(), hostTarget()] : [hostTarget()];
  // Deduplicate when host is already windows/amd64.
  const seen = new Set();
  const built = [];
  for (const t of targets) {
    const key = `${t.goos}/${t.goarch}/${t.outName}`;
    if (seen.has(key)) continue;
    seen.add(key);
    built.push(build(t));
  }
  console.log("");
  console.log("tokentimer-adcs-cmc: unsigned build produced:");
  for (const outPath of built) console.log(`  ${outPath}`);
}

main();
