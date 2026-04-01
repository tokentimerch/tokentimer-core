#!/usr/bin/env node
"use strict";

const { spawnSync } = require("child_process");
const { readFileSync, existsSync } = require("fs");
const path = require("path");

const projectRoot = path.resolve(__dirname, "..");
const suitesDir = path.join(projectRoot, "tests", "integration", "suites");
const suiteName = process.env.TT_TEST_SUITE || process.argv[2] || "core";

const suiteFile = path.join(suitesDir, `${suiteName}.txt`);
if (!existsSync(suiteFile)) {
  console.error(
    `Unknown test suite "${suiteName}". Expected file: ${path.relative(projectRoot, suiteFile)}`,
  );
  process.exit(1);
}

const files = readFileSync(suiteFile, "utf8")
  .split(/\r?\n/)
  .map((line) => line.trim())
  .filter((line) => line && !line.startsWith("#"))
  .map((relPath) => path.join(projectRoot, relPath));

if (files.length === 0) {
  console.error(`Suite "${suiteName}" has no test files.`);
  process.exit(1);
}

const mochaArgs = [
  ...files,
  "--timeout",
  "60000",
  "--exit",
  "--reporter",
  "spec",
];
function resolveLocal(specifier) {
  return require.resolve(specifier, {
    paths: [projectRoot, path.join(projectRoot, "apps", "api")],
  });
}

function hasPromClientIntegrity() {
  try {
    const promMain = resolveLocal("prom-client");
    const promClient = require(promMain);
    return Boolean(promClient && promClient.register);
  } catch (_) {
    return false;
  }
}

function ensureTestDeps() {
  const autoInstallDeps = process.env.TT_AUTO_INSTALL_TEST_DEPS === "1";
  const allowForceInstall = process.env.TT_ALLOW_FORCE_INSTALL === "1";
  try {
    resolveLocal("mocha/bin/mocha.js");
    resolveLocal("chai");
    resolveLocal("bcryptjs");
    resolveLocal("otplib");
    if (!hasPromClientIntegrity()) throw new Error("prom-client is incomplete");
    return true;
  } catch (_) {
    if (!autoInstallDeps) {
      return false;
    }
    const installAttempts = [
      [
        "install",
        "--frozen-lockfile",
        "--ignore-scripts",
        "--prefer-offline",
        "--child-concurrency=1",
      ],
    ];
    if (allowForceInstall) {
      installAttempts.push(
        [
          "install",
          "--frozen-lockfile",
          "--ignore-scripts",
          "--prefer-offline",
          "--force",
          "--child-concurrency=1",
        ],
        [
          "install",
          "--ignore-scripts",
          "--prefer-offline",
          "--force",
          "--child-concurrency=1",
        ],
      );
    }
    for (const args of installAttempts) {
      const installRes = spawnSync("pnpm", args, {
        cwd: projectRoot,
        stdio: "inherit",
        shell: process.platform === "win32",
      });
      if (installRes.status !== 0) continue;
      try {
        resolveLocal("mocha/bin/mocha.js");
        resolveLocal("chai");
        resolveLocal("bcryptjs");
        resolveLocal("otplib");
        if (!hasPromClientIntegrity()) continue;
        return true;
      } catch (_) {}
    }
    return false;
  }
}

if (!ensureTestDeps()) {
  console.error(
    "Unable to resolve test dependencies (mocha/chai/bcryptjs/otplib/prom-client). " +
      "Run `pnpm install --frozen-lockfile --ignore-scripts` once. " +
      "Set TT_AUTO_INSTALL_TEST_DEPS=1 to enable auto-repair attempts.",
  );
  process.exit(1);
}

const mochaBin = resolveLocal("mocha/bin/mocha.js");
const result = spawnSync(process.execPath, [mochaBin, ...mochaArgs], {
  cwd: projectRoot,
  stdio: "inherit",
  shell: false,
});

if (typeof result.status === "number") {
  process.exit(result.status);
}
process.exit(1);
