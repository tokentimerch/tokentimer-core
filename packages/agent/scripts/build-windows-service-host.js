"use strict";

/**
 * Cross-compiles the Windows service host binary (windows-service-host/)
 * for both architectures install-agent.ps1 supports (see its OS/arch gate:
 * AMD64, ARM64) and writes them to bin/ alongside the agent's own
 * JavaScript entry points.
 *
 * Runs from any OS with a Go toolchain: the host has no cgo dependency
 * (only golang.org/x/sys/windows, which is pure Go), so GOOS=windows
 * cross-compilation works identically on the Linux release runner
 * (release.yml's pack-agent job) and on a Windows dev machine.
 *
 * This is a separate script from check-shipped-sources.js (the agent's
 * "build" step) rather than folded into it: check-shipped-sources.js
 * validates JavaScript/PowerShell sources and intentionally has zero
 * external tool dependencies; requiring a Go toolchain there would break
 * that script everywhere it currently runs unconditionally.
 *
 *   node scripts/build-windows-service-host.js [--out-dir DIR]
 */

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const packageRoot = path.resolve(__dirname, "..");
const moduleDir = path.join(packageRoot, "windows-service-host");

/** install-agent.ps1's OS/arch gate accepts exactly these two, and maps
 * PROCESSOR_ARCHITECTURE values AMD64/ARM64 to these lowercase GOARCH
 * names 1:1; keep this list and that gate in sync. */
const TARGET_ARCHES = ["amd64", "arm64"];

function parseArgs(argv) {
  let outDir = path.join(packageRoot, "bin");
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--out-dir") {
      outDir = path.resolve(argv[++i] || "");
    } else if (arg.startsWith("--out-dir=")) {
      outDir = path.resolve(arg.slice("--out-dir=".length));
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  return { outDir };
}

function hostBinaryName(arch) {
  return `tokentimer-agent-host-${arch}.exe`;
}

function buildOne(arch, outDir) {
  const outputPath = path.join(outDir, hostBinaryName(arch));
  const result = spawnSync(
    "go",
    ["build", "-trimpath", "-ldflags=-s -w", "-o", outputPath, "."],
    {
      cwd: moduleDir,
      encoding: "utf8",
      env: {
        ...process.env,
        GOOS: "windows",
        GOARCH: arch,
        CGO_ENABLED: "0",
      },
    },
  );
  if (result.error) {
    throw new Error(
      `build-windows-service-host: could not run "go build" (is Go installed and on PATH?): ${result.error.message}`,
    );
  }
  if (result.status !== 0) {
    throw new Error(
      `build-windows-service-host: "go build" for GOARCH=${arch} failed (exit ${result.status}):\n${result.stdout || ""}\n${result.stderr || ""}`,
    );
  }
  if (!fs.existsSync(outputPath)) {
    throw new Error(`build-windows-service-host: expected output missing after build: ${outputPath}`);
  }
  return outputPath;
}

function main(argv = process.argv.slice(2)) {
  const { outDir } = parseArgs(argv);
  fs.mkdirSync(outDir, { recursive: true });

  const built = TARGET_ARCHES.map((arch) => buildOne(arch, outDir));

  process.stdout.write(
    `Built the Windows service host for ${TARGET_ARCHES.join(", ")}:\n` +
      built.map((p) => `  - ${p}`).join("\n") +
      "\n",
  );
  return built;
}

module.exports = { main, TARGET_ARCHES, hostBinaryName };

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`build-windows-service-host: ${error.message}\n`);
    process.exitCode = 1;
  }
}
