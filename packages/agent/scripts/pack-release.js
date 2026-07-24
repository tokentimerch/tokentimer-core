"use strict";

/**
 * Build a release tarball for @tokentimer/agent and write a SHA-256 checksum
 * sidecar. Distribution is tarball + install-agent.sh (package stays private;
 * see README.md). This does not sign the artifact — signing infrastructure is
 * not present in this repository yet.
 *
 *   node scripts/pack-release.js [--out-dir DIR]
 */

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");

const packageRoot = path.resolve(__dirname, "..");
const pkg = JSON.parse(
  fs.readFileSync(path.join(packageRoot, "package.json"), "utf8"),
);

function parseArgs(argv) {
  let outDir = path.join(packageRoot, "dist");
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--out-dir") {
      outDir = path.resolve(argv[++i] || "");
    } else if (arg.startsWith("--out-dir=")) {
      outDir = path.resolve(arg.slice("--out-dir=".length));
    } else if (arg === "-h" || arg === "--help") {
      process.stdout.write("Usage: node scripts/pack-release.js [--out-dir DIR]\n");
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  return { outDir };
}

function sha256File(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
}

function main(argv = process.argv.slice(2)) {
  if (pkg.private !== true) {
    throw new Error(
      "refusing to pack: @tokentimer/agent is expected to remain private; " +
        "distribution is via tarball + install-agent.sh (see README.md)",
    );
  }

  const { outDir } = parseArgs(argv);
  fs.mkdirSync(outDir, { recursive: true });

  const pack = spawnSync(
    "npm",
    ["pack", "--pack-destination", outDir],
    {
      cwd: packageRoot,
      encoding: "utf8",
      shell: process.platform === "win32",
    },
  );
  if (pack.status !== 0) {
    throw new Error(
      `npm pack failed:\n${pack.stdout || ""}\n${pack.stderr || ""}`,
    );
  }

  const tarballName = pack.stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .pop();
  if (!tarballName || !tarballName.endsWith(".tgz")) {
    throw new Error(`npm pack did not report a tarball name: ${pack.stdout}`);
  }

  const tarballPath = path.join(outDir, tarballName);
  if (!fs.existsSync(tarballPath)) {
    throw new Error(`packed tarball missing: ${tarballPath}`);
  }

  const digest = sha256File(tarballPath);
  const checksumName = `${tarballName}.sha256`;
  const checksumPath = path.join(outDir, checksumName);
  // Coreutils `sha256sum -c` friendly format: "<hash>  <filename>"
  fs.writeFileSync(checksumPath, `${digest}  ${tarballName}\n`, "utf8");

  process.stdout.write(
    [
      `Packed ${tarballName}`,
      `Version ${pkg.version}`,
      `SHA256 ${digest}`,
      `Checksum file ${checksumName}`,
      "Signing: not available in this repository (document checksum out-of-band).",
      "",
    ].join("\n"),
  );

  return { tarballPath, checksumPath, digest, version: pkg.version };
}

module.exports = { main, sha256File };

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`pack-release: ${error.message}\n`);
    process.exitCode = 1;
  }
}
