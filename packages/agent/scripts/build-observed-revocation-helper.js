"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { assertPeArchitecture } = require("./build-windows-chain-helper");

const root = path.resolve(__dirname, "..");
const moduleDir = path.join(root, "reference", "observed-revocation");
const targets = Object.freeze([
  { os: "linux", arch: "amd64" }, { os: "linux", arch: "arm64" },
  { os: "windows", arch: "amd64" }, { os: "windows", arch: "arm64" },
]);

function binaryName({ os, arch }) {
  if (!targets.some((t) => t.os === os && t.arch === arch)) throw new Error("Unsupported revocation helper target");
  return `tokentimer-observed-revocation-${os}-${arch}${os === "windows" ? ".exe" : ""}`;
}

function validateBinary(file, target) {
  if (target.os === "windows") return assertPeArchitecture(file, target.arch);
  const b = fs.readFileSync(file);
  if (b.length < 20 || b[0] !== 0x7f || b.toString("ascii", 1, 4) !== "ELF" || b[4] !== 2 || b[5] !== 1 || b.readUInt16LE(18) !== { amd64: 62, arm64: 183 }[target.arch]) throw new Error("Revocation helper ELF architecture mismatch");
}

function buildOne(target, outDir, { run = spawnSync, sourceDir = moduleDir } = {}) {
  const output = path.join(outDir, binaryName(target));
  const temporary = `${output}.building-${process.pid}`;
  try {
    fs.rmSync(temporary, { force: true });
    const result = run("go", ["build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", temporary, "./cmd/observed-revocation"], {
      cwd: sourceDir, encoding: "utf8", windowsHide: true,
      env: { ...process.env, GOOS: target.os, GOARCH: target.arch, CGO_ENABLED: "0" },
    });
    if (result.error || result.status !== 0) throw new Error(`Revocation helper ${target.os}/${target.arch} build failed`);
    validateBinary(temporary, target);
    if (target.os === "linux") fs.chmodSync(temporary, 0o755);
    fs.renameSync(temporary, output);
    return output;
  } finally { fs.rmSync(temporary, { force: true }); }
}

function main(argv = []) {
  let outDir = path.join(root, "bin");
  if (argv.length === 2 && argv[0] === "--out-dir") outDir = path.resolve(argv[1]);
  else if (argv.length) throw new Error("Usage: build-observed-revocation-helper.js [--out-dir DIR]");
  fs.mkdirSync(outDir, { recursive: true });
  return targets.map((target) => buildOne(target, outDir));
}

module.exports = { binaryName, validateBinary, buildOne, main, targets };
if (require.main === module) { try { main(process.argv.slice(2)); } catch (err) { console.error(err.message); process.exitCode = 1; } }
