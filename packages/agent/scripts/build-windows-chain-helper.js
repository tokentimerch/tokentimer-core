"use strict";
/** Cross-compile the current public Windows chain/store-query helper for both
 * shipped architectures. Canonical pack-release invokes this before npm pack;
 * binaries are unsigned candidate bytes, never copied from a host dist folder.
 * Requires Go but performs no certificate-store or native executable operation. */
const fs = require("node:fs"),
  path = require("node:path"),
  { spawnSync } = require("node:child_process");
const packageRoot = path.resolve(__dirname, ".."),
  moduleDir = path.join(packageRoot, "reference/adcs-chain"),
  TARGET_ARCHES = ["amd64", "arm64"];
function binaryName(arch) {
  if (!TARGET_ARCHES.includes(arch))
    throw new Error("Unsupported Windows helper architecture");
  return `tokentimer-adcs-chain-${arch}.exe`;
}
function assertPeArchitecture(file, arch) {
  const bytes = fs.readFileSync(file);
  if (bytes.length < 64 || bytes.readUInt16LE(0) !== 0x5a4d)
    throw new Error("Windows helper is not a PE executable");
  const offset = bytes.readUInt32LE(0x3c);
  if (
    offset > bytes.length - 6 ||
    bytes.readUInt32LE(offset) !== 0x4550 ||
    bytes.readUInt16LE(offset + 4) !== { amd64: 0x8664, arm64: 0xaa64 }[arch]
  )
    throw new Error("Windows helper PE architecture mismatch");
}
function buildOne(arch, outDir, { run = spawnSync } = {}) {
  const output = path.join(outDir, binaryName(arch)),
    temporary = output + `.building-${process.pid}`;
  try {
    fs.rmSync(temporary, { force: true });
    const result = run(
      "go",
      [
        "build",
        "-mod=readonly",
        "-trimpath",
        "-buildvcs=false",
        "-ldflags=-s -w",
        "-o",
        temporary,
        ".",
      ],
      {
        cwd: moduleDir,
        encoding: "utf8",
        windowsHide: true,
        env: {
          ...process.env,
          GOOS: "windows",
          GOARCH: arch,
          CGO_ENABLED: "0",
        },
      },
    );
    if (result.error || result.status !== 0)
      throw new Error(
        `adcs-chain ${arch} build failed; package will not be produced`,
      );
    assertPeArchitecture(temporary, arch);
    fs.renameSync(temporary, output);
    return output;
  } finally {
    fs.rmSync(temporary, { force: true });
  }
}
function main(argv = []) {
  let outDir = path.join(packageRoot, "bin");
  for (let index = 0; index < argv.length; index++) {
    if (argv[index] === "--out-dir" && argv[index + 1])
      outDir = path.resolve(argv[++index]);
    else
      throw new Error("Usage: build-windows-chain-helper.js [--out-dir DIR]");
  }
  fs.mkdirSync(outDir, { recursive: true });
  const built = TARGET_ARCHES.map((arch) => buildOne(arch, outDir));
  console.log("Built current Windows chain helper for amd64 and arm64");
  return built;
}
module.exports = {
  main,
  buildOne,
  binaryName,
  assertPeArchitecture,
  TARGET_ARCHES,
};
if (require.main === module) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
