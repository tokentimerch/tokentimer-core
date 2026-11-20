"use strict";

// The pinned ZIP digests are published by the Node.js release project.
// Update both the ZIP and executable digests when upgrading Node.
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");

const VERSION = "24.22.3";
const RUNTIMES = Object.freeze({
  amd64: { upstream: "x64", zipSha256: "e612af99f626ab415ea225af6bce5c971feb448cb5cae250bb1c3fa50c5f7d9f", sha256: "86fc4785327db5f5c7558dc6156c543b433c313e813a222e088086222ab4afa6" },
  arm64: { upstream: "arm64", zipSha256: "b3cc74a295b39d4f273271e96f58c06dd2b35757ca12abec64c7d0598b434f14", sha256: "172e320db179ce416fc012b96b9917dacfb442beb081de57c4deaed7b5a24644" },
});

function digest(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }
function run(command, args, options = {}) {
  const result = spawnSync(command, args, { maxBuffer: 128 * 1024 * 1024, ...options });
  if (result.error || result.status !== 0) throw new Error(`${command} failed: ${result.error?.message || String(result.stderr)}`);
  return result.stdout;
}
function extractZipEntry(zip, entry) {
  if (process.platform === "win32") return run("tar", ["-xOf", zip, entry]);
  return run("unzip", ["-p", zip, entry]);
}
function markBundledPackage(packageRoot) {
  const filename = path.join(packageRoot, "package.json");
  const metadata = JSON.parse(fs.readFileSync(filename, "utf8"));
  if (Object.hasOwn(metadata, "windowsBundledRuntime")) throw new Error("Generic package already declares a Windows runtime flavor");
  metadata.windowsBundledRuntime = true;
  fs.writeFileSync(filename, JSON.stringify(metadata, null, 2) + "\n");
}
function markBundledInstaller(packageRoot) {
  const filename = path.join(packageRoot, "scripts", "install-agent.ps1");
  const source = fs.readFileSync(filename, "utf8");
  const markers = source.match(/^\$script:RequiresBundledRuntime = \$(?:true|false)\r?$/gm) || [];
  if (markers.length !== 1 || markers[0].trimEnd() !== "$script:RequiresBundledRuntime = $false") {
    throw new Error("Generic installer must contain exactly one false bundled-runtime marker");
  }
  fs.writeFileSync(filename, source.replace(markers[0], markers[0].replace("$false", "$true")));
}
function buildWindowsArchives(genericArchive, zipDirectory, outputDirectory, version) {
  const outputs = [];
  for (const [architecture, pin] of Object.entries(RUNTIMES)) {
    const zipName = `node-v${VERSION}-win-${pin.upstream}.zip`;
    const zipPath = path.resolve(zipDirectory, zipName);
    if (digest(fs.readFileSync(zipPath)) !== pin.zipSha256) throw new Error(`Node archive checksum mismatch: ${zipName}`);
    const prefix = `node-v${VERSION}-win-${pin.upstream}`;
    const executable = extractZipEntry(zipPath, `${prefix}/node.exe`);
    if (digest(executable) !== pin.sha256) throw new Error(`Node executable checksum mismatch: ${architecture}`);
    const license = extractZipEntry(zipPath, `${prefix}/LICENSE`);
    if (!license.length) throw new Error(`Node license missing: ${architecture}`);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tt-windows-agent-pack-"));
    try {
      run("tar", ["-xzf", genericArchive, "-C", tmp]);
      markBundledPackage(path.join(tmp, "package"));
      markBundledInstaller(path.join(tmp, "package"));
      const runtime = path.join(tmp, "package", "runtime");
      const runtimeArch = path.join(runtime, architecture);
      fs.mkdirSync(runtimeArch, { recursive: true });
      fs.writeFileSync(path.join(runtimeArch, "node.exe"), executable);
      fs.writeFileSync(path.join(runtime, "LICENSE"), license);
      fs.writeFileSync(path.join(runtime, "manifest.json"), JSON.stringify({ version: VERSION, architecture, path: `runtime/${architecture}/node.exe`, sha256: pin.sha256 }, null, 2) + "\n");
      const filename = `tokentimer-agent-${version}-windows-${architecture}.tgz`;
      const archive = path.join(outputDirectory, filename);
      run("tar", ["-czf", archive, "-C", tmp, "package"]);
      const hash = digest(fs.readFileSync(archive));
      fs.writeFileSync(`${archive}.sha256`, `${hash}  ${filename}\n`);
      outputs.push({ archive, sha256: hash, architecture });
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  }
  return outputs;
}
module.exports = { VERSION, RUNTIMES, digest, markBundledPackage, markBundledInstaller, buildWindowsArchives };
