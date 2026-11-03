"use strict";

// Inspect the actual release archive, not unshipped working-tree binaries.
// This gate binds six Windows PE hashes/build settings to the package checksum
// and observed source checkout; the separate Grype gate evaluates advisories.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { VERSION: NODE_VERSION, RUNTIMES } = require("../packages/agent/scripts/windows-runtime-package");

const ARCHITECTURES = { amd64: 0x8664, arm64: 0xaa64 };
const MODULE_PATHS = {
  "tokentimer-agent-host": "github.com/tokentimerch/tokentimer-core/packages/agent/windows-service-host",
  "tokentimer-adcs-chain": "tokentimer-adcs-chain",
  "tokentimer-adcs-cmc": "tokentimer-adcs-cmc",
};
const EXPECTED_BINARIES = Object.keys(MODULE_PATHS)
  .flatMap((name) => Object.keys(ARCHITECTURES).map((arch) => "package/bin/" + name + "-" + arch + ".exe"))
  .sort();

function parseArgs(argv) {
  const options = {};
  const allowed = new Set(["archive", "go-version", "source-sha", "out"]);
  for (let i = 0; i < argv.length; i += 2) {
    const name = argv[i]?.replace(/^--/, "");
    assert.ok(argv[i]?.startsWith("--") && allowed.has(name) && argv[i + 1] && !argv[i + 1].startsWith("--") && !options[name], "Expected each --option exactly once with a value");
    options[name] = argv[i + 1];
  }
  for (const name of allowed) assert.ok(options[name], "Missing --" + name);
  assert.match(options["go-version"], /^1\.\d+\.\d+$/, "Expected an exact stable Go patch version");
  assert.match(options["source-sha"], /^[a-f0-9]{40}$/, "Expected a full source SHA");
  return options;
}

function assertBinaryEntries(entries, runtimeArch = null) {
  for (const name of entries) {
    assert.ok(name.startsWith("package/") && !name.includes("\\") && !name.split("/").includes(".."), "Unsafe archive path: " + name);
  }
  const binaries = entries.filter((name) => /\.exe$/i.test(name)).sort();
  const expected = [...EXPECTED_BINARIES];
  if (runtimeArch) {
    assert.ok(Object.hasOwn(RUNTIMES, runtimeArch), "Unsupported packaged Node architecture");
    expected.push(`package/runtime/${runtimeArch}/node.exe`);
  }
  assert.deepEqual(binaries, expected.sort(), "Archive must contain exactly the six expected Windows binaries and approved runtime, with no duplicates");
  return binaries;
}

function assertPackageFlavor(metadata, runtimeArch = null) {
  if (runtimeArch) {
    assert.equal(metadata.windowsBundledRuntime, true, "Windows runtime archive must declare its bundled runtime flavor");
  } else {
    assert.equal(Object.hasOwn(metadata, "windowsBundledRuntime"), false, "Generic archive must retain legacy runtime behavior");
  }
}

function assertInstallerFlavor(source, runtimeArch = null) {
  const markers = source.match(/^\$script:RequiresBundledRuntime = \$(?:true|false)\r?$/gm) || [];
  assert.equal(markers.length, 1, "Installer must declare exactly one bundled-runtime marker");
  assert.equal(markers[0].trimEnd(), `$script:RequiresBundledRuntime = $${runtimeArch ? "true" : "false"}`, "Installer runtime flavor differs from archive flavor");
}

function assertPeArchitecture(bytes, architecture) {
  assert.ok(bytes.length >= 64 && bytes.toString("ascii", 0, 2) === "MZ", "Not a Windows PE executable");
  const offset = bytes.readUInt32LE(0x3c);
  assert.ok(offset <= bytes.length - 6 && bytes.toString("ascii", offset, offset + 4) === "PE\u0000\u0000", "Invalid Windows PE header");
  assert.equal(bytes.readUInt16LE(offset + 4), ARCHITECTURES[architecture], "PE architecture does not match its package filename");
}

function parseBuildInfo(output, expectedGoVersion, architecture, expectedModulePath) {
  const lines = output.trim().split(/\r?\n/);
  const version = /: (go1\.\d+\.\d+)$/.exec(lines[0])?.[1];
  assert.equal(version, "go" + expectedGoVersion, "Packaged binary was built with an unexpected Go toolchain");
  const settings = {};
  for (const line of lines.slice(1)) {
    const match = /^\s*build\t([^=\s]+)=(.*)$/.exec(line);
    if (match) {
      assert.ok(!Object.hasOwn(settings, match[1]), "Duplicate Go build setting");
      settings[match[1]] = match[2];
    }
  }
  assert.equal(settings.GOOS, "windows", "Packaged binary must target Windows");
  assert.equal(settings.GOARCH, architecture, "Go architecture does not match its package filename");
  assert.equal(settings.CGO_ENABLED, "0", "Packaged binary must use the expected pure-Go build");
  const modulePath = lines.map((line) => /^\s*path\t(.+)$/.exec(line)?.[1]).find(Boolean);
  assert.ok(modulePath, "Missing Go module path");
  assert.equal(modulePath, expectedModulePath, "Go module does not match the expected executable family");
  return { goVersion: version, modulePath, settings };
}

function run(command, args, binary = false) {
  const result = spawnSync(command, args, { encoding: binary ? null : "utf8", timeout: 120_000, maxBuffer: 128 * 1024 * 1024 });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, command + " failed: " + String(result.stderr).trim());
  return result.stdout;
}

function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  assert.equal(run("git", ["rev-parse", "HEAD"]).trim(), options["source-sha"], "Observed source checkout differs from declared source");
  assert.equal(run("git", ["diff", "--name-only", "HEAD", "--", "packages/agent"]).trim(), "", "Agent build sources have uncommitted changes");
  assert.equal(process.env.GOTOOLCHAIN, "local", "GOTOOLCHAIN=local is required to forbid automatic toolchain selection");
  assert.equal(run("go", ["env", "GOVERSION"]).trim(), "go" + options["go-version"], "Inspector is not the pinned Go toolchain");
  const archive = path.resolve(options.archive);
  const runtimeMatch = /-windows-(amd64|arm64)\.tgz$/.exec(archive);
  const runtimeArch = runtimeMatch?.[1] || null;
  const entries = run("tar", ["-tzf", archive]).trim().split(/\r?\n/);
  const binaries = assertBinaryEntries(entries, runtimeArch);
  assertPackageFlavor(JSON.parse(run("tar", ["-xOzf", archive, "package/package.json"])), runtimeArch);
  assertInstallerFlavor(run("tar", ["-xOzf", archive, "package/scripts/install-agent.ps1"]), runtimeArch);
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "tt-agent-native-verify-"));
  try {
    const receipt = { schemaVersion: 1, status: "passed", archive: path.basename(archive), archiveSha256: sha256(fs.readFileSync(archive)), sourceSha: options["source-sha"], goVersion: "go" + options["go-version"], goToolchain: "local", builtAtRun: process.env.GITHUB_RUN_ID || null, verifiedAt: new Date().toISOString(), binaries: [] };
    for (const entry of binaries) {
      if (entry.startsWith("package/runtime/")) {
        const bytes = run("tar", ["-xOzf", archive, entry], true);
        assertPeArchitecture(bytes, runtimeArch);
        assert.equal(sha256(bytes), RUNTIMES[runtimeArch].sha256, "Packaged Node digest does not match pinned release");
        const manifest = JSON.parse(run("tar", ["-xOzf", archive, "package/runtime/manifest.json"]));
        assert.deepEqual(manifest, { version: NODE_VERSION, architecture: runtimeArch, path: `runtime/${runtimeArch}/node.exe`, sha256: RUNTIMES[runtimeArch].sha256 });
        const license = run("tar", ["-xOzf", archive, "package/runtime/LICENSE"], true);
        assert.ok(license.length, "Packaged Node license missing");
        const pin = RUNTIMES[runtimeArch];
        receipt.binaries.push({ path: entry, sha256: sha256(bytes), bytes: bytes.length, nodeVersion: NODE_VERSION, architecture: runtimeArch, upstreamArchive: `node-v${NODE_VERSION}-win-${pin.upstream}.zip`, upstreamArchiveSha256: pin.zipSha256, licenseSha256: sha256(license) });
        continue;
      }
      const architecture = /-(amd64|arm64)\.exe$/.exec(entry)[1];
      const family = path.basename(entry).replace(/-(amd64|arm64)\.exe$/, "");
      const bytes = run("tar", ["-xOzf", archive, entry], true);
      assertPeArchitecture(bytes, architecture);
      const filename = path.join(temporary, path.basename(entry));
      fs.writeFileSync(filename, bytes, { mode: 0o600 });
      const info = parseBuildInfo(run("go", ["version", "-m", filename]), options["go-version"], architecture, MODULE_PATHS[family]);
      receipt.binaries.push({ path: entry, sha256: sha256(bytes), bytes: bytes.length, ...info });
    }
    fs.mkdirSync(path.dirname(path.resolve(options.out)), { recursive: true });
    fs.writeFileSync(options.out, JSON.stringify(receipt, null, 2) + "\n");
    process.stdout.write("Verified six packaged Windows binaries: " + receipt.goVersion + ", archive sha256:" + receipt.archiveSha256 + "\n");
    return receipt;
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
}

if (require.main === module) {
  try { main(); } catch (error) { process.stderr.write(error.message + "\n"); process.exitCode = 1; }
}
module.exports = { parseArgs, assertBinaryEntries, assertPackageFlavor, assertInstallerFlavor, assertPeArchitecture, parseBuildInfo, EXPECTED_BINARIES, MODULE_PATHS };
