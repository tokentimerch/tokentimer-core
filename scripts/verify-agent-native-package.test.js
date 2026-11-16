"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { parseArgs, assertBinaryEntries, assertLinuxEntries, assertScriptEntries, assertExecutableModes, assertPinnedDigest, assertPackageFlavor, assertInstallerFlavor, assertPeArchitecture, assertElfArchitecture, parseBuildInfo, EXPECTED_BINARIES, EXPECTED_LINUX, EXPECTED_POWERSHELL, EXPECTED_SHELL, MODULE_PATHS } = require("./verify-agent-native-package");
const HOST_MODULE = MODULE_PATHS["tokentimer-agent-host"];

test("a changed pinned runtime is rejected", () => {
  const crypto = require("node:crypto");
  const bytes = Buffer.from("runtime fixture");
  const pin = crypto.createHash("sha256").update(bytes).digest("hex");
  assertPinnedDigest(bytes, pin);
  assert.throws(() => assertPinnedDigest(Buffer.from("runtime fixturE"), pin), /digest does not match/);
});

const buildInfo = (version = "1.26.10", arch = "amd64", goos = "windows") =>
  `/tmp/agent.exe: go${version}\n\tpath\tgithub.com/tokentimerch/tokentimer-core/packages/agent/windows-service-host\n\tbuild\tCGO_ENABLED=0\n\tbuild\tGOOS=${goos}\n\tbuild\tGOARCH=${arch}\n`;

test("native gate requires exact patch and source provenance", () => {
  const args = ["--archive", "agent.tgz", "--go-version", "1.26.10", "--source-sha", "a".repeat(40), "--out", "receipt.json"];
  assert.equal(parseArgs(args)["go-version"], "1.26.10");
  for (const version of ["1.26", "1.26.x", "latest", "1.27rc1"]) {
    const invalid = [...args]; invalid[3] = version;
    assert.throws(() => parseArgs(invalid), /exact stable Go patch/);
  }
  assert.throws(() => parseArgs(args.filter((_, index) => index !== 4 && index !== 5)), /source-sha/);
});

test("archive gate refuses missing, duplicated or unexpected executable entries", () => {
  assertBinaryEntries(["package/package.json", ...EXPECTED_BINARIES]);
  for (const name of EXPECTED_BINARIES) assert.throws(() => assertBinaryEntries(EXPECTED_BINARIES.filter(item => item !== name)), /eight expected/);
  assert.throws(() => assertBinaryEntries([...EXPECTED_BINARIES, EXPECTED_BINARIES[0]]), /eight expected/);
  assert.throws(() => assertBinaryEntries([...EXPECTED_BINARIES, "package/bin/unknown.exe"]), /eight expected/);
  assert.throws(() => assertBinaryEntries([...EXPECTED_BINARIES, "package/../outside"]), /Unsafe archive/);
});

test("Linux helpers are exact, executable and match their declared architecture", () => {
  assertLinuxEntries(EXPECTED_LINUX);
  for (const name of EXPECTED_LINUX) assert.throws(() => assertLinuxEntries(EXPECTED_LINUX.filter(item => item !== name)), /expected Linux/);
  assert.throws(() => assertLinuxEntries([...EXPECTED_LINUX, "package/bin/unknown"]), /expected Linux/);
  assert.throws(() => assertLinuxEntries([...EXPECTED_LINUX, EXPECTED_LINUX[0]]), /expected Linux/);
  const paths = ["package/scripts/install-agent.sh", ...EXPECTED_LINUX];
  const listing = paths.map(name => `-rwxr-xr-x 0 0 12 Jan 01 00:00 ${name}`).join("\n");
  assertExecutableModes(listing);
  for (const name of paths) assert.throws(() => assertExecutableModes(listing.replace(`-rwxr-xr-x 0 0 12 Jan 01 00:00 ${name}`, `-rw-r--r-- 0 0 12 Jan 01 00:00 ${name}`)), /execute bit/);
  for (const [arch, machine] of [["amd64", 62], ["arm64", 183]]) {
    const b=Buffer.alloc(20); b[0]=0x7f; b.write("ELF",1); b[4]=2; b[5]=1; b.writeUInt16LE(machine,18);
    assertElfArchitecture(b,arch);
    assert.throws(() => assertElfArchitecture(b,arch === "amd64" ? "arm64" : "amd64"), /ELF architecture/);
    b[1]=0; assert.throws(() => assertElfArchitecture(b,arch), /Invalid.*ELF/);
  }
});

test("all expected scripts are present without unknown PowerShell or shell scripts", () => {
  const scripts=[...EXPECTED_POWERSHELL,...EXPECTED_SHELL];
  assertScriptEntries(scripts);
  for(const name of scripts) assert.throws(() => assertScriptEntries(scripts.filter(item=>item!==name)), /exactly the expected/);
  for(const extra of ["package/src/rogue.ps1","package/src/rogue.psm1","package/src/rogue.sh"]) {
    assert.throws(() => assertScriptEntries([...scripts,extra]), /exactly the expected/);
  }
  for(const extra of ["package/src/rogue.cmd","package/src/rogue.so.1","package/src/rogue.dylib"]) {
    assert.throws(() => assertScriptEntries([...scripts,extra]), /unsupported executable/);
  }
});

test("Windows archives require exactly the matching bundled runtime executable", () => {
  const amd = "package/runtime/amd64/node.exe";
  const arm = "package/runtime/arm64/node.exe";
  assertBinaryEntries([...EXPECTED_BINARIES, amd], "amd64");
  assertBinaryEntries([...EXPECTED_BINARIES, arm], "arm64");
  assert.throws(() => assertBinaryEntries(EXPECTED_BINARIES, "amd64"), /approved runtime/);
  assert.throws(() => assertBinaryEntries([...EXPECTED_BINARIES, arm], "amd64"), /approved runtime/);
  assert.throws(() => assertBinaryEntries([...EXPECTED_BINARIES, amd, arm], "amd64"), /approved runtime/);
  assert.throws(() => assertBinaryEntries([...EXPECTED_BINARIES, amd, amd], "amd64"), /approved runtime/);
  assert.throws(() => assertBinaryEntries([...EXPECTED_BINARIES, amd], "unknown"), /Unsupported/);
});

test("Windows and generic artifacts declare distinct runtime flavors", () => {
  assertPackageFlavor({ name: "agent" });
  assertPackageFlavor({ name: "agent", windowsBundledRuntime: true }, "amd64");
  assert.throws(() => assertPackageFlavor({ name: "agent" }, "amd64"), /must declare/);
  assert.throws(() => assertPackageFlavor({ windowsBundledRuntime: false }, "amd64"), /must declare/);
  assert.throws(() => assertPackageFlavor({ windowsBundledRuntime: true }), /legacy runtime behavior/);
});

test("packaged installer marker must match the selected archive flavor", () => {
  assertInstallerFlavor("$script:RequiresBundledRuntime = $false\r\n");
  assertInstallerFlavor("$script:RequiresBundledRuntime = $true\n", "amd64");
  assert.throws(() => assertInstallerFlavor("$script:RequiresBundledRuntime = $false\n", "amd64"), /differs/);
  assert.throws(() => assertInstallerFlavor("$script:RequiresBundledRuntime = $true\n"), /differs/);
  assert.throws(() => assertInstallerFlavor("# missing\n", "amd64"), /exactly one/);
  assert.throws(() => assertInstallerFlavor("$script:RequiresBundledRuntime = $true\n$script:RequiresBundledRuntime = $false\n", "amd64"), /exactly one/);
});

test("build metadata refuses vulnerable toolchain or mismatched target", () => {
  assert.equal(parseBuildInfo(buildInfo(), "1.26.10", "amd64", HOST_MODULE).goVersion, "go1.26.10");
  for (const version of ["1.24.13", "1.25.0", "1.26.9"]) {
    assert.throws(() => parseBuildInfo(buildInfo(version), "1.26.10", "amd64", HOST_MODULE), /unexpected Go toolchain/);
  }
  assert.throws(() => parseBuildInfo(buildInfo("1.26.10", "arm64"), "1.26.10", "amd64", HOST_MODULE), /Go architecture/);
  assert.throws(() => parseBuildInfo(buildInfo("1.26.10", "amd64", "linux"), "1.26.10", "amd64", HOST_MODULE), /target Windows/);
  assert.throws(() => parseBuildInfo(buildInfo().replace("CGO_ENABLED=0", "CGO_ENABLED=1"), "1.26.10", "amd64", HOST_MODULE), /pure-Go/);
  assert.throws(() => parseBuildInfo(buildInfo() + "\tbuild\tGOARCH=arm64\n", "1.26.10", "amd64", HOST_MODULE), /Duplicate/);
});

test("correct toolchain and architecture cannot hide a renamed executable from another helper family", () => {
  const chainInfo = buildInfo().replace(HOST_MODULE, MODULE_PATHS["tokentimer-adcs-chain"]);
  parseBuildInfo(chainInfo, "1.26.10", "amd64", MODULE_PATHS["tokentimer-adcs-chain"]);
  assert.throws(() => parseBuildInfo(chainInfo, "1.26.10", "amd64", MODULE_PATHS["tokentimer-adcs-cmc"]), /expected executable family/);
  assert.throws(() => parseBuildInfo(chainInfo, "1.26.10", "amd64", HOST_MODULE), /expected executable family/);
});

test("PE machine header independently verifies the filename architecture", () => {
  for (const [architecture, machine] of [["amd64", 0x8664], ["arm64", 0xaa64]]) {
    const bytes = Buffer.alloc(80);
    bytes.write("MZ"); bytes.writeUInt32LE(64, 0x3c); bytes.write("PE\0\0", 64); bytes.writeUInt16LE(machine, 68);
    assertPeArchitecture(bytes, architecture);
    assert.throws(() => assertPeArchitecture(bytes, architecture === "amd64" ? "arm64" : "amd64"), /PE architecture/);
    bytes.writeUInt32LE(0xffffffff, 0x3c);
    assert.throws(() => assertPeArchitecture(bytes, architecture), /Invalid Windows PE/);
  }
  assert.throws(() => assertPeArchitecture(Buffer.from("not an executable"), "amd64"), /Not a Windows PE/);
});
