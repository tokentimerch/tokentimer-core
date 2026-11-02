"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { parseArgs, assertBinaryEntries, assertPeArchitecture, parseBuildInfo, EXPECTED_BINARIES, MODULE_PATHS } = require("./verify-agent-native-package");
const HOST_MODULE = MODULE_PATHS["tokentimer-agent-host"];

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
  assert.throws(() => assertBinaryEntries(EXPECTED_BINARIES.slice(1)), /six expected/);
  assert.throws(() => assertBinaryEntries([...EXPECTED_BINARIES, EXPECTED_BINARIES[0]]), /six expected/);
  assert.throws(() => assertBinaryEntries([...EXPECTED_BINARIES, "package/bin/unknown.exe"]), /six expected/);
  assert.throws(() => assertBinaryEntries([...EXPECTED_BINARIES, "package/../outside"]), /Unsafe archive/);
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
