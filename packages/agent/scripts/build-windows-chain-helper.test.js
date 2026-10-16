"use strict";
/** Portable build-failure and architecture-selection regressions. Synthetic PE
 * headers exercise rejection only; real Go cross-build/archive checks live in
 * pack-release.test.js. No helper executable or certificate command runs here. */
const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const {
    buildOne,
    binaryName,
    assertPeArchitecture,
  } = require("./build-windows-chain-helper"),
  { resolveAdcsChainHelperPath } = require("../src/issuers/chain-helper");
function owned(work) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "chain-package-test-"));
  try {
    work(dir);
  } finally {
    const absolute = path.resolve(dir);
    assert.equal(path.dirname(absolute), path.resolve(os.tmpdir()));
    assert.match(
      path.basename(absolute),
      /^chain-package-test-[A-Za-z0-9]{6}$/,
    );
    assert.equal(fs.lstatSync(absolute).isSymbolicLink(), false);
    fs.rmSync(absolute, { recursive: true, force: true });
  }
}
test("failed build cannot reuse a stale output or package a partial executable", () =>
  owned((dir) => {
    const file = path.join(dir, binaryName("arm64"));
    fs.writeFileSync(file, "stale");
    assert.throws(
      () =>
        buildOne("arm64", dir, {
          run(_command, _argv, options) {
            assert.equal(options.env.GOARCH, "arm64");
            assert.equal(options.env.GOOS, "windows");
            return { status: 1 };
          },
        }),
      /build failed/,
    );
    assert.equal(fs.readFileSync(file, "utf8"), "stale");
    assert.deepEqual(fs.readdirSync(dir), [binaryName("arm64")]);
  }));
test("ARM resolver never falls back to an amd64 or ambiguous host executable", () =>
  owned((dir) => {
    fs.mkdirSync(path.join(dir, "bin"));
    fs.writeFileSync(
      path.join(dir, "bin", binaryName("amd64")),
      "not executed",
    );
    fs.mkdirSync(path.join(dir, "reference/adcs-chain/dist"), {
      recursive: true,
    });
    fs.writeFileSync(
      path.join(dir, "reference/adcs-chain/dist/tokentimer-adcs-chain.exe"),
      "ambiguous",
    );
    assert.ok(
      resolveAdcsChainHelperPath({
        packageRoot: dir,
        platform: "win32",
        arch: "arm64",
      }).error,
    );
    assert.ok(
      resolveAdcsChainHelperPath({
        packageRoot: dir,
        platform: "win32",
        arch: "ia32",
      }).error,
    );
    fs.writeFileSync(
      path.join(dir, "bin", binaryName("arm64")),
      "not executed",
    );
    assert.equal(
      resolveAdcsChainHelperPath({
        packageRoot: dir,
        platform: "win32",
        arch: "arm64",
      }).path,
      path.join(dir, "bin", binaryName("arm64")),
    );
  }));
test("PE verification refuses wrong architecture or malformed header", () =>
  owned((dir) => {
    const file = path.join(dir, "fixture.exe"),
      bytes = Buffer.alloc(128);
    bytes.writeUInt16LE(0x5a4d);
    bytes.writeUInt32LE(64, 60);
    bytes.writeUInt32LE(0x4550, 64);
    bytes.writeUInt16LE(0x8664, 68);
    fs.writeFileSync(file, bytes);
    assertPeArchitecture(file, "amd64");
    assert.throws(() => assertPeArchitecture(file, "arm64"), /architecture/);
    fs.writeFileSync(file, "malformed");
    assert.throws(() => assertPeArchitecture(file, "amd64"), /PE/);
  }));
