"use strict";

const { describe, it, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const {
  main,
  sha256File,
  assertNoPrivateKeyMaterial,
} = require("./pack-release.js");

const packageJsonPath = path.resolve(__dirname, "..", "package.json");
const expectedVersion = JSON.parse(
  fs.readFileSync(packageJsonPath, "utf8"),
).version;

describe("pack-release (H10)", () => {
  let outDir;

  after(() => {
    if (outDir) fs.rmSync(outDir, { recursive: true, force: true });
  });

  it("builds a versioned tarball and matching sha256 sidecar", () => {
    outDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "tokentimer-agent-release-"),
    );
    const result = main([`--out-dir=${outDir}`]);
    assert.equal(result.version, expectedVersion);
    assert.ok(fs.existsSync(result.tarballPath));
    assert.ok(fs.existsSync(result.checksumPath));
    assert.match(
      path.basename(result.tarballPath),
      new RegExp(
        `tokentimer-agent-${expectedVersion.replace(/\./g, "\\.")}\\.tgz$`,
      ),
    );

    const checksum = fs.readFileSync(result.checksumPath, "utf8").trim();
    assert.equal(
      checksum,
      `${result.digest}  ${path.basename(result.tarballPath)}`,
    );
    assert.equal(sha256File(result.tarballPath), result.digest);
  });

  it("the real packed tarball contains no private-key material (fixtures excluded)", () => {
    // Regression guard for the release blocker where src/verify/fixtures/*.key.pem
    // (test-only X.509 fixtures) shipped inside the production npm tarball.
    outDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "tokentimer-agent-release-scan-"),
    );
    const result = main([`--out-dir=${outDir}`]);
    assert.doesNotThrow(() => assertNoPrivateKeyMaterial(result.tarballPath));

    const list = spawnSync("tar", ["-tzf", result.tarballPath], {
      encoding: "utf8",
    });
    assert.equal(list.status, 0);
    assert.doesNotMatch(list.stdout, /\.key\.pem$/m);
    assert.doesNotMatch(list.stdout, /fixtures\//);
  });

  it("ships Windows service host binaries under package/bin, not --out-dir", () => {
    // Regression for pack-agent writing tokentimer-agent-host-*.exe into
    // agent-dist/ (inherited --out-dir) so released tarballs omitted them
    // and install-agent.ps1 failed without a local rebuild.
    outDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "tokentimer-agent-release-host-"),
    );
    const stale = path.resolve(__dirname, "../bin/tokentimer-adcs-chain.exe");
    let ownedStale = false,
      result;
    try {
      if (!fs.existsSync(stale)) {
        fs.writeFileSync(stale, "stale ambiguous host binary must not ship", {
          flag: "wx",
        });
        ownedStale = true;
      }
      result = main([`--out-dir=${outDir}`]);
    } finally {
      if (ownedStale) fs.unlinkSync(stale);
    }
    const list = spawnSync("tar", ["-tzf", result.tarballPath], {
      encoding: "utf8",
    });
    assert.equal(list.status, 0);
    assert.match(list.stdout, /package\/bin\/tokentimer-agent-host-amd64\.exe/);
    assert.match(list.stdout, /package\/bin\/tokentimer-agent-host-arm64\.exe/);
    for (const arch of ["amd64", "arm64"])
      assert.ok(
        list.stdout.includes(`package/bin/tokentimer-adcs-chain-${arch}.exe`),
      );
    for (const arch of ["amd64", "arm64"])
      assert.ok(list.stdout.includes(`package/bin/tokentimer-adcs-cmc-${arch}.exe`));
    assert.doesNotMatch(list.stdout, /reference\/adcs-chain\/dist/);
    assert.doesNotMatch(
      list.stdout,
      /package\/bin\/tokentimer-adcs-chain\.exe/,
    );
    const executableEntries = list.stdout
      .split(/\r?\n/)
      .filter((file) => file.endsWith(".exe"));
    assert.equal(
      executableEntries.length,
      6,
      "Only two service hosts, two chain helpers and two CMC helpers may ship",
    );
    const extracted = path.join(outDir, "extracted");
    fs.mkdirSync(extracted);
    assert.equal(
      spawnSync("tar", ["-xzf", result.tarballPath, "-C", extracted]).status,
      0,
    );
    const { assertPeArchitecture } = require("./build-windows-chain-helper");
    const {
      resolveAdcsChainHelperPath,
    } = require("../src/issuers/chain-helper");
    for (const [runtimeArch, arch] of [
      ["x64", "amd64"],
      ["arm64", "arm64"],
    ]) {
      const cmc = path.join(extracted, "package", "bin", `tokentimer-adcs-cmc-${arch}.exe`);
      assertPeArchitecture(cmc, arch);
      assert.deepEqual(require("../src/issuers/adcs-enrollment").resolveAdcsCmcHelperPath({
        packageRoot: path.join(extracted, "package"), platform: "win32", arch: runtimeArch,
      }), { path: cmc });
      const expected = path.join(
        extracted,
        "package",
        "bin",
        `tokentimer-adcs-chain-${arch}.exe`,
      );
      assertPeArchitecture(expected, arch);
      assert.deepEqual(
        resolveAdcsChainHelperPath({
          packageRoot: path.join(extracted, "package"),
          platform: "win32",
          arch: runtimeArch,
        }),
        { path: expected },
      );
    }

    assert.equal(
      fs.existsSync(path.join(outDir, "tokentimer-agent-host-amd64.exe")),
      false,
      "host exe must not land in pack --out-dir",
    );
    assert.ok(
      fs.existsSync(
        path.join(
          path.resolve(__dirname, "..", "bin"),
          "tokentimer-agent-host-amd64.exe",
        ),
      ),
      "host exe must be built into packages/agent/bin/",
    );
  });

  it("assertNoPrivateKeyMaterial rejects a tarball containing a private key", () => {
    const scratchDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "tokentimer-agent-release-bad-"),
    );
    try {
      const payloadDir = path.join(scratchDir, "payload");
      fs.mkdirSync(payloadDir, { recursive: true });
      fs.writeFileSync(
        path.join(payloadDir, "oops.key.pem"),
        "-----BEGIN PRIVATE KEY-----\nMIIBVQ==\n-----END PRIVATE KEY-----\n",
      );
      const badTarball = path.join(scratchDir, "bad.tgz");
      const tarResult = spawnSync(
        "tar",
        ["-czf", badTarball, "-C", payloadDir, "."],
        {
          encoding: "utf8",
        },
      );
      assert.equal(tarResult.status, 0);

      assert.throws(
        () => assertNoPrivateKeyMaterial(badTarball),
        /private-key material/,
      );
    } finally {
      fs.rmSync(scratchDir, { recursive: true, force: true });
    }
  });
});
