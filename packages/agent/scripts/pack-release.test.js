"use strict";

const { describe, it, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { main, sha256File, assertNoPrivateKeyMaterial } = require("./pack-release.js");

const packageJsonPath = path.resolve(__dirname, "..", "package.json");
const expectedVersion = JSON.parse(fs.readFileSync(packageJsonPath, "utf8")).version;

describe("pack-release (H10)", () => {
  let outDir;

  after(() => {
    if (outDir) fs.rmSync(outDir, { recursive: true, force: true });
  });

  it("builds a versioned tarball and matching sha256 sidecar", () => {
    outDir = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-agent-release-"));
    const result = main([`--out-dir=${outDir}`]);
    assert.equal(result.version, expectedVersion);
    assert.ok(fs.existsSync(result.tarballPath));
    assert.ok(fs.existsSync(result.checksumPath));
    assert.match(
      path.basename(result.tarballPath),
      new RegExp(`tokentimer-agent-${expectedVersion.replace(/\./g, "\\.")}\\.tgz$`),
    );

    const checksum = fs.readFileSync(result.checksumPath, "utf8").trim();
    assert.equal(checksum, `${result.digest}  ${path.basename(result.tarballPath)}`);
    assert.equal(sha256File(result.tarballPath), result.digest);
  });

  it("the real packed tarball contains no private-key material (fixtures excluded)", () => {
    // Regression guard for the release blocker where src/verify/fixtures/*.key.pem
    // (test-only X.509 fixtures) shipped inside the production npm tarball.
    outDir = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-agent-release-scan-"));
    const result = main([`--out-dir=${outDir}`]);
    assert.doesNotThrow(() => assertNoPrivateKeyMaterial(result.tarballPath));

    const list = spawnSync("tar", ["-tzf", result.tarballPath], { encoding: "utf8" });
    assert.equal(list.status, 0);
    assert.doesNotMatch(list.stdout, /\.key\.pem$/m);
    assert.doesNotMatch(list.stdout, /fixtures\//);
  });

  it("ships Windows service host binaries under package/bin, not --out-dir", () => {
    // Regression for pack-agent writing tokentimer-agent-host-*.exe into
    // agent-dist/ (inherited --out-dir) so released tarballs omitted them
    // and install-agent.ps1 failed without a local rebuild.
    outDir = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-agent-release-host-"));
    const result = main([`--out-dir=${outDir}`]);
    const list = spawnSync("tar", ["-tzf", result.tarballPath], { encoding: "utf8" });
    assert.equal(list.status, 0);
    assert.match(list.stdout, /package\/bin\/tokentimer-agent-host-amd64\.exe/);
    assert.match(list.stdout, /package\/bin\/tokentimer-agent-host-arm64\.exe/);
    assert.equal(
      fs.existsSync(path.join(outDir, "tokentimer-agent-host-amd64.exe")),
      false,
      "host exe must not land in pack --out-dir",
    );
    assert.ok(
      fs.existsSync(
        path.join(path.resolve(__dirname, "..", "bin"), "tokentimer-agent-host-amd64.exe"),
      ),
      "host exe must be built into packages/agent/bin/",
    );
  });

  it("assertNoPrivateKeyMaterial rejects a tarball containing a private key", () => {
    const scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-agent-release-bad-"));
    try {
      const payloadDir = path.join(scratchDir, "payload");
      fs.mkdirSync(payloadDir, { recursive: true });
      fs.writeFileSync(
        path.join(payloadDir, "oops.key.pem"),
        "-----BEGIN PRIVATE KEY-----\nMIIBVQ==\n-----END PRIVATE KEY-----\n",
      );
      const badTarball = path.join(scratchDir, "bad.tgz");
      const tarResult = spawnSync("tar", ["-czf", badTarball, "-C", payloadDir, "."], {
        encoding: "utf8",
      });
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
