"use strict";

const { describe, it, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { main, sha256File } = require("./pack-release.js");

describe("pack-release (H10)", () => {
  let outDir;

  after(() => {
    if (outDir) fs.rmSync(outDir, { recursive: true, force: true });
  });

  it("builds a versioned tarball and matching sha256 sidecar", () => {
    outDir = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-agent-release-"));
    const result = main([`--out-dir=${outDir}`]);
    assert.equal(result.version, "0.11.0");
    assert.ok(fs.existsSync(result.tarballPath));
    assert.ok(fs.existsSync(result.checksumPath));
    assert.match(path.basename(result.tarballPath), /tokentimer-agent-0\.11\.0\.tgz$/);

    const checksum = fs.readFileSync(result.checksumPath, "utf8").trim();
    assert.equal(checksum, `${result.digest}  ${path.basename(result.tarballPath)}`);
    assert.equal(sha256File(result.tarballPath), result.digest);
  });
});
