"use strict";
/* Read-only historical public Windows archive provenance/checksum/package verifier used by
 * upgrade qualification. Missing shipped helpers fail explicitly; it never injects current
 * binaries into a historical release or claims source-built artifacts were published.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const published = Object.freeze({ tag: "v0.17.3", version: "0.17.3", releaseId: 406680731, assetId: 621428291, size: 410054, url: "https://github.com/tokentimerch/tokentimer-core/releases/download/v0.17.3/tokentimer-agent-0.17.3.tgz", publishedArchiveSha256: "ec74ed8e1026b7a76b50e0ddc843ee8dc42d1283923ff01be11603069f94c6bb" });
const { verifyArchiveDigest } = require("../packages/agent/scripts/host/package-fixture");
function verifyReleaseMetadata(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.equal(value.id, published.releaseId); assert.equal(value.tag_name, published.tag);
  assert.equal(value.draft, false); assert.equal(value.prerelease, false);
  assert.ok(Array.isArray(value.assets));
  const matches = value.assets.filter(asset => asset.name === `tokentimer-agent-${published.version}.tgz`);
  assert.equal(matches.length, 1, "Exactly one pinned public archive asset is required");
  const asset = matches[0]; assert.equal(asset.id, published.assetId); assert.equal(asset.size, published.size);
  assert.equal(asset.digest, `sha256:${published.publishedArchiveSha256}`); assert.equal(asset.browser_download_url, published.url);
  return true;
}
function inspect(archive, checksum, releaseMetadata) {
  verifyReleaseMetadata(releaseMetadata);
  const archiveSha256 = verifyArchiveDigest(archive, checksum);
  assert.equal(path.basename(archive), `tokentimer-agent-${published.version}.tgz`);
  assert.equal(archiveSha256, published.publishedArchiveSha256, "published baseline must match independently pinned public asset digest");
  assert.equal(fs.statSync(archive).size, published.size);
  const listing = spawnSync(process.platform === "win32" ? "tar.exe" : "tar", ["-tzf", archive], { encoding: "utf8", timeout: 30000 });
  assert.ifError(listing.error); assert.equal(listing.status, 0);
  const members = listing.stdout.split(/\r?\n/).filter(Boolean);
  assert.ok(members.every((name) => name.startsWith("package/") && !name.includes("\\") && !name.split("/").includes("..")), "unsafe archive member");
  const packageJson = spawnSync(process.platform === "win32" ? "tar.exe" : "tar", ["-xOf", archive, "package/package.json"], { encoding: "utf8", timeout: 30000 });
  assert.ifError(packageJson.error); assert.equal(packageJson.status, 0);
  assert.equal(JSON.parse(packageJson.stdout).version, published.version);
  const missingHelpers = ["amd64", "arm64"].map((arch) => `package/bin/tokentimer-agent-host-${arch}.exe`).filter((name) => !members.includes(name));
  return { schemaVersion: 1, provenance: "published-release-archive", tag: published.tag, archiveSha256,
    releaseMetadataVerified: true, publishedReleaseId: published.releaseId, publishedAssetId: published.assetId,
    checksumVerified: true, versionVerified: true, signatureQualified: false,
    missingHelpers, status: missingHelpers.length ? "blocked" : "prerequisites-present", actualUpgradeExecuted: false };
}
if (require.main === module) {
  try {
    assert.equal(process.argv.length, 6, "Archive, checksum, report and public release metadata are required");
    const result = inspect(process.argv[2], process.argv[3], JSON.parse(fs.readFileSync(process.argv[5], "utf8")));
    fs.mkdirSync(path.dirname(process.argv[4]), { recursive: true });
    fs.writeFileSync(process.argv[4], JSON.stringify(result));
    if (result.missingHelpers.length) throw new Error("Published Windows upgrade baseline is incomplete: both released service-host architectures are mandatory; no current binary substitution is permitted");
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { inspect, published, verifyReleaseMetadata };
