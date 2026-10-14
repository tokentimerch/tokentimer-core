"use strict";
/* Read-only historical public Windows archive provenance/checksum/package verifier used by
 * upgrade qualification. Missing shipped helpers fail explicitly; it never injects current
 * binaries into a historical release or claims source-built artifacts were published.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { historical } = require("./certops-historical-windows-package");
const { verifyArchiveDigest } = require("../packages/agent/scripts/host/package-fixture");
function inspect(archive, checksum) {
  const archiveSha256 = verifyArchiveDigest(archive, checksum);
  assert.equal(path.basename(archive), `tokentimer-agent-${historical.version}.tgz`);
  assert.equal(archiveSha256, historical.publishedArchiveSha256, "published baseline must match independently pinned public asset digest");
  const listing = spawnSync(process.platform === "win32" ? "tar.exe" : "tar", ["-tzf", archive], { encoding: "utf8", timeout: 30000 });
  assert.ifError(listing.error); assert.equal(listing.status, 0);
  const members = listing.stdout.split(/\r?\n/).filter(Boolean);
  assert.ok(members.every((name) => name.startsWith("package/") && !name.includes("\\") && !name.split("/").includes("..")), "unsafe archive member");
  const packageJson = spawnSync(process.platform === "win32" ? "tar.exe" : "tar", ["-xOf", archive, "package/package.json"], { encoding: "utf8", timeout: 30000 });
  assert.ifError(packageJson.error); assert.equal(packageJson.status, 0);
  assert.equal(JSON.parse(packageJson.stdout).version, historical.version);
  const missingHelpers = ["amd64", "arm64"].map((arch) => `package/bin/tokentimer-agent-host-${arch}.exe`).filter((name) => !members.includes(name));
  return { schemaVersion: 1, provenance: "published-release-archive", tag: historical.tag, archiveSha256,
    checksumVerified: true, versionVerified: true, signatureQualified: false,
    missingHelpers, status: missingHelpers.length ? "blocked" : "prerequisites-present", actualUpgradeExecuted: false };
}
if (require.main === module) {
  try {
    const result = inspect(process.argv[2], process.argv[3]);
    fs.mkdirSync(path.dirname(process.argv[4]), { recursive: true });
    fs.writeFileSync(process.argv[4], JSON.stringify(result));
    if (result.missingHelpers.length) throw new Error("Published Windows upgrade baseline is incomplete: both released service-host architectures are mandatory; no current binary substitution is permitted");
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { inspect };
