"use strict";
/* Build a genuine immutable historical-source Windows agent package for the upgrade qualification
 * workflow. Verifies historical source provenance and compiles both native helpers from that
 * checkout; it does not relabel candidate binaries as a published historical artifact.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const historical = Object.freeze({ tag: "v0.17.2", version: "0.17.2",
  commit: "6c902405c7b5d229e2f47b4d5436d780e91c5e17", tagObject: "853ac07cce5d3ea01900c1cdfa7ad32c070d3b49",
  publishedArchiveSha256: "c602fe36825c74d423c2c9b89680df3b1ac76542f71804de14dc5e2ec5aa85bf" });
const sha = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
function run(program, args, options) {
  const result = spawnSync(program, args, { encoding: "utf8", timeout: 300000, ...options });
  assert.ifError(result.error);
  assert.equal(result.status, 0, "historical source build command failed; raw subprocess output is withheld");
  return result.stdout.trim();
}
function prepare(sourceDir, outputDir) {
  sourceDir = path.resolve(sourceDir); outputDir = path.resolve(outputDir);
  assert.equal(run("git", ["-c", `safe.directory=${sourceDir}`, "rev-parse", "HEAD"], { cwd: sourceDir }), historical.commit);
  assert.equal(run("git", ["-c", `safe.directory=${sourceDir}`, "status", "--porcelain"], { cwd: sourceDir }), "", "historical source checkout must be pristine before build");
  const agent = path.join(sourceDir, "packages/agent");
  assert.equal(JSON.parse(fs.readFileSync(path.join(agent, "package.json"))).version, historical.version);
  assert.equal(fs.existsSync(outputDir), false, "refuse an existing historical package destination");
  fs.mkdirSync(outputDir, { recursive: true });
  // Both binaries come exclusively from the immutable historical module;
  // no current checkout executable is copied into this package.
  run(process.execPath, [path.join(agent, "scripts/build-windows-service-host.js")], { cwd: agent });
  run(process.execPath, [path.join(agent, "scripts/pack-release.js"), "--out-dir", outputDir], { cwd: agent });
  const archive = path.join(outputDir, `tokentimer-agent-${historical.version}.tgz`);
  const checksum = `${archive}.sha256`;
  const digest = require("../packages/agent/scripts/host/package-fixture").verifyArchiveDigest(archive, checksum);
  const listing = run("tar.exe", ["-tzf", archive]);
  for (const arch of ["amd64", "arm64"]) assert.ok(listing.split(/\r?\n/).includes(`package/bin/tokentimer-agent-host-${arch}.exe`));
  const evidence = { provenance: "historical-source-build", ...historical, archiveSha256: digest,
    publishedArchiveUsedForInstallation: false, helpers: {} };
  for (const arch of ["amd64", "arm64"]) evidence.helpers[arch] = sha(path.join(agent, "bin", `tokentimer-agent-host-${arch}.exe`));
  fs.writeFileSync(path.join(outputDir, "historical-source-build.json"), JSON.stringify(evidence));
  return evidence;
}
if (require.main === module) {
  try { prepare(process.argv[2], process.argv[3]); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { prepare, historical };
