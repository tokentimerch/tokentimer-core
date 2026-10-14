"use strict";
/** Actual Windows source-oplock/copy/swap control using only temporary public
 * files. No installer top-level, service, registry or certificate operation runs.
 * This proves external interception mechanics, never full installer coverage. */
const assert = require("node:assert/strict"), fs = require("node:fs"), os = require("node:os"), path = require("node:path");
async function main() {
  assert.equal(process.platform, "win32");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-cli-oplock-support-"));
  fs.mkdirSync(path.join(root, "app")); fs.writeFileSync(path.join(root, "app/version.txt"), "original-public-version");
  const source = path.join(root, "candidate"); fs.mkdirSync(path.join(source, "bin"), { recursive: true });
  const file = path.join(source, "bin/tokentimer-agent.js"); fs.writeFileSync(file, "public candidate source control");
  let success = false;
  try {
    const mechanics = await require("../tests/e2e/helpers/certops-windows-cli-oplock").runFault({ installer: path.join(__dirname, "certops-cli-oplock-support-worker.ps1"), installerArgs: ["-InstallerSource", path.resolve(__dirname, "../packages/agent/scripts/install-agent.ps1"), "-PackageDirectory", source, "-InstallRoot", root], sourceFile: file, installRoot: root, protocolParent: root });
    assert.equal(fs.readFileSync(path.join(root, "app/version.txt"), "utf8"), "original-public-version");
    console.log(JSON.stringify({ scope: "temporary-native-source-oplock-production-functions-not-installer-cli", mechanics })); success = true;
  } finally {
    // Failure deliberately preserves the directory for bounded diagnosis; the
    // orchestrator already verifies/drains each exact child before returning.
    if (success) { const target = path.resolve(root), parent = path.resolve(os.tmpdir()); assert.ok(target.startsWith(parent + path.sep) && path.basename(target).startsWith("certops-cli-oplock-support-")); fs.rmSync(target, { recursive: true }); }
  }
}
if (require.main === module) main().catch(error => { console.error(error.message); process.exitCode = 1; });
module.exports = { main };
