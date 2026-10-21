"use strict";
/** Explicit Windows supporting regression, invoked by the PowerShell installer
 * filesystem check. Creates only a unique temporary app/package, runs the real
 * activation-function fault driver, and removes files after verified child exit.
 * It never installs, queries or changes a service/certificate/registry setting. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os");
async function main() {
  assert.equal(process.platform, "win32");
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "certops-second-rename-support-"),
  );
  const app = path.join(root, "app"),
    pkg = path.join(root, "candidate");
  fs.mkdirSync(app);
  fs.mkdirSync(pkg);
  fs.writeFileSync(path.join(app, "version.txt"), "actual predecessor fixture");
  fs.writeFileSync(path.join(pkg, "version.txt"), "actual candidate fixture");
  let drained = false;
  try {
    const facts =
      await require("../tests/e2e/helpers/certops-windows-second-rename").runActivationFault(
        {
          repoRoot: path.resolve(__dirname, ".."),
          workDir: root,
          packageDir: pkg,
        },
      );
    drained = facts.ownedChildDrained;
    for (const field of [
      "childIdentityVerifiedBeforeActivation",
      "nativeOrderedRestoreEvents",
      "originalDirectoryIdentityRestored",
      "explicitStagingCleanupFailure",
      "predecessorFilesUnchanged",
      "nativeHandleReleased",
      "ownedStagingRemoved",
      "ownedChildDrained",
    ])
      assert.equal(facts[field], true, field);
    assert.equal(
      fs.readFileSync(path.join(app, "version.txt"), "utf8"),
      "actual predecessor fixture",
    );
    console.log(
      "Second-rename supporting regression passed: actual ordered native restoration events and temporary filesystem only",
    );
  } finally {
    // The protocol helper throws on uncertain process drainage. Retain its exact
    // temporary root for diagnostics rather than recursively deleting live state.
    if (drained) {
      assert.equal(path.dirname(root), path.resolve(os.tmpdir()));
      assert.match(path.basename(root), /^certops-second-rename-support-/);
      fs.rmSync(root, { recursive: true, force: true });
      assert.equal(fs.existsSync(root), false);
    }
  }
}
if (require.main === module)
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
module.exports = { main };
