"use strict";
/** Benign cold-start counterexample in a fresh Node process. Delay only the owned
 * wrapper, then execute the unchanged containment driver and actual temporary
 * activation control. This is supporting filesystem coverage, not qualification
 * of an installed service or certificate operation. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const childProcess = require("node:child_process");
const support = require("./certops-installer-second-rename-support");
async function main() {
  assert.equal(process.platform, "win32");
  const driver =
    require.resolve("../tests/e2e/helpers/certops-windows-contained-process.ps1");
  assert.equal(
    require.cache[
      require.resolve("../tests/e2e/helpers/certops-windows-contained-process")
    ],
    undefined,
    "Cold-start control requires a fresh Node process",
  );
  const spawn = childProcess.spawn;
  let delayed = false;
  childProcess.spawn = function (executable, args, options) {
    const file = args.indexOf("-File");
    if (
      file >= 0 &&
      args[file + 1] === driver &&
      args.includes("-ProtocolDirectory")
    ) {
      assert.equal(delayed, false);
      const protocol = args[args.indexOf("-ProtocolDirectory") + 1];
      const root = path.dirname(protocol);
      assert.equal(fs.realpathSync.native(root), root);
      assert.equal(path.dirname(root), fs.realpathSync.native(os.tmpdir()));
      assert.match(path.basename(root), /^certops-second-rename-support-/);
      assert.match(path.basename(protocol), /^\.contained-process-/);
      const wrapper = path.join(root, "cold-start-wrapper.ps1");
      fs.writeFileSync(
        wrapper,
        `param([string]$Original,[string]$ProtocolDirectory,[string]$Token,[int]$OwnerProcessId,[string]$OwnerSha256)
Start-Sleep -Seconds 35
. $Original -ProtocolDirectory $ProtocolDirectory -Token $Token -OwnerProcessId $OwnerProcessId -OwnerSha256 $OwnerSha256
`,
        { flag: "wx" },
      );
      args = [
        ...args.slice(0, file + 1),
        wrapper,
        "-Original",
        driver,
        ...args.slice(file + 2),
      ];
      delayed = true;
    }
    return spawn.call(childProcess, executable, args, options);
  };
  try {
    await support.main();
    assert.equal(
      delayed,
      true,
      "The actual owned wrapper must cross the old readiness deadline",
    );
    console.log(
      "Cold-start installer control passed after delayed readiness and actual owned restoration",
    );
  } finally {
    childProcess.spawn = spawn;
  }
}
if (require.main === module)
  main().catch((error) => {
    console.error(
      "Cold-start installer control failed: " +
        JSON.stringify(support.failureSummary(error)),
    );
    process.exitCode = 1;
  });
module.exports = { main };
