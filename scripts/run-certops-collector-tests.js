"use strict";
/** Discover only the repository's narrowly named pure collector regressions.
 * The original trust/archive suite is mandatory; no native fixture is executed.
 * A shared three-minute deadline bounds all children and failures propagate. */
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), { spawnSync } = require("node:child_process");
const MAX_COLLECTOR_MODULES = 64;
function discover(root = path.resolve(__dirname, "..")) {
  const files = fs.readdirSync(path.join(root, "scripts"), { withFileTypes: true }).filter(entry => entry.isFile() && /^certops-[a-z0-9-]+-collector\.test\.py$/.test(entry.name)).map(entry => `scripts/${entry.name}`).sort();
  assert.ok(files.includes("scripts/certops-release-collector.test.py"), "Original release collector regressions are mandatory");
  // Reserve expansion room for new lifecycle collectors while retaining the
  // same three-minute deadline across all child processes.
  assert.ok(files.length <= MAX_COLLECTOR_MODULES, "Collector regression discovery exceeds reviewed bound");
  return files;
}
function main({ root = path.resolve(__dirname, ".."), run = spawnSync, now = Date.now } = {}) {
  const files = discover(root), deadline = now() + 180000;
  for (const file of files) {
    const timeout = deadline - now(); assert.ok(timeout > 0, "Collector regressions exceeded their shared deadline");
    const result = run(process.platform === "win32" ? "python" : "python3", [file], { cwd: root, stdio: "inherit", windowsHide: true, timeout });
    assert.ok(!result.error && result.status === 0, "Collector regression failed or exceeded its bound");
  }
  return files;
}
if (require.main === module) { try { main(); } catch { console.error("Collector regression discovery/execution failed"); process.exitCode = 1; } }
module.exports = { discover, main, MAX_COLLECTOR_MODULES };
