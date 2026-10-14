"use strict";
/** Manual fresh-host canonical installer producer; no ACME or private provider
 * prerequisites. The native lifecycle sidecar and protocol executions are both
 * mandatory. This is candidate reapplication, not published upgrade evidence. */
const assert = require("node:assert/strict"), fs = require("node:fs"), { spawnSync } = require("node:child_process");
const fixture = require("../tests/e2e/helpers/certops-windows-fixed-root");
const journey = "real Windows canonical root: unmodified installer registers restarts reapplies and uninstalls";
const scope = "windows-canonical-root-protocol";
function main() {
  assert.equal(process.platform, "win32");
  fs.mkdirSync("qualification-results", { recursive: true });
  const report = "qualification-results/windows-canonical-root-protocol.jsonl";
  const result = spawnSync(process.execPath, ["--test", "--test-reporter=./scripts/certops-stack-reporter.js", `--test-reporter-destination=${report}`, "tests/e2e/certops-agent-e2e.test.js"], { stdio: "inherit", timeout: 900000, env: { ...process.env, CERTOPS_E2E_REQUIRED: "1", CERTOPS_REAL_WINDOWS_FIXED_ROOT_REQUIRED: "1", CERTOPS_REAL_WINDOWS_REQUIRED: "0", CERTOPS_CSR_DISPOSABLE_STACK: "1", CERTOPS_REPORT_SCOPE: scope } });
  assert.ifError(result.error); assert.equal(result.status, 0, "Canonical root native lifecycle failed");
  require("./certops-stack-report").verify(fs.readFileSync(report, "utf8"), [...require("../tests/e2e/agent-protocol-required-tests.json").requiredTests, journey], "certops-agent-e2e.test.js", scope);
  const native = JSON.parse(fs.readFileSync("qualification-results/windows-canonical-root.json", "utf8"));
  assert.equal(native.suite, fixture.suite);
  assert.deepEqual(require("./certops-qualification-report").verifyReport(native, fixture.requiredScenarios), []);
  fixture.verifyProof(native.nativeCanonicalRoot);
  console.log("Canonical root native lifecycle and protocol reports verified");
}
if (require.main === module) { try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; } }
module.exports = { main, journey, scope };
