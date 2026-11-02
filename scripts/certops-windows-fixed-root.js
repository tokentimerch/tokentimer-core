"use strict";
/** Manual fresh-host canonical installer producer; no ACME or private provider
 * prerequisites. The native lifecycle sidecar and protocol executions are both
 * mandatory. This is candidate reapplication, not published upgrade evidence. */
const assert = require("node:assert/strict"), fs = require("node:fs"), { spawnSync } = require("node:child_process");
const fixture = require("../tests/e2e/helpers/certops-windows-fixed-root");
const journey = "real Windows canonical root: unmodified installer registers restarts reapplies and uninstalls";
const scope = "windows-canonical-root-protocol";
function main() {
  if (process.argv[2] === "--local-contract") {
    try {
      let result;
      if (process.argv[3]) {
        const body = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
        const manifest = fixture.createRunManifest(body);
        result = fixture.preserveExistingFixedRoot(manifest, body.observed);
        if (Array.isArray(body.extraCommands)) fixture.assertPlanDoesNotRewrite(manifest, body.extraCommands);
        result = { passed: false, nativeQualified: false, planSafe: true, proof: result.proof };
        process.stdout.write(`${JSON.stringify(result)}\n`);
        return;
      }
      result = fixture.runLocal({
        probe: fixture.probeLocalHost(),
        execute: process.env.CERTOPS_WINDOWS_FIXED_ROOT_LOCAL_EXECUTE === "1",
      });
      process.stdout.write(`${JSON.stringify(result)}\n`);
    } catch (error) {
      process.stdout.write(`${JSON.stringify({ passed: false, nativeQualified: false, reason: error.message })}\n`);
    }
    process.exitCode = 1;
    return;
  }
  assert.equal(process.platform, "win32");
  fs.mkdirSync("qualification-results", { recursive: true });
  const report = "qualification-results/windows-canonical-root-protocol.jsonl";
  const result = spawnSync(process.execPath, ["--test", "--test-reporter=./scripts/certops-stack-reporter.js", `--test-reporter-destination=${report}`, "tests/e2e/certops-agent-e2e.test.js"], { stdio: "inherit", timeout: 1200000, env: { ...process.env, CERTOPS_E2E_REQUIRED: "1", CERTOPS_REAL_WINDOWS_FIXED_ROOT_REQUIRED: "1", CERTOPS_REAL_WINDOWS_REQUIRED: "0", CERTOPS_CSR_DISPOSABLE_STACK: "1", CERTOPS_REPORT_SCOPE: scope } });
  assert.ifError(result.error); assert.equal(result.status, 0, "Canonical root native lifecycle failed");
  require("./certops-stack-report").verify(fs.readFileSync(report, "utf8"), [...require("../tests/e2e/agent-protocol-required-tests.json").requiredTests, journey], "certops-agent-e2e.test.js", scope);
  const native = JSON.parse(fs.readFileSync("qualification-results/windows-canonical-root.json", "utf8"));
  assert.equal(native.suite, fixture.suite);
  assert.deepEqual(require("./certops-qualification-report").verifyReport(native, fixture.requiredScenarios), []);
  fixture.verifyProof(native.nativeCanonicalRoot);
  const rollback = require("../tests/e2e/helpers/certops-windows-cli-second-rename");
  const cli = JSON.parse(fs.readFileSync("qualification-results/windows-cli-second-rename.json", "utf8"));
  assert.equal(cli.suite, rollback.suite); assert.deepEqual(require("./certops-qualification-report").verifyReport(cli, rollback.requiredScenarios), []); rollback.verifyProof(cli.nativeCliSecondRename);
  console.log("Canonical root lifecycle, full CLI rollback and protocol reports verified");
}
if (require.main === module) { try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; } }
module.exports = { main, journey, scope, runLocal: (options) => fixture.runLocal(options) };
