"use strict";
/* Windows journey producer invoked by the trusted manual Windows workflow. Starts only owned
 * Pebble processes and forwards the candidate environment to the public protocol/API suite;
 * reports installed-agent evidence separately from temporary CA fixture startup.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const { spawnSync } = require("node:child_process");
const { withPebble } = require("./certops-real-acme");
const { verify } = require("./certops-stack-report");
const required = require("../tests/e2e/agent-protocol-required-tests.json").requiredTests;
const journey = "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence";
async function main() {
  assert.equal(process.platform, "win32");
  const keyProfile = process.env.CERTOPS_WINDOWS_KEY_PROFILE || "rsa-2048";
  assert.ok(["rsa-2048", "rsa-3072", "rsa-4096", "ec-p256", "ec-p384"].includes(keyProfile));
  const scope = `real-agent-windows-acme-iis/${keyProfile}`;
  fs.mkdirSync("qualification-results", { recursive: true });
  await withPebble(async (fixtureEnv) => {
    const report = `qualification-results/windows-real-${keyProfile}.jsonl`;
    const result = spawnSync(process.execPath, ["--test", "--test-reporter=./scripts/certops-stack-reporter.js", `--test-reporter-destination=${report}`, "tests/e2e/certops-agent-e2e.test.js"], { stdio: "inherit", timeout: 1200000, env: { ...process.env, ...fixtureEnv, CERTOPS_E2E_REQUIRED: "1", CERTOPS_REAL_WINDOWS_REQUIRED: "1", CERTOPS_CSR_DISPOSABLE_STACK: "1", CERTOPS_REPORT_SCOPE: scope } });
    assert.equal(result.status, 0, "Windows installed-agent journey failed");
    const adoption = JSON.parse(fs.readFileSync(`qualification-results/windows-adoption-${keyProfile}.json`, "utf8"));
    assert.equal(adoption.suite, "windows-adoption-retention-real");
    const adoptionResult = require("./certops-qualification-report").verifyReport(adoption, require("../tests/e2e/windows-adoption-retention-journey").requiredScenarios);
    assert.deepEqual(adoptionResult, [], JSON.stringify(adoptionResult));
    verify(fs.readFileSync(report, "utf8"), [...required, journey], "certops-agent-e2e.test.js", scope);
    console.log("Windows installed-agent qualification report verified");
  });
}
if (require.main === module) main().catch((error) => { console.error(error.message); process.exitCode = 1; });
module.exports = { main };
