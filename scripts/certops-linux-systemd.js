/**
 * Entry point for installed Linux agent qualification on an owned GitHub-hosted VM.
 * certops-linux-systemd.yml authorizes native installer/systemd and write-path changes.
 * The child journey must emit every mandatory case; cleanup uses the separately proved
 * unit/process ownership receipt. This must not run on a shared developer machine. */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const { spawnSync } = require("node:child_process");
const { verify } = require("./certops-stack-report");
const required = require("../tests/e2e/agent-protocol-required-tests.json").requiredTests;
const journey = "real Linux systemd: installer registers non-root agent protects credentials recovers and retires without restart";
async function main() {
  assert.equal(process.platform, "linux");
  assert.equal(process.getuid(), 0);
  require("./certops-linux-systemd-ownership").validateHostedEnvironment(process.env);
  assert.equal(process.env.CERTOPS_PROTOCOL_DISPOSABLE_STACK, "1");
  assert.equal(process.env.CERTOPS_LINUX_SYSTEMD_DISPOSABLE_HOST, "1");
  fs.mkdirSync("qualification-results", { recursive: true });
  const report = "qualification-results/linux-systemd.jsonl";
  const scope = "real-agent-linux-systemd";
  // The native test includes a second actual installer run and two additional
  // service restarts; keep two minutes outside its ten-minute deadline for protocol/report work.
  const result = spawnSync(process.execPath, ["--test", "--test-reporter=./scripts/certops-stack-reporter.js",
    `--test-reporter-destination=${report}`, "tests/e2e/certops-agent-e2e.test.js"], {
    stdio: "inherit", timeout: 720000,
    env: { ...process.env, CERTOPS_E2E_REQUIRED: "1", CERTOPS_REAL_LINUX_SYSTEMD_REQUIRED: "1", CERTOPS_REPORT_SCOPE: scope },
  });
  assert.equal(result.status, 0, "real Linux installer/systemd suite failed");
  const writeReport=JSON.parse(fs.readFileSync("qualification-results/linux-systemd-writepath.json","utf8"));assert.equal(writeReport.suite,"linux-systemd-writepath");assert.deepEqual(require("./certops-qualification-report").verifyReport(writeReport,["linux-systemd-native-writepath-allowed-peer-erofs","linux-systemd-native-writepath-owned-cleanup"]),[]);
  const reapplyReport=JSON.parse(fs.readFileSync("qualification-results/linux-systemd-reapply.json","utf8"));assert.equal(reapplyReport.suite,"linux-systemd-reapply");assert.deepEqual(require("./certops-qualification-report").verifyReport(reapplyReport),[]);require("../tests/e2e/helpers/linux-systemd-reapply").verifyProof(reapplyReport.nativeInstallerReapply);
  console.log(JSON.stringify(verify(fs.readFileSync(report, "utf8"), [...required, journey], "certops-agent-e2e.test.js", scope)));
}
module.exports = { main, journey };
if (require.main === module) main().catch((error) => { console.error(error.message); process.exitCode = 1; });
