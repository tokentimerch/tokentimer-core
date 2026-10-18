"use strict";
/** Manual Azure-free installed failed-rollback producer. The installed native journey writes
 * facts only after its owned native/API/database cleanup succeeds. This producer
 * cannot turn an interrupted run or a partial sidecar into a passing report. */
const { createProducer } = require("./certops-windows-installed-producer");
module.exports = createProducer({
  proof: require("../tests/e2e/helpers/certops-windows-installed-failed-rollback"),
  SOURCES: require("./certops-windows-failed-rollback-sources"),
  SOURCE: "scripts/certops-windows-failed-rollback.js",
  SUITE: "windows-installed-failed-rollback-renewal",
  requiredFlag: "CERTOPS_WINDOWS_FAILED_ROLLBACK_REQUIRED",
  candidateMessage: "Stop/offline scope requires only current candidate",
  factsName: "windows-failed-rollback-native-facts.json",
  reportName: "windows-installed-failed-rollback.json",
  timeout: 1320000,
  scope: "real-agent-windows-failed-rollback/rsa-2048",
  failureMessage: "Installed failed-rollback journey failed",
  reportField: "nativeInstalledFailedRollback",
  readOwned:
    require("../tests/e2e/helpers/certops-windows-installed-verify-rollback")
      .readOwned,
});
if (require.main === module)
  module.exports.main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
